//! The sole network transport for DKG-backed ceremonies.
//!
//! Control messages and private shares use authenticated direct QUIC streams.
//! Public contributions are individually endpoint-signed, collected by the
//! canonical leader, and relayed in canonical batches over a transient Gossip
//! topic. Fresh DKG, refresh, and reshare all use this transport.

use async_trait::async_trait;
use bytes::Bytes;
use futures::{stream::FuturesUnordered, StreamExt};
use network::{Connection, Message, PeerId, ProtocolHandler, PubSubEvent, SignedPayload, Topic};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, Weak};
use tokio::task::JoinSet;
use tokio::time::{sleep, timeout, Duration, Instant};

use crate::app_state::AppState;
use crate::constants::{
    DKG_ATTEMPT_TIMEOUT, DKG_FORWARDED_START_RESPONSE_GRACE, DKG_GOSSIP_ISOLATION_GRACE,
    DKG_MAX_REPAIR_BACKOFF, DKG_PREPARATION_RETRY_MAX_BACKOFF, DKG_PREPARATION_TIMEOUT,
    DKG_REPAIR_STALL_INTERVAL, DKG_TOPOLOGY_PROBE_INTERVAL, MAX_DKG_COMMITTEE_SIZE,
    PEER_RESPONSE_TIMEOUT, PSS_GRACE_PERIOD_SECS,
};
use crate::dkg::v0::coordinator::evidence::{
    handle_invalid_commitment_evidence_relay, handle_invalid_share_evidence_relay,
};
use crate::dkg::v0::coordinator::message_handlers::{
    drive_accepted_share, handle_commitment_audit_message, handle_commitment_hash_message,
    handle_commitment_message, handle_reshare_participant_set, handle_reshare_share_ack,
    handle_session_init, preflight_commitment_audit_message, preflight_commitment_hash_message,
    preflight_commitment_message, preflight_reshare_participant_set,
};
use crate::dkg::v0::coordinator::refresh_health_check::{handle_result, preflight_result};
use crate::dkg::v0::coordinator::types::{CoordinatorDkg, CoordinatorReportSigner};
use crate::dkg::v0::coordinator::DkgCoordinator;
use crate::dkg::v0::error::{DkgError, Result};
use crate::dkg::v0::helpers::{
    derive_fresh_dkg_session_id, derive_refresh_session_id, derive_reshare_session_id,
    ring_payload_matches_ring_key, validate_fresh_dkg_ring_payload,
};
use crate::dkg::v0::messages::{SessionKind, SignedDkgCommitment, SignedDkgShare};
#[cfg(test)]
use crate::dkg::v0::session_state::CreateSessionOutcome;
use crate::dkg::v0::session_state::{
    MessageProcessingClaim, PublicBatchRecordOutcome, PublicContributionRecordOutcome,
    PublicRepairClaimOutcome, TopicTaskDisposition, TopologyAckRecordOutcome,
    TransportActivationOutcome, TransportBeginOutcome, TransportConfigureOutcome,
};
use crate::dkg::v0::transport::{
    self, AttemptId, AttemptKey, CeremonyConfig, CeremonyId, CommitteeConfig, CommitteeScope,
    DkgControlMessage, DkgPrivateMessage, DkgPublicContribution, DkgPublicMessage,
    DkgPublicPayload, MessageId, ParticipantRef, PhaseManifest, PrepareSession, PublicPhase,
    PUBLIC_CONTRIBUTION_SIGNING_DOMAIN,
};
use crate::helpers::auth::current_unix_time;
use crate::helpers::identity::{extract_node_part, is_self_peer_id, validate_peer_id};
use crate::helpers::node_routes::{
    canonical_node_id_assignments_from_node_keys, peer_ids_from_routes, resolve_node_routes,
    NodeRoute,
};
use crate::helpers::protocol_version::read_ring_for_route;
#[cfg(test)]
use crate::helpers::test_helpers::create_test_app_state_default;
use crate::metrics::{DkgCeremonyKind, PrivatePairMetricsGuard};
use crate::ring_state::RingShareBundle;
use bulletin::r#trait::RingPayload;
use crypto::SignImpl;

const MAX_CONTROL_MESSAGE_BYTES: usize = 2 * 1024 * 1024;
/// Keep repair pages comfortably below Iroh's current 1 MiB message ceiling.
const MAX_PUBLIC_REPAIR_PAGE_BYTES: usize = 512 * 1024;
const MAX_PUBLIC_COMMIT_RECEIPTS: usize = 4096;
const INITIAL_CONTROL_RETRY_BACKOFF: Duration = Duration::from_millis(250);
const INITIAL_PRIVATE_RETRY_BACKOFF: Duration = Duration::from_millis(100);
const PRIVATE_BUSY_RETRY_AFTER: Duration = Duration::from_millis(250);
const PRIVATE_INBOUND_QUEUE_WAIT: Duration = Duration::from_millis(500);

#[derive(Default)]
struct GossipNeighborTracker {
    neighbors: BTreeSet<String>,
    ever_had_neighbor: bool,
    isolation_deadline: Option<Instant>,
}

impl GossipNeighborTracker {
    fn neighbor_up(&mut self, peer: &PeerId) {
        self.neighbors.insert(hex::encode(peer.as_bytes()));
        self.ever_had_neighbor = true;
        self.isolation_deadline = None;
    }

    fn neighbor_down(&mut self, peer: &PeerId, now: Instant) -> bool {
        let removed = self.neighbors.remove(&hex::encode(peer.as_bytes()));
        if removed
            && self.neighbors.is_empty()
            && self.ever_had_neighbor
            && self.isolation_deadline.is_none()
        {
            self.isolation_deadline = Some(now + DKG_GOSSIP_ISOLATION_GRACE);
        }
        removed
    }

    fn isolation_deadline(&self) -> Option<Instant> {
        self.isolation_deadline
    }

    fn is_isolated(&self) -> bool {
        self.neighbors.is_empty() && self.ever_had_neighbor
    }

    fn reset_after_rejoin(&mut self) {
        self.neighbors.clear();
        self.ever_had_neighbor = false;
        self.isolation_deadline = None;
    }

    fn neighbor_count(&self) -> usize {
        self.neighbors.len()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PublicBatchMode {
    Complete,
    Incremental,
}

fn public_batch_mode(kind: &SessionKind, phase: PublicPhase) -> Option<PublicBatchMode> {
    match (kind, phase) {
        (SessionKind::Fresh, PublicPhase::CommitmentHashes | PublicPhase::Commitments)
        | (
            SessionKind::Refresh { .. },
            PublicPhase::Commitments | PublicPhase::RefreshHealthCheck,
        )
        | (SessionKind::Reshare { .. }, PublicPhase::ReshareParticipantSet) => {
            Some(PublicBatchMode::Complete)
        }
        (
            SessionKind::Refresh { .. } | SessionKind::Reshare { .. },
            PublicPhase::CommitmentAudit,
        )
        | (SessionKind::Reshare { .. }, PublicPhase::Commitments) => {
            Some(PublicBatchMode::Incremental)
        }
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PublicViolationAccused {
    Leader,
    Origin(ParticipantRef),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PublicProtocolViolationKind {
    MalformedLeaderMessage,
    MalformedOriginMessage,
    InvalidManifest,
    ConflictingManifest,
    InvalidChunk,
    ConflictingChunk,
    InvalidContribution,
    BatchMismatch,
    OriginEquivocation,
    BufferLimit,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PublicProtocolViolation {
    kind: PublicProtocolViolationKind,
    accused: PublicViolationAccused,
    phase: Option<PublicPhase>,
    root: Option<[u8; 32]>,
    message_ids: Vec<MessageId>,
    detail: String,
}

impl PublicProtocolViolation {
    fn leader(
        kind: PublicProtocolViolationKind,
        phase: Option<PublicPhase>,
        root: Option<[u8; 32]>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            accused: PublicViolationAccused::Leader,
            phase,
            root,
            message_ids: Vec::new(),
            detail: detail.into(),
        }
    }

    fn origin(
        phase: PublicPhase,
        root: Option<[u8; 32]>,
        origin: ParticipantRef,
        detail: impl Into<String>,
    ) -> Self {
        Self::origin_with_kind(
            PublicProtocolViolationKind::OriginEquivocation,
            phase,
            root,
            origin,
            detail,
        )
    }

    fn origin_with_kind(
        kind: PublicProtocolViolationKind,
        phase: PublicPhase,
        root: Option<[u8; 32]>,
        origin: ParticipantRef,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            accused: PublicViolationAccused::Origin(origin),
            phase: Some(phase),
            root,
            message_ids: Vec::new(),
            detail: detail.into(),
        }
    }

    fn with_message_ids(mut self, first: MessageId, second: MessageId) -> Self {
        self.message_ids = vec![first, second];
        self
    }

    fn with_message_id(mut self, message_id: MessageId) -> Self {
        self.message_ids = vec![message_id];
        self
    }
}

#[derive(Debug, Clone, PartialEq)]
struct VerifiedPublicContribution {
    signed: SignedPayload,
    contribution: DkgPublicContribution,
}

#[derive(Default)]
struct PendingPublicBatch {
    manifest: Option<ReceivedPublicManifest>,
    chunks: BTreeMap<u32, ReceivedPublicChunk>,
}

struct ReceivedPublicManifest {
    manifest: PhaseManifest,
    event_digest: [u8; 32],
}

struct ReceivedPublicChunk {
    contributions: Vec<VerifiedPublicContribution>,
    event_digest: [u8; 32],
}

struct CompletedPublicBatch {
    manifest_event_digest: [u8; 32],
    chunk_digests: BTreeMap<u32, [u8; 32]>,
}

#[derive(Debug)]
enum PublicBatchAssembly {
    Pending {
        manifest_added: bool,
    },
    Duplicate,
    Complete {
        phase: PublicPhase,
        root: [u8; 32],
        contributions: Vec<VerifiedPublicContribution>,
    },
}

#[derive(Default)]
struct ManifestRepairSchedule {
    deadlines: BTreeMap<PublicPhase, Instant>,
}

impl ManifestRepairSchedule {
    /// Arm one delayed repair per phase. Existing deadlines are deliberately
    /// not extended: a leader cannot postpone repair by dripping manifests.
    fn arm(&mut self, phase: PublicPhase, deadline: Instant) -> bool {
        if self.deadlines.contains_key(&phase) {
            return false;
        }
        self.deadlines.insert(phase, deadline);
        true
    }

    fn cancel(&mut self, phase: PublicPhase) -> bool {
        self.deadlines.remove(&phase).is_some()
    }

    fn next_deadline(&self) -> Option<Instant> {
        self.deadlines.values().copied().min()
    }

    fn take_due(&mut self, now: Instant) -> Vec<PublicPhase> {
        let due: Vec<_> = self
            .deadlines
            .iter()
            .filter_map(|(phase, deadline)| (*deadline <= now).then_some(*phase))
            .collect();
        for phase in &due {
            self.deadlines.remove(phase);
        }
        due
    }
}

#[derive(Default)]
struct PublicBatchAssembler {
    pending: HashMap<(PublicPhase, [u8; 32]), PendingPublicBatch>,
    completed: HashMap<(PublicPhase, [u8; 32]), CompletedPublicBatch>,
    complete_phase_roots: HashMap<PublicPhase, [u8; 32]>,
    observed_origins: HashMap<(PublicPhase, ParticipantRef), (MessageId, [u8; 32])>,
}

impl PublicBatchAssembler {
    fn insert_manifest(
        &mut self,
        mode: PublicBatchMode,
        manifest: PhaseManifest,
        event_digest: [u8; 32],
        expected_origins: &BTreeSet<ParticipantRef>,
    ) -> std::result::Result<PublicBatchAssembly, PublicProtocolViolation> {
        let phase = manifest.phase;
        let root = manifest.phase_root;
        manifest.validate(expected_origins).map_err(|detail| {
            PublicProtocolViolation::leader(
                PublicProtocolViolationKind::InvalidManifest,
                Some(phase),
                Some(root),
                detail,
            )
        })?;
        let expected_complete = mode == PublicBatchMode::Complete;
        if manifest.complete != expected_complete {
            return Err(PublicProtocolViolation::leader(
                PublicProtocolViolationKind::InvalidManifest,
                Some(phase),
                Some(root),
                format!(
                    "manifest complete={} does not match {mode:?} phase publication",
                    manifest.complete
                ),
            ));
        }

        let key = (phase, root);
        if let Some(completed) = self.completed.get(&key) {
            return if completed.manifest_event_digest == event_digest {
                Ok(PublicBatchAssembly::Duplicate)
            } else {
                Err(PublicProtocolViolation::leader(
                    PublicProtocolViolationKind::ConflictingManifest,
                    Some(phase),
                    Some(root),
                    "manifest metadata conflicts with a completed batch",
                ))
            };
        }
        if let Some(existing) = self
            .pending
            .get(&key)
            .and_then(|batch| batch.manifest.as_ref())
        {
            return if existing.manifest == manifest && existing.event_digest == event_digest {
                Ok(PublicBatchAssembly::Duplicate)
            } else {
                Err(PublicProtocolViolation::leader(
                    PublicProtocolViolationKind::ConflictingManifest,
                    Some(phase),
                    Some(root),
                    "manifest metadata conflicts for the same phase root",
                ))
            };
        }

        self.claim_phase_root(mode, phase, root, expected_origins.len())?;
        let buffered_manifest_entries: usize = self
            .pending
            .iter()
            .filter(|((candidate_phase, _), _)| *candidate_phase == phase)
            .filter_map(|(_, batch)| batch.manifest.as_ref())
            .map(|received| received.manifest.contribution_ids.len())
            .sum();
        if buffered_manifest_entries.saturating_add(manifest.contribution_ids.len())
            > expected_origins.len()
        {
            return Err(PublicProtocolViolation::leader(
                PublicProtocolViolationKind::BufferLimit,
                Some(phase),
                Some(root),
                format!(
                    "pending manifest entries exceed the expected origin count {}",
                    expected_origins.len()
                ),
            ));
        }
        self.pending.entry(key).or_default().manifest = Some(ReceivedPublicManifest {
            manifest,
            event_digest,
        });
        self.try_complete(key, true)
    }

    fn insert_chunk(
        &mut self,
        mode: PublicBatchMode,
        phase: PublicPhase,
        root: [u8; 32],
        index: u32,
        contributions: Vec<VerifiedPublicContribution>,
        event_digest: [u8; 32],
        expected_origin_count: usize,
    ) -> std::result::Result<PublicBatchAssembly, PublicProtocolViolation> {
        if contributions.is_empty() {
            return Err(PublicProtocolViolation::leader(
                PublicProtocolViolationKind::InvalidChunk,
                Some(phase),
                Some(root),
                "public batch chunk is empty",
            ));
        }
        if index as usize >= expected_origin_count {
            return Err(PublicProtocolViolation::leader(
                PublicProtocolViolationKind::BufferLimit,
                Some(phase),
                Some(root),
                format!(
                    "chunk index {index} exceeds the maximum {} chunks for this phase",
                    expected_origin_count
                ),
            ));
        }

        let key = (phase, root);
        if let Some(completed) = self.completed.get(&key) {
            return match completed.chunk_digests.get(&index) {
                Some(existing) if existing == &event_digest => Ok(PublicBatchAssembly::Duplicate),
                Some(_) => Err(PublicProtocolViolation::leader(
                    PublicProtocolViolationKind::ConflictingChunk,
                    Some(phase),
                    Some(root),
                    format!("chunk {index} conflicts with the completed batch"),
                )),
                None => Err(PublicProtocolViolation::leader(
                    PublicProtocolViolationKind::InvalidChunk,
                    Some(phase),
                    Some(root),
                    format!("extra chunk {index} follows the completed batch"),
                )),
            };
        }
        // For incremental publications, attribute a proven origin contradiction
        // before enforcing the root-count bound. For complete publications, claim
        // the single allowed root first so a second root remains an attributable
        // leader contradiction even when it contains an origin equivocation.
        if mode == PublicBatchMode::Incremental {
            self.ensure_no_origin_equivocation(phase, root, &contributions)?;
        }
        self.claim_phase_root(mode, phase, root, expected_origin_count)?;
        if mode == PublicBatchMode::Complete {
            self.ensure_no_origin_equivocation(phase, root, &contributions)?;
        }

        if let Some(existing) = self
            .pending
            .get(&key)
            .and_then(|batch| batch.chunks.get(&index))
        {
            return if existing.event_digest == event_digest
                && existing.contributions == contributions
            {
                Ok(PublicBatchAssembly::Duplicate)
            } else {
                Err(PublicProtocolViolation::leader(
                    PublicProtocolViolationKind::ConflictingChunk,
                    Some(phase),
                    Some(root),
                    format!("leader published different contents for chunk {index}"),
                ))
            };
        }
        let buffered_for_root: usize = self
            .pending
            .get(&key)
            .into_iter()
            .flat_map(|batch| batch.chunks.values())
            .map(|chunk| chunk.contributions.len())
            .sum();
        if buffered_for_root.saturating_add(contributions.len()) > expected_origin_count {
            return Err(PublicProtocolViolation::leader(
                PublicProtocolViolationKind::BufferLimit,
                Some(phase),
                Some(root),
                format!(
                    "buffered contributions exceed the expected origin count {expected_origin_count}"
                ),
            ));
        }
        let buffered_for_phase: usize = self
            .pending
            .iter()
            .filter(|((candidate_phase, _), _)| *candidate_phase == phase)
            .flat_map(|(_, batch)| batch.chunks.values())
            .map(|chunk| chunk.contributions.len())
            .sum();
        if buffered_for_phase.saturating_add(contributions.len()) > expected_origin_count {
            return Err(PublicProtocolViolation::leader(
                PublicProtocolViolationKind::BufferLimit,
                Some(phase),
                Some(root),
                format!(
                    "pending contributions exceed the expected origin count {expected_origin_count}"
                ),
            ));
        }
        for verified in &contributions {
            let contribution = &verified.contribution;
            self.observed_origins
                .entry((phase, contribution.origin))
                .or_insert((contribution.message_id, root));
        }
        self.pending.entry(key).or_default().chunks.insert(
            index,
            ReceivedPublicChunk {
                contributions,
                event_digest,
            },
        );
        self.try_complete(key, false)
    }

    fn ensure_no_origin_equivocation(
        &self,
        phase: PublicPhase,
        root: [u8; 32],
        contributions: &[VerifiedPublicContribution],
    ) -> std::result::Result<(), PublicProtocolViolation> {
        for verified in contributions {
            let contribution = &verified.contribution;
            let origin_key = (phase, contribution.origin);
            if let Some((existing_id, existing_root)) = self.observed_origins.get(&origin_key) {
                if existing_id != &contribution.message_id {
                    return Err(PublicProtocolViolation::origin(
                        phase,
                        Some(root),
                        contribution.origin,
                        "origin signed different messages for the same attempt and phase",
                    )
                    .with_message_ids(*existing_id, contribution.message_id));
                }
                if existing_root != &root {
                    return Err(PublicProtocolViolation::leader(
                        PublicProtocolViolationKind::BatchMismatch,
                        Some(phase),
                        Some(root),
                        format!(
                            "origin {:?} was repeated across incremental batch roots",
                            contribution.origin
                        ),
                    )
                    .with_message_id(contribution.message_id));
                }
            }
        }
        Ok(())
    }

    fn claim_phase_root(
        &mut self,
        mode: PublicBatchMode,
        phase: PublicPhase,
        root: [u8; 32],
        expected_origin_count: usize,
    ) -> std::result::Result<(), PublicProtocolViolation> {
        if mode == PublicBatchMode::Complete {
            if let Some(existing) = self.complete_phase_roots.get(&phase) {
                if existing != &root {
                    return Err(PublicProtocolViolation::leader(
                        PublicProtocolViolationKind::ConflictingManifest,
                        Some(phase),
                        Some(root),
                        format!(
                            "complete phase already committed to root {}",
                            hex::encode(existing)
                        ),
                    ));
                }
            } else {
                self.complete_phase_roots.insert(phase, root);
            }
            return Ok(());
        }

        let root_known = self.pending.contains_key(&(phase, root))
            || self.completed.contains_key(&(phase, root));
        if !root_known {
            let roots = self
                .pending
                .keys()
                .chain(self.completed.keys())
                .filter(|(candidate_phase, _)| *candidate_phase == phase)
                .count();
            if roots >= expected_origin_count {
                return Err(PublicProtocolViolation::leader(
                    PublicProtocolViolationKind::BufferLimit,
                    Some(phase),
                    Some(root),
                    format!(
                        "incremental phase exceeds its maximum {expected_origin_count} batch roots"
                    ),
                ));
            }
        }
        Ok(())
    }

    fn try_complete(
        &mut self,
        key: (PublicPhase, [u8; 32]),
        manifest_added: bool,
    ) -> std::result::Result<PublicBatchAssembly, PublicProtocolViolation> {
        let Some(batch) = self.pending.get(&key) else {
            return Ok(PublicBatchAssembly::Pending { manifest_added });
        };
        let Some(received_manifest) = batch.manifest.as_ref() else {
            return Ok(PublicBatchAssembly::Pending { manifest_added });
        };
        let manifest = &received_manifest.manifest;
        let chunk_count = manifest.chunk_count;
        if let Some(index) = batch
            .chunks
            .keys()
            .find(|index| **index >= chunk_count)
            .copied()
        {
            return Err(PublicProtocolViolation::leader(
                PublicProtocolViolationKind::InvalidChunk,
                Some(key.0),
                Some(key.1),
                format!("chunk index {index} is outside manifest chunk count {chunk_count}"),
            ));
        }
        if batch.chunks.len() < chunk_count as usize {
            return Ok(PublicBatchAssembly::Pending { manifest_added });
        }

        let batch = self
            .pending
            .remove(&key)
            .expect("the complete pending batch was checked above");
        let received_manifest = batch
            .manifest
            .expect("the complete pending batch has a manifest");
        let manifest = received_manifest.manifest;
        let mut contributions = Vec::new();
        let mut chunk_digests = BTreeMap::new();
        for index in 0..manifest.chunk_count {
            let chunk = batch.chunks.get(&index).ok_or_else(|| {
                PublicProtocolViolation::leader(
                    PublicProtocolViolationKind::InvalidChunk,
                    Some(key.0),
                    Some(key.1),
                    format!("manifest batch is missing chunk {index}"),
                )
            })?;
            chunk_digests.insert(index, chunk.event_digest);
            contributions.extend(chunk.contributions.iter().cloned());
        }

        let canonical_origins: Vec<_> = manifest.contribution_ids.keys().copied().collect();
        let actual_origins: Vec<_> = contributions
            .iter()
            .map(|verified| verified.contribution.origin)
            .collect();
        if actual_origins != canonical_origins {
            return Err(PublicProtocolViolation::leader(
                PublicProtocolViolationKind::BatchMismatch,
                Some(key.0),
                Some(key.1),
                "chunk contributions are not in the manifest's canonical origin order",
            ));
        }
        let actual_ids: BTreeMap<_, _> = contributions
            .iter()
            .map(|verified| {
                (
                    verified.contribution.origin,
                    verified.contribution.message_id,
                )
            })
            .collect();
        if actual_ids.len() != contributions.len() || actual_ids != manifest.contribution_ids {
            return Err(PublicProtocolViolation::leader(
                PublicProtocolViolationKind::BatchMismatch,
                Some(key.0),
                Some(key.1),
                "chunk contribution IDs do not match the manifest",
            ));
        }

        self.completed.insert(
            key,
            CompletedPublicBatch {
                manifest_event_digest: received_manifest.event_digest,
                chunk_digests,
            },
        );
        Ok(PublicBatchAssembly::Complete {
            phase: key.0,
            root: key.1,
            contributions,
        })
    }
}

fn authenticated_public_event_digest(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"orbis-dkg-authenticated-public-event-v1");
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    hasher.finalize().into()
}

fn missing_topology_peers(
    expected: &BTreeSet<String>,
    acknowledged: &BTreeSet<String>,
) -> Vec<String> {
    expected.difference(acknowledged).cloned().collect()
}

fn missing_topology_peer_prefixes(missing: &[String]) -> String {
    missing
        .iter()
        .map(|peer| peer.chars().take(12).collect::<String>())
        .collect::<Vec<_>>()
        .join(",")
}

async fn expected_public_origins<D>(
    state: &Arc<AppState<D>>,
    prepare: &PrepareSession,
    phase: PublicPhase,
) -> BTreeSet<ParticipantRef>
where
    D: CoordinatorDkg,
{
    if phase == PublicPhase::RefreshHealthCheck {
        return prepare
            .current_participant(&prepare.leader_node_key)
            .into_iter()
            .collect();
    }
    if phase == PublicPhase::ReshareParticipantSet {
        return BTreeSet::from([ParticipantRef::next(1)]);
    }
    if matches!(prepare.kind, SessionKind::Reshare { .. }) && phase == PublicPhase::CommitmentAudit
    {
        return prepare
            .committees
            .next
            .as_ref()
            .into_iter()
            .flat_map(|next| next.node_id_assignments.values().copied())
            .map(ParticipantRef::next)
            .collect();
    }
    if matches!(prepare.kind, SessionKind::Reshare { .. }) && phase == PublicPhase::Commitments {
        return state
            .dkg_session_state
            .transport_active_dealers(&prepare.ceremony_id.0)
            .await
            .unwrap_or_default()
            .into_iter()
            .collect();
    }
    prepare
        .committees
        .current
        .node_id_assignments
        .values()
        .copied()
        .map(ParticipantRef::current)
        .collect()
}

fn control_request_scope(
    request: &DkgControlMessage,
) -> (&'static str, Option<CeremonyId>, Option<AttemptId>) {
    match request {
        DkgControlMessage::StartFresh { .. } => ("start-fresh", None, None),
        DkgControlMessage::StartReshare { .. } => ("start-reshare", None, None),
        DkgControlMessage::StartRefresh { .. } => ("start-refresh", None, None),
        DkgControlMessage::Prepare(prepare) => (
            "prepare",
            Some(prepare.ceremony_id),
            Some(prepare.attempt_id),
        ),
        DkgControlMessage::TopologyProbeAck {
            ceremony_id,
            attempt_id,
            ..
        } => ("topology-probe-ack", Some(*ceremony_id), Some(*attempt_id)),
        DkgControlMessage::Activate {
            ceremony_id,
            attempt_id,
            ..
        } => ("activate", Some(*ceremony_id), Some(*attempt_id)),
        DkgControlMessage::Begin {
            ceremony_id,
            attempt_id,
            ..
        } => ("begin", Some(*ceremony_id), Some(*attempt_id)),
        DkgControlMessage::Abort {
            ceremony_id,
            attempt_id,
            ..
        } => ("abort", Some(*ceremony_id), Some(*attempt_id)),
        DkgControlMessage::GetPublicContribution {
            ceremony_id,
            attempt_id,
            ..
        } => (
            "get-public-contribution",
            Some(*ceremony_id),
            Some(*attempt_id),
        ),
        DkgControlMessage::GetPublicPhase {
            ceremony_id,
            attempt_id,
            ..
        } => ("get-public-phase", Some(*ceremony_id), Some(*attempt_id)),
        _ => ("dkg-control", None, None),
    }
}

fn control_timeout_message(
    peer: &str,
    request: &DkgControlMessage,
    response_timeout: Duration,
) -> String {
    let (operation, ceremony_id, attempt_id) = control_request_scope(request);
    let peer = extract_node_part(peer);
    let peer_prefix: String = peer.chars().take(12).collect();
    format!(
        "control {operation} response timed out after {:.1}s for peer {peer_prefix} ceremony={} attempt={}",
        response_timeout.as_secs_f64(),
        ceremony_id.map_or_else(|| "-".into(), |id| id.0.to_string()),
        attempt_id.map_or_else(|| "-".into(), |id| hex::encode(&id.0[..6])),
    )
}

fn public_phase_response_page(
    ceremony_id: CeremonyId,
    attempt_id: AttemptId,
    phase: PublicPhase,
    retained: &BTreeMap<ParticipantRef, SignedPayload>,
    after: Option<ParticipantRef>,
) -> Result<DkgControlMessage> {
    let entries: Vec<_> = retained
        .iter()
        .filter(|(origin, _)| after.is_none_or(|cursor| **origin > cursor))
        .collect();
    if entries.is_empty() {
        return Ok(DkgControlMessage::PublicPhaseResponse {
            ceremony_id,
            attempt_id,
            phase,
            contributions: Vec::new(),
            next_cursor: None,
        });
    }

    let mut contributions = Vec::new();
    let mut last_origin = None;
    for (position, (origin, signed)) in entries.iter().enumerate() {
        contributions.push((*signed).clone());
        let has_more = position + 1 < entries.len();
        let candidate = DkgControlMessage::PublicPhaseResponse {
            ceremony_id,
            attempt_id,
            phase,
            contributions: contributions.clone(),
            next_cursor: has_more.then_some(**origin),
        };
        let encoded_len = transport::encode(&candidate)
            .map_err(DkgError::Serialization)?
            .len();
        if encoded_len > MAX_PUBLIC_REPAIR_PAGE_BYTES {
            contributions.pop();
            let Some(cursor) = last_origin else {
                crate::metrics::record_dkg_transport_event(
                    "public",
                    "repair_contribution_oversize",
                );
                return Err(DkgError::ProtocolError(format!(
                    "one signed public contribution exceeds the {}-byte repair page limit",
                    MAX_PUBLIC_REPAIR_PAGE_BYTES
                )));
            };
            return Ok(DkgControlMessage::PublicPhaseResponse {
                ceremony_id,
                attempt_id,
                phase,
                contributions,
                next_cursor: Some(cursor),
            });
        }
        last_origin = Some(**origin);
        if !has_more {
            return Ok(candidate);
        }
    }

    unreachable!("a non-empty retained page returns from the loop")
}

fn validate_public_repair_page_progress(
    after: Option<ParticipantRef>,
    origins: &[ParticipantRef],
    next_cursor: Option<ParticipantRef>,
    seen: &BTreeSet<ParticipantRef>,
) -> Result<()> {
    if origins.is_empty() {
        if next_cursor.is_some() {
            return Err(DkgError::ProtocolError(
                "empty public repair page supplied a continuation cursor".into(),
            ));
        }
        return Ok(());
    }
    if after.is_some_and(|cursor| origins[0] <= cursor) {
        return Err(DkgError::ProtocolError(
            "public repair page did not advance beyond its requested cursor".into(),
        ));
    }
    if origins.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(DkgError::ProtocolError(
            "public repair page origins are not in strict canonical order".into(),
        ));
    }
    if origins.iter().any(|origin| seen.contains(origin)) {
        return Err(DkgError::ProtocolError(
            "public repair response repeated an origin across pages".into(),
        ));
    }
    if next_cursor.is_some_and(|cursor| Some(&cursor) != origins.last()) {
        return Err(DkgError::ProtocolError(
            "public repair continuation cursor does not name the page's final origin".into(),
        ));
    }
    Ok(())
}

fn repairable_public_phases(kind: &SessionKind) -> &'static [PublicPhase] {
    const FRESH: &[PublicPhase] = &[PublicPhase::CommitmentHashes, PublicPhase::Commitments];
    const REFRESH: &[PublicPhase] = &[
        PublicPhase::Commitments,
        PublicPhase::CommitmentAudit,
        PublicPhase::RefreshHealthCheck,
    ];
    const RESHARE: &[PublicPhase] = &[
        PublicPhase::Commitments,
        PublicPhase::CommitmentAudit,
        PublicPhase::ReshareParticipantSet,
    ];
    match kind {
        SessionKind::Fresh => FRESH,
        SessionKind::Refresh { .. } => REFRESH,
        SessionKind::Reshare { .. } => RESHARE,
    }
}

fn wire_error(error: impl ToString) -> DkgControlMessage {
    DkgControlMessage::Error {
        ceremony_id: None,
        attempt_id: None,
        message: error.to_string(),
    }
}

fn peer_matches_route(peer: &PeerId, route: &str) -> bool {
    hex::encode(peer.as_bytes()) == extract_node_part(route).to_lowercase()
}

fn leader_bootstrap(
    local_node_key: &str,
    leader_node_key: &str,
    leader_route: &str,
) -> Result<Vec<PeerId>> {
    if local_node_key == leader_node_key {
        return Ok(Vec::new());
    }
    validate_peer_id(leader_route)
        .map_err(|error| DkgError::InvalidInput(format!("invalid leader route: {error}")))?;
    // Preserve the authoritative direct address. The pub-sub adapter pins the
    // connection to the node ID while registering the address with Iroh's
    // static provider, which is required when discovery and relays are disabled.
    Ok(vec![PeerId::from_bytes(leader_route.as_bytes())])
}

fn validate_reshare_next_transport_committee(
    next: &CommitteeConfig,
    expected_node_keys: &[String],
    expected_threshold: u32,
    resolved_routes: &[NodeRoute],
) -> Result<()> {
    let expected_assignments = canonical_node_id_assignments_from_node_keys(expected_node_keys)
        .map_err(DkgError::InvalidInput)?;
    let expected_keys: BTreeSet<_> = expected_node_keys.iter().collect();
    let supplied_keys: BTreeSet<_> = next.node_keys.iter().collect();
    if supplied_keys.len() != next.node_keys.len() || supplied_keys != expected_keys {
        return Err(DkgError::Unauthorized(
            "Reshare next transport committee does not match the announced next committee".into(),
        ));
    }
    if next.threshold != expected_threshold {
        return Err(DkgError::Unauthorized(format!(
            "Reshare next transport threshold {} does not match announced threshold {}",
            next.threshold, expected_threshold
        )));
    }
    if next.node_id_assignments != expected_assignments {
        return Err(DkgError::Unauthorized(
            "Reshare next transport node-ID assignments are not canonical".into(),
        ));
    }

    let expected_routes: BTreeMap<_, _> = resolved_routes
        .iter()
        .map(|route| (route.node_key.as_str(), route.peer_id.as_str()))
        .collect();
    if expected_routes.len() != expected_node_keys.len()
        || expected_node_keys
            .iter()
            .any(|node_key| !expected_routes.contains_key(node_key.as_str()))
    {
        return Err(DkgError::InvalidState(
            "resolved SourceHub routes do not cover the reshare next committee".into(),
        ));
    }
    let supplied_routes: BTreeMap<_, _> = next
        .node_keys
        .iter()
        .zip(&next.peer_routes)
        .map(|(node_key, peer_route)| (node_key.as_str(), peer_route.as_str()))
        .collect();
    if supplied_routes.len() != next.node_keys.len() || supplied_routes != expected_routes {
        // TODO(reporting): retain evidence that the authenticated reshare
        // leader supplied transport routes contradicting SourceHub NodeInfo.
        return Err(DkgError::Unauthorized(
            "Reshare next transport routes do not match resolved SourceHub NodeInfo routes".into(),
        ));
    }
    Ok(())
}

async fn validate_reshare_transport_routes<D>(
    state: &Arc<AppState<D>>,
    prepare: &PrepareSession,
) -> Result<()>
where
    D: CoordinatorDkg,
{
    let SessionKind::Reshare {
        new_peer_node_keys,
        new_threshold,
        ..
    } = &prepare.kind
    else {
        return Ok(());
    };
    let next = prepare.committees.next.as_ref().ok_or_else(|| {
        DkgError::Unauthorized("Reshare Prepare omits the next transport committee".into())
    })?;
    let resolved_routes = resolve_node_routes(&state.bulletin, new_peer_node_keys)
        .await
        .map_err(DkgError::Unauthorized)?;
    validate_reshare_next_transport_committee(
        next,
        new_peer_node_keys,
        *new_threshold,
        &resolved_routes,
    )
}

struct CeremonyStartGuard {
    ceremony_id: u128,
    lock: Weak<tokio::sync::Mutex<()>>,
    locks: Arc<tokio::sync::Mutex<HashMap<u128, Arc<tokio::sync::Mutex<()>>>>>,
    guard: Option<tokio::sync::OwnedMutexGuard<()>>,
}

impl Drop for CeremonyStartGuard {
    fn drop(&mut self) {
        drop(self.guard.take());
        let ceremony_id = self.ceremony_id;
        let lock = self.lock.clone();
        let locks = self.locks.clone();
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        runtime.spawn(async move {
            let mut locks = locks.lock().await;
            let remove = locks.get(&ceremony_id).is_some_and(|current| {
                Weak::ptr_eq(&lock, &Arc::downgrade(current)) && Arc::strong_count(current) == 1
            });
            if remove {
                locks.remove(&ceremony_id);
            }
        });
    }
}

async fn lock_ceremony_start<D>(
    state: &Arc<AppState<D>>,
    ceremony_id: CeremonyId,
) -> CeremonyStartGuard
where
    D: CoordinatorDkg,
{
    let lock = {
        let mut locks = state.dkg_ceremony_start_locks.lock().await;
        locks
            .entry(ceremony_id.0)
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    };
    let weak_lock = Arc::downgrade(&lock);
    let guard = lock.lock_owned().await;
    CeremonyStartGuard {
        ceremony_id: ceremony_id.0,
        lock: weak_lock,
        locks: state.dkg_ceremony_start_locks.clone(),
        guard: Some(guard),
    }
}

async fn control_request_with_timeout<D>(
    state: &Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    peer: &str,
    request: DkgControlMessage,
    response_timeout: Duration,
) -> Result<DkgControlMessage>
where
    D: CoordinatorDkg,
{
    crate::metrics::record_dkg_transport_message("control", request.metric_label(), "sent");
    let timeout_error = control_timeout_message(peer, &request, response_timeout);
    let mut attempt_connection = None;
    let exchange = timeout(response_timeout, async {
        let (stream, parent_connection) = state
            .peer_connection_pool
            .open_stream_with_connection(&state.network, peer, routes.dkg_control_alpn)
            .await
            .map_err(|error| DkgError::NetworkConnection(error.to_string()))?;
        attempt_connection = Some(parent_connection);
        let encoded = transport::encode(&request).map_err(DkgError::Serialization)?;
        stream
            .send(Message::new(encoded, routes.dkg_control_alpn.to_vec()))
            .await
            .map_err(|error| DkgError::NetworkCommunication(error.to_string()))?;
        stream
            .recv()
            .await
            .map_err(|error| DkgError::NetworkCommunication(error.to_string()))
    })
    .await;
    let response = match exchange {
        Ok(Ok(response)) => response,
        Ok(Err(error)) => {
            invalidate_failed_control_connection(
                state,
                routes,
                peer,
                attempt_connection.as_ref(),
                &error,
            )
            .await;
            return Err(error);
        }
        Err(_) => {
            let error = DkgError::NetworkConnection(timeout_error);
            invalidate_failed_control_connection(
                state,
                routes,
                peer,
                attempt_connection.as_ref(),
                &error,
            )
            .await;
            return Err(error);
        }
    };
    let response = transport::decode(&response.data, MAX_CONTROL_MESSAGE_BYTES)
        .map_err(DkgError::Deserialization)?;
    match response {
        DkgControlMessage::Error { message, .. } => Err(DkgError::ProtocolError(message)),
        response => Ok(response),
    }
}

async fn invalidate_failed_control_connection<D>(
    state: &Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    peer: &str,
    connection: Option<&Arc<dyn network::PeerConnection>>,
    error: &DkgError,
) where
    D: CoordinatorDkg,
{
    if !retryable_control_error(error) {
        return;
    }
    let Some(connection) = connection else {
        return;
    };
    if state
        .peer_connection_pool
        .invalidate_if_same(peer, routes.dkg_control_alpn, connection)
        .await
    {
        crate::metrics::record_dkg_transport_event("control", "connection_invalidated");
        tracing::warn!(
            peer = %extract_node_part(peer),
            %error,
            "invalidated failed DKG control connection"
        );
    }
}

fn retryable_control_error(error: &DkgError) -> bool {
    matches!(
        error,
        DkgError::NetworkConnection(_) | DkgError::NetworkCommunication(_)
    )
}

async fn retry_preparation_control<D>(
    state: &Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    peer: &str,
    request: DkgControlMessage,
    deadline: Instant,
) -> Result<DkgControlMessage>
where
    D: CoordinatorDkg,
{
    let (operation, ceremony_id, attempt_id) = control_request_scope(&request);
    let mut backoff = INITIAL_CONTROL_RETRY_BACKOFF;
    loop {
        let now = Instant::now();
        if now >= deadline {
            return Err(DkgError::NetworkCommunication(format!(
                "{operation} exceeded the preparation deadline for peer {} ceremony={} attempt={}",
                extract_node_part(peer),
                ceremony_id.map_or_else(|| "-".into(), |id| id.0.to_string()),
                attempt_id.map_or_else(|| "-".into(), |id| hex::encode(&id.0[..6])),
            )));
        }
        let remaining = deadline.saturating_duration_since(now);
        match control_request_with_timeout(
            state,
            routes,
            peer,
            request.clone(),
            PEER_RESPONSE_TIMEOUT.min(remaining),
        )
        .await
        {
            Ok(response) => return Ok(response),
            Err(error) if retryable_control_error(&error) => {
                crate::metrics::record_dkg_transport_event("control", "preparation_retry");
                tracing::warn!(
                    %error,
                    operation,
                    peer = %extract_node_part(peer),
                    "preparation control request failed; retrying"
                );
            }
            Err(error) => return Err(error),
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            continue;
        }
        sleep(backoff.min(remaining)).await;
        backoff = (backoff * 2).min(DKG_PREPARATION_RETRY_MAX_BACKOFF);
    }
}

/// Inbound request/response handler for the direct control plane.
pub struct DkgControlHandler<D>
where
    D: CoordinatorDkg,
{
    state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
}

impl<D> DkgControlHandler<D>
where
    D: CoordinatorDkg,
{
    pub fn new(state: Arc<AppState<D>>, routes: &'static network::ProtocolRoutes) -> Self {
        Self { state, routes }
    }
}

#[async_trait]
impl<D> ProtocolHandler for DkgControlHandler<D>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    async fn handle(&self, connection: Box<dyn Connection>) -> network::Result<()> {
        let peer = connection.peer_id().clone();
        let request = connection.recv().await?;
        let response = match transport::decode::<DkgControlMessage>(
            &request.data,
            MAX_CONTROL_MESSAGE_BYTES,
        ) {
            Ok(request) => {
                crate::metrics::record_dkg_transport_message(
                    "control",
                    request.metric_label(),
                    "received",
                );
                handle_control(self.state.clone(), self.routes, request, &peer)
                    .await
                    .unwrap_or_else(wire_error)
            }
            Err(error) => wire_error(error),
        };
        let bytes =
            transport::encode(&response).map_err(network::error::NetworkError::Serialization)?;
        connection
            .send(Message::new(bytes, self.routes.dkg_control_alpn.to_vec()))
            .await
    }
}

async fn handle_control<D>(
    state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    request: DkgControlMessage,
    sender: &PeerId,
) -> Result<DkgControlMessage>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    match request {
        DkgControlMessage::StartFresh {
            ring_id,
            token_string,
        } => {
            let (ceremony_id, attempt_id) =
                coordinate_fresh(state, routes, ring_id, token_string).await?;
            Ok(DkgControlMessage::StartAccepted {
                ceremony_id,
                attempt_id,
            })
        }
        DkgControlMessage::StartReshare {
            ring_id,
            expected_ring_pk,
        } => {
            validate_reshare_start_sender(&state, routes, &ring_id, &expected_ring_pk, sender)
                .await?;
            let outcome = coordinate_reshare(state, routes, ring_id, expected_ring_pk).await?;
            let (ceremony_id, attempt_id) = match outcome {
                ReshareStartOutcome::Started(ceremony_id, attempt_id)
                | ReshareStartOutcome::AlreadyActive(ceremony_id, attempt_id) => {
                    (ceremony_id, attempt_id)
                }
                ReshareStartOutcome::Forwarded(_, _) => {
                    return Err(DkgError::InvalidState(
                        "canonical next-committee leader forwarded a reshare start".into(),
                    ));
                }
            };
            Ok(DkgControlMessage::ReshareStartAccepted {
                ceremony_id,
                attempt_id,
            })
        }
        DkgControlMessage::StartRefresh {
            ring_id,
            expected_ring_pk,
            requester_node_key,
        } => {
            validate_refresh_start_sender(
                &state,
                routes,
                &ring_id,
                &expected_ring_pk,
                &requester_node_key,
                sender,
            )
            .await?;
            let outcome = coordinate_refresh(state, routes, ring_id, expected_ring_pk).await?;
            match outcome {
                RefreshStartOutcome::Started(ceremony_id, attempt_id)
                | RefreshStartOutcome::AlreadyActive(ceremony_id, attempt_id) => {
                    Ok(DkgControlMessage::RefreshStartAccepted {
                        ceremony_id,
                        attempt_id,
                    })
                }
                RefreshStartOutcome::NotDue => Ok(DkgControlMessage::RefreshNotDue),
                RefreshStartOutcome::Forwarded(_, _) => Err(DkgError::InvalidState(
                    "coordinate_refresh unexpectedly forwarded a refresh start".into(),
                )),
            }
        }
        DkgControlMessage::Prepare(prepare) => {
            prepare_participant(state, routes, *prepare, sender).await
        }
        DkgControlMessage::TopologyProbeAck {
            ceremony_id,
            attempt_id,
            nonce,
        } => {
            validate_leader_local(&state, ceremony_id.0).await?;
            let peer = canonical_committee_peer(&state, ceremony_id.0, sender).await?;
            match state
                .dkg_session_state
                .record_topology_probe_ack(&ceremony_id.0, attempt_id, nonce, peer)
                .await
            {
                TopologyAckRecordOutcome::Recorded => {
                    crate::metrics::record_dkg_transport_event("control", "probe_ack");
                }
                TopologyAckRecordOutcome::Duplicate => {}
                TopologyAckRecordOutcome::StaleAttempt => {
                    return Err(DkgError::ProtocolError(
                        "topology acknowledgement targets a stale attempt".into(),
                    ));
                }
                TopologyAckRecordOutcome::WrongNonce => {
                    return Err(DkgError::ProtocolError(
                        "topology acknowledgement has the wrong nonce".into(),
                    ));
                }
                TopologyAckRecordOutcome::MissingSession => {
                    return Err(DkgError::SessionNotFound(ceremony_id.0.to_string()));
                }
            }
            Ok(DkgControlMessage::TopologyProbeAck {
                ceremony_id,
                attempt_id,
                nonce,
            })
        }
        DkgControlMessage::Activate {
            ceremony_id,
            attempt_id,
            activation_digest,
            active_dealers,
        } => {
            validate_leader_sender(&state, ceremony_id.0, sender).await?;
            let (_, configured_attempt, config_digest) = state
                .dkg_session_state
                .transport_configuration(&ceremony_id.0)
                .await
                .ok_or_else(|| DkgError::SessionNotFound(ceremony_id.0.to_string()))?;
            if configured_attempt != attempt_id
                || transport::activation_digest(config_digest, &active_dealers)
                    .map_err(DkgError::ProtocolError)?
                    != activation_digest
            {
                return Err(DkgError::Unauthorized(
                    "activation digest or dealer set does not match prepared attempt".into(),
                ));
            }
            let activation = state
                .dkg_session_state
                .activate_transport(
                    &ceremony_id.0,
                    attempt_id,
                    activation_digest,
                    active_dealers,
                )
                .await;
            match activation {
                TransportActivationOutcome::AlreadyActivated => {
                    return Ok(DkgControlMessage::Activated {
                        ceremony_id,
                        attempt_id,
                        activation_digest,
                    });
                }
                TransportActivationOutcome::Activated => {}
                TransportActivationOutcome::StaleAttempt
                | TransportActivationOutcome::MissingSession => {
                    return Err(DkgError::ProtocolError("activate for stale attempt".into()));
                }
            }
            Ok(DkgControlMessage::Activated {
                ceremony_id,
                attempt_id,
                activation_digest,
            })
        }
        DkgControlMessage::Begin {
            ceremony_id,
            attempt_id,
            activation_digest,
        } => {
            validate_leader_sender(&state, ceremony_id.0, sender).await?;
            match state
                .dkg_session_state
                .begin_transport(&ceremony_id.0, attempt_id, activation_digest)
                .await
            {
                TransportBeginOutcome::Begun => {
                    spawn_cryptographic_attempt(
                        state,
                        routes,
                        AttemptKey::new(ceremony_id, attempt_id),
                    );
                }
                TransportBeginOutcome::AlreadyBegun => {}
                TransportBeginOutcome::NotActivated => {
                    return Err(DkgError::InvalidState(
                        "begin received before transport activation".into(),
                    ));
                }
                TransportBeginOutcome::StaleAttempt | TransportBeginOutcome::MissingSession => {
                    return Err(DkgError::ProtocolError("begin for stale attempt".into()));
                }
            }
            Ok(DkgControlMessage::Begun {
                ceremony_id,
                attempt_id,
                activation_digest,
            })
        }
        DkgControlMessage::PublicContribution(signed) => {
            if signed.origin.as_slice() != sender.as_bytes() {
                return Err(DkgError::Unauthorized(
                    "direct public contribution sender differs from embedded origin".into(),
                ));
            }
            let contribution = verify_signed_contribution(&state, &signed).await?;
            tracing::info!(
                session_id = contribution.ceremony_id.0,
                origin = ?contribution.origin,
                phase = ?contribution.payload.phase(),
                "leader received signed public DKG contribution"
            );
            validate_leader_local(&state, contribution.ceremony_id.0).await?;
            if let Err(error) =
                preflight_public_contribution_if_new(&state, routes, &signed, &contribution).await
            {
                if attributable_public_preflight_error(&error) {
                    let attempt =
                        AttemptKey::new(contribution.ceremony_id, contribution.attempt_id);
                    let participant_routes = state
                        .dkg_session_state
                        .with_attempt_state(attempt, |session| {
                            session.transport.participant_routes.clone()
                        })
                        .await
                        .unwrap_or_default();
                    tracing::error!(
                        session_id = contribution.ceremony_id.0,
                        attempt_id = %hex::encode(contribution.attempt_id.0),
                        phase = ?contribution.payload.phase(),
                        origin = ?contribution.origin,
                        message_id = %hex::encode(contribution.message_id.0),
                        %error,
                        "leader aborting DKG attempt after direct-origin payload failed preflight"
                    );
                    crate::metrics::record_dkg_transport_event(
                        "public",
                        "protocol_violation_abort",
                    );
                    // TODO(reporting): retain the authenticated origin envelope
                    // and submit invalid-public-contribution evidence.
                    state
                        .dkg_session_state
                        .abort_transport_attempt(attempt, TopicTaskDisposition::Abort)
                        .await;
                    broadcast_attempt_abort(
                        &state,
                        routes,
                        participant_routes,
                        contribution.ceremony_id,
                        contribution.attempt_id,
                        format!("direct-origin public contribution failed preflight: {error}"),
                    )
                    .await;
                }
                return Err(error);
            }
            record_public_contribution_at_leader(&state, routes, signed.clone(), &contribution)
                .await?;
            publish_phase_if_complete(
                state.clone(),
                routes,
                contribution.ceremony_id.0,
                contribution.attempt_id,
                contribution.payload.phase(),
            )
            .await?;
            // The direct ACK confirms authenticated retention by the leader,
            // not completion of the leader's local protocol transition. The
            // last contribution in a phase can enter Phase 2 and wait for
            // every private pair exchange; withholding the ACK until then
            // deadlocks the contributing follower before it can consume the
            // public batch and generate its reciprocal share. Dispatch is
            // attempt-scoped and idempotent, so a retry may safely schedule it
            // again after an earlier application failure.
            let dispatch_state = state.clone();
            let dispatch_contribution = contribution.clone();
            tokio::spawn(async move {
                if let Err(error) = dispatch_public_contribution(
                    dispatch_state,
                    routes,
                    signed,
                    dispatch_contribution.clone(),
                )
                .await
                {
                    tracing::warn!(
                        %error,
                        session_id = dispatch_contribution.ceremony_id.0,
                        origin = ?dispatch_contribution.origin,
                        phase = ?dispatch_contribution.payload.phase(),
                        "leader failed to apply retained public DKG contribution"
                    );
                }
            });
            Ok(DkgControlMessage::PublicContributionAck {
                ceremony_id: contribution.ceremony_id,
                attempt_id: contribution.attempt_id,
                message_id: contribution.message_id,
            })
        }
        DkgControlMessage::StageRefreshResult(signed) => {
            if signed.origin.as_slice() != sender.as_bytes() {
                return Err(DkgError::Unauthorized(
                    "staged refresh-result sender differs from embedded origin".into(),
                ));
            }
            let contribution = verify_signed_contribution(&state, &signed).await?;
            validate_leader_sender(&state, contribution.ceremony_id.0, sender).await?;
            if contribution.payload.phase() != PublicPhase::RefreshHealthCheck {
                return Err(DkgError::Unauthorized(
                    "only a refresh health-check result may use the result barrier".into(),
                ));
            }
            if let Err(error) =
                preflight_public_contribution_if_new(&state, routes, &signed, &contribution).await
            {
                if attributable_public_preflight_error(&error) {
                    let attempt =
                        AttemptKey::new(contribution.ceremony_id, contribution.attempt_id);
                    tracing::error!(
                        session_id = contribution.ceremony_id.0,
                        attempt_id = %hex::encode(contribution.attempt_id.0),
                        message_id = %hex::encode(contribution.message_id.0),
                        %error,
                        "aborting DKG attempt after staged leader result failed preflight"
                    );
                    // TODO(reporting): retain the authenticated leader envelope
                    // and report the invalid staged refresh result.
                    state
                        .dkg_session_state
                        .abort_transport_attempt(attempt, TopicTaskDisposition::Abort)
                        .await;
                }
                return Err(error);
            }
            record_public_contribution(&state, signed, &contribution).await?;
            crate::metrics::record_dkg_transport_event("public", "result_staged");
            Ok(DkgControlMessage::PublicContributionAck {
                ceremony_id: contribution.ceremony_id,
                attempt_id: contribution.attempt_id,
                message_id: contribution.message_id,
            })
        }
        DkgControlMessage::CommitRefreshResult {
            ceremony_id,
            attempt_id,
            message_id,
        } => {
            let receipt_key = (ceremony_id, attempt_id, message_id);
            {
                let now = Instant::now();
                let mut receipts = state.dkg_public_commit_receipts.lock().await;
                receipts.retain(|_, (_, recorded_at)| {
                    now.duration_since(*recorded_at) <= DKG_ATTEMPT_TIMEOUT
                });
                if let Some((leader_peer, _)) = receipts.get(&receipt_key) {
                    if leader_peer.as_slice() != sender.as_bytes() {
                        return Err(DkgError::Unauthorized(
                            "refresh-result retry did not come from its original leader".into(),
                        ));
                    }
                    return Ok(DkgControlMessage::PublicContributionAck {
                        ceremony_id,
                        attempt_id,
                        message_id,
                    });
                }
            }

            validate_leader_sender(&state, ceremony_id.0, sender).await?;
            if state
                .dkg_session_state
                .transport_attempt(&ceremony_id.0)
                .await
                != Some(attempt_id)
            {
                return Err(DkgError::ProtocolError(
                    "refresh-result commit targets a stale attempt".into(),
                ));
            }
            let retained = state
                .dkg_session_state
                .public_contributions(&ceremony_id.0, attempt_id, PublicPhase::RefreshHealthCheck)
                .await
                .unwrap_or_default();
            let mut selected = None;
            for signed in retained.into_values() {
                let contribution = verify_signed_contribution(&state, &signed).await?;
                if contribution.message_id == message_id {
                    selected = Some((signed, contribution));
                    break;
                }
            }
            let (signed, contribution) = selected.ok_or_else(|| {
                DkgError::InvalidState(
                    "refresh-result commit arrived before the exact result was staged".into(),
                )
            })?;
            // StageRefreshResult already retained this exact signed message.
            // Commit is the authorization to apply it, so bypass the generic
            // record-and-deduplicate helper: treating the retained record as a
            // completed application would leave followers staged forever.
            if let Err(error) =
                dispatch_public_contribution(state.clone(), routes, signed, contribution.clone())
                    .await
            {
                if attributable_public_preflight_error(&error) {
                    tracing::error!(
                        session_id = ceremony_id.0,
                        attempt_id = %hex::encode(attempt_id.0),
                        message_id = %hex::encode(message_id.0),
                        %error,
                        "aborting DKG attempt after committed leader result failed validation"
                    );
                    crate::metrics::record_dkg_transport_event(
                        "public",
                        "protocol_violation_abort",
                    );
                    // TODO(reporting): retain the authenticated leader result
                    // and report the invalid committed refresh result.
                    state
                        .dkg_session_state
                        .abort_transport_attempt(
                            AttemptKey::new(ceremony_id, attempt_id),
                            TopicTaskDisposition::Abort,
                        )
                        .await;
                }
                return Err(error);
            }

            let now = Instant::now();
            let mut receipts = state.dkg_public_commit_receipts.lock().await;
            if receipts.len() >= MAX_PUBLIC_COMMIT_RECEIPTS {
                if let Some(oldest) = receipts
                    .iter()
                    .min_by_key(|(_, (_, recorded_at))| *recorded_at)
                    .map(|(key, _)| *key)
                {
                    receipts.remove(&oldest);
                }
            }
            receipts.insert(receipt_key, (sender.as_bytes().to_vec(), now));
            crate::metrics::record_dkg_transport_event("public", "result_committed");
            Ok(DkgControlMessage::PublicContributionAck {
                ceremony_id,
                attempt_id,
                message_id,
            })
        }
        DkgControlMessage::ReshareShareAck {
            ceremony_id,
            attempt_id,
            idempotency_key,
            receiver,
            dealer,
        } => {
            let attempt = AttemptKey::new(ceremony_id, attempt_id);
            if receiver.scope != CommitteeScope::Next
                || dealer.scope != CommitteeScope::Current
                || receiver.node_id == 0
                || dealer.node_id == 0
            {
                return Err(DkgError::Unauthorized(
                    "reshare acknowledgement has invalid scoped participants".into(),
                ));
            }
            let expected_sender = state
                .dkg_session_state
                .peer_id_for_participant(&ceremony_id.0, receiver)
                .await
                .ok_or_else(|| DkgError::Unauthorized("receiver route is missing".into()))?;
            if !peer_matches_route(sender, &expected_sender) {
                return Err(DkgError::Unauthorized(
                    "reshare acknowledgement sender is not its named receiver".into(),
                ));
            }
            let expected_key = transport::derive_control_message_id(
                ceremony_id,
                attempt_id,
                "reshare-share-ack",
                receiver,
                ParticipantRef::next(1),
                &dealer,
            )
            .map_err(DkgError::Serialization)?;
            if expected_key != idempotency_key
                || state
                    .dkg_session_state
                    .transport_attempt(&ceremony_id.0)
                    .await
                    != Some(attempt_id)
            {
                return Err(DkgError::Unauthorized(
                    "reshare acknowledgement key or attempt is invalid".into(),
                ));
            }
            loop {
                match state
                    .dkg_session_state
                    .claim_transport_message(attempt, idempotency_key)
                    .await
                {
                    MessageProcessingClaim::Claimed => break,
                    MessageProcessingClaim::AlreadyProcessed => {
                        return Ok(DkgControlMessage::ReshareShareAcked {
                            ceremony_id,
                            attempt_id,
                            idempotency_key,
                        });
                    }
                    MessageProcessingClaim::AlreadyProcessing => {
                        sleep(Duration::from_millis(10)).await;
                    }
                    MessageProcessingClaim::MissingSession => {
                        return Err(DkgError::SessionNotFound(ceremony_id.0.to_string()));
                    }
                    MessageProcessingClaim::StaleAttempt => {
                        return Err(DkgError::Unauthorized(
                            "reshare acknowledgement targets a stale attempt".into(),
                        ));
                    }
                }
            }
            let coordinator = DkgCoordinator::with_routes(state.clone(), routes);
            let result =
                handle_reshare_share_ack(&coordinator, attempt, receiver.node_id, dealer.node_id)
                    .await;
            state
                .dkg_session_state
                .finish_transport_message(attempt, idempotency_key, result.is_ok())
                .await;
            result?;
            Ok(DkgControlMessage::ReshareShareAcked {
                ceremony_id,
                attempt_id,
                idempotency_key,
            })
        }
        DkgControlMessage::RelayInvalidShareEvidence {
            ceremony_id,
            attempt_id,
            idempotency_key,
            evidence,
        } => {
            let attempt = AttemptKey::new(ceremony_id, attempt_id);
            let origin = ParticipantRef::next(evidence.statement.to_node_id);
            let expected_sender = state
                .dkg_session_state
                .peer_id_for_participant(&ceremony_id.0, origin)
                .await
                .ok_or_else(|| DkgError::Unauthorized("evidence sender route is missing".into()))?;
            if !peer_matches_route(sender, &expected_sender) {
                return Err(DkgError::Unauthorized(
                    "invalid-share evidence sender is not its named receiver".into(),
                ));
            }
            let local_id = state
                .dkg_session_state
                .with_state(&ceremony_id.0, |session| session.node.node_id())
                .await
                .ok_or_else(|| DkgError::SessionNotFound(ceremony_id.0.to_string()))?;
            let recipient = ParticipantRef::current(local_id);
            let expected_key = transport::derive_control_message_id(
                ceremony_id,
                attempt_id,
                "invalid-share-evidence",
                origin,
                recipient,
                &evidence,
            )
            .map_err(DkgError::Serialization)?;
            if expected_key != idempotency_key
                || state
                    .dkg_session_state
                    .transport_attempt(&ceremony_id.0)
                    .await
                    != Some(attempt_id)
            {
                return Err(DkgError::Unauthorized(
                    "evidence idempotency key or attempt mismatch".into(),
                ));
            }
            if !claim_control_message(&state, attempt, idempotency_key).await? {
                return Ok(DkgControlMessage::EvidenceAccepted {
                    ceremony_id,
                    attempt_id,
                    idempotency_key,
                });
            }
            let coordinator = DkgCoordinator::with_routes(state.clone(), routes);
            let result = handle_invalid_share_evidence_relay(&coordinator, attempt, evidence).await;
            state
                .dkg_session_state
                .finish_transport_message(attempt, idempotency_key, result.is_ok())
                .await;
            result?;
            Ok(DkgControlMessage::EvidenceAccepted {
                ceremony_id,
                attempt_id,
                idempotency_key,
            })
        }
        DkgControlMessage::RelayInvalidCommitmentEvidence {
            ceremony_id,
            attempt_id,
            idempotency_key,
            commitment_a,
            commitment_b,
        } => {
            let attempt = AttemptKey::new(ceremony_id, attempt_id);
            let (origin, recipient) = state
                .dkg_session_state
                .with_state(&ceremony_id.0, |session| {
                    let origin = session
                        .routing
                        .reshare_new_node_id_to_peer_id
                        .iter()
                        .find_map(|(node_id, peer)| {
                            peer_matches_route(sender, peer)
                                .then_some(ParticipantRef::next(*node_id))
                        });
                    (origin, ParticipantRef::current(session.node.node_id()))
                })
                .await
                .ok_or_else(|| DkgError::SessionNotFound(ceremony_id.0.to_string()))?;
            let origin = origin.ok_or_else(|| {
                DkgError::Unauthorized(
                    "equivocation evidence sender is not in next committee".into(),
                )
            })?;
            let expected_key = transport::derive_control_message_id(
                ceremony_id,
                attempt_id,
                "invalid-commitment-evidence",
                origin,
                recipient,
                &(commitment_a.clone(), commitment_b.clone()),
            )
            .map_err(DkgError::Serialization)?;
            if expected_key != idempotency_key
                || state
                    .dkg_session_state
                    .transport_attempt(&ceremony_id.0)
                    .await
                    != Some(attempt_id)
            {
                return Err(DkgError::Unauthorized(
                    "evidence idempotency key or attempt mismatch".into(),
                ));
            }
            if !claim_control_message(&state, attempt, idempotency_key).await? {
                return Ok(DkgControlMessage::EvidenceAccepted {
                    ceremony_id,
                    attempt_id,
                    idempotency_key,
                });
            }
            let coordinator = DkgCoordinator::with_routes(state.clone(), routes);
            let result = handle_invalid_commitment_evidence_relay(
                &coordinator,
                attempt,
                commitment_a,
                commitment_b,
            )
            .await;
            state
                .dkg_session_state
                .finish_transport_message(attempt, idempotency_key, result.is_ok())
                .await;
            result?;
            Ok(DkgControlMessage::EvidenceAccepted {
                ceremony_id,
                attempt_id,
                idempotency_key,
            })
        }
        DkgControlMessage::GetPublicContribution {
            ceremony_id,
            attempt_id,
            phase,
            origin,
        } => {
            canonical_committee_peer(&state, ceremony_id.0, sender).await?;
            state
                .dkg_session_state
                .with_state(&ceremony_id.0, |_| ())
                .await
                .ok_or_else(|| DkgError::SessionNotFound(ceremony_id.0.to_string()))?;
            let committees = state
                .dkg_session_state
                .transport_committees(&ceremony_id.0)
                .await
                .ok_or_else(|| {
                    DkgError::InvalidState("ceremony committee configuration is missing".into())
                })?;
            if committees.node_key(origin) != Some(state.node_key.as_str()) {
                return Err(DkgError::Unauthorized(
                    "public origin repair must be requested from that origin".into(),
                ));
            }
            let contribution = state
                .dkg_session_state
                .public_contributions(&ceremony_id.0, attempt_id, phase)
                .await
                .and_then(|items| items.get(&origin).cloned());
            Ok(DkgControlMessage::PublicContributionResponse {
                ceremony_id,
                attempt_id,
                contribution,
            })
        }
        DkgControlMessage::GetPublicPhase {
            ceremony_id,
            attempt_id,
            phase,
            after,
        } => {
            validate_leader_local(&state, ceremony_id.0).await?;
            canonical_committee_peer(&state, ceremony_id.0, sender).await?;
            if state
                .dkg_session_state
                .transport_attempt(&ceremony_id.0)
                .await
                != Some(attempt_id)
            {
                return Err(DkgError::ProtocolError(
                    "public phase repair targets a stale attempt".into(),
                ));
            }
            let retained = state
                .dkg_session_state
                .public_contributions(&ceremony_id.0, attempt_id, phase)
                .await
                .ok_or_else(|| DkgError::SessionNotFound(ceremony_id.0.to_string()))?;
            let response =
                public_phase_response_page(ceremony_id, attempt_id, phase, &retained, after)?;
            let encoded_len = transport::encode(&response)
                .map_err(DkgError::Serialization)?
                .len();
            let (contribution_count, next_cursor) = match &response {
                DkgControlMessage::PublicPhaseResponse {
                    contributions,
                    next_cursor,
                    ..
                } => (contributions.len(), *next_cursor),
                _ => unreachable!("public repair page builder returned a different message"),
            };
            crate::metrics::record_dkg_transport_event("public", "repair_page_served");
            tracing::debug!(
                session_id = ceremony_id.0,
                attempt_id = %hex::encode(attempt_id.0),
                phase = ?phase,
                after = ?after,
                next_cursor = ?next_cursor,
                contribution_count,
                encoded_len,
                "served byte-bounded public DKG repair page"
            );
            Ok(response)
        }
        DkgControlMessage::Abort {
            ceremony_id,
            attempt_id,
            reason,
        } => {
            let attempt = AttemptKey::new(ceremony_id, attempt_id);
            validate_leader_sender_for_attempt(&state, attempt, sender).await?;
            tracing::warn!(
                session_id = ceremony_id.0,
                attempt_id = %hex::encode(attempt_id.0),
                %reason,
                "transport DKG attempt aborted"
            );
            state
                .dkg_session_state
                .abort_transport_attempt(attempt, TopicTaskDisposition::Abort)
                .await;
            Ok(DkgControlMessage::Abort {
                ceremony_id,
                attempt_id,
                reason,
            })
        }
        other => Err(DkgError::ProtocolError(format!(
            "unexpected control request: {other:?}"
        ))),
    }
}

/// Begin cryptographic work only after the leader has observed an activation
/// acknowledgement from every active participant. Keeping this separate from
/// `Activate` prevents fast incremental reshare traffic from reaching a peer
/// whose matching attempt is prepared but not active yet.
async fn begin_cryptographic_attempt<D>(
    state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    attempt: AttemptKey,
) -> Result<()>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    let coordinator = DkgCoordinator::with_routes(state.clone(), routes);
    let (peer_ids, kind) = state
        .dkg_session_state
        .with_attempt_state(attempt, |session| {
            (session.routing.peer_ids.clone(), session.kind.clone())
        })
        .await
        .map_err(|error| crate::dkg::v0::coordinator::attempt_state_error(attempt, error))?;
    match kind {
        SessionKind::Fresh => {
            coordinator
                .initiate_phase0_commitment_hashes(attempt, &peer_ids)
                .await?;
        }
        SessionKind::Refresh { .. } => {
            coordinator
                .initiate_phase1_commitments(attempt, &peer_ids)
                .await?;
        }
        SessionKind::Reshare { .. } => {
            coordinator
                .initiate_phase1_commitments(attempt, &peer_ids)
                .await?;
            spawn_reshare_receiver_pair_openers(state, routes, attempt);
        }
    }
    Ok(())
}

fn spawn_cryptographic_attempt<D>(
    state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    attempt: AttemptKey,
) where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    tokio::spawn(async move {
        let Ok(mut cancelled) = state.dkg_session_state.attempt_cancellation(attempt).await else {
            return;
        };
        let result = tokio::select! {
            result = begin_cryptographic_attempt(state.clone(), routes, attempt) => Some(result),
            _ = cancelled.changed() => None,
        };
        let Some(Err(error)) = result else {
            return;
        };
        tracing::error!(
            session_id = attempt.session_id(),
            attempt_id = %hex::encode(attempt.attempt_id.0),
            %error,
            "activated DKG attempt failed while beginning cryptographic work"
        );
        state
            .dkg_session_state
            .abort_transport_attempt(attempt, TopicTaskDisposition::Abort)
            .await;
    });
}

/// Claim an attempt-scoped control idempotency key. A completed duplicate is
/// acknowledged without re-running its side effects; a concurrent duplicate
/// waits for the first handler to publish its outcome.
async fn claim_control_message<D>(
    state: &Arc<AppState<D>>,
    attempt: AttemptKey,
    message_id: MessageId,
) -> Result<bool>
where
    D: CoordinatorDkg,
{
    loop {
        match state
            .dkg_session_state
            .claim_transport_message(attempt, message_id)
            .await
        {
            MessageProcessingClaim::Claimed => return Ok(true),
            MessageProcessingClaim::AlreadyProcessed => {
                return Ok(false);
            }
            MessageProcessingClaim::AlreadyProcessing => {
                sleep(Duration::from_millis(10)).await;
            }
            MessageProcessingClaim::MissingSession => {
                return Err(DkgError::SessionNotFound(attempt.session_id().to_string()));
            }
            MessageProcessingClaim::StaleAttempt => {
                return Err(DkgError::Unauthorized(
                    "control message targets a stale attempt".into(),
                ));
            }
        }
    }
}

async fn validate_leader_sender<D>(
    state: &Arc<AppState<D>>,
    session_id: u128,
    sender: &PeerId,
) -> Result<()>
where
    D: CoordinatorDkg,
{
    state
        .dkg_session_state
        .transport_info(&session_id)
        .await
        .ok_or_else(|| DkgError::SessionNotFound(session_id.to_string()))?;
    let route = state
        .dkg_session_state
        .transport_leader_route(&session_id)
        .await
        .ok_or_else(|| DkgError::InvalidState("leader route is missing".into()))?;
    if !peer_matches_route(sender, &route) {
        return Err(DkgError::Unauthorized(
            "control sender is not canonical leader".into(),
        ));
    }
    Ok(())
}

async fn validate_leader_sender_for_attempt<D>(
    state: &Arc<AppState<D>>,
    attempt: AttemptKey,
    sender: &PeerId,
) -> Result<()>
where
    D: CoordinatorDkg,
{
    let route = state
        .dkg_session_state
        .with_attempt_state(attempt, |session| {
            session.transport.leader_peer_route.clone()
        })
        .await
        .map_err(|error| crate::dkg::v0::coordinator::attempt_state_error(attempt, error))?
        .ok_or_else(|| DkgError::InvalidState("leader route is missing".into()))?;
    if !peer_matches_route(sender, &route) {
        return Err(DkgError::Unauthorized(
            "control sender is not canonical leader".into(),
        ));
    }
    Ok(())
}

async fn canonical_committee_peer<D>(
    state: &Arc<AppState<D>>,
    session_id: u128,
    sender: &PeerId,
) -> Result<String>
where
    D: CoordinatorDkg,
{
    let peers = state
        .dkg_session_state
        .transport_participant_routes(&session_id)
        .await
        .ok_or_else(|| DkgError::SessionNotFound(session_id.to_string()))?;
    peers
        .iter()
        .find(|peer| peer_matches_route(sender, peer))
        .map(|peer| extract_node_part(peer).to_lowercase())
        .ok_or_else(|| {
            DkgError::Unauthorized("direct repair requester is not in the committee".into())
        })
}

async fn validate_leader_local<D>(state: &Arc<AppState<D>>, session_id: u128) -> Result<()>
where
    D: CoordinatorDkg,
{
    let leader = state
        .dkg_session_state
        .transport_info(&session_id)
        .await
        .map(|(_, _, _, leader, _)| leader)
        .ok_or_else(|| DkgError::SessionNotFound(session_id.to_string()))?;
    if leader != state.node_key {
        return Err(DkgError::Unauthorized(
            "public contribution sent to non-leader".into(),
        ));
    }
    Ok(())
}

/// Route a fresh-DKG start to the canonical leader, or coordinate it locally.
pub async fn start_fresh<D>(
    state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    ring_id: String,
    token_string: String,
) -> Result<(CeremonyId, AttemptId)>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    let ring = read_ring_for_route(&*state.bulletin, &ring_id, routes.version)
        .await
        .map_err(DkgError::ProtocolError)?;
    validate_fresh_dkg_ring_payload(&ring_id, &ring)?;
    let leader = transport::canonical_leader(&ring.peer_node_keys)
        .ok_or(DkgError::InvalidParticipantCount(0))?
        .to_string();
    if leader == state.node_key {
        return coordinate_fresh(state, routes, ring_id, token_string).await;
    }
    let resolved = resolve_node_routes(&state.bulletin, &ring.peer_node_keys)
        .await
        .map_err(DkgError::Unauthorized)?;
    let leader_peer = resolved
        .iter()
        .find_map(|route| (route.node_key == leader).then_some(route.peer_id.as_str()))
        .ok_or_else(|| DkgError::InvalidState("canonical leader route is missing".into()))?;
    match control_request_with_timeout(
        &state,
        routes,
        leader_peer,
        DkgControlMessage::StartFresh {
            ring_id,
            token_string,
        },
        DKG_PREPARATION_TIMEOUT + DKG_FORWARDED_START_RESPONSE_GRACE,
    )
    .await?
    {
        DkgControlMessage::StartAccepted {
            ceremony_id,
            attempt_id,
        } => Ok((ceremony_id, attempt_id)),
        response => Err(DkgError::ProtocolError(format!(
            "leader returned unexpected start response: {response:?}"
        ))),
    }
}

/// Coordinate a due PSS refresh. Any current-committee member may call
/// `start_refresh`; nonleaders forward to the one canonical leader.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RefreshStartOutcome {
    Started(CeremonyId, AttemptId),
    AlreadyActive(CeremonyId, AttemptId),
    /// The canonical leader accepted a request forwarded by this member.
    Forwarded(CeremonyId, AttemptId),
    NotDue,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReshareStartOutcome {
    Started(CeremonyId, AttemptId),
    AlreadyActive(CeremonyId, AttemptId),
    Forwarded(CeremonyId, AttemptId),
}

fn pending_reshare_parameters(
    ring: &RingPayload,
    expected_ring_pk: &str,
) -> Result<(Vec<String>, u32)> {
    if !ring_payload_matches_ring_key(expected_ring_pk, &ring.ring_pk) {
        return Err(DkgError::InvalidState(
            "reshare ring public key differs from SourceHub state".into(),
        ));
    }
    let next_keys = ring
        .new_peer_node_keys
        .clone()
        .unwrap_or_else(|| ring.peer_node_keys.clone());
    let next_threshold = ring.new_threshold.unwrap_or(ring.threshold);
    if next_keys == ring.peer_node_keys && next_threshold == ring.threshold {
        return Err(DkgError::InvalidState(
            "SourceHub ring has no pending reshare transition".into(),
        ));
    }
    Ok((next_keys, next_threshold))
}

/// Observe a pending transition as a current member and route it to the
/// canonical next-committee leader. Any current member may forward; the next
/// leader independently authenticates the sender and SourceHub state.
pub(crate) async fn start_reshare<D>(
    state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    ring_id: String,
    ring_pk: String,
) -> Result<ReshareStartOutcome>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    let ring = read_ring_for_route(&*state.bulletin, &ring_id, routes.version)
        .await
        .map_err(DkgError::ProtocolError)?;
    let (next_keys, next_threshold) = pending_reshare_parameters(&ring, &ring_pk)?;
    if !ring.peer_node_keys.contains(&state.node_key) {
        return Err(DkgError::Unauthorized(
            "only a current-committee member may request reshare start".into(),
        ));
    }
    let ceremony = CeremonyId(derive_reshare_session_id(
        &ring_pk,
        &ring_id,
        &ring.peer_node_keys,
        &next_keys,
        next_threshold,
    )?);
    if let Some(attempt) = state.dkg_session_state.transport_attempt(&ceremony.0).await {
        crate::metrics::record_dkg_transport_event("control", "reshare_start_duplicate");
        return Ok(ReshareStartOutcome::AlreadyActive(ceremony, attempt));
    }

    let leader = transport::canonical_leader(&next_keys)
        .ok_or(DkgError::InvalidParticipantCount(0))?
        .to_string();
    crate::metrics::record_dkg_transport_event("control", "reshare_next_leader_selected");
    if leader == state.node_key {
        return coordinate_reshare(state, routes, ring_id, ring_pk).await;
    }

    let next_routes = resolve_node_routes(&state.bulletin, &next_keys)
        .await
        .map_err(DkgError::Unauthorized)?;
    let leader_peer = next_routes
        .iter()
        .find_map(|route| (route.node_key == leader).then_some(route.peer_id.as_str()))
        .ok_or_else(|| DkgError::InvalidState("next-committee leader route is missing".into()))?;
    crate::metrics::record_dkg_transport_event("control", "reshare_start_forwarded");
    tracing::info!(
        ring_id = %ring_id,
        leader = %leader,
        "forwarding pending reshare to canonical next-committee leader"
    );
    let forwarding_deadline =
        Instant::now() + DKG_PREPARATION_TIMEOUT + DKG_FORWARDED_START_RESPONSE_GRACE;
    match retry_preparation_control(
        &state,
        routes,
        leader_peer,
        DkgControlMessage::StartReshare {
            ring_id,
            expected_ring_pk: ring_pk,
        },
        forwarding_deadline,
    )
    .await?
    {
        DkgControlMessage::ReshareStartAccepted {
            ceremony_id,
            attempt_id,
        } if ceremony_id == ceremony => Ok(ReshareStartOutcome::Forwarded(ceremony_id, attempt_id)),
        response => Err(DkgError::ProtocolError(format!(
            "next-committee leader returned unexpected reshare start response: {response:?}"
        ))),
    }
}

async fn validate_reshare_start_sender<D>(
    state: &Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    ring_id: &str,
    expected_ring_pk: &str,
    sender: &PeerId,
) -> Result<()>
where
    D: CoordinatorDkg,
{
    let ring = read_ring_for_route(&*state.bulletin, ring_id, routes.version)
        .await
        .map_err(DkgError::ProtocolError)?;
    let (next_keys, _) = pending_reshare_parameters(&ring, expected_ring_pk)?;
    let expected_leader =
        transport::canonical_leader(&next_keys).ok_or(DkgError::InvalidParticipantCount(0))?;
    if expected_leader != state.node_key {
        crate::metrics::record_dkg_transport_event("control", "reshare_start_rejected");
        return Err(DkgError::Unauthorized(
            "StartReshare reached a nonleader next-committee receiver".into(),
        ));
    }
    let current_routes = resolve_node_routes(&state.bulletin, &ring.peer_node_keys)
        .await
        .map_err(DkgError::Unauthorized)?;
    if current_routes
        .iter()
        .all(|route| !peer_matches_route(sender, &route.peer_id))
    {
        crate::metrics::record_dkg_transport_event("control", "reshare_start_rejected");
        return Err(DkgError::Unauthorized(
            "StartReshare sender is not in the current committee".into(),
        ));
    }
    Ok(())
}

/// Coordinate the pending SourceHub transition as the canonical next-committee
/// receiver. Only this function creates an attempt ID.
async fn coordinate_reshare<D>(
    state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    ring_id: String,
    ring_pk: String,
) -> Result<ReshareStartOutcome>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    let ring = read_ring_for_route(&*state.bulletin, &ring_id, routes.version)
        .await
        .map_err(DkgError::ProtocolError)?;
    let (next_keys, next_threshold) = pending_reshare_parameters(&ring, &ring_pk)?;
    let leader = transport::canonical_leader(&next_keys)
        .ok_or(DkgError::InvalidParticipantCount(0))?
        .to_string();
    if leader != state.node_key {
        return Err(DkgError::Unauthorized(
            "only the canonical next-committee leader may coordinate reshare".into(),
        ));
    }
    let ceremony = CeremonyId(derive_reshare_session_id(
        &ring_pk,
        &ring_id,
        &ring.peer_node_keys,
        &next_keys,
        next_threshold,
    )?);
    if let Some(attempt) = state.dkg_session_state.transport_attempt(&ceremony.0).await {
        crate::metrics::record_dkg_transport_event("control", "reshare_start_duplicate");
        return Ok(ReshareStartOutcome::AlreadyActive(ceremony, attempt));
    }
    let _start_guard = lock_ceremony_start(&state, ceremony).await;
    if let Some(attempt) = state.dkg_session_state.transport_attempt(&ceremony.0).await {
        crate::metrics::record_dkg_transport_event("control", "reshare_start_duplicate");
        return Ok(ReshareStartOutcome::AlreadyActive(ceremony, attempt));
    }

    let current_routes = resolve_node_routes(&state.bulletin, &ring.peer_node_keys)
        .await
        .map_err(DkgError::Unauthorized)?;
    let next_routes = resolve_node_routes(&state.bulletin, &next_keys)
        .await
        .map_err(DkgError::Unauthorized)?;
    let current_assignments = canonical_node_id_assignments_from_node_keys(&ring.peer_node_keys)
        .map_err(DkgError::InvalidInput)?;
    let next_assignments =
        canonical_node_id_assignments_from_node_keys(&next_keys).map_err(DkgError::InvalidInput)?;
    let attempt = AttemptId::random();
    let transition_digest =
        transport::ceremony_committee_digest(&ring.peer_node_keys, Some(&next_keys));
    let topic = transport::derive_topic_id(
        &state.bulletin.chain_id(),
        &ring_id,
        &transition_digest,
        ceremony,
        attempt,
    );
    let mut prepare = PrepareSession {
        ceremony_id: ceremony,
        attempt_id: attempt,
        config_digest: [0; 32],
        topic_id: *topic.as_bytes(),
        leader_node_key: leader,
        committees: CeremonyConfig {
            current: CommitteeConfig {
                node_keys: ring.peer_node_keys.clone(),
                peer_routes: peer_ids_from_routes(&current_routes),
                node_id_assignments: current_assignments,
                threshold: ring.threshold,
            },
            next: Some(CommitteeConfig {
                node_keys: next_keys.clone(),
                peer_routes: peer_ids_from_routes(&next_routes),
                node_id_assignments: next_assignments,
                threshold: next_threshold,
            }),
        },
        token_string: String::new(),
        kind: SessionKind::Reshare {
            ring_pk_hex: ring_pk,
            new_peer_node_keys: next_keys,
            new_threshold: next_threshold,
            bulletin_post_id: ring_id.clone(),
        },
        pss_interval: ring.pss_interval,
        policy_id: ring.policy_id,
        ring_id,
    };
    prepare.config_digest = transport::config_digest(&prepare).map_err(DkgError::Serialization)?;
    let (ceremony, attempt) = coordinate_prepared(state, routes, prepare).await?;
    crate::metrics::record_dkg_transport_event("control", "reshare_start_accepted");
    Ok(ReshareStartOutcome::Started(ceremony, attempt))
}

async fn validate_refresh_start_sender<D>(
    state: &Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    ring_id: &str,
    expected_ring_pk: &str,
    requester_node_key: &str,
    sender: &PeerId,
) -> Result<()>
where
    D: CoordinatorDkg,
{
    let ring = read_ring_for_route(&*state.bulletin, ring_id, routes.version)
        .await
        .map_err(DkgError::ProtocolError)?;
    if !ring_payload_matches_ring_key(expected_ring_pk, &ring.ring_pk) {
        return Err(DkgError::InvalidState(
            "refresh ring public key differs from SourceHub state".into(),
        ));
    }
    let canonical_leader = transport::canonical_leader(&ring.peer_node_keys)
        .ok_or(DkgError::InvalidParticipantCount(0))?;
    if canonical_leader != state.node_key {
        crate::metrics::record_dkg_transport_event("control", "refresh_start_rejected");
        return Err(DkgError::Unauthorized(
            "StartRefresh must be handled by the canonical leader".into(),
        ));
    }
    if !ring
        .peer_node_keys
        .iter()
        .any(|node_key| node_key == requester_node_key)
    {
        crate::metrics::record_dkg_transport_event("control", "refresh_start_rejected");
        return Err(DkgError::Unauthorized(
            "StartRefresh requester is not in the current committee".into(),
        ));
    }
    let requester_routes = resolve_node_routes(&state.bulletin, &[requester_node_key.to_string()])
        .await
        .map_err(DkgError::Unauthorized)?;
    if requester_routes
        .first()
        .is_none_or(|route| !peer_matches_route(sender, &route.peer_id))
    {
        crate::metrics::record_dkg_transport_event("control", "refresh_start_rejected");
        return Err(DkgError::Unauthorized(
            "StartRefresh sender does not match the requester SourceHub route".into(),
        ));
    }
    Ok(())
}

/// Coordinate a due PSS refresh as the canonical current-committee leader.
/// Callable both by the leader's local scheduler and by its `StartRefresh`
/// control handler after authenticating a current-committee requester.
async fn coordinate_refresh<D>(
    state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    ring_id: String,
    ring_pk: String,
) -> Result<RefreshStartOutcome>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    let ring = read_ring_for_route(&*state.bulletin, &ring_id, routes.version)
        .await
        .map_err(DkgError::ProtocolError)?;
    if !ring_payload_matches_ring_key(&ring_pk, &ring.ring_pk) {
        return Err(DkgError::InvalidState(
            "refresh ring public key differs from SourceHub state".into(),
        ));
    }
    let canonical_leader = transport::canonical_leader(&ring.peer_node_keys)
        .ok_or(DkgError::InvalidParticipantCount(0))?;
    if canonical_leader != state.node_key {
        return Err(DkgError::Unauthorized(
            "only the canonical current-committee leader may coordinate PSS refresh".into(),
        ));
    }
    if let Some(session_id) = state
        .dkg_session_state
        .active_ring_pss_session(&ring_pk)
        .await
    {
        if let Some(attempt_id) = state.dkg_session_state.transport_attempt(&session_id).await {
            return Ok(RefreshStartOutcome::AlreadyActive(
                CeremonyId(session_id),
                attempt_id,
            ));
        }
    }
    let bundle = RingShareBundle::load_by_ring_key(&state.local_storage, &ring_pk)
        .map_err(|error| DkgError::Storage(error.to_string()))?;
    let session_id = derive_refresh_session_id(
        &ring_pk,
        &ring.peer_node_keys,
        ring.threshold,
        &bundle.public_polynomial,
    )?;
    let _start_guard = lock_ceremony_start(&state, CeremonyId(session_id)).await;
    // The scheduler's first due check precedes an asynchronous SourceHub read.
    // A previous refresh can complete during that read and advance `last_pss`.
    // Re-read under the start singleflight before creating an attempt so each
    // completion cannot produce a guaranteed-too-early follow-up attempt.
    let current_bundle = RingShareBundle::load_by_ring_key(&state.local_storage, &ring_pk)
        .map_err(|error| DkgError::Storage(error.to_string()))?;
    let now = current_unix_time().map_err(DkgError::SystemTime)?;
    let elapsed = now.saturating_sub(current_bundle.last_pss);
    if elapsed + PSS_GRACE_PERIOD_SECS < ring.pss_interval {
        return Ok(RefreshStartOutcome::NotDue);
    }
    if let Some(attempt_id) = state.dkg_session_state.transport_attempt(&session_id).await {
        return Ok(RefreshStartOutcome::AlreadyActive(
            CeremonyId(session_id),
            attempt_id,
        ));
    }
    let ceremony_id = CeremonyId(session_id);
    let attempt_id = AttemptId::random();
    let committee = transport::ceremony_committee_digest(&ring.peer_node_keys, None);
    let resolved = resolve_node_routes(&state.bulletin, &ring.peer_node_keys)
        .await
        .map_err(DkgError::Unauthorized)?;
    let peer_ids = peer_ids_from_routes(&resolved);
    let assignments = canonical_node_id_assignments_from_node_keys(&ring.peer_node_keys)
        .map_err(DkgError::InvalidInput)?;
    let topic = transport::derive_topic_id(
        &state.bulletin.chain_id(),
        &ring_id,
        &committee,
        ceremony_id,
        attempt_id,
    );
    let mut prepare = PrepareSession {
        ceremony_id,
        attempt_id,
        config_digest: [0; 32],
        topic_id: *topic.as_bytes(),
        leader_node_key: state.node_key.clone(),
        committees: CeremonyConfig {
            current: CommitteeConfig {
                node_keys: ring.peer_node_keys,
                peer_routes: peer_ids,
                node_id_assignments: assignments,
                threshold: ring.threshold,
            },
            next: None,
        },
        token_string: String::new(),
        kind: SessionKind::Refresh {
            ring_pk_hex: ring_pk,
        },
        pss_interval: ring.pss_interval,
        policy_id: ring.policy_id,
        ring_id,
    };
    prepare.config_digest = transport::config_digest(&prepare).map_err(DkgError::Serialization)?;
    coordinate_prepared(state, routes, prepare)
        .await
        .map(|(ceremony_id, attempt_id)| RefreshStartOutcome::Started(ceremony_id, attempt_id))
}

/// Trigger a due PSS refresh. Any current-committee member may call this, but
/// only the deterministic canonical leader coordinates the attempt. Repeated
/// forwarded starts retry that same leader and coalesce through its local
/// ceremony-start lock.
pub(crate) async fn start_refresh<D>(
    state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    ring_id: String,
    ring_pk: String,
) -> Result<RefreshStartOutcome>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    let ring = read_ring_for_route(&*state.bulletin, &ring_id, routes.version)
        .await
        .map_err(DkgError::ProtocolError)?;
    if !ring.peer_node_keys.contains(&state.node_key) {
        return Err(DkgError::Unauthorized(
            "only a current-committee member may trigger PSS refresh".into(),
        ));
    }
    let canonical_leader = transport::canonical_leader(&ring.peer_node_keys)
        .ok_or(DkgError::InvalidParticipantCount(0))?
        .to_string();
    if canonical_leader == state.node_key {
        return coordinate_refresh(state, routes, ring_id, ring_pk).await;
    }

    let leader_routes =
        resolve_node_routes(&state.bulletin, std::slice::from_ref(&canonical_leader))
            .await
            .map_err(DkgError::Unauthorized)?;
    let leader_route = leader_routes
        .first()
        .map(|route| route.peer_id.as_str())
        .ok_or_else(|| {
            DkgError::InvalidState("canonical refresh leader route is missing".into())
        })?;
    crate::metrics::record_dkg_transport_event("control", "refresh_start_forwarded");
    let forwarding_deadline =
        Instant::now() + DKG_PREPARATION_TIMEOUT + DKG_FORWARDED_START_RESPONSE_GRACE;
    match retry_preparation_control(
        &state,
        routes,
        leader_route,
        DkgControlMessage::StartRefresh {
            ring_id,
            expected_ring_pk: ring_pk,
            requester_node_key: state.node_key.clone(),
        },
        forwarding_deadline,
    )
    .await?
    {
        DkgControlMessage::RefreshStartAccepted {
            ceremony_id,
            attempt_id,
        } => Ok(RefreshStartOutcome::Forwarded(ceremony_id, attempt_id)),
        DkgControlMessage::RefreshNotDue => Ok(RefreshStartOutcome::NotDue),
        other => Err(DkgError::ProtocolError(format!(
            "canonical refresh leader returned unexpected start response: {other:?}"
        ))),
    }
}

async fn coordinate_fresh<D>(
    state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    ring_id: String,
    token_string: String,
) -> Result<(CeremonyId, AttemptId)>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    let ring = read_ring_for_route(&*state.bulletin, &ring_id, routes.version)
        .await
        .map_err(DkgError::ProtocolError)?;
    validate_fresh_dkg_ring_payload(&ring_id, &ring)?;
    let leader = transport::canonical_leader(&ring.peer_node_keys)
        .ok_or(DkgError::InvalidParticipantCount(0))?
        .to_string();
    if leader != state.node_key {
        return Err(DkgError::Unauthorized(
            "StartFresh must be handled by the canonical leader".into(),
        ));
    }
    let session_id = derive_fresh_dkg_session_id(&ring_id)?;
    let _start_guard = lock_ceremony_start(&state, CeremonyId(session_id)).await;
    if let Some(attempt_id) = state.dkg_session_state.transport_attempt(&session_id).await {
        return Ok((CeremonyId(session_id), attempt_id));
    }
    let ceremony_id = CeremonyId(session_id);
    let attempt_id = AttemptId::random();
    let committee = transport::ceremony_committee_digest(&ring.peer_node_keys, None);
    let resolved = resolve_node_routes(&state.bulletin, &ring.peer_node_keys)
        .await
        .map_err(DkgError::Unauthorized)?;
    let peer_ids = peer_ids_from_routes(&resolved);
    let assignments = canonical_node_id_assignments_from_node_keys(&ring.peer_node_keys)
        .map_err(DkgError::InvalidInput)?;
    let topic = transport::derive_topic_id(
        &state.bulletin.chain_id(),
        &ring_id,
        &committee,
        ceremony_id,
        attempt_id,
    );
    let mut prepare = PrepareSession {
        ceremony_id,
        attempt_id,
        config_digest: [0; 32],
        topic_id: *topic.as_bytes(),
        leader_node_key: leader,
        committees: CeremonyConfig {
            current: CommitteeConfig {
                node_keys: ring.peer_node_keys.clone(),
                peer_routes: peer_ids.clone(),
                node_id_assignments: assignments,
                threshold: ring.threshold,
            },
            next: None,
        },
        token_string,
        kind: SessionKind::Fresh,
        pss_interval: ring.pss_interval,
        policy_id: ring.policy_id.clone(),
        ring_id,
    };
    prepare.config_digest = transport::config_digest(&prepare).map_err(DkgError::Serialization)?;

    coordinate_prepared(state, routes, prepare).await
}

async fn coordinate_prepared<D>(
    state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    prepare: PrepareSession,
) -> Result<(CeremonyId, AttemptId)>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    let result = coordinate_prepared_inner(state.clone(), routes, prepare.clone()).await;
    if let Err(error) = &result {
        abort_prepared_attempt(&state, routes, &prepare, error.to_string()).await;
        state
            .dkg_session_state
            .abort_transport_preparation(
                &prepare.ceremony_id.0,
                prepare.attempt_id,
                TopicTaskDisposition::Abort,
            )
            .await;
    }
    result
}

const RESHARE_DEALER_INCLUSION_GRACE: Duration = Duration::from_secs(3);

#[derive(Debug, Eq, PartialEq)]
enum ResharePreparationErrorAction {
    Retry,
    ExcludeOld,
    Fail,
}

fn reshare_preparation_error_action(
    is_next_member: bool,
    error: &DkgError,
) -> ResharePreparationErrorAction {
    if retryable_control_error(error) {
        ResharePreparationErrorAction::Retry
    } else if is_next_member {
        ResharePreparationErrorAction::Fail
    } else {
        ResharePreparationErrorAction::ExcludeOld
    }
}

async fn prepare_transport_participants<D>(
    state: &Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    prepare: &PrepareSession,
    deadline: Instant,
) -> Result<(Vec<String>, Vec<ParticipantRef>)>
where
    D: CoordinatorDkg,
{
    let all_routes = prepare.participant_routes();
    if prepare.committees.next.is_none() {
        let mut tasks = JoinSet::new();
        for peer in all_routes
            .iter()
            .filter(|peer| !is_self_peer_id(&state.network, peer))
        {
            let state = state.clone();
            let peer = peer.clone();
            let prepare = prepare.clone();
            tasks.spawn(async move {
                let response = retry_preparation_control(
                    &state,
                    routes,
                    &peer,
                    DkgControlMessage::Prepare(Box::new(prepare)),
                    deadline,
                )
                .await?;
                Ok::<_, DkgError>((peer, response))
            });
        }
        while let Some(result) = tasks.join_next().await {
            let (peer, response) =
                result.map_err(|error| DkgError::NetworkCommunication(error.to_string()))??;
            validate_prepared_response(prepare, &peer, response)?;
        }
        let mut dealers: Vec<_> = prepare
            .committees
            .current
            .node_id_assignments
            .values()
            .copied()
            .map(ParticipantRef::current)
            .collect();
        dealers.sort();
        return Ok((all_routes, dealers));
    }

    let next = prepare
        .committees
        .next
        .as_ref()
        .expect("reshare branch checked above");
    let current = &prepare.committees.current;
    let normalize = |route: &str| extract_node_part(route).to_lowercase();
    let route_by_id: BTreeMap<String, String> = all_routes
        .iter()
        .map(|route| (normalize(route), route.clone()))
        .collect();
    let next_routes: BTreeSet<String> = next
        .peer_routes
        .iter()
        .map(|route| normalize(route))
        .collect();
    let current_routes: BTreeMap<String, u32> = current
        .node_keys
        .iter()
        .zip(&current.peer_routes)
        .filter_map(|(key, route)| {
            current
                .node_id_assignments
                .get(key)
                .copied()
                .map(|node_id| (normalize(route), node_id))
        })
        .collect();
    let mut prepared: BTreeSet<String> = all_routes
        .iter()
        .filter(|route| is_self_peer_id(&state.network, route))
        .map(|route| normalize(route))
        .collect();
    let mut excluded_old = BTreeSet::new();
    let mut grace_started = None;

    loop {
        let now = Instant::now();
        let ready_old = current_routes
            .keys()
            .filter(|route| prepared.contains(*route))
            .count();
        let missing_new: Vec<_> = next_routes.difference(&prepared).cloned().collect();
        let threshold_ready = missing_new.is_empty() && ready_old >= current.threshold as usize;
        if threshold_ready {
            let grace = grace_started.get_or_insert(now);
            if ready_old == current.len()
                || now.duration_since(*grace) >= RESHARE_DEALER_INCLUSION_GRACE
            {
                break;
            }
        }
        if now >= deadline {
            let shortfall = (current.threshold as usize).saturating_sub(ready_old);
            return Err(DkgError::NetworkCommunication(format!(
                "reshare preparation expired: missing_new=[{}], old_dealer_shortfall={shortfall}",
                missing_new
                    .iter()
                    .map(|peer| peer.chars().take(12).collect::<String>())
                    .collect::<Vec<_>>()
                    .join(",")
            )));
        }

        let request_timeout = PEER_RESPONSE_TIMEOUT.min(deadline.saturating_duration_since(now));
        let mut round = JoinSet::new();
        for (route_id, peer) in &route_by_id {
            if prepared.contains(route_id) || excluded_old.contains(route_id) {
                continue;
            }
            let state = state.clone();
            let peer = peer.clone();
            let route_id = route_id.clone();
            let request = DkgControlMessage::Prepare(Box::new(prepare.clone()));
            round.spawn(async move {
                (
                    route_id,
                    peer.clone(),
                    control_request_with_timeout(&state, routes, &peer, request, request_timeout)
                        .await,
                )
            });
        }
        while let Some(result) = round.join_next().await {
            let (route_id, peer, response) =
                result.map_err(|error| DkgError::NetworkCommunication(error.to_string()))?;
            let response =
                response.and_then(|response| validate_prepared_response(prepare, &peer, response));
            match response {
                Ok(()) => {
                    prepared.insert(route_id);
                }
                Err(error) => {
                    match reshare_preparation_error_action(next_routes.contains(&route_id), &error)
                    {
                        ResharePreparationErrorAction::Retry => {
                            crate::metrics::record_dkg_transport_event(
                                "control",
                                "preparation_retry",
                            );
                        }
                        ResharePreparationErrorAction::ExcludeOld => {
                            tracing::warn!(
                                peer = %extract_node_part(&peer),
                                %error,
                                "excluding unprepared old dealer from reshare"
                            );
                            excluded_old.insert(route_id);
                        }
                        ResharePreparationErrorAction::Fail => return Err(error),
                    }
                }
            }
        }
        sleep(DKG_TOPOLOGY_PROBE_INTERVAL.min(deadline.saturating_duration_since(Instant::now())))
            .await;
    }

    let mut active_dealers: Vec<_> = current_routes
        .iter()
        .filter_map(|(route, node_id)| {
            prepared
                .contains(route)
                .then_some(ParticipantRef::current(*node_id))
        })
        .collect();
    active_dealers.sort();
    let active_route_ids: BTreeSet<_> = next_routes
        .iter()
        .cloned()
        .chain(
            current_routes
                .keys()
                .filter(|route| prepared.contains(*route))
                .cloned(),
        )
        .collect();
    let active_routes = active_route_ids
        .iter()
        .filter_map(|route| route_by_id.get(route).cloned())
        .collect();
    Ok((active_routes, active_dealers))
}

fn validate_prepared_response(
    prepare: &PrepareSession,
    peer: &str,
    response: DkgControlMessage,
) -> Result<()> {
    match response {
        DkgControlMessage::Prepared {
            ceremony_id,
            attempt_id,
            config_digest,
        } if ceremony_id == prepare.ceremony_id
            && attempt_id == prepare.attempt_id
            && config_digest == prepare.config_digest =>
        {
            Ok(())
        }
        _ => Err(DkgError::ProtocolError(format!(
            "peer {peer} returned invalid Prepared response"
        ))),
    }
}

async fn cleanup_excluded_reshare_dealers<D>(
    state: &Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    prepare: &PrepareSession,
    active_routes: &[String],
) where
    D: CoordinatorDkg,
{
    if prepare.committees.next.is_none() {
        return;
    }
    let active: BTreeSet<_> = active_routes
        .iter()
        .map(|route| extract_node_part(route).to_lowercase())
        .collect();
    let mut cleanups = JoinSet::new();
    for peer in &prepare.committees.current.peer_routes {
        if active.contains(&extract_node_part(peer).to_lowercase())
            || is_self_peer_id(&state.network, peer)
        {
            continue;
        }
        let state = state.clone();
        let peer = peer.clone();
        let ceremony_id = prepare.ceremony_id;
        let attempt_id = prepare.attempt_id;
        cleanups.spawn(async move {
            let _ = control_request_with_timeout(
                &state,
                routes,
                &peer,
                DkgControlMessage::Abort {
                    ceremony_id,
                    attempt_id,
                    reason: "old dealer excluded from frozen active set".into(),
                },
                Duration::from_secs(2),
            )
            .await;
        });
    }
    while cleanups.join_next().await.is_some() {}
}

async fn coordinate_prepared_inner<D>(
    state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    prepare: PrepareSession,
) -> Result<(CeremonyId, AttemptId)>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    let readiness_start = Instant::now();
    let deadline = readiness_start + DKG_PREPARATION_TIMEOUT;
    let ceremony_kind = match &prepare.kind {
        SessionKind::Fresh => DkgCeremonyKind::Fresh,
        SessionKind::Refresh { .. } => DkgCeremonyKind::Refresh,
        SessionKind::Reshare { .. } => DkgCeremonyKind::Reshare,
    };
    let ceremony_id = prepare.ceremony_id;
    let attempt_id = prepare.attempt_id;
    let session_id = ceremony_id.0;
    // Prepare self first. This atomically claims the deterministic session ID,
    // preventing concurrent starts from creating competing attempts.
    let self_peer = state.network.local_peer_id();
    match prepare_participant(state.clone(), routes, prepare.clone(), &self_peer).await? {
        DkgControlMessage::Prepared { .. } => {}
        response => {
            return Err(DkgError::ProtocolError(format!(
                "local prepare returned unexpected response: {response:?}"
            )))
        }
    }

    let (peer_ids, active_dealers) =
        prepare_transport_participants(&state, routes, &prepare, deadline).await?;
    cleanup_excluded_reshare_dealers(&state, routes, &prepare, &peer_ids).await;

    let nonce: [u8; 32] = rand::random();
    let topic_handle = state
        .dkg_session_state
        .transport_topic(&session_id)
        .await
        .ok_or_else(|| DkgError::InvalidState("leader did not join transient topic".into()))?;
    let probe = transport::encode(&DkgPublicMessage::TopologyProbe {
        ceremony_id,
        attempt_id,
        nonce,
    })
    .map_err(DkgError::Serialization)?;
    let expected_peers: BTreeSet<String> = peer_ids
        .iter()
        .map(|peer| extract_node_part(peer).to_lowercase())
        .collect();
    let self_route = peer_ids
        .iter()
        .find(|peer| is_self_peer_id(&state.network, peer))
        .map(|peer| extract_node_part(peer).to_lowercase())
        .ok_or_else(|| {
            DkgError::InvalidState("leader route is absent from its committee".into())
        })?;
    let probe_notify = state
        .dkg_session_state
        .begin_topology_probe(&session_id, attempt_id, nonce, self_route)
        .await
        .ok_or_else(|| DkgError::InvalidState("leader cannot begin topology probe".into()))?;
    crate::metrics::record_dkg_transport_event("control", "probe_ack");
    let probe = Bytes::from(probe);
    let mut probe_tick = tokio::time::interval(DKG_TOPOLOGY_PROBE_INTERVAL);
    probe_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let missing = loop {
        let acknowledged = state
            .dkg_session_state
            .topology_probe_acknowledgements(&session_id, attempt_id, nonce)
            .await
            .ok_or_else(|| DkgError::InvalidState("topology probe attempt disappeared".into()))?;
        let missing = missing_topology_peers(&expected_peers, &acknowledged);
        if missing.is_empty() || Instant::now() >= deadline {
            break missing;
        }
        tokio::select! {
            _ = probe_notify.notified() => {}
            _ = probe_tick.tick() => {
                match topic_handle.broadcast(probe.clone()).await {
                    Ok(()) => {
                        crate::metrics::record_dkg_transport_event("public", "probe_broadcast");
                    }
                    Err(error) => {
                        crate::metrics::record_dkg_transport_event("public", "probe_broadcast_failure");
                        tracing::warn!(%error, session_id, "topology probe broadcast failed; retrying");
                    }
                }
            }
            _ = tokio::time::sleep_until(deadline) => {}
        }
    };
    if !missing.is_empty() {
        let missing_routes: Vec<String> = peer_ids
            .iter()
            .filter(|peer| missing.contains(&extract_node_part(peer).to_lowercase()))
            .cloned()
            .collect();
        // TODO: this only logs today. `missing_routes` already has everything
        // `queue_pss_offline_report_task` needs (peer route, prepare.kind,
        // prepare.ring_id, session_id) — that function doesn't require a live
        // session and already no-ops for SessionKind::Fresh, so reporting a
        // participant that never acknowledges the topology probe during
        // preparation should be a small addition (spawn a report per missing
        // peer here, same pattern as `report_abandoned_pss_session`), not a
        // new detection mechanism. Needed because refresh/reshare require
        // every current member (refresh) or every next-committee receiver
        // (reshare) to ack before activation, and today only the later
        // Phase1Commitments/Phase2Shares stall path (G1) produces a
        // `node_offline` report — a member unreachable from the very start
        // never gets past this barrier, so it's never reported at all.
        tracing::error!(
            session_id,
            attempt_id = %hex::encode(attempt_id.0),
            missing_peers = ?missing_routes,
            "topology preparation barrier expired"
        );
        let prefixes = missing_topology_peer_prefixes(&missing);
        return Err(DkgError::NetworkCommunication(format!(
            "topology probe acknowledgement missing from {} participants before preparation deadline: {prefixes}",
            missing.len()
        )));
    }

    // Activation and cryptographic start are separate barriers. Every active
    // participant must first persist the same activation digest; only then may
    // any node generate a contribution or open a private exchange.
    let activation_digest = transport::activation_digest(prepare.config_digest, &active_dealers)
        .map_err(DkgError::ProtocolError)?;
    let leader_activation = state
        .dkg_session_state
        .activate_transport(
            &session_id,
            attempt_id,
            activation_digest,
            active_dealers.clone(),
        )
        .await;
    match leader_activation {
        TransportActivationOutcome::Activated | TransportActivationOutcome::AlreadyActivated => {}
        TransportActivationOutcome::StaleAttempt | TransportActivationOutcome::MissingSession => {
            return Err(DkgError::ProtocolError(
                "failed to activate the leader's transport attempt".into(),
            ));
        }
    }

    let mut activations = JoinSet::new();
    for peer in peer_ids
        .iter()
        .filter(|peer| !is_self_peer_id(&state.network, peer))
    {
        let state = state.clone();
        let peer = peer.clone();
        let active_dealers = active_dealers.clone();
        activations.spawn(async move {
            retry_preparation_control(
                &state,
                routes,
                &peer,
                DkgControlMessage::Activate {
                    ceremony_id,
                    attempt_id,
                    activation_digest,
                    active_dealers,
                },
                deadline,
            )
            .await
        });
    }
    while let Some(result) = activations.join_next().await {
        match result.map_err(|error| DkgError::NetworkCommunication(error.to_string()))?? {
            DkgControlMessage::Activated {
                ceremony_id: got_ceremony,
                attempt_id: got_attempt,
                activation_digest: got_activation,
            } if got_ceremony == ceremony_id
                && got_attempt == attempt_id
                && got_activation == activation_digest => {}
            response => {
                return Err(DkgError::ProtocolError(format!(
                    "invalid activation response: {response:?}"
                )))
            }
        }
    }

    match state
        .dkg_session_state
        .begin_transport(&session_id, attempt_id, activation_digest)
        .await
    {
        TransportBeginOutcome::Begun => {
            spawn_cryptographic_attempt(
                state.clone(),
                routes,
                AttemptKey::new(ceremony_id, attempt_id),
            );
        }
        TransportBeginOutcome::AlreadyBegun => {}
        TransportBeginOutcome::NotActivated
        | TransportBeginOutcome::StaleAttempt
        | TransportBeginOutcome::MissingSession => {
            return Err(DkgError::ProtocolError(
                "failed to begin the leader's activated transport attempt".into(),
            ));
        }
    }

    let mut beginnings = JoinSet::new();
    for peer in peer_ids
        .iter()
        .filter(|peer| !is_self_peer_id(&state.network, peer))
    {
        let state = state.clone();
        let peer = peer.clone();
        beginnings.spawn(async move {
            retry_preparation_control(
                &state,
                routes,
                &peer,
                DkgControlMessage::Begin {
                    ceremony_id,
                    attempt_id,
                    activation_digest,
                },
                deadline,
            )
            .await
        });
    }
    while let Some(result) = beginnings.join_next().await {
        match result.map_err(|error| DkgError::NetworkCommunication(error.to_string()))?? {
            DkgControlMessage::Begun {
                ceremony_id: got_ceremony,
                attempt_id: got_attempt,
                activation_digest: got_activation,
            } if got_ceremony == ceremony_id
                && got_attempt == attempt_id
                && got_activation == activation_digest => {}
            response => {
                return Err(DkgError::ProtocolError(format!(
                    "invalid begin response: {response:?}"
                )))
            }
        }
    }
    crate::metrics::record_dkg_control_readiness(
        ceremony_kind,
        readiness_start.elapsed().as_secs_f64(),
    );
    crate::metrics::record_dkg_transport_event("control", "activated");
    Ok((ceremony_id, attempt_id))
}

async fn abort_prepared_attempt<D>(
    state: &Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    prepare: &PrepareSession,
    reason: String,
) where
    D: CoordinatorDkg,
{
    broadcast_attempt_abort(
        state,
        routes,
        prepare.participant_routes(),
        prepare.ceremony_id,
        prepare.attempt_id,
        reason,
    )
    .await;
}

async fn broadcast_attempt_abort<D>(
    state: &Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    participant_routes: Vec<String>,
    ceremony_id: CeremonyId,
    attempt_id: AttemptId,
    reason: String,
) where
    D: CoordinatorDkg,
{
    let mut aborts = JoinSet::new();
    for peer in participant_routes
        .into_iter()
        .filter(|peer| !is_self_peer_id(&state.network, peer))
    {
        let state = state.clone();
        let reason = reason.clone();
        aborts.spawn(async move {
            timeout(
                Duration::from_secs(2),
                control_request_with_timeout(
                    &state,
                    routes,
                    &peer,
                    DkgControlMessage::Abort {
                        ceremony_id,
                        attempt_id,
                        reason,
                    },
                    PEER_RESPONSE_TIMEOUT,
                ),
            )
            .await
        });
    }
    while aborts.join_next().await.is_some() {}
    crate::metrics::record_dkg_transport_event("control", "abort");
}

async fn prepare_participant<D>(
    state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    prepare: PrepareSession,
    sender: &PeerId,
) -> Result<DkgControlMessage>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    let leader_authorized =
        prepare.canonical_leader_node_key() == Some(prepare.leader_node_key.as_str());
    if !leader_authorized {
        if matches!(&prepare.kind, SessionKind::Refresh { .. }) {
            // TODO(reporting): retain the authenticated noncanonical refresh
            // Prepare as evidence of attributable leader impersonation.
            crate::metrics::record_dkg_transport_event("control", "refresh_start_rejected");
        }
        return Err(DkgError::Unauthorized(
            "Prepare names an unauthorized leader".into(),
        ));
    }
    let leader_route = prepare
        .leader_route()
        .ok_or_else(|| DkgError::InvalidInput("Prepare omits leader route".into()))?;
    if !peer_matches_route(sender, leader_route) {
        return Err(DkgError::Unauthorized(
            "Prepare sender is not canonical leader".into(),
        ));
    }
    let expected = transport::config_digest(&prepare).map_err(DkgError::Serialization)?;
    if expected != prepare.config_digest {
        return Err(DkgError::Unauthorized(
            "Prepare configuration digest mismatch".into(),
        ));
    }
    validate_reshare_transport_routes(&state, &prepare).await?;
    let coordinator = DkgCoordinator::with_routes(state.clone(), routes);
    handle_session_init(
        &coordinator,
        AttemptKey::new(prepare.ceremony_id, prepare.attempt_id),
        prepare.committees.current.threshold,
        prepare.committees.current.len() as u32,
        &prepare.committees.current.peer_routes,
        &prepare.committees.current.node_keys,
        &prepare.committees.current.node_id_assignments,
        &prepare.token_string,
        &prepare.kind,
        prepare.pss_interval,
        prepare.policy_id.clone(),
        prepare.ring_id.clone(),
        sender,
    )
    .await?;

    // A lost Prepared response may cause the leader to retry the exact request.
    // Do not create and immediately drop another Gossip subscription in that case;
    // doing so emits neighbor churn across the whole transient mesh.
    if let Some((ceremony_id, attempt_id, config_digest)) = state
        .dkg_session_state
        .transport_configuration(&prepare.ceremony_id.0)
        .await
    {
        if ceremony_id == prepare.ceremony_id
            && attempt_id == prepare.attempt_id
            && config_digest == prepare.config_digest
        {
            return Ok(DkgControlMessage::Prepared {
                ceremony_id: prepare.ceremony_id,
                attempt_id: prepare.attempt_id,
                config_digest: prepare.config_digest,
            });
        }
        return Err(DkgError::ProtocolError(
            "Prepare conflicts with the configured transport attempt".into(),
        ));
    }

    let pubsub = state.network.pubsub().ok_or_else(|| {
        DkgError::InvalidState("network backend does not provide authenticated pub-sub".into())
    })?;
    // The leader creates the topic without waiting for peers. Followers join
    // through the already-subscribed leader, avoiding a circular join barrier
    // during preparation.
    let bootstrap = leader_bootstrap(&state.node_key, &prepare.leader_node_key, leader_route)?;
    let topic_id = network::TopicId::new(prepare.topic_id);
    let topic = pubsub
        .subscribe(topic_id, bootstrap)
        .await
        .map_err(|error| DkgError::NetworkCommunication(error.to_string()))?;
    let outcome = state
        .dkg_session_state
        .configure_transport(
            &prepare.ceremony_id.0,
            prepare.ceremony_id,
            prepare.attempt_id,
            prepare.committee_digest(),
            prepare.config_digest,
            topic_id,
            prepare.leader_node_key.clone(),
            leader_route.to_string(),
            prepare.participant_routes(),
            prepare.committees.clone(),
            topic.clone(),
        )
        .await;
    if matches!(
        outcome,
        TransportConfigureOutcome::ConflictingAttempt | TransportConfigureOutcome::MissingSession
    ) {
        return Err(DkgError::ProtocolError(format!(
            "cannot configure transport attempt: {outcome:?}"
        )));
    }
    if matches!(outcome, TransportConfigureOutcome::Configured) {
        let task = tokio::spawn(topic_listener(
            state.clone(),
            routes,
            prepare.clone(),
            topic,
        ));
        state
            .dkg_session_state
            .set_transport_topic_task(&prepare.ceremony_id.0, task.abort_handle())
            .await;
    }
    Ok(DkgControlMessage::Prepared {
        ceremony_id: prepare.ceremony_id,
        attempt_id: prepare.attempt_id,
        config_digest: prepare.config_digest,
    })
}

async fn send_topology_probe_ack<D>(
    state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    prepare: PrepareSession,
    leader_route: String,
    nonce: [u8; 32],
) -> Result<[u8; 32]>
where
    D: CoordinatorDkg,
{
    let deadline = state
        .dkg_session_state
        .transport_preparation_deadline(&prepare.ceremony_id.0, prepare.attempt_id)
        .await
        .map(Instant::from_std)
        .ok_or_else(|| DkgError::SessionNotFound(prepare.ceremony_id.0.to_string()))?;
    let request = DkgControlMessage::TopologyProbeAck {
        ceremony_id: prepare.ceremony_id,
        attempt_id: prepare.attempt_id,
        nonce,
    };
    let mut backoff = INITIAL_CONTROL_RETRY_BACKOFF;
    loop {
        if state
            .dkg_session_state
            .transport_attempt(&prepare.ceremony_id.0)
            .await
            != Some(prepare.attempt_id)
        {
            return Err(DkgError::ProtocolError(
                "topology acknowledgement attempt was removed".into(),
            ));
        }
        let now = Instant::now();
        if now >= deadline {
            return Err(DkgError::NetworkCommunication(
                "topology acknowledgement exceeded the preparation deadline".into(),
            ));
        }
        let remaining = deadline.saturating_duration_since(now);
        match control_request_with_timeout(
            &state,
            routes,
            &leader_route,
            request.clone(),
            PEER_RESPONSE_TIMEOUT.min(remaining),
        )
        .await
        {
            Ok(DkgControlMessage::TopologyProbeAck {
                ceremony_id,
                attempt_id,
                nonce: acknowledged_nonce,
            }) if ceremony_id == prepare.ceremony_id
                && attempt_id == prepare.attempt_id
                && acknowledged_nonce == nonce =>
            {
                return Ok(nonce)
            }
            Ok(response) => {
                return Err(DkgError::ProtocolError(format!(
                    "leader returned invalid topology acknowledgement response: {response:?}"
                )));
            }
            Err(error) if retryable_control_error(&error) => {
                crate::metrics::record_dkg_transport_event("control", "preparation_retry");
                tracing::warn!(
                    %error,
                    session_id = prepare.ceremony_id.0,
                    "topology acknowledgement failed; retrying identical bytes"
                );
            }
            Err(error) => return Err(error),
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            continue;
        }
        sleep(backoff.min(remaining)).await;
        backoff = (backoff * 2).min(DKG_PREPARATION_RETRY_MAX_BACKOFF);
    }
}

async fn abort_public_protocol_violation_from_listener<D>(
    state: &Arc<AppState<D>>,
    prepare: &PrepareSession,
    violation: &PublicProtocolViolation,
) where
    D: CoordinatorDkg,
{
    abort_public_protocol_violation(
        state,
        prepare,
        violation,
        TopicTaskDisposition::DetachCurrent,
    )
    .await;
}

async fn abort_public_protocol_violation<D>(
    state: &Arc<AppState<D>>,
    prepare: &PrepareSession,
    violation: &PublicProtocolViolation,
    topic_task: TopicTaskDisposition,
) where
    D: CoordinatorDkg,
{
    let root = violation.root.map(hex::encode);
    let message_ids: Vec<_> = violation
        .message_ids
        .iter()
        .map(|message_id| hex::encode(message_id.0))
        .collect();
    tracing::error!(
        session_id = prepare.ceremony_id.0,
        attempt_id = %hex::encode(prepare.attempt_id.0),
        phase = ?violation.phase,
        root = ?root,
        message_ids = ?message_ids,
        accused = ?violation.accused,
        violation = ?violation.kind,
        detail = %violation.detail,
        "aborting DKG attempt after authenticated public protocol violation"
    );
    crate::metrics::record_dkg_transport_event("public", "protocol_violation_abort");
    // TODO(reporting): preserve the authenticated leader/origin delivery or
    // both origin-signed envelopes and submit the appropriate DKG fault or
    // equivocation report. Reporting evidence/schema work is intentionally
    // deferred.
    state
        .dkg_session_state
        .abort_transport_attempt(
            AttemptKey::new(prepare.ceremony_id, prepare.attempt_id),
            topic_task,
        )
        .await;
}

async fn apply_validated_public_batch<D>(
    state: &Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    prepare: &PrepareSession,
    phase: PublicPhase,
    root: [u8; 32],
    contributions: Vec<VerifiedPublicContribution>,
) -> std::result::Result<bool, PublicProtocolViolation>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    for verified in &contributions {
        if let Err(error) = preflight_public_contribution_if_new(
            state,
            routes,
            &verified.signed,
            &verified.contribution,
        )
        .await
        {
            if state
                .dkg_session_state
                .transport_attempt(&prepare.ceremony_id.0)
                .await
                != Some(prepare.attempt_id)
            {
                return Ok(false);
            }
            if !attributable_public_preflight_error(&error) {
                tracing::warn!(
                    %error,
                    phase = ?phase,
                    root = %hex::encode(root),
                    origin = ?verified.contribution.origin,
                    "deferring public DKG batch after local payload preflight could not complete"
                );
                crate::metrics::record_dkg_transport_event("public", "batch_preflight_deferred");
                return Ok(true);
            }
            return Err(PublicProtocolViolation::leader(
                PublicProtocolViolationKind::InvalidContribution,
                Some(phase),
                Some(root),
                format!(
                    "origin {:?} contribution failed payload preflight: {error}",
                    verified.contribution.origin
                ),
            )
            .with_message_id(verified.contribution.message_id));
        }
    }
    let retained: BTreeMap<_, _> = contributions
        .iter()
        .map(|verified| (verified.contribution.origin, verified.signed.clone()))
        .collect();
    match state
        .dkg_session_state
        .record_public_batch(&prepare.ceremony_id.0, prepare.attempt_id, phase, retained)
        .await
    {
        PublicBatchRecordOutcome::Recorded => {}
        PublicBatchRecordOutcome::DuplicateSame => {
            crate::metrics::record_dkg_transport_event("public", "batch_duplicate");
        }
        PublicBatchRecordOutcome::ConflictingDuplicate { origin } => {
            return Err(PublicProtocolViolation::origin(
                phase,
                Some(root),
                origin,
                "manifest-validated batch conflicts with a retained signed contribution",
            ));
        }
        PublicBatchRecordOutcome::StaleAttempt | PublicBatchRecordOutcome::MissingSession => {
            return Ok(false);
        }
    }

    // A refresh result uses a two-step control barrier. Gossip reception retains
    // the exact validated result, but only CommitRefreshResult promotes it.
    if phase != PublicPhase::RefreshHealthCheck {
        for verified in contributions {
            let message_id = verified.contribution.message_id;
            if let Err(error) = dispatch_public_contribution(
                state.clone(),
                routes,
                verified.signed,
                verified.contribution,
            )
            .await
            {
                if state
                    .dkg_session_state
                    .transport_attempt(&prepare.ceremony_id.0)
                    .await
                    != Some(prepare.attempt_id)
                {
                    return Ok(false);
                }
                if matches!(
                    &error,
                    DkgError::Unauthorized(_)
                        | DkgError::Deserialization(_)
                        | DkgError::Crypto(_)
                        | DkgError::InvalidInput(_)
                        | DkgError::CommitmentVerificationFailed(_)
                ) {
                    return Err(PublicProtocolViolation::leader(
                        PublicProtocolViolationKind::InvalidContribution,
                        Some(phase),
                        Some(root),
                        format!("validated contribution failed protocol application: {error}"),
                    )
                    .with_message_id(message_id));
                }
                tracing::warn!(
                    %error,
                    phase = ?phase,
                    root = %hex::encode(root),
                    "failed to dispatch manifest-validated public DKG contribution"
                );
            }
        }
    }

    crate::metrics::record_dkg_transport_event("public", "batch_validated");
    tracing::info!(
        session_id = prepare.ceremony_id.0,
        attempt_id = %hex::encode(prepare.attempt_id.0),
        phase = ?phase,
        root = %hex::encode(root),
        "validated and applied public DKG Gossip batch"
    );
    Ok(true)
}

async fn topic_listener<D>(
    state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    prepare: PrepareSession,
    topic: Arc<dyn Topic>,
) where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    let leader_route = prepare
        .leader_route()
        .map(str::to_owned)
        .unwrap_or_default();
    let mut repair_tick = tokio::time::interval(DKG_REPAIR_STALL_INTERVAL);
    repair_tick.tick().await;
    let mut topic = topic;
    let mut neighbor_tracker = GossipNeighborTracker::default();
    let mut acknowledgement_tasks = JoinSet::new();
    let mut acknowledgement_in_flight = false;
    let mut acknowledged_nonce: Option<[u8; 32]> = None;
    let mut public_batches = PublicBatchAssembler::default();
    let mut manifest_repairs = ManifestRepairSchedule::default();
    let mut rejected_gossip_frames = 0u64;
    'listener: loop {
        if state
            .dkg_session_state
            .transport_attempt(&prepare.ceremony_id.0)
            .await
            != Some(prepare.attempt_id)
        {
            // Completion/abort owns topic teardown and all listener-owned work.
            break;
        }
        let isolation_deadline = neighbor_tracker.isolation_deadline();
        let manifest_repair_deadline = manifest_repairs.next_deadline();
        let event = tokio::select! {
            acknowledgement = acknowledgement_tasks.join_next(), if !acknowledgement_tasks.is_empty() => {
                acknowledgement_in_flight = false;
                match acknowledgement {
                    Some(Ok(Ok(nonce))) => acknowledged_nonce = Some(nonce),
                    Some(Ok(Err(error))) => tracing::warn!(
                        %error,
                        session_id = prepare.ceremony_id.0,
                        "topology acknowledgement worker ended without acknowledgement"
                    ),
                    Some(Err(error)) => tracing::warn!(
                        %error,
                        session_id = prepare.ceremony_id.0,
                        "topology acknowledgement worker failed"
                    ),
                    None => {}
                }
                continue;
            }
            _ = async {
                match isolation_deadline {
                    Some(deadline) => tokio::time::sleep_until(deadline).await,
                    None => std::future::pending::<()>().await,
                }
            } => {
                if neighbor_tracker.is_isolated() {
                    tracing::warn!(
                        session_id = prepare.ceremony_id.0,
                        "DKG Gossip topic remained isolated beyond grace period; rejoining"
                    );
                    match rejoin_public_topic_with_retry(
                        &state, &prepare, &leader_route, "rejoin_isolation",
                    ).await {
                        Ok(rejoined) => {
                            topic = rejoined;
                            neighbor_tracker.reset_after_rejoin();
                        }
                        Err(error) => {
                            tracing::warn!(%error, "failed to recover isolated DKG Gossip topic");
                            break;
                        }
                    }
                }
                continue;
            }
            _ = async {
                match manifest_repair_deadline {
                    Some(deadline) => tokio::time::sleep_until(deadline).await,
                    None => std::future::pending::<()>().await,
                }
            } => {
                for phase in manifest_repairs.take_due(Instant::now()) {
                    if let Err(error) = repair_public_phase(
                        state.clone(),
                        routes,
                        prepare.clone(),
                        phase,
                        false,
                        TopicTaskDisposition::DetachCurrent,
                    ).await {
                        tracing::warn!(
                            %error,
                            phase = ?phase,
                            "scheduled public DKG completeness repair failed"
                        );
                    }
                }
                continue;
            }
            event = topic.recv() => event,
            _ = repair_tick.tick() => {
                if state.dkg_session_state.transport_repair_due(
                    &prepare.ceremony_id.0,
                    prepare.attempt_id,
                    DKG_REPAIR_STALL_INTERVAL,
                ).await {
                    for &phase in repairable_public_phases(&prepare.kind) {
                        if let Err(error) = repair_public_phase(
                            state.clone(),
                            routes,
                            prepare.clone(),
                            phase,
                            false,
                            TopicTaskDisposition::DetachCurrent,
                        ).await {
                            tracing::debug!(%error, phase = ?phase,
                                "periodic public DKG completeness repair did not complete");
                        }
                    }
                }
                continue;
            }
        };
        match event {
            Ok(PubSubEvent::Received(message)) => {
                if !peer_matches_route(&message.origin, &leader_route) {
                    tracing::warn!("discarding DKG Gossip message not published by leader");
                    continue;
                }
                let event_digest = authenticated_public_event_digest(&message.data);
                let public = match transport::decode::<DkgPublicMessage>(
                    &message.data,
                    MAX_CONTROL_MESSAGE_BYTES,
                ) {
                    Ok(public) => public,
                    Err(error) => {
                        let violation = PublicProtocolViolation::leader(
                            PublicProtocolViolationKind::MalformedLeaderMessage,
                            None,
                            None,
                            error,
                        );
                        abort_public_protocol_violation_from_listener(&state, &prepare, &violation)
                            .await;
                        break 'listener;
                    }
                };
                match public {
                    DkgPublicMessage::TopologyProbe {
                        ceremony_id,
                        attempt_id,
                        nonce,
                    } if ceremony_id == prepare.ceremony_id && attempt_id == prepare.attempt_id => {
                        let accepted = state
                            .dkg_session_state
                            .record_topology_probe(&ceremony_id.0, attempt_id, nonce)
                            .await
                            == Some(true);
                        if !accepted {
                            tracing::warn!(
                                session_id = ceremony_id.0,
                                "discarding conflicting or stale topology probe"
                            );
                            continue;
                        }
                        if state.node_key != prepare.leader_node_key
                            && acknowledged_nonce != Some(nonce)
                            && !acknowledgement_in_flight
                        {
                            acknowledgement_in_flight = true;
                            acknowledgement_tasks.spawn(send_topology_probe_ack(
                                state.clone(),
                                routes,
                                prepare.clone(),
                                leader_route.clone(),
                                nonce,
                            ));
                        }
                    }
                    DkgPublicMessage::Chunk {
                        ceremony_id,
                        attempt_id,
                        phase,
                        phase_root,
                        index,
                        contributions,
                    } if ceremony_id == prepare.ceremony_id && attempt_id == prepare.attempt_id => {
                        let Some(mode) = public_batch_mode(&prepare.kind, phase) else {
                            let violation = PublicProtocolViolation::leader(
                                PublicProtocolViolationKind::InvalidChunk,
                                Some(phase),
                                Some(phase_root),
                                "public chunk is not allowed for this ceremony kind",
                            );
                            abort_public_protocol_violation_from_listener(
                                &state, &prepare, &violation,
                            )
                            .await;
                            break 'listener;
                        };
                        if message.data.len() > transport::MAX_PUBLIC_CHUNK_BYTES {
                            let violation = PublicProtocolViolation::leader(
                                PublicProtocolViolationKind::BufferLimit,
                                Some(phase),
                                Some(phase_root),
                                format!(
                                    "encoded chunk is {} bytes, exceeding the {}-byte limit",
                                    message.data.len(),
                                    transport::MAX_PUBLIC_CHUNK_BYTES
                                ),
                            );
                            abort_public_protocol_violation_from_listener(
                                &state, &prepare, &violation,
                            )
                            .await;
                            break 'listener;
                        }

                        let mut verified = Vec::with_capacity(contributions.len());
                        for signed in contributions {
                            match verify_signed_contribution(&state, &signed).await {
                                Ok(contribution)
                                    if contribution.payload.phase() == phase
                                        && contribution.ceremony_id == ceremony_id
                                        && contribution.attempt_id == attempt_id =>
                                {
                                    verified.push(VerifiedPublicContribution {
                                        signed,
                                        contribution,
                                    });
                                }
                                Ok(contribution) => {
                                    let violation = PublicProtocolViolation::leader(
                                        PublicProtocolViolationKind::InvalidContribution,
                                        Some(phase),
                                        Some(phase_root),
                                        format!(
                                            "chunk contribution {:?} has the wrong public scope",
                                            contribution.origin
                                        ),
                                    );
                                    abort_public_protocol_violation_from_listener(
                                        &state, &prepare, &violation,
                                    )
                                    .await;
                                    break 'listener;
                                }
                                Err(error) => {
                                    if state
                                        .dkg_session_state
                                        .transport_attempt(&ceremony_id.0)
                                        .await
                                        != Some(attempt_id)
                                    {
                                        break 'listener;
                                    }
                                    let violation = PublicProtocolViolation::leader(
                                        PublicProtocolViolationKind::InvalidContribution,
                                        Some(phase),
                                        Some(phase_root),
                                        error.to_string(),
                                    );
                                    abort_public_protocol_violation_from_listener(
                                        &state, &prepare, &violation,
                                    )
                                    .await;
                                    break 'listener;
                                }
                            }
                        }

                        let expected_origins =
                            expected_public_origins(&state, &prepare, phase).await;
                        let assembly = public_batches.insert_chunk(
                            mode,
                            phase,
                            phase_root,
                            index,
                            verified,
                            event_digest,
                            expected_origins.len(),
                        );
                        match assembly {
                            Ok(PublicBatchAssembly::Pending { .. }) => {
                                crate::metrics::record_dkg_transport_event(
                                    "public",
                                    "batch_buffered",
                                );
                            }
                            Ok(PublicBatchAssembly::Duplicate) => {
                                crate::metrics::record_dkg_transport_event(
                                    "public",
                                    "batch_duplicate",
                                );
                            }
                            Ok(PublicBatchAssembly::Complete {
                                phase,
                                root,
                                contributions,
                            }) => {
                                if mode == PublicBatchMode::Complete {
                                    manifest_repairs.cancel(phase);
                                }
                                match apply_validated_public_batch(
                                    &state,
                                    routes,
                                    &prepare,
                                    phase,
                                    root,
                                    contributions,
                                )
                                .await
                                {
                                    Ok(true) => {}
                                    Ok(false) => break 'listener,
                                    Err(violation) => {
                                        abort_public_protocol_violation_from_listener(
                                            &state, &prepare, &violation,
                                        )
                                        .await;
                                        break 'listener;
                                    }
                                }
                            }
                            Err(violation) => {
                                abort_public_protocol_violation_from_listener(
                                    &state, &prepare, &violation,
                                )
                                .await;
                                break 'listener;
                            }
                        }
                    }
                    DkgPublicMessage::Manifest(manifest)
                        if manifest.ceremony_id == prepare.ceremony_id
                            && manifest.attempt_id == prepare.attempt_id =>
                    {
                        let expected_origins =
                            expected_public_origins(&state, &prepare, manifest.phase).await;
                        let phase = manifest.phase;
                        let Some(mode) = public_batch_mode(&prepare.kind, phase) else {
                            let violation = PublicProtocolViolation::leader(
                                PublicProtocolViolationKind::InvalidManifest,
                                Some(phase),
                                Some(manifest.phase_root),
                                "public manifest is not allowed for this ceremony kind",
                            );
                            abort_public_protocol_violation_from_listener(
                                &state, &prepare, &violation,
                            )
                            .await;
                            break 'listener;
                        };
                        match public_batches.insert_manifest(
                            mode,
                            manifest,
                            event_digest,
                            &expected_origins,
                        ) {
                            Ok(PublicBatchAssembly::Pending {
                                manifest_added: true,
                            }) => {
                                tracing::debug!(phase = ?phase,
                                    "received public DKG manifest; awaiting chunks");
                                let event = if manifest_repairs
                                    .arm(phase, Instant::now() + DKG_REPAIR_STALL_INTERVAL)
                                {
                                    "manifest_repair_scheduled"
                                } else {
                                    "manifest_repair_coalesced"
                                };
                                crate::metrics::record_dkg_transport_event("public", event);
                            }
                            Ok(PublicBatchAssembly::Pending {
                                manifest_added: false,
                            }) => {}
                            Ok(PublicBatchAssembly::Duplicate) => {
                                crate::metrics::record_dkg_transport_event(
                                    "public",
                                    "batch_duplicate",
                                );
                            }
                            Ok(PublicBatchAssembly::Complete {
                                phase,
                                root,
                                contributions,
                            }) => {
                                if mode == PublicBatchMode::Complete {
                                    manifest_repairs.cancel(phase);
                                }
                                match apply_validated_public_batch(
                                    &state,
                                    routes,
                                    &prepare,
                                    phase,
                                    root,
                                    contributions,
                                )
                                .await
                                {
                                    Ok(true) => {}
                                    Ok(false) => break 'listener,
                                    Err(violation) => {
                                        abort_public_protocol_violation_from_listener(
                                            &state, &prepare, &violation,
                                        )
                                        .await;
                                        break 'listener;
                                    }
                                }
                            }
                            Err(violation) => {
                                abort_public_protocol_violation_from_listener(
                                    &state, &prepare, &violation,
                                )
                                .await;
                                break 'listener;
                            }
                        }
                    }
                    _ => tracing::debug!("discarding stale DKG Gossip message"),
                }
            }
            Ok(PubSubEvent::Lagged) => {
                tracing::warn!(
                    session_id = prepare.ceremony_id.0,
                    "DKG Gossip subscriber lagged; rejoining topic and running direct repair"
                );
                match rejoin_public_topic_with_retry(&state, &prepare, &leader_route, "rejoin_lag")
                    .await
                {
                    Ok(rejoined) => {
                        topic = rejoined;
                        neighbor_tracker.reset_after_rejoin();
                    }
                    Err(error) => {
                        tracing::warn!(%error, "failed to rejoin lagged DKG Gossip topic");
                        break;
                    }
                }
                for &phase in repairable_public_phases(&prepare.kind) {
                    let state = state.clone();
                    let prepare = prepare.clone();
                    tokio::spawn(async move {
                        if let Err(error) = repair_public_phase(
                            state,
                            routes,
                            prepare,
                            phase,
                            true,
                            TopicTaskDisposition::Abort,
                        )
                        .await
                        {
                            tracing::warn!(%error, "public DKG lag repair failed");
                        }
                    });
                }
            }
            Ok(PubSubEvent::Rejected {
                delivered_from: _,
                reason,
            }) => {
                rejected_gossip_frames = rejected_gossip_frames.saturating_add(1);
                crate::metrics::record_dkg_transport_event("public", "gossip_frame_rejected");
                // Invalid outer envelopes are not attributable to their claimed
                // publisher. `delivered_from` may only be an honest Gossip relay.
                // Keep the healthy subscription and let the listener service its
                // normal timers between rejected frames.
                if rejected_gossip_frames == 1 || rejected_gossip_frames.is_power_of_two() {
                    tracing::warn!(
                        session_id = prepare.ceremony_id.0,
                        attempt_id = %hex::encode(prepare.attempt_id.0),
                        %reason,
                        rejected_frames = rejected_gossip_frames,
                        "discarding unauthenticated DKG Gossip frame"
                    );
                }
            }
            Ok(PubSubEvent::NeighborUp(peer)) => {
                neighbor_tracker.neighbor_up(&peer);
            }
            Ok(PubSubEvent::NeighborDown(peer)) => {
                crate::metrics::record_dkg_transport_event("public", "neighbor_down");
                tracing::debug!(
                    session_id = prepare.ceremony_id.0,
                    peer = %hex::encode(peer.as_bytes()),
                    remaining_neighbors = neighbor_tracker.neighbor_count().saturating_sub(1),
                    "DKG Gossip neighbor disconnected"
                );
                neighbor_tracker.neighbor_down(&peer, Instant::now());
            }
            Err(error) => {
                tracing::warn!(%error, "DKG Gossip subscription ended; rejoining");
                match rejoin_public_topic_with_retry(
                    &state,
                    &prepare,
                    &leader_route,
                    "rejoin_subscription_error",
                )
                .await
                {
                    Ok(rejoined) => {
                        topic = rejoined;
                        neighbor_tracker.reset_after_rejoin();
                    }
                    Err(error) => {
                        tracing::warn!(%error, "failed to recover ended DKG Gossip subscription");
                        break;
                    }
                }
            }
        }
    }
}

async fn rejoin_public_topic<D>(
    state: &Arc<AppState<D>>,
    prepare: &PrepareSession,
    leader_route: &str,
) -> Result<Arc<dyn Topic>>
where
    D: CoordinatorDkg,
{
    let pubsub = state.network.pubsub().ok_or_else(|| {
        DkgError::InvalidState("network backend does not provide authenticated pub-sub".into())
    })?;
    let bootstrap = leader_bootstrap(&state.node_key, &prepare.leader_node_key, leader_route)?;
    let topic = pubsub
        .subscribe(network::TopicId::new(prepare.topic_id), bootstrap)
        .await
        .map_err(|error| DkgError::NetworkCommunication(error.to_string()))?;
    if state
        .dkg_session_state
        .replace_transport_topic(&prepare.ceremony_id.0, prepare.attempt_id, topic.clone())
        .await
        != Some(true)
    {
        return Err(DkgError::ProtocolError(
            "cannot rejoin a stale DKG attempt".into(),
        ));
    }
    Ok(topic)
}

async fn rejoin_public_topic_with_retry<D>(
    state: &Arc<AppState<D>>,
    prepare: &PrepareSession,
    leader_route: &str,
    metric_event: &'static str,
) -> Result<Arc<dyn Topic>>
where
    D: CoordinatorDkg,
{
    let hard_deadline = state
        .dkg_session_state
        .transport_hard_deadline(&prepare.ceremony_id.0, prepare.attempt_id)
        .await
        .map(Instant::from_std)
        .ok_or_else(|| DkgError::SessionNotFound(prepare.ceremony_id.0.to_string()))?;
    let mut backoff = INITIAL_CONTROL_RETRY_BACKOFF;
    loop {
        if state
            .dkg_session_state
            .transport_attempt(&prepare.ceremony_id.0)
            .await
            != Some(prepare.attempt_id)
        {
            return Err(DkgError::ProtocolError(
                "cannot rejoin a stale DKG attempt".into(),
            ));
        }
        match rejoin_public_topic(state, prepare, leader_route).await {
            Ok(topic) => {
                crate::metrics::record_dkg_transport_event("public", metric_event);
                return Ok(topic);
            }
            Err(error) => {
                crate::metrics::record_dkg_transport_event("public", "rejoin_failure");
                tracing::warn!(
                    %error,
                    session_id = prepare.ceremony_id.0,
                    metric_event,
                    "DKG Gossip topic rejoin failed; retrying"
                );
            }
        }
        let remaining = hard_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(DkgError::NetworkCommunication(
                "DKG Gossip rejoin reached the hard attempt deadline".into(),
            ));
        }
        sleep(backoff.min(remaining)).await;
        backoff = (backoff * 2).min(DKG_MAX_REPAIR_BACKOFF);
    }
}

#[derive(Debug)]
enum PublicRepairFailure {
    Error(DkgError),
    Violation(PublicProtocolViolation),
}

impl From<DkgError> for PublicRepairFailure {
    fn from(error: DkgError) -> Self {
        Self::Error(error)
    }
}

type PublicRepairResult<T> = std::result::Result<T, PublicRepairFailure>;

#[derive(Debug, Clone, PartialEq, Eq)]
enum LeaderPublicRepairOutcome {
    Complete,
    Incomplete { retained: usize },
    Unavailable { retained: usize, detail: String },
}

#[derive(Debug)]
enum OriginPublicRepairOutcome {
    Verified(Box<VerifiedPublicContribution>),
    Missing {
        origin: ParticipantRef,
    },
    Unavailable {
        origin: ParticipantRef,
        detail: String,
    },
    Violation(PublicProtocolViolation),
    Error(DkgError),
}

#[derive(Debug, Clone, Copy)]
enum RepairContributionSource {
    Leader,
    Origin,
}

#[async_trait]
trait PublicRepairRequester: Send + Sync {
    async fn request(&self, peer: &str, request: DkgControlMessage) -> Result<DkgControlMessage>;
}

struct NetworkPublicRepairRequester<D>
where
    D: CoordinatorDkg,
{
    state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
}

#[async_trait]
impl<D> PublicRepairRequester for NetworkPublicRepairRequester<D>
where
    D: CoordinatorDkg,
{
    async fn request(&self, peer: &str, request: DkgControlMessage) -> Result<DkgControlMessage> {
        control_request_with_timeout(
            &self.state,
            self.routes,
            peer,
            request,
            PEER_RESPONSE_TIMEOUT,
        )
        .await
    }
}

async fn public_repair_retained_count<D>(
    state: &Arc<AppState<D>>,
    prepare: &PrepareSession,
    phase: PublicPhase,
) -> usize
where
    D: CoordinatorDkg,
{
    state
        .dkg_session_state
        .public_contributions(&prepare.ceremony_id.0, prepare.attempt_id, phase)
        .await
        .map_or(0, |items| items.len())
}

fn retryable_public_repair_control_error(error: &DkgError) -> bool {
    matches!(
        error,
        DkgError::NetworkConnection(_)
            | DkgError::NetworkCommunication(_)
            | DkgError::ProtocolError(_)
    )
}

fn repair_contribution_violation(
    source: RepairContributionSource,
    phase: PublicPhase,
    origin: ParticipantRef,
    detail: impl Into<String>,
) -> PublicProtocolViolation {
    match source {
        RepairContributionSource::Leader => PublicProtocolViolation::leader(
            PublicProtocolViolationKind::InvalidContribution,
            Some(phase),
            None,
            detail,
        ),
        RepairContributionSource::Origin => PublicProtocolViolation::origin_with_kind(
            PublicProtocolViolationKind::InvalidContribution,
            phase,
            None,
            origin,
            detail,
        ),
    }
}

async fn apply_repair_contributions<D>(
    state: &Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    prepare: &PrepareSession,
    phase: PublicPhase,
    contributions: Vec<VerifiedPublicContribution>,
    source: RepairContributionSource,
) -> PublicRepairResult<bool>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    if contributions.is_empty() {
        return Ok(true);
    }
    for verified in &contributions {
        if let Err(error) = preflight_public_contribution_if_new(
            state,
            routes,
            &verified.signed,
            &verified.contribution,
        )
        .await
        {
            if state
                .dkg_session_state
                .transport_attempt(&prepare.ceremony_id.0)
                .await
                != Some(prepare.attempt_id)
            {
                return Ok(false);
            }
            if attributable_public_preflight_error(&error) {
                return Err(PublicRepairFailure::Violation(
                    repair_contribution_violation(
                        source,
                        phase,
                        verified.contribution.origin,
                        format!("direct-repair contribution failed payload preflight: {error}"),
                    )
                    .with_message_id(verified.contribution.message_id),
                ));
            }
            return Err(PublicRepairFailure::Error(error));
        }
    }
    let retained: BTreeMap<_, _> = contributions
        .iter()
        .map(|verified| (verified.contribution.origin, verified.signed.clone()))
        .collect();
    match state
        .dkg_session_state
        .record_public_batch(&prepare.ceremony_id.0, prepare.attempt_id, phase, retained)
        .await
    {
        PublicBatchRecordOutcome::Recorded => {}
        PublicBatchRecordOutcome::DuplicateSame => {
            crate::metrics::record_dkg_transport_event("public", "batch_duplicate");
        }
        PublicBatchRecordOutcome::ConflictingDuplicate { origin } => {
            return Err(PublicRepairFailure::Violation(
                PublicProtocolViolation::origin(
                    phase,
                    None,
                    origin,
                    "direct repair conflicts with a retained signed contribution",
                ),
            ));
        }
        PublicBatchRecordOutcome::StaleAttempt | PublicBatchRecordOutcome::MissingSession => {
            return Ok(false);
        }
    }

    if phase == PublicPhase::RefreshHealthCheck {
        return Ok(true);
    }
    for verified in contributions {
        let origin = verified.contribution.origin;
        let message_id = verified.contribution.message_id;
        if let Err(error) = dispatch_public_contribution(
            state.clone(),
            routes,
            verified.signed,
            verified.contribution,
        )
        .await
        {
            if state
                .dkg_session_state
                .transport_attempt(&prepare.ceremony_id.0)
                .await
                != Some(prepare.attempt_id)
            {
                return Ok(false);
            }
            if matches!(
                &error,
                DkgError::Unauthorized(_)
                    | DkgError::Deserialization(_)
                    | DkgError::Crypto(_)
                    | DkgError::InvalidInput(_)
                    | DkgError::ProtocolError(_)
                    | DkgError::CommitmentVerificationFailed(_)
            ) {
                return Err(PublicRepairFailure::Violation(
                    repair_contribution_violation(
                        source,
                        phase,
                        origin,
                        format!(
                            "verified repair contribution failed protocol application: {error}"
                        ),
                    )
                    .with_message_id(message_id),
                ));
            }
            tracing::warn!(
                %error,
                phase = ?phase,
                origin = ?origin,
                "failed to dispatch a verified direct-repair contribution"
            );
        }
    }
    Ok(true)
}

async fn dispatch_retained_public_repair<D>(
    state: &Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    prepare: &PrepareSession,
    phase: PublicPhase,
) -> PublicRepairResult<bool>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    if phase == PublicPhase::RefreshHealthCheck {
        return Ok(true);
    }
    let items = state
        .dkg_session_state
        .public_contributions(&prepare.ceremony_id.0, prepare.attempt_id, phase)
        .await
        .unwrap_or_default();
    let mut verified = Vec::with_capacity(items.len());
    for signed in items.into_values() {
        let contribution = verify_signed_contribution(state, &signed).await?;
        verified.push(VerifiedPublicContribution {
            signed,
            contribution,
        });
    }
    apply_repair_contributions(
        state,
        routes,
        prepare,
        phase,
        verified,
        RepairContributionSource::Origin,
    )
    .await
}

async fn collect_public_phase_from_leader<D, R>(
    state: &Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    requester: &R,
    prepare: &PrepareSession,
    phase: PublicPhase,
    expected_origins: &BTreeSet<ParticipantRef>,
) -> PublicRepairResult<LeaderPublicRepairOutcome>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
    R: PublicRepairRequester + ?Sized,
{
    let leader_peer = prepare
        .leader_route()
        .ok_or_else(|| DkgError::InvalidState("leader repair route is missing".into()))?;
    let max_pages = expected_origins.len().max(1);
    let mut after = None;
    let mut seen_origins = BTreeSet::new();
    let mut page_count = 0usize;

    loop {
        if page_count >= max_pages {
            return Err(PublicRepairFailure::Violation(
                PublicProtocolViolation::leader(
                    PublicProtocolViolationKind::BatchMismatch,
                    Some(phase),
                    None,
                    format!("public repair exceeded its maximum {max_pages} pages"),
                ),
            ));
        }
        let response = match requester
            .request(
                leader_peer,
                DkgControlMessage::GetPublicPhase {
                    ceremony_id: prepare.ceremony_id,
                    attempt_id: prepare.attempt_id,
                    phase,
                    after,
                },
            )
            .await
        {
            Ok(response) => response,
            Err(error) if retryable_public_repair_control_error(&error) => {
                return Ok(LeaderPublicRepairOutcome::Unavailable {
                    retained: public_repair_retained_count(state, prepare, phase).await,
                    detail: error.to_string(),
                });
            }
            Err(DkgError::Deserialization(error)) => {
                return Err(PublicRepairFailure::Violation(
                    PublicProtocolViolation::leader(
                        PublicProtocolViolationKind::MalformedLeaderMessage,
                        Some(phase),
                        None,
                        error,
                    ),
                ));
            }
            Err(error) => return Err(PublicRepairFailure::Error(error)),
        };
        let encoded_len = transport::encode(&response)
            .map_err(DkgError::Serialization)?
            .len();
        if encoded_len > MAX_PUBLIC_REPAIR_PAGE_BYTES {
            return Err(PublicRepairFailure::Violation(
                PublicProtocolViolation::leader(
                    PublicProtocolViolationKind::BufferLimit,
                    Some(phase),
                    None,
                    format!(
                        "encoded public repair page is {encoded_len} bytes, exceeding the {MAX_PUBLIC_REPAIR_PAGE_BYTES}-byte limit"
                    ),
                ),
            ));
        }
        let DkgControlMessage::PublicPhaseResponse {
            ceremony_id,
            attempt_id,
            phase: response_phase,
            contributions,
            next_cursor,
        } = response
        else {
            return Err(PublicRepairFailure::Violation(
                PublicProtocolViolation::leader(
                    PublicProtocolViolationKind::MalformedLeaderMessage,
                    Some(phase),
                    None,
                    "leader returned an unexpected public repair response",
                ),
            ));
        };
        if ceremony_id != prepare.ceremony_id
            || attempt_id != prepare.attempt_id
            || response_phase != phase
        {
            return Err(PublicRepairFailure::Violation(
                PublicProtocolViolation::leader(
                    PublicProtocolViolationKind::BatchMismatch,
                    Some(phase),
                    None,
                    "leader public repair response scope mismatch",
                ),
            ));
        }

        let mut verified_page = Vec::with_capacity(contributions.len());
        let mut page_origins = Vec::with_capacity(contributions.len());
        for signed in contributions {
            let contribution =
                verify_signed_contribution(state, &signed)
                    .await
                    .map_err(|error| {
                        PublicRepairFailure::Violation(PublicProtocolViolation::leader(
                            PublicProtocolViolationKind::InvalidContribution,
                            Some(phase),
                            None,
                            error.to_string(),
                        ))
                    })?;
            if contribution.payload.phase() != phase
                || !expected_origins.contains(&contribution.origin)
            {
                return Err(PublicRepairFailure::Violation(
                    PublicProtocolViolation::leader(
                        PublicProtocolViolationKind::InvalidContribution,
                        Some(phase),
                        None,
                        format!(
                            "leader repair returned contribution {:?} outside the expected phase scope",
                            contribution.origin
                        ),
                    )
                    .with_message_id(contribution.message_id),
                ));
            }
            page_origins.push(contribution.origin);
            verified_page.push(VerifiedPublicContribution {
                signed,
                contribution,
            });
        }
        validate_public_repair_page_progress(after, &page_origins, next_cursor, &seen_origins)
            .map_err(|error| {
                PublicRepairFailure::Violation(PublicProtocolViolation::leader(
                    PublicProtocolViolationKind::BatchMismatch,
                    Some(phase),
                    None,
                    error.to_string(),
                ))
            })?;
        seen_origins.extend(page_origins.iter().copied());
        if !apply_repair_contributions(
            state,
            routes,
            prepare,
            phase,
            verified_page,
            RepairContributionSource::Leader,
        )
        .await?
        {
            return Err(PublicRepairFailure::Error(DkgError::ProtocolError(
                "public repair targets an inactive attempt".into(),
            )));
        }

        page_count += 1;
        crate::metrics::record_dkg_transport_event("public", "repair_page_received");
        tracing::debug!(
            session_id = prepare.ceremony_id.0,
            attempt_id = %hex::encode(prepare.attempt_id.0),
            phase = ?phase,
            page_count,
            after = ?after,
            next_cursor = ?next_cursor,
            contribution_count = page_origins.len(),
            encoded_len,
            "received public DKG repair page"
        );

        let Some(cursor) = next_cursor else {
            let retained = public_repair_retained_count(state, prepare, phase).await;
            return Ok(if retained >= expected_origins.len() {
                LeaderPublicRepairOutcome::Complete
            } else {
                LeaderPublicRepairOutcome::Incomplete { retained }
            });
        };
        after = Some(cursor);
    }
}

async fn fetch_public_contribution_from_origin<D, R>(
    state: Arc<AppState<D>>,
    requester: &R,
    prepare: PrepareSession,
    phase: PublicPhase,
    origin: ParticipantRef,
    origin_peer: String,
) -> OriginPublicRepairOutcome
where
    D: CoordinatorDkg,
    R: PublicRepairRequester + ?Sized,
{
    let response = match requester
        .request(
            &origin_peer,
            DkgControlMessage::GetPublicContribution {
                ceremony_id: prepare.ceremony_id,
                attempt_id: prepare.attempt_id,
                phase,
                origin,
            },
        )
        .await
    {
        Ok(response) => response,
        Err(error) if retryable_public_repair_control_error(&error) => {
            return OriginPublicRepairOutcome::Unavailable {
                origin,
                detail: error.to_string(),
            };
        }
        Err(DkgError::Deserialization(error)) => {
            return OriginPublicRepairOutcome::Violation(
                PublicProtocolViolation::origin_with_kind(
                    PublicProtocolViolationKind::MalformedOriginMessage,
                    phase,
                    None,
                    origin,
                    error,
                ),
            );
        }
        Err(error) => return OriginPublicRepairOutcome::Error(error),
    };
    let encoded_len = match transport::encode(&response) {
        Ok(encoded) => encoded.len(),
        Err(error) => {
            return OriginPublicRepairOutcome::Error(DkgError::Serialization(error));
        }
    };
    if encoded_len > MAX_PUBLIC_REPAIR_PAGE_BYTES {
        return OriginPublicRepairOutcome::Violation(
            PublicProtocolViolation::origin_with_kind(
                PublicProtocolViolationKind::BufferLimit,
                phase,
                None,
                origin,
                format!(
                    "encoded origin repair response is {encoded_len} bytes, exceeding the {MAX_PUBLIC_REPAIR_PAGE_BYTES}-byte limit"
                ),
            ),
        );
    }
    let DkgControlMessage::PublicContributionResponse {
        ceremony_id,
        attempt_id,
        contribution,
    } = response
    else {
        return OriginPublicRepairOutcome::Violation(PublicProtocolViolation::origin_with_kind(
            PublicProtocolViolationKind::MalformedOriginMessage,
            phase,
            None,
            origin,
            "origin returned an unexpected public repair response",
        ));
    };
    if ceremony_id != prepare.ceremony_id || attempt_id != prepare.attempt_id {
        return OriginPublicRepairOutcome::Violation(PublicProtocolViolation::origin_with_kind(
            PublicProtocolViolationKind::MalformedOriginMessage,
            phase,
            None,
            origin,
            "origin public repair response scope mismatch",
        ));
    }
    let Some(signed) = contribution else {
        return OriginPublicRepairOutcome::Missing { origin };
    };
    let contribution = match verify_signed_contribution(&state, &signed).await {
        Ok(contribution) => contribution,
        Err(error)
            if state
                .dkg_session_state
                .transport_attempt(&prepare.ceremony_id.0)
                .await
                != Some(prepare.attempt_id) =>
        {
            return OriginPublicRepairOutcome::Error(error);
        }
        Err(error) => {
            return OriginPublicRepairOutcome::Violation(
                PublicProtocolViolation::origin_with_kind(
                    PublicProtocolViolationKind::InvalidContribution,
                    phase,
                    None,
                    origin,
                    error.to_string(),
                ),
            );
        }
    };
    if contribution.origin != origin || contribution.payload.phase() != phase {
        return OriginPublicRepairOutcome::Violation(
            PublicProtocolViolation::origin_with_kind(
                PublicProtocolViolationKind::InvalidContribution,
                phase,
                None,
                origin,
                "origin public repair returned the wrong contribution",
            )
            .with_message_id(contribution.message_id),
        );
    }
    OriginPublicRepairOutcome::Verified(Box::new(VerifiedPublicContribution {
        signed,
        contribution,
    }))
}

async fn collect_public_phase_from_origins<D, R>(
    state: &Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    requester: &R,
    prepare: &PrepareSession,
    phase: PublicPhase,
    expected_origins: &BTreeSet<ParticipantRef>,
) -> PublicRepairResult<()>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
    R: PublicRepairRequester + ?Sized,
{
    let retained = state
        .dkg_session_state
        .public_contributions(&prepare.ceremony_id.0, prepare.attempt_id, phase)
        .await
        .unwrap_or_default();
    let retained_origins: BTreeSet<_> = retained.keys().copied().collect();
    let missing: Vec<_> = expected_origins
        .difference(&retained_origins)
        .copied()
        .collect();
    let mut requests = FuturesUnordered::new();
    for origin in missing {
        let origin_peer = prepare
            .committees
            .route(origin)
            .ok_or_else(|| {
                DkgError::InvalidState(format!("origin repair route for {origin:?} is missing"))
            })?
            .to_owned();
        requests.push(fetch_public_contribution_from_origin(
            state.clone(),
            requester,
            prepare.clone(),
            phase,
            origin,
            origin_peer,
        ));
    }

    let mut verified = BTreeMap::new();
    while let Some(outcome) = requests.next().await {
        match outcome {
            OriginPublicRepairOutcome::Verified(contribution) => {
                verified.insert(contribution.contribution.origin, *contribution);
            }
            OriginPublicRepairOutcome::Missing { origin } => {
                crate::metrics::record_dkg_transport_event("public", "origin_repair_missing");
                tracing::debug!(
                    session_id = prepare.ceremony_id.0,
                    attempt_id = %hex::encode(prepare.attempt_id.0),
                    phase = ?phase,
                    origin = ?origin,
                    "origin has not retained the requested public contribution"
                );
            }
            OriginPublicRepairOutcome::Unavailable { origin, detail } => {
                crate::metrics::record_dkg_transport_event("public", "origin_repair_unavailable");
                tracing::warn!(
                    session_id = prepare.ceremony_id.0,
                    attempt_id = %hex::encode(prepare.attempt_id.0),
                    phase = ?phase,
                    origin = ?origin,
                    detail,
                    "public contribution origin is unavailable during direct repair"
                );
            }
            OriginPublicRepairOutcome::Violation(violation) => {
                return Err(PublicRepairFailure::Violation(violation));
            }
            OriginPublicRepairOutcome::Error(error) => {
                return Err(PublicRepairFailure::Error(error));
            }
        }
    }

    let verified: Vec<_> = verified.into_values().collect();
    let repaired_count = verified.len();
    if !apply_repair_contributions(
        state,
        routes,
        prepare,
        phase,
        verified,
        RepairContributionSource::Origin,
    )
    .await?
    {
        return Err(PublicRepairFailure::Error(DkgError::ProtocolError(
            "origin repair targets an inactive attempt".into(),
        )));
    }
    for _ in 0..repaired_count {
        crate::metrics::record_dkg_transport_event("public", "origin_repair");
    }
    Ok(())
}

async fn repair_public_phase_claimed<D, R>(
    state: &Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    requester: &R,
    prepare: &PrepareSession,
    phase: PublicPhase,
) -> PublicRepairResult<()>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
    R: PublicRepairRequester + ?Sized,
{
    let expected_origins = expected_public_origins(state, prepare, phase).await;
    let expected = expected_origins.len();
    if expected > MAX_DKG_COMMITTEE_SIZE {
        return Err(PublicRepairFailure::Error(DkgError::InvalidState(format!(
            "public repair expected {expected} origins, maximum is {MAX_DKG_COMMITTEE_SIZE}"
        ))));
    }
    let present = public_repair_retained_count(state, prepare, phase).await;
    if present >= expected {
        dispatch_retained_public_repair(state, routes, prepare, phase).await?;
        return Ok(());
    }

    tracing::info!(
        session_id = prepare.ceremony_id.0,
        attempt_id = %hex::encode(prepare.attempt_id.0),
        phase = ?phase,
        present,
        expected,
        "requesting public DKG completeness repair"
    );
    let leader_outcome = collect_public_phase_from_leader(
        state,
        routes,
        requester,
        prepare,
        phase,
        &expected_origins,
    )
    .await?;
    match &leader_outcome {
        LeaderPublicRepairOutcome::Complete => {}
        LeaderPublicRepairOutcome::Incomplete { retained } => {
            crate::metrics::record_dkg_transport_event("public", "leader_repair_fallback");
            tracing::warn!(
                session_id = prepare.ceremony_id.0,
                attempt_id = %hex::encode(prepare.attempt_id.0),
                phase = ?phase,
                retained,
                expected,
                "leader repair completed without every expected origin; using direct origins"
            );
        }
        LeaderPublicRepairOutcome::Unavailable { retained, detail } => {
            crate::metrics::record_dkg_transport_event("public", "leader_repair_fallback");
            tracing::warn!(
                session_id = prepare.ceremony_id.0,
                attempt_id = %hex::encode(prepare.attempt_id.0),
                phase = ?phase,
                retained,
                expected,
                detail,
                "leader repair is unavailable; using direct origins"
            );
        }
    }
    if phase == PublicPhase::CommitmentAudit {
        crate::metrics::record_dkg_transport_event("public", "repair");
        return Ok(());
    }
    if !matches!(leader_outcome, LeaderPublicRepairOutcome::Complete) {
        collect_public_phase_from_origins(
            state,
            routes,
            requester,
            prepare,
            phase,
            &expected_origins,
        )
        .await?;
    }

    let repaired = public_repair_retained_count(state, prepare, phase).await;
    if repaired < expected {
        crate::metrics::record_dkg_transport_event("public", "repair_incomplete");
        return Err(PublicRepairFailure::Error(DkgError::NetworkCommunication(
            format!("public phase repair retained {repaired} of {expected} contributions"),
        )));
    }
    dispatch_retained_public_repair(state, routes, prepare, phase).await?;
    crate::metrics::record_dkg_transport_event("public", "repair");
    tracing::info!(
        session_id = prepare.ceremony_id.0,
        attempt_id = %hex::encode(prepare.attempt_id.0),
        phase = ?phase,
        "applied direct public DKG completeness repair"
    );
    Ok(())
}

async fn repair_public_phase<D>(
    state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    prepare: PrepareSession,
    phase: PublicPhase,
    force_after_lag: bool,
    violation_topic_task: TopicTaskDisposition,
) -> Result<()>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    if prepare.leader_node_key == state.node_key {
        return Ok(());
    }
    let activated = state
        .dkg_session_state
        .transport_info(&prepare.ceremony_id.0)
        .await
        .is_some_and(|(_, attempt_id, _, _, activated)| {
            attempt_id == prepare.attempt_id && activated
        });
    if !activated {
        return Ok(());
    }
    if !force_after_lag
        && !state
            .dkg_session_state
            .transport_repair_due(
                &prepare.ceremony_id.0,
                prepare.attempt_id,
                DKG_REPAIR_STALL_INTERVAL,
            )
            .await
    {
        return Ok(());
    }
    match state
        .dkg_session_state
        .claim_public_phase_repair(&prepare.ceremony_id.0, prepare.attempt_id, phase)
        .await
    {
        PublicRepairClaimOutcome::Claimed => {}
        PublicRepairClaimOutcome::InFlight => {
            crate::metrics::record_dkg_transport_event("public", "repair_coalesced");
            return Ok(());
        }
        PublicRepairClaimOutcome::Backoff | PublicRepairClaimOutcome::StaleAttempt => {
            return Ok(());
        }
    }

    let before = public_repair_retained_count(&state, &prepare, phase).await;
    let requester = NetworkPublicRepairRequester {
        state: state.clone(),
        routes,
    };
    let result = repair_public_phase_claimed(&state, routes, &requester, &prepare, phase).await;
    if let Err(PublicRepairFailure::Violation(violation)) = &result {
        abort_public_protocol_violation(&state, &prepare, violation, violation_topic_task).await;
        return Err(DkgError::ProtocolError(format!(
            "authenticated public repair violation {:?}: {}",
            violation.kind, violation.detail
        )));
    }
    let after = public_repair_retained_count(&state, &prepare, phase).await;
    state
        .dkg_session_state
        .finish_public_phase_repair(
            &prepare.ceremony_id.0,
            prepare.attempt_id,
            phase,
            after > before,
            DKG_MAX_REPAIR_BACKOFF,
        )
        .await;
    match result {
        Ok(()) => Ok(()),
        Err(PublicRepairFailure::Error(error)) => Err(error),
        Err(PublicRepairFailure::Violation(_)) => {
            unreachable!("public repair violations return after attempt cleanup")
        }
    }
}

async fn verify_signed_contribution<D>(
    state: &Arc<AppState<D>>,
    signed: &SignedPayload,
) -> Result<DkgPublicContribution>
where
    D: CoordinatorDkg,
{
    let pubsub = state.network.pubsub().ok_or_else(|| {
        DkgError::InvalidState("network backend does not provide authenticated pub-sub".into())
    })?;
    let verified = pubsub
        .verify(PUBLIC_CONTRIBUTION_SIGNING_DOMAIN, signed)
        .await
        .map_err(|error| DkgError::Unauthorized(error.to_string()))?;
    let contribution: DkgPublicContribution =
        transport::decode(&verified.data, MAX_CONTROL_MESSAGE_BYTES)
            .map_err(DkgError::Deserialization)?;
    contribution
        .validate_message_id()
        .map_err(DkgError::Unauthorized)?;
    let info = state
        .dkg_session_state
        .transport_info(&contribution.ceremony_id.0)
        .await
        .ok_or_else(|| DkgError::SessionNotFound(contribution.ceremony_id.0.to_string()))?;
    if info.1 != contribution.attempt_id || info.2 != contribution.committee_digest {
        return Err(DkgError::Unauthorized(
            "stale or foreign public contribution".into(),
        ));
    }
    let expected_ring_id = state
        .dkg_session_state
        .ring_id_for_session(&contribution.ceremony_id.0)
        .await
        .ok_or_else(|| DkgError::InvalidState("session ring ID is missing".into()))?;
    if contribution.ring_id != expected_ring_id {
        return Err(DkgError::Unauthorized(
            "public contribution ring ID does not match the active session".into(),
        ));
    }
    let expected_peer = state
        .dkg_session_state
        .peer_id_for_participant(&contribution.ceremony_id.0, contribution.origin)
        .await
        .ok_or_else(|| {
            DkgError::Unauthorized("public contribution origin is not in committee".into())
        })?;
    if !peer_matches_route(&verified.origin, &expected_peer) {
        return Err(DkgError::Unauthorized(
            "public contribution endpoint identity does not match SourceHub NodeInfo".into(),
        ));
    }
    let (kind, active_dealers) = state
        .dkg_session_state
        .with_state(&contribution.ceremony_id.0, |session| {
            (
                session.kind.clone(),
                session.transport.active_dealers.clone(),
            )
        })
        .await
        .ok_or_else(|| DkgError::SessionNotFound(contribution.ceremony_id.0.to_string()))?;
    let phase = contribution.payload.phase();
    let allowed = match kind {
        SessionKind::Fresh => {
            contribution.origin.scope == CommitteeScope::Current
                && matches!(
                    phase,
                    PublicPhase::CommitmentHashes | PublicPhase::Commitments
                )
        }
        SessionKind::Refresh { .. } => {
            contribution.origin.scope == CommitteeScope::Current
                && matches!(
                    phase,
                    PublicPhase::Commitments
                        | PublicPhase::CommitmentAudit
                        | PublicPhase::RefreshHealthCheck
                )
        }
        SessionKind::Reshare { .. } => match phase {
            PublicPhase::Commitments => active_dealers.contains(&contribution.origin),
            PublicPhase::CommitmentAudit => contribution.origin.scope == CommitteeScope::Next,
            PublicPhase::ReshareParticipantSet => contribution.origin == ParticipantRef::next(1),
            PublicPhase::CommitmentHashes | PublicPhase::RefreshHealthCheck => false,
        },
    };
    if !allowed {
        return Err(DkgError::Unauthorized(
            "public contribution origin is not permitted for this ceremony phase".into(),
        ));
    }
    Ok(contribution)
}

async fn record_public_contribution_at_leader<D>(
    state: &Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    signed: SignedPayload,
    contribution: &DkgPublicContribution,
) -> Result<bool>
where
    D: CoordinatorDkg,
{
    let outcome = state
        .dkg_session_state
        .record_public_contribution(
            &contribution.ceremony_id.0,
            contribution.attempt_id,
            contribution.payload.phase(),
            contribution.origin,
            signed,
        )
        .await;
    match outcome {
        PublicContributionRecordOutcome::Recorded => {
            crate::metrics::record_dkg_transport_event("public", "contribution");
            Ok(true)
        }
        PublicContributionRecordOutcome::DuplicateSame => Ok(false),
        PublicContributionRecordOutcome::ConflictingDuplicate => {
            let reason = format!(
                "origin {:?} equivocated in public phase {:?}",
                contribution.origin,
                contribution.payload.phase()
            );
            tracing::error!(
                session_id = contribution.ceremony_id.0,
                attempt_id = %hex::encode(contribution.attempt_id.0),
                phase = ?contribution.payload.phase(),
                origin = ?contribution.origin,
                message_id = %hex::encode(contribution.message_id.0),
                "leader aborting DKG attempt after signed origin equivocation"
            );
            crate::metrics::record_dkg_transport_event("public", "protocol_violation_abort");
            // TODO(reporting): submit both origin-signed contribution envelopes
            // as DKG equivocation evidence before removing the attempt.
            let participant_routes = state
                .dkg_session_state
                .transport_participant_routes(&contribution.ceremony_id.0)
                .await
                .unwrap_or_default();
            state
                .dkg_session_state
                .abort_transport_attempt(
                    AttemptKey::new(contribution.ceremony_id, contribution.attempt_id),
                    TopicTaskDisposition::Abort,
                )
                .await;
            broadcast_attempt_abort(
                state,
                routes,
                participant_routes,
                contribution.ceremony_id,
                contribution.attempt_id,
                reason.clone(),
            )
            .await;
            Err(DkgError::ProtocolError(reason))
        }
        PublicContributionRecordOutcome::StaleAttempt => Err(DkgError::ProtocolError(
            "public contribution targets a stale attempt".into(),
        )),
        PublicContributionRecordOutcome::MissingSession => Err(DkgError::SessionNotFound(
            contribution.ceremony_id.0.to_string(),
        )),
    }
}

async fn record_public_contribution<D>(
    state: &Arc<AppState<D>>,
    signed: SignedPayload,
    contribution: &DkgPublicContribution,
) -> Result<bool>
where
    D: CoordinatorDkg,
{
    let outcome = state
        .dkg_session_state
        .record_public_contribution(
            &contribution.ceremony_id.0,
            contribution.attempt_id,
            contribution.payload.phase(),
            contribution.origin,
            signed.clone(),
        )
        .await;
    match outcome {
        PublicContributionRecordOutcome::DuplicateSame => return Ok(false),
        PublicContributionRecordOutcome::Recorded => {}
        PublicContributionRecordOutcome::StaleAttempt => {
            return Err(DkgError::ProtocolError(
                "public contribution targets a stale attempt".into(),
            ))
        }
        PublicContributionRecordOutcome::ConflictingDuplicate => {
            tracing::error!(
                session_id = contribution.ceremony_id.0,
                attempt_id = %hex::encode(contribution.attempt_id.0),
                phase = ?contribution.payload.phase(),
                origin = ?contribution.origin,
                message_id = %hex::encode(contribution.message_id.0),
                "aborting DKG attempt after signed origin equivocation"
            );
            crate::metrics::record_dkg_transport_event("public", "protocol_violation_abort");
            // TODO(reporting): submit both origin-signed contribution envelopes
            // as DKG equivocation evidence before removing the attempt.
            state
                .dkg_session_state
                .abort_transport_attempt(
                    AttemptKey::new(contribution.ceremony_id, contribution.attempt_id),
                    TopicTaskDisposition::Abort,
                )
                .await;
            return Err(DkgError::ProtocolError(
                "conflicting duplicate public contribution".into(),
            ));
        }
        PublicContributionRecordOutcome::MissingSession => {
            return Err(DkgError::SessionNotFound(
                contribution.ceremony_id.0.to_string(),
            ))
        }
    }
    crate::metrics::record_dkg_transport_event("public", "contribution");
    Ok(true)
}

/// Validate the contribution's protocol payload without retaining it, mutating
/// cryptographic state, advancing a phase, or performing network/bulletin writes.
async fn preflight_public_contribution<D>(
    state: &Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    contribution: &DkgPublicContribution,
) -> Result<()>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    let attempt = AttemptKey::new(contribution.ceremony_id, contribution.attempt_id);
    let local_is_origin = state
        .dkg_session_state
        .with_attempt_state(attempt, |session| session.transport.committees.clone())
        .await
        .map_err(|error| crate::dkg::v0::coordinator::attempt_state_error(attempt, error))?
        .and_then(|committees| {
            committees
                .node_key(contribution.origin)
                .map(|node_key| node_key == state.node_key)
        })
        .unwrap_or(false);
    if contribution.origin.scope == CommitteeScope::Current && local_is_origin {
        return Ok(());
    }
    let coordinator = DkgCoordinator::with_routes(state.clone(), routes);
    match &contribution.payload {
        DkgPublicPayload::CommitmentHash { commitment_hash } => {
            preflight_commitment_hash_message(
                &coordinator,
                attempt,
                contribution.origin.node_id,
                *commitment_hash,
            )
            .await
        }
        DkgPublicPayload::Commitment {
            commitment,
            report_evidence,
        } => {
            preflight_commitment_message(
                &coordinator,
                attempt,
                contribution.origin.node_id,
                commitment,
                report_evidence.as_ref(),
            )
            .await
        }
        DkgPublicPayload::CommitmentAudit { .. } => {
            preflight_commitment_audit_message(&coordinator, attempt).await
        }
        DkgPublicPayload::RefreshHealthCheckResult {
            statement,
            signature,
        } => {
            preflight_result(
                &coordinator,
                attempt,
                contribution.origin.node_id,
                statement,
                signature.as_deref(),
            )
            .await
        }
        DkgPublicPayload::ReshareParticipantSet { selected_dealers } => {
            if selected_dealers
                .iter()
                .any(|dealer| dealer.scope != CommitteeScope::Current)
            {
                return Err(DkgError::Unauthorized(
                    "ReshareParticipantSet dealers must use current-committee scope".into(),
                ));
            }
            let selected_dealer_ids = selected_dealers
                .iter()
                .map(|dealer| dealer.node_id)
                .collect::<Vec<_>>();
            preflight_reshare_participant_set(
                &coordinator,
                attempt,
                contribution.origin.node_id,
                &selected_dealer_ids,
            )
            .await
        }
    }
}

/// Exact retransmissions have already crossed the preflight barrier. Conflicts
/// are intentionally left to the atomic record operation, which classifies
/// origin equivocation without applying either value.
async fn preflight_public_contribution_if_new<D>(
    state: &Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    signed: &SignedPayload,
    contribution: &DkgPublicContribution,
) -> Result<()>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    let attempt = AttemptKey::new(contribution.ceremony_id, contribution.attempt_id);
    let existing = state
        .dkg_session_state
        .with_attempt_state(attempt, |session| {
            session
                .transport
                .public_contributions
                .get(&contribution.payload.phase())
                .and_then(|items| items.get(&contribution.origin))
                .cloned()
        })
        .await
        .map_err(|error| crate::dkg::v0::coordinator::attempt_state_error(attempt, error))?;
    if existing.is_some() {
        // Both identical retransmissions and signed conflicts are handled by
        // the following atomic record operation. Neither should be applied as
        // a new contribution during preflight.
        return Ok(());
    }
    let ids = BTreeMap::from([(contribution.origin, contribution.message_id)]);
    let root = transport::phase_root(
        contribution.ceremony_id,
        contribution.attempt_id,
        contribution.payload.phase(),
        &ids,
    );
    let single = DkgPublicMessage::Chunk {
        ceremony_id: contribution.ceremony_id,
        attempt_id: contribution.attempt_id,
        phase: contribution.payload.phase(),
        phase_root: root,
        index: 0,
        contributions: vec![signed.clone()],
    };
    let encoded_len = transport::encode(&single)
        .map_err(DkgError::Serialization)?
        .len();
    if encoded_len > transport::MAX_PUBLIC_CHUNK_BYTES {
        return Err(DkgError::InvalidInput(format!(
            "signed public contribution requires a {encoded_len}-byte Gossip chunk, exceeding the {}-byte limit",
            transport::MAX_PUBLIC_CHUNK_BYTES
        )));
    }
    preflight_public_contribution(state, routes, contribution).await
}

fn attributable_public_preflight_error(error: &DkgError) -> bool {
    matches!(
        error,
        DkgError::Unauthorized(_)
            | DkgError::Deserialization(_)
            | DkgError::Crypto(_)
            | DkgError::InvalidInput(_)
            | DkgError::CommitmentVerificationFailed(_)
    )
}

async fn dispatch_public_contribution<D>(
    state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    signed: SignedPayload,
    contribution: DkgPublicContribution,
) -> Result<()>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    let attempt = AttemptKey::new(contribution.ceremony_id, contribution.attempt_id);
    let session_id = attempt.session_id();
    let message_id = contribution.message_id;
    loop {
        match state
            .dkg_session_state
            .claim_transport_message(attempt, message_id)
            .await
        {
            MessageProcessingClaim::Claimed => break,
            MessageProcessingClaim::AlreadyProcessed => return Ok(()),
            MessageProcessingClaim::AlreadyProcessing => {
                sleep(Duration::from_millis(10)).await;
            }
            MessageProcessingClaim::MissingSession => {
                return Err(DkgError::SessionNotFound(session_id.to_string()));
            }
            MessageProcessingClaim::StaleAttempt => return Ok(()),
        }
    }

    let result =
        dispatch_public_contribution_once(state.clone(), routes, signed, contribution).await;
    state
        .dkg_session_state
        .finish_transport_message(attempt, message_id, result.is_ok())
        .await;
    result
}

async fn dispatch_public_contribution_once<D>(
    state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    _signed: SignedPayload,
    contribution: DkgPublicContribution,
) -> Result<()>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    let attempt = AttemptKey::new(contribution.ceremony_id, contribution.attempt_id);
    let local_is_origin = state
        .dkg_session_state
        .with_attempt_state(attempt, |session| session.transport.committees.clone())
        .await
        .map_err(|error| crate::dkg::v0::coordinator::attempt_state_error(attempt, error))?
        .and_then(|committees| {
            committees
                .node_key(contribution.origin)
                .map(|node_key| node_key == state.node_key)
        })
        .unwrap_or(false);
    if contribution.origin.scope == CommitteeScope::Current && local_is_origin {
        return Ok(());
    }
    let coordinator = DkgCoordinator::with_routes(state, routes);
    match contribution.payload {
        DkgPublicPayload::CommitmentHash { commitment_hash } => {
            Box::pin(handle_commitment_hash_message(
                &coordinator,
                attempt,
                contribution.origin.node_id,
                commitment_hash,
            ))
            .await?
        }
        DkgPublicPayload::Commitment {
            commitment,
            report_evidence,
        } => {
            Box::pin(handle_commitment_message(
                &coordinator,
                attempt,
                contribution.origin.node_id,
                commitment,
                report_evidence,
            ))
            .await?
        }
        DkgPublicPayload::CommitmentAudit { revealed } => {
            Box::pin(handle_commitment_audit_message(
                &coordinator,
                attempt,
                revealed,
            ))
            .await?
        }
        DkgPublicPayload::RefreshHealthCheckResult {
            statement,
            signature,
        } => {
            Box::pin(handle_result(
                &coordinator,
                attempt,
                contribution.origin.node_id,
                statement,
                signature,
            ))
            .await?
        }
        DkgPublicPayload::ReshareParticipantSet { selected_dealers } => {
            if contribution.origin != ParticipantRef::next(1) {
                return Err(DkgError::Unauthorized(
                    "reshare participant set must originate from next-committee selector 1".into(),
                ));
            }
            let selected = selected_dealers
                .into_iter()
                .map(|dealer| dealer.node_id)
                .collect();
            Box::pin(handle_reshare_participant_set(
                &coordinator,
                attempt,
                contribution.origin.node_id,
                selected,
            ))
            .await?;
        }
    }
    Ok(())
}

fn contribution_ids(
    items: &BTreeMap<ParticipantRef, SignedPayload>,
) -> BTreeMap<ParticipantRef, transport::MessageId> {
    items
        .iter()
        .filter_map(|(origin, signed)| {
            transport::decode::<DkgPublicContribution>(&signed.data, MAX_CONTROL_MESSAGE_BYTES)
                .ok()
                .map(|contribution| (*origin, contribution.message_id))
        })
        .collect()
}

async fn publish_phase_if_complete<D>(
    state: Arc<AppState<D>>,
    _routes: &'static network::ProtocolRoutes,
    session_id: u128,
    attempt_id: AttemptId,
    phase: PublicPhase,
) -> Result<()>
where
    D: CoordinatorDkg,
{
    let attempt = AttemptKey::new(CeremonyId(session_id), attempt_id);
    let kind = state
        .dkg_session_state
        .with_attempt_state(attempt, |session| session.kind.clone())
        .await
        .map_err(|error| crate::dkg::v0::coordinator::attempt_state_error(attempt, error))?;
    let mode = public_batch_mode(&kind, phase).ok_or_else(|| {
        DkgError::ProtocolError(format!(
            "public phase {phase:?} is not valid for ceremony kind {kind:?}"
        ))
    })?;
    if mode == PublicBatchMode::Incremental {
        return publish_incremental_public_contributions(state, session_id, attempt_id, phase)
            .await;
    }
    let expected = if matches!(
        phase,
        PublicPhase::RefreshHealthCheck | PublicPhase::ReshareParticipantSet
    ) {
        1
    } else {
        state
            .dkg_session_state
            .with_state(&session_id, |session| session.node.total_nodes())
            .await
            .ok_or_else(|| DkgError::SessionNotFound(session_id.to_string()))?
    };
    let items = state
        .dkg_session_state
        .public_contributions(&session_id, attempt_id, phase)
        .await
        .ok_or_else(|| DkgError::SessionNotFound(session_id.to_string()))?;
    if items.len() != expected {
        return Ok(());
    }
    let hard_deadline = state
        .dkg_session_state
        .transport_hard_deadline(&session_id, attempt_id)
        .await
        .ok_or_else(|| DkgError::InvalidState("transport hard deadline is missing".into()))?
        .into();
    let batch = prepare_public_batch(CeremonyId(session_id), attempt_id, phase, items, true)?;
    if !state
        .dkg_session_state
        .claim_public_phase_publish(&session_id, attempt_id, phase, expected)
        .await
    {
        return Ok(());
    }
    if let Some(elapsed) = state
        .dkg_session_state
        .public_phase_collection_elapsed(&session_id, attempt_id, phase)
        .await
    {
        crate::metrics::record_dkg_public_transport(
            phase.as_metric_label(),
            "collection",
            elapsed.as_secs_f64(),
        );
    }
    let dissemination_start = Instant::now();
    publish_claimed_public_batches(
        state,
        session_id,
        attempt_id,
        phase,
        PublicPublishClaim::CompletePhase,
        vec![batch],
        hard_deadline,
        dissemination_start,
    )
    .await
}

async fn publish_incremental_public_contributions<D>(
    state: Arc<AppState<D>>,
    session_id: u128,
    attempt_id: AttemptId,
    phase: PublicPhase,
) -> Result<()>
where
    D: CoordinatorDkg,
{
    // Coalesce contributions that arrive in the same short relay window. Every
    // caller observes the same retained map; attempt-scoped publish claims make
    // exactly one caller responsible for each contribution.
    sleep(Duration::from_millis(50)).await;
    let items = state
        .dkg_session_state
        .public_contributions(&session_id, attempt_id, phase)
        .await
        .ok_or_else(|| DkgError::SessionNotFound(session_id.to_string()))?;
    let hard_deadline = state
        .dkg_session_state
        .transport_hard_deadline(&session_id, attempt_id)
        .await
        .ok_or_else(|| DkgError::InvalidState("transport hard deadline is missing".into()))?
        .into();
    let mut decoded = Vec::with_capacity(items.len());
    for (origin, signed) in items {
        let contribution =
            transport::decode::<DkgPublicContribution>(&signed.data, MAX_CONTROL_MESSAGE_BYTES)
                .map_err(DkgError::Deserialization)?;
        decoded.push((origin, signed, contribution.message_id));
    }
    let message_ids = decoded
        .iter()
        .map(|(_, _, message_id)| *message_id)
        .collect::<Vec<_>>();
    let claimed = state
        .dkg_session_state
        .claim_public_messages_publish(&session_id, attempt_id, &message_ids)
        .await
        .into_iter()
        .collect::<BTreeSet<_>>();
    if claimed.is_empty() {
        return Ok(());
    }
    let mut pending = decoded
        .into_iter()
        .filter(|(_, _, message_id)| claimed.contains(message_id))
        .map(|(origin, signed, _)| (origin, signed))
        .collect::<BTreeMap<_, _>>();
    if pending.is_empty() {
        return Ok(());
    }

    let ceremony_id = CeremonyId(session_id);
    let prepared = (|| {
        let mut batches = Vec::new();
        let mut current = BTreeMap::new();
        for (origin, signed) in std::mem::take(&mut pending) {
            let mut candidate = current.clone();
            candidate.insert(origin, signed.clone());
            let candidate_ids = contribution_ids(&candidate);
            let candidate_root =
                transport::phase_root(ceremony_id, attempt_id, phase, &candidate_ids);
            let chunks = transport::chunk_public_contributions(
                ceremony_id,
                attempt_id,
                phase,
                candidate_root,
                candidate.clone(),
            )
            .map_err(DkgError::Serialization)?;
            if chunks.len() > 1 && !current.is_empty() {
                batches.push(current);
                current = BTreeMap::from([(origin, signed)]);
            } else {
                current = candidate;
            }
        }
        if !current.is_empty() {
            batches.push(current);
        }
        batches
            .into_iter()
            .map(|batch| prepare_public_batch(ceremony_id, attempt_id, phase, batch, false))
            .collect::<Result<Vec<_>>>()
    })();
    let prepared = match prepared {
        Ok(prepared) => prepared,
        Err(error) => {
            state
                .dkg_session_state
                .finish_public_messages_publish(
                    &session_id,
                    attempt_id,
                    &claimed.iter().copied().collect::<Vec<_>>(),
                    false,
                )
                .await;
            return Err(error);
        }
    };
    publish_claimed_public_batches(
        state,
        session_id,
        attempt_id,
        phase,
        PublicPublishClaim::IncrementalMessages(claimed.into_iter().collect()),
        prepared,
        hard_deadline,
        Instant::now(),
    )
    .await
}

#[derive(Clone)]
struct PreparedPublicBatch {
    root: [u8; 32],
    contribution_count: usize,
    messages: Vec<Bytes>,
}

#[derive(Clone)]
enum PublicPublishClaim {
    CompletePhase,
    IncrementalMessages(Vec<MessageId>),
}

fn prepare_public_batch(
    ceremony_id: CeremonyId,
    attempt_id: AttemptId,
    phase: PublicPhase,
    contributions: BTreeMap<ParticipantRef, SignedPayload>,
    complete: bool,
) -> Result<PreparedPublicBatch> {
    let contribution_count = contributions.len();
    let ids = contribution_ids(&contributions);
    let root = transport::phase_root(ceremony_id, attempt_id, phase, &ids);
    let chunks =
        transport::chunk_public_contributions(ceremony_id, attempt_id, phase, root, contributions)
            .map_err(DkgError::Serialization)?;
    let manifest = DkgPublicMessage::Manifest(PhaseManifest {
        ceremony_id,
        attempt_id,
        phase,
        phase_root: root,
        contribution_ids: ids,
        chunk_count: chunks.len() as u32,
        complete,
    });
    let mut messages = Vec::with_capacity(chunks.len() + 1);
    messages.push(Bytes::from(
        transport::encode(&manifest).map_err(DkgError::Serialization)?,
    ));
    for chunk in chunks {
        messages.push(Bytes::from(
            transport::encode(&chunk).map_err(DkgError::Serialization)?,
        ));
    }
    Ok(PreparedPublicBatch {
        root,
        contribution_count,
        messages,
    })
}

async fn broadcast_public_batches(
    topic: &dyn Topic,
    batches: &[PreparedPublicBatch],
) -> network::Result<()> {
    for batch in batches {
        for message in &batch.messages {
            topic.broadcast(message.clone()).await?;
        }
    }
    Ok(())
}

async fn finish_public_publish_claim<D>(
    state: &Arc<AppState<D>>,
    session_id: u128,
    attempt_id: AttemptId,
    phase: PublicPhase,
    claim: &PublicPublishClaim,
    published: bool,
) -> bool
where
    D: CoordinatorDkg,
{
    match claim {
        PublicPublishClaim::CompletePhase => {
            state
                .dkg_session_state
                .finish_public_phase_publish(&session_id, attempt_id, phase, published)
                .await
        }
        PublicPublishClaim::IncrementalMessages(message_ids) => {
            state
                .dkg_session_state
                .finish_public_messages_publish(&session_id, attempt_id, message_ids, published)
                .await
        }
    }
}

fn record_public_batches_published(
    session_id: u128,
    attempt_id: AttemptId,
    phase: PublicPhase,
    batches: &[PreparedPublicBatch],
    dissemination_start: Instant,
) {
    crate::metrics::record_dkg_public_transport(
        phase.as_metric_label(),
        "dissemination",
        dissemination_start.elapsed().as_secs_f64(),
    );
    for _ in batches {
        crate::metrics::record_dkg_transport_event("public", "batch_published");
    }
    tracing::info!(
        session_id,
        attempt = %hex::encode(attempt_id.0),
        phase = ?phase,
        roots = ?batches
            .iter()
            .map(|batch| hex::encode(batch.root))
            .collect::<Vec<_>>(),
        contribution_count = batches
            .iter()
            .map(|batch| batch.contribution_count)
            .sum::<usize>(),
        batch_count = batches.len(),
        "leader published canonical public DKG batch"
    );
}

async fn broadcast_public_batches_for_attempt<D>(
    state: &Arc<AppState<D>>,
    session_id: u128,
    attempt_id: AttemptId,
    batches: &[PreparedPublicBatch],
) -> Result<()>
where
    D: CoordinatorDkg,
{
    let topic = state
        .dkg_session_state
        .transport_topic_for_attempt(&session_id, attempt_id)
        .await
        .ok_or_else(|| {
            DkgError::InvalidState("transport topic is missing or attempt is stale".into())
        })?;
    broadcast_public_batches(&*topic, batches)
        .await
        .map_err(|error| DkgError::NetworkCommunication(error.to_string()))
}

#[allow(clippy::too_many_arguments)]
async fn retry_claimed_public_batches<D>(
    weak_state: Weak<AppState<D>>,
    session_id: u128,
    attempt_id: AttemptId,
    phase: PublicPhase,
    claim: PublicPublishClaim,
    batches: Vec<PreparedPublicBatch>,
    hard_deadline: Instant,
    dissemination_start: Instant,
) where
    D: CoordinatorDkg,
{
    let mut backoff = INITIAL_CONTROL_RETRY_BACKOFF;
    let mut retry = 0u32;
    loop {
        let Some(state) = weak_state.upgrade() else {
            return;
        };
        if state.dkg_session_state.transport_attempt(&session_id).await != Some(attempt_id) {
            return;
        }
        let remaining = hard_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            finish_public_publish_claim(&state, session_id, attempt_id, phase, &claim, false).await;
            crate::metrics::record_dkg_transport_event("public", "batch_publish_abandoned");
            tracing::warn!(
                session_id,
                attempt = %hex::encode(attempt_id.0),
                phase = ?phase,
                "public DKG batch publication reached the hard attempt deadline"
            );
            return;
        }
        drop(state);
        sleep(backoff.min(remaining)).await;
        if Instant::now() >= hard_deadline {
            continue;
        }
        let Some(state) = weak_state.upgrade() else {
            return;
        };
        if state.dkg_session_state.transport_attempt(&session_id).await != Some(attempt_id) {
            return;
        }
        retry = retry.saturating_add(1);
        match broadcast_public_batches_for_attempt(&state, session_id, attempt_id, &batches).await {
            Ok(()) => {
                if finish_public_publish_claim(&state, session_id, attempt_id, phase, &claim, true)
                    .await
                {
                    record_public_batches_published(
                        session_id,
                        attempt_id,
                        phase,
                        &batches,
                        dissemination_start,
                    );
                }
                return;
            }
            Err(error) => {
                crate::metrics::record_dkg_transport_event("public", "batch_publish_retry");
                tracing::warn!(
                    %error,
                    session_id,
                    attempt = %hex::encode(attempt_id.0),
                    phase = ?phase,
                    retry,
                    "public DKG batch publication failed; retrying"
                );
                backoff = (backoff * 2).min(DKG_MAX_REPAIR_BACKOFF);
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn publish_claimed_public_batches<D>(
    state: Arc<AppState<D>>,
    session_id: u128,
    attempt_id: AttemptId,
    phase: PublicPhase,
    claim: PublicPublishClaim,
    batches: Vec<PreparedPublicBatch>,
    hard_deadline: Instant,
    dissemination_start: Instant,
) -> Result<()>
where
    D: CoordinatorDkg,
{
    match broadcast_public_batches_for_attempt(&state, session_id, attempt_id, &batches).await {
        Ok(()) => {
            if finish_public_publish_claim(&state, session_id, attempt_id, phase, &claim, true)
                .await
            {
                record_public_batches_published(
                    session_id,
                    attempt_id,
                    phase,
                    &batches,
                    dissemination_start,
                );
            }
        }
        Err(error) => {
            crate::metrics::record_dkg_transport_event("public", "batch_publish_retry");
            tracing::warn!(
                %error,
                session_id,
                attempt = %hex::encode(attempt_id.0),
                phase = ?phase,
                "initial public DKG batch publication failed; retrying in background"
            );
            tokio::spawn(retry_claimed_public_batches(
                Arc::downgrade(&state),
                session_id,
                attempt_id,
                phase,
                claim,
                batches,
                hard_deadline,
                dissemination_start,
            ));
        }
    }
    Ok(())
}

async fn send_refresh_result_barrier<D>(
    state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    peers: Vec<String>,
    request: DkgControlMessage,
    ceremony_id: CeremonyId,
    attempt_id: AttemptId,
    message_id: MessageId,
    hard_deadline: Instant,
    step: &'static str,
) -> Result<()>
where
    D: CoordinatorDkg,
{
    let mut requests = JoinSet::new();
    for peer in peers {
        let state = state.clone();
        let request = request.clone();
        requests.spawn(async move {
            let mut backoff = INITIAL_CONTROL_RETRY_BACKOFF;
            let mut attempt = 0u32;
            loop {
                attempt = attempt.saturating_add(1);
                let now = Instant::now();
                if now >= hard_deadline {
                    return Err(DkgError::NetworkCommunication(format!(
                        "refresh-result {step} barrier reached the hard attempt deadline for peer {peer}"
                    )));
                }
                let remaining = hard_deadline.saturating_duration_since(now);
                let response = timeout(
                    remaining,
                    control_request_with_timeout(
                        &state,
                        routes,
                        &peer,
                        request.clone(),
                        PEER_RESPONSE_TIMEOUT,
                    ),
                )
                .await;
                match response {
                    Ok(Ok(DkgControlMessage::PublicContributionAck {
                        ceremony_id: got_ceremony,
                        attempt_id: got_attempt,
                        message_id: got_message,
                    })) if got_ceremony == ceremony_id
                        && got_attempt == attempt_id
                        && got_message == message_id =>
                    {
                        return Ok(())
                    }
                    Ok(Ok(other)) => tracing::warn!(
                        peer = %peer,
                        step,
                        attempt,
                        response = ?other,
                        "refresh-result barrier received an invalid acknowledgement"
                    ),
                    Ok(Err(error)) => tracing::warn!(
                        peer = %peer,
                        step,
                        attempt,
                        %error,
                        "refresh-result barrier control request failed; retrying"
                    ),
                    Err(_) => {
                        return Err(DkgError::NetworkCommunication(format!(
                            "refresh-result {step} barrier reached the hard attempt deadline for peer {peer}"
                        )))
                    }
                }
                crate::metrics::record_dkg_transport_event("control", "retry");
                let remaining = hard_deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    continue;
                }
                sleep(backoff.min(remaining)).await;
                backoff = (backoff * 2).min(DKG_MAX_REPAIR_BACKOFF);
            }
        });
    }
    while let Some(result) = requests.join_next().await {
        result.map_err(|error| DkgError::NetworkCommunication(error.to_string()))??;
    }
    Ok(())
}

async fn distribute_refresh_result<D>(
    state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    session_id: u128,
    signed: SignedPayload,
    contribution: &DkgPublicContribution,
) -> Result<()>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    let peers = state
        .dkg_session_state
        .get_peer_ids(&session_id)
        .await
        .ok_or_else(|| DkgError::SessionNotFound(session_id.to_string()))?
        .into_iter()
        .filter(|peer| !is_self_peer_id(&state.network, peer))
        .collect::<Vec<_>>();
    let hard_deadline = state
        .dkg_session_state
        .transport_hard_deadline(&session_id, contribution.attempt_id)
        .await
        .ok_or_else(|| DkgError::InvalidState("transport hard deadline is missing".into()))?
        .into();

    send_refresh_result_barrier(
        state.clone(),
        routes,
        peers.clone(),
        DkgControlMessage::StageRefreshResult(signed),
        contribution.ceremony_id,
        contribution.attempt_id,
        contribution.message_id,
        hard_deadline,
        "stage",
    )
    .await?;
    crate::metrics::record_dkg_transport_event("public", "result_stage_barrier");

    publish_phase_if_complete(
        state.clone(),
        routes,
        session_id,
        contribution.attempt_id,
        PublicPhase::RefreshHealthCheck,
    )
    .await?;

    send_refresh_result_barrier(
        state,
        routes,
        peers,
        DkgControlMessage::CommitRefreshResult {
            ceremony_id: contribution.ceremony_id,
            attempt_id: contribution.attempt_id,
            message_id: contribution.message_id,
        },
        contribution.ceremony_id,
        contribution.attempt_id,
        contribution.message_id,
        hard_deadline,
        "commit",
    )
    .await?;
    crate::metrics::record_dkg_transport_event("public", "result_commit_barrier");
    Ok(())
}

/// Sign and submit one public contribution, retaining exact bytes until the
/// leader acknowledges it.
pub(crate) async fn submit_public_contribution<D>(
    coord: &DkgCoordinator<D>,
    attempt: AttemptKey,
    payload: DkgPublicPayload,
) -> Result<()>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    let session_id = attempt.session_id();
    let (
        committee_digest,
        leader,
        leader_peer,
        activated,
        node_id,
        is_reshare,
        next_node_id,
        ring_id,
    ) = coord
        .app_state
        .dkg_session_state
        .with_attempt_state(attempt, |session| {
            (
                session.transport.committee_digest,
                session.transport.leader_node_key.clone(),
                session.transport.leader_peer_route.clone(),
                session.transport.activated,
                session.node.node_id(),
                matches!(session.kind, SessionKind::Reshare { .. }),
                session
                    .reshare
                    .params
                    .as_ref()
                    .and_then(|params| params.new_node_id),
                session.routing.ring_id.clone(),
            )
        })
        .await
        .map_err(|error| crate::dkg::v0::coordinator::attempt_state_error(attempt, error))?;
    let committee_digest = committee_digest
        .ok_or_else(|| DkgError::InvalidState("committee digest is missing".into()))?;
    let leader =
        leader.ok_or_else(|| DkgError::InvalidState("leader node key is missing".into()))?;
    if !activated {
        return Err(DkgError::ProtocolError(
            "public contribution generated before attempt activation".into(),
        ));
    }
    let uses_next_identity = matches!(&payload, DkgPublicPayload::ReshareParticipantSet { .. })
        || (is_reshare && matches!(&payload, DkgPublicPayload::CommitmentAudit { .. }));
    let origin = if uses_next_identity {
        let next_node_id = next_node_id.ok_or_else(|| {
            DkgError::Unauthorized(
                "only a next-committee receiver may publish the participant set".into(),
            )
        })?;
        ParticipantRef::next(next_node_id)
    } else {
        ParticipantRef::current(node_id)
    };
    let ceremony_id = attempt.ceremony_id;
    let attempt_id = attempt.attempt_id;
    let contribution = DkgPublicContribution::new(
        ceremony_id,
        attempt_id,
        ring_id,
        committee_digest,
        origin,
        payload,
    )
    .map_err(DkgError::Serialization)?;
    let encoded = transport::encode(&contribution).map_err(DkgError::Serialization)?;
    let pubsub = coord.app_state.network.pubsub().ok_or_else(|| {
        DkgError::InvalidState("network backend does not provide authenticated pub-sub".into())
    })?;
    let signed = pubsub
        .sign(PUBLIC_CONTRIBUTION_SIGNING_DOMAIN, Bytes::from(encoded))
        .await
        .map_err(|error| DkgError::NetworkCommunication(error.to_string()))?;
    tracing::info!(
        session_id,
        node_id,
        phase = ?contribution.payload.phase(),
        leader = %leader,
        "submitting signed public DKG contribution"
    );
    preflight_public_contribution_if_new(&coord.app_state, coord.routes, &signed, &contribution)
        .await?;
    // Retain the exact signed bytes in the same phase index used for direct
    // repair. This lets an origin serve its own contribution even if the
    // leader omits a chunk or the local subscriber never receives the relay.
    record_public_contribution(&coord.app_state, signed.clone(), &contribution).await?;
    if leader == coord.app_state.node_key {
        if contribution.payload.phase() == PublicPhase::RefreshHealthCheck {
            return distribute_refresh_result(
                coord.app_state.clone(),
                coord.routes,
                session_id,
                signed,
                &contribution,
            )
            .await;
        }
        dispatch_public_contribution(
            coord.app_state.clone(),
            coord.routes,
            signed,
            contribution.clone(),
        )
        .await?;
        return publish_phase_if_complete(
            coord.app_state.clone(),
            coord.routes,
            session_id,
            attempt_id,
            contribution.payload.phase(),
        )
        .await;
    }
    let leader_peer =
        leader_peer.ok_or_else(|| DkgError::InvalidState("leader peer route is missing".into()))?;
    match control_request_with_timeout(
        &coord.app_state,
        coord.routes,
        &leader_peer,
        DkgControlMessage::PublicContribution(signed),
        PEER_RESPONSE_TIMEOUT,
    )
    .await?
    {
        DkgControlMessage::PublicContributionAck {
            ceremony_id: got_ceremony,
            attempt_id: got_attempt,
            message_id,
        } if got_ceremony == ceremony_id
            && got_attempt == attempt_id
            && message_id == contribution.message_id =>
        {
            Ok(())
        }
        response => Err(DkgError::ProtocolError(format!(
            "invalid public contribution ACK: {response:?}"
        ))),
    }
}

pub(crate) async fn send_reshare_share_ack<D>(
    coord: &DkgCoordinator<D>,
    attempt: AttemptKey,
    receiver_node_id: u32,
    dealer_id: u32,
    selector_peer: &str,
) -> Result<()>
where
    D: CoordinatorDkg,
{
    coord
        .app_state
        .dkg_session_state
        .with_attempt_state(attempt, |_| ())
        .await
        .map_err(|error| crate::dkg::v0::coordinator::attempt_state_error(attempt, error))?;
    let ceremony_id = attempt.ceremony_id;
    let attempt_id = attempt.attempt_id;
    let receiver = ParticipantRef::next(receiver_node_id);
    let dealer = ParticipantRef::current(dealer_id);
    let idempotency_key = transport::derive_control_message_id(
        ceremony_id,
        attempt_id,
        "reshare-share-ack",
        receiver,
        ParticipantRef::next(1),
        &dealer,
    )
    .map_err(DkgError::Serialization)?;
    match control_request_with_timeout(
        &coord.app_state,
        coord.routes,
        selector_peer,
        DkgControlMessage::ReshareShareAck {
            ceremony_id,
            attempt_id,
            idempotency_key,
            receiver,
            dealer,
        },
        PEER_RESPONSE_TIMEOUT,
    )
    .await?
    {
        DkgControlMessage::ReshareShareAcked {
            ceremony_id: got_ceremony,
            attempt_id: got_attempt,
            idempotency_key: got_key,
        } if got_ceremony == ceremony_id
            && got_attempt == attempt_id
            && got_key == idempotency_key =>
        {
            Ok(())
        }
        response => Err(DkgError::ProtocolError(format!(
            "selector returned invalid reshare acknowledgement response: {response:?}"
        ))),
    }
}

pub(crate) async fn relay_invalid_share_evidence<D>(
    coord: &DkgCoordinator<D>,
    attempt: AttemptKey,
    evidence: SignedDkgShare,
) -> Result<()>
where
    D: CoordinatorDkg,
{
    relay_private_evidence(
        coord,
        attempt,
        ParticipantRef::next(evidence.statement.to_node_id),
        |ceremony_id, attempt_id, key| DkgControlMessage::RelayInvalidShareEvidence {
            ceremony_id,
            attempt_id,
            idempotency_key: key,
            evidence: evidence.clone(),
        },
        "invalid-share-evidence",
        &evidence,
    )
    .await
}

pub(crate) async fn relay_invalid_commitment_evidence<D>(
    coord: &DkgCoordinator<D>,
    attempt: AttemptKey,
    commitment_a: SignedDkgCommitment,
    commitment_b: SignedDkgCommitment,
) -> Result<()>
where
    D: CoordinatorDkg,
{
    let next_node_id = coord
        .app_state
        .dkg_session_state
        .with_attempt_state(attempt, |session| {
            session
                .reshare
                .params
                .as_ref()
                .and_then(|params| params.new_node_id)
        })
        .await
        .map_err(|error| crate::dkg::v0::coordinator::attempt_state_error(attempt, error))?
        .ok_or_else(|| {
            DkgError::Unauthorized("evidence relay requires next-committee role".into())
        })?;
    let payload = (commitment_a.clone(), commitment_b.clone());
    relay_private_evidence(
        coord,
        attempt,
        ParticipantRef::next(next_node_id),
        |ceremony_id, attempt_id, key| DkgControlMessage::RelayInvalidCommitmentEvidence {
            ceremony_id,
            attempt_id,
            idempotency_key: key,
            commitment_a: commitment_a.clone(),
            commitment_b: commitment_b.clone(),
        },
        "invalid-commitment-evidence",
        &payload,
    )
    .await
}

async fn relay_private_evidence<D, T, F>(
    coord: &DkgCoordinator<D>,
    attempt: AttemptKey,
    origin: ParticipantRef,
    make_request: F,
    message_kind: &str,
    payload: &T,
) -> Result<()>
where
    D: CoordinatorDkg,
    T: serde::Serialize,
    F: Fn(CeremonyId, AttemptId, MessageId) -> DkgControlMessage,
{
    let attempt_id = attempt.attempt_id;
    let current_routes = coord
        .app_state
        .dkg_session_state
        .with_attempt_state(attempt, |session| {
            session.routing.node_id_to_peer_id.clone()
        })
        .await
        .map_err(|error| crate::dkg::v0::coordinator::attempt_state_error(attempt, error))?;
    let ceremony_id = attempt.ceremony_id;
    let mut accepted = 0usize;
    for (node_id, peer) in current_routes {
        let recipient = ParticipantRef::current(node_id);
        let key = transport::derive_control_message_id(
            ceremony_id,
            attempt_id,
            message_kind,
            origin,
            recipient,
            payload,
        )
        .map_err(DkgError::Serialization)?;
        if let Ok(DkgControlMessage::EvidenceAccepted {
            ceremony_id: got_ceremony,
            attempt_id: got_attempt,
            idempotency_key,
        }) = control_request_with_timeout(
            &coord.app_state,
            coord.routes,
            &peer,
            make_request(ceremony_id, attempt_id, key),
            PEER_RESPONSE_TIMEOUT,
        )
        .await
        {
            if got_ceremony == ceremony_id && got_attempt == attempt_id && idempotency_key == key {
                accepted += 1;
            }
        }
    }
    if accepted == 0 {
        return Err(DkgError::NetworkCommunication(
            "private evidence was not accepted by any current-committee member".into(),
        ));
    }
    Ok(())
}

/// Inbound handler for one deterministic bidirectional private pair exchange.
pub struct DkgPrivateHandler<D>
where
    D: CoordinatorDkg,
{
    state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
}

impl<D> DkgPrivateHandler<D>
where
    D: CoordinatorDkg,
{
    pub fn new(state: Arc<AppState<D>>, routes: &'static network::ProtocolRoutes) -> Self {
        Self { state, routes }
    }
}

#[async_trait]
impl<D> ProtocolHandler for DkgPrivateHandler<D>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    async fn handle(&self, connection: Box<dyn Connection>) -> network::Result<()> {
        let peer = connection.peer_id().clone();
        let peer_prefix: String = hex::encode(peer.as_bytes()).chars().take(12).collect();
        let first = timeout(PEER_RESPONSE_TIMEOUT, recv_private(&*connection))
            .await
            .map_err(|_| {
                network::error::NetworkError::Protocol(format!(
                    "private pair opener {peer_prefix} did not send its first message within {}ms",
                    PEER_RESPONSE_TIMEOUT.as_millis()
                ))
            })??;
        if matches!(first, DkgPrivateMessage::PairHello { .. }) {
            return handle_inbound_pair_hello(
                self.state.clone(),
                self.routes,
                &*connection,
                &peer,
                first,
            )
            .await;
        }
        let DkgPrivateMessage::ShareDelivery {
            ceremony_id,
            attempt_id,
            message_id: incoming_id,
            from,
            to,
            share_value,
            nonce,
            report_evidence,
        } = first
        else {
            return Err(network::error::NetworkError::Protocol(
                "private pair exchange must start with ShareDelivery".into(),
            ));
        };
        let session_id = ceremony_id.0;
        let is_reshare_delivery =
            from.scope == CommitteeScope::Current && to.scope == CommitteeScope::Next;
        if !is_reshare_delivery
            && (from.scope != CommitteeScope::Current
                || to.scope != CommitteeScope::Current
                || !transport::is_canonical_pair_opener(from.node_id, to.node_id))
        {
            return Err(network::error::NetworkError::Protocol(
                "private pair exchange was opened by the non-canonical endpoint".into(),
            ));
        }
        let incoming = DkgPrivateMessage::ShareDelivery {
            ceremony_id,
            attempt_id,
            message_id: incoming_id,
            from,
            to,
            share_value,
            nonce,
            report_evidence,
        };
        validate_private_delivery(&self.state, &incoming, &peer)
            .await
            .map_err(|error| network::error::NetworkError::Protocol(error.to_string()))?;
        if is_reshare_delivery {
            validate_reshare_pair_opener(&self.state, session_id, from, to, from)
                .await
                .map_err(|error| network::error::NetworkError::Protocol(error.to_string()))?;
        }
        let semaphore = self.state.dkg_private_exchange_permits.clone();
        let permit = match timeout(PRIVATE_INBOUND_QUEUE_WAIT, semaphore.acquire_owned()).await {
            Ok(Ok(permit)) => permit,
            Ok(Err(_)) => {
                return Err(network::error::NetworkError::Protocol(
                    "private exchange semaphore closed".into(),
                ));
            }
            Err(_) => {
                crate::metrics::record_dkg_transport_event("private", "busy");
                send_private_busy(
                    &*connection,
                    self.routes.dkg_private_alpn,
                    ceremony_id,
                    attempt_id,
                )
                .await?;
                return Ok(());
            }
        };
        let pair_metrics = PrivatePairMetricsGuard::new();
        tracing::info!(
            session_id,
            from = ?from,
            to = ?to,
            "accepted inbound private DKG pair exchange"
        );
        if is_reshare_delivery {
            let reciprocal_recipient =
                reciprocal_reshare_recipient(&self.state, session_id, from, to)
                    .await
                    .map_err(|error| network::error::NetworkError::Protocol(error.to_string()))?;
            let reciprocal = match reciprocal_recipient {
                Some(recipient) => {
                    let Some(bytes) = self
                        .state
                        .dkg_session_state
                        .private_message_for_recipient(&session_id, recipient)
                        .await
                    else {
                        send_private_busy(
                            &*connection,
                            self.routes.dkg_private_alpn,
                            ceremony_id,
                            attempt_id,
                        )
                        .await?;
                        return Ok(());
                    };
                    Some(
                        transport::decode::<DkgPrivateMessage>(&bytes, MAX_CONTROL_MESSAGE_BYTES)
                            .map_err(network::error::NetworkError::Serialization)?,
                    )
                }
                None => None,
            };
            let completion = timeout(PEER_RESPONSE_TIMEOUT, async {
                if let Some(outgoing) = &reciprocal {
                    send_private(&*connection, self.routes.dkg_private_alpn, outgoing).await?;
                    let ack = recv_private(&*connection).await?;
                    validate_share_ack(outgoing, &ack)
                        .map_err(network::error::NetworkError::Protocol)?;
                    if let DkgPrivateMessage::ShareAck { message_id, .. } = ack {
                        self.state
                            .dkg_session_state
                            .acknowledge_private_message(&session_id, attempt_id, message_id)
                            .await;
                    }
                }
                let completion =
                    accept_private_delivery(self.state.clone(), self.routes, &incoming, &peer)
                        .await
                        .map_err(|error| {
                            network::error::NetworkError::Protocol(error.to_string())
                        })?;
                let ack =
                    share_ack_for(&incoming).map_err(network::error::NetworkError::Protocol)?;
                send_private(&*connection, self.routes.dkg_private_alpn, &ack).await?;
                Ok::<PrivateShareCompletion, network::error::NetworkError>(completion)
            })
            .await
            .map_err(|_| {
                crate::metrics::record_dkg_transport_event("private", "inbound_timeout");
                network::error::NetworkError::Protocol(format!(
                    "inbound reshare delivery from {peer_prefix} timed out after {}ms",
                    PEER_RESPONSE_TIMEOUT.as_millis()
                ))
            })??;
            drop(permit);
            pair_metrics.complete();
            crate::metrics::record_dkg_transport_event("private", "pair_completed");
            drive_private_completion(self.state.clone(), self.routes, completion)
                .await
                .map_err(|error| network::error::NetworkError::Protocol(error.to_string()))?;
            return Ok(());
        }
        let Some(outgoing_bytes) = self
            .state
            .dkg_session_state
            .private_message_for_recipient(&session_id, from)
            .await
        else {
            send_private_busy(
                &*connection,
                self.routes.dkg_private_alpn,
                ceremony_id,
                attempt_id,
            )
            .await?;
            return Ok(());
        };
        let outgoing: DkgPrivateMessage =
            transport::decode(&outgoing_bytes, MAX_CONTROL_MESSAGE_BYTES)
                .map_err(network::error::NetworkError::Serialization)?;
        let completion = timeout(PEER_RESPONSE_TIMEOUT, async {
            send_private(&*connection, self.routes.dkg_private_alpn, &outgoing).await?;
            let ack = recv_private(&*connection).await?;
            validate_share_ack(&outgoing, &ack).map_err(network::error::NetworkError::Protocol)?;
            if let DkgPrivateMessage::ShareAck { message_id, .. } = ack {
                self.state
                    .dkg_session_state
                    .acknowledge_private_message(&session_id, attempt_id, message_id)
                    .await;
            }
            let completion =
                accept_private_delivery(self.state.clone(), self.routes, &incoming, &peer)
                    .await
                    .map_err(|error| network::error::NetworkError::Protocol(error.to_string()))?;
            let incoming_ack =
                share_ack_for(&incoming).map_err(network::error::NetworkError::Protocol)?;
            send_private(&*connection, self.routes.dkg_private_alpn, &incoming_ack).await?;
            Ok::<PrivateShareCompletion, network::error::NetworkError>(completion)
        })
        .await
        .map_err(|_| {
            crate::metrics::record_dkg_transport_event("private", "inbound_timeout");
            network::error::NetworkError::Protocol(format!(
                "inbound private pair exchange with {peer_prefix} timed out after {}ms",
                PEER_RESPONSE_TIMEOUT.as_millis()
            ))
        })??;
        drop(permit);
        pair_metrics.complete();
        crate::metrics::record_dkg_transport_event("private", "pair_completed");
        drive_private_completion(self.state.clone(), self.routes, completion)
            .await
            .map_err(|error| network::error::NetworkError::Protocol(error.to_string()))?;
        Ok(())
    }
}

async fn validate_reshare_pair_opener<D>(
    state: &Arc<AppState<D>>,
    session_id: u128,
    first: ParticipantRef,
    second: ParticipantRef,
    actual_opener: ParticipantRef,
) -> Result<()>
where
    D: CoordinatorDkg,
{
    let committees = state
        .dkg_session_state
        .transport_committees(&session_id)
        .await
        .ok_or_else(|| {
            DkgError::InvalidState("ceremony committee configuration is missing".into())
        })?;
    if committees.canonical_pair_opener(first, second) != Some(actual_opener) {
        return Err(DkgError::Unauthorized(
            "reshare private stream was opened by the non-canonical node key".into(),
        ));
    }
    Ok(())
}

async fn reciprocal_reshare_recipient<D>(
    state: &Arc<AppState<D>>,
    session_id: u128,
    remote_dealer: ParticipantRef,
    _local_receiver: ParticipantRef,
) -> Result<Option<ParticipantRef>>
where
    D: CoordinatorDkg,
{
    let committees = state
        .dkg_session_state
        .transport_committees(&session_id)
        .await
        .ok_or_else(|| {
            DkgError::InvalidState("ceremony committee configuration is missing".into())
        })?;
    let remote_key = committees.node_key(remote_dealer).ok_or_else(|| {
        DkgError::Unauthorized("remote dealer is outside current committee".into())
    })?;
    let Some(next) = committees.next.as_ref() else {
        return Ok(None);
    };
    let Some(remote_receiver) = next.participant(CommitteeScope::Next, remote_key) else {
        return Ok(None);
    };
    let Some(local_dealer) = committees
        .current
        .participant(CommitteeScope::Current, &state.node_key)
    else {
        return Ok(None);
    };
    let active = state
        .dkg_session_state
        .transport_active_dealers(&session_id)
        .await
        .unwrap_or_default();
    Ok(active.contains(&local_dealer).then_some(remote_receiver))
}

async fn handle_inbound_pair_hello<D>(
    state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    connection: &dyn Connection,
    peer: &PeerId,
    hello: DkgPrivateMessage,
) -> network::Result<()>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    let DkgPrivateMessage::PairHello {
        ceremony_id,
        attempt_id,
        pair_id,
        opener,
        responder,
    } = hello
    else {
        unreachable!("caller accepts only PairHello");
    };
    if opener.scope != CommitteeScope::Next || responder.scope != CommitteeScope::Current {
        return Err(network::error::NetworkError::Protocol(
            "reshare PairHello must be next-receiver to current-dealer".into(),
        ));
    }
    let session_id = ceremony_id.0;
    let (_, active_attempt, _, _, activated) = state
        .dkg_session_state
        .transport_info(&session_id)
        .await
        .ok_or_else(|| network::error::NetworkError::Protocol("pair session is missing".into()))?;
    if active_attempt != attempt_id || !activated {
        return Err(network::error::NetworkError::Protocol(
            "PairHello targets a stale or inactive attempt".into(),
        ));
    }
    if pair_id != transport::derive_pair_hello_id(ceremony_id, attempt_id, opener, responder) {
        return Err(network::error::NetworkError::Protocol(
            "PairHello idempotency key is invalid".into(),
        ));
    }
    let committees = state
        .dkg_session_state
        .transport_committees(&session_id)
        .await
        .ok_or_else(|| {
            network::error::NetworkError::Protocol(
                "ceremony committee configuration is missing".into(),
            )
        })?;
    if committees.node_key(responder) != Some(state.node_key.as_str())
        || committees
            .route(opener)
            .is_none_or(|route| !peer_matches_route(peer, route))
    {
        return Err(network::error::NetworkError::Protocol(
            "PairHello identities do not match authenticated routes".into(),
        ));
    }
    validate_reshare_pair_opener(&state, session_id, opener, responder, opener)
        .await
        .map_err(|error| network::error::NetworkError::Protocol(error.to_string()))?;
    let active_dealers = state
        .dkg_session_state
        .transport_active_dealers(&session_id)
        .await
        .unwrap_or_default();
    if !active_dealers.contains(&responder) {
        return Err(network::error::NetworkError::Protocol(
            "PairHello targets an inactive dealer".into(),
        ));
    }
    let semaphore = state.dkg_private_exchange_permits.clone();
    let permit = match timeout(PRIVATE_INBOUND_QUEUE_WAIT, semaphore.acquire_owned()).await {
        Ok(Ok(permit)) => permit,
        Ok(Err(_)) => {
            return Err(network::error::NetworkError::Protocol(
                "private exchange semaphore closed".into(),
            ));
        }
        Err(_) => {
            send_private_busy(connection, routes.dkg_private_alpn, ceremony_id, attempt_id).await?;
            return Ok(());
        }
    };
    let Some(outgoing_bytes) = state
        .dkg_session_state
        .private_message_for_recipient(&session_id, opener)
        .await
    else {
        send_private_busy(connection, routes.dkg_private_alpn, ceremony_id, attempt_id).await?;
        return Ok(());
    };
    let outgoing: DkgPrivateMessage = transport::decode(&outgoing_bytes, MAX_CONTROL_MESSAGE_BYTES)
        .map_err(network::error::NetworkError::Serialization)?;
    timeout(PEER_RESPONSE_TIMEOUT, async {
        send_private(connection, routes.dkg_private_alpn, &outgoing).await?;
        let ack = recv_private(connection).await?;
        validate_share_ack(&outgoing, &ack).map_err(network::error::NetworkError::Protocol)?;
        if let DkgPrivateMessage::ShareAck { message_id, .. } = ack {
            state
                .dkg_session_state
                .acknowledge_private_message(&session_id, attempt_id, message_id)
                .await;
        }
        Ok::<(), network::error::NetworkError>(())
    })
    .await
    .map_err(|_| {
        network::error::NetworkError::Protocol(
            "responder-only private pair exchange timed out".into(),
        )
    })??;
    drop(permit);
    crate::metrics::record_dkg_transport_event("private", "pair_completed");
    Ok(())
}

async fn send_private(
    connection: &dyn Connection,
    alpn: &[u8],
    message: &DkgPrivateMessage,
) -> network::Result<()> {
    crate::metrics::record_dkg_transport_message("private", message.metric_label(), "sent");
    let bytes = transport::encode(message).map_err(network::error::NetworkError::Serialization)?;
    connection.send(Message::new(bytes, alpn.to_vec())).await
}

async fn send_private_busy(
    connection: &dyn Connection,
    alpn: &[u8],
    ceremony_id: CeremonyId,
    attempt_id: AttemptId,
) -> network::Result<()> {
    timeout(
        PEER_RESPONSE_TIMEOUT,
        send_private(
            connection,
            alpn,
            &DkgPrivateMessage::Busy {
                ceremony_id,
                attempt_id,
                retry_after_ms: PRIVATE_BUSY_RETRY_AFTER.as_millis() as u64,
            },
        ),
    )
    .await
    .map_err(|_| {
        network::error::NetworkError::Protocol(format!(
            "sending private Busy response timed out after {}ms",
            PEER_RESPONSE_TIMEOUT.as_millis()
        ))
    })?
}

async fn recv_private(connection: &dyn Connection) -> network::Result<DkgPrivateMessage> {
    let message = connection.recv().await?;
    let decoded: DkgPrivateMessage = transport::decode(&message.data, MAX_CONTROL_MESSAGE_BYTES)
        .map_err(network::error::NetworkError::Serialization)?;
    crate::metrics::record_dkg_transport_message("private", decoded.metric_label(), "received");
    Ok(decoded)
}

fn share_ack_for(message: &DkgPrivateMessage) -> std::result::Result<DkgPrivateMessage, String> {
    let DkgPrivateMessage::ShareDelivery {
        ceremony_id,
        attempt_id,
        message_id,
        from,
        to,
        share_value,
        nonce,
        ..
    } = message
    else {
        return Err("cannot acknowledge a non-share private message".into());
    };
    Ok(DkgPrivateMessage::ShareAck {
        ceremony_id: *ceremony_id,
        attempt_id: *attempt_id,
        message_id: *message_id,
        share_digest: transport::share_digest(
            *ceremony_id,
            *attempt_id,
            *from,
            *to,
            share_value,
            nonce,
        ),
    })
}

fn validate_share_ack(
    delivery: &DkgPrivateMessage,
    ack: &DkgPrivateMessage,
) -> std::result::Result<(), String> {
    let expected = share_ack_for(delivery)?;
    if &expected != ack {
        return Err("private share acknowledgement digest or attempt did not match".into());
    }
    Ok(())
}

async fn validate_private_delivery<D>(
    state: &Arc<AppState<D>>,
    message: &DkgPrivateMessage,
    sender: &PeerId,
) -> Result<()>
where
    D: CoordinatorDkg,
{
    let DkgPrivateMessage::ShareDelivery {
        ceremony_id,
        attempt_id,
        message_id,
        from,
        to,
        share_value,
        nonce,
        ..
    } = message
    else {
        return Err(DkgError::ProtocolError(
            "expected private ShareDelivery".into(),
        ));
    };
    let (expected_ceremony, expected_attempt, _, _, activated) = state
        .dkg_session_state
        .transport_info(&ceremony_id.0)
        .await
        .ok_or_else(|| DkgError::SessionNotFound(ceremony_id.0.to_string()))?;
    if expected_ceremony != *ceremony_id || expected_attempt != *attempt_id || !activated {
        return Err(DkgError::Unauthorized(format!(
            "stale or inactive private exchange: expected ceremony={} attempt={} activated={activated}, got ceremony={} attempt={}",
            expected_ceremony.0,
            hex::encode(expected_attempt.0),
            ceremony_id.0,
            hex::encode(attempt_id.0),
        )));
    }
    let local_node_id = state
        .dkg_session_state
        .with_state(&ceremony_id.0, |session| session.node.node_id())
        .await
        .ok_or_else(|| DkgError::SessionNotFound(ceremony_id.0.to_string()))?;
    let expected_local_id = if to.scope == CommitteeScope::Next {
        state
            .dkg_session_state
            .with_state(&ceremony_id.0, |session| {
                session
                    .reshare
                    .params
                    .as_ref()
                    .and_then(|params| params.new_node_id)
            })
            .await
            .flatten()
    } else {
        Some(local_node_id)
    };
    if expected_local_id != Some(to.node_id) {
        return Err(DkgError::Unauthorized(
            "private share delivered to wrong recipient".into(),
        ));
    }
    let expected_sender = state
        .dkg_session_state
        .get_peer_id_for_node(&ceremony_id.0, from.node_id)
        .await
        .ok_or_else(|| DkgError::Unauthorized("private share sender is not in committee".into()))?;
    if !peer_matches_route(sender, &expected_sender) {
        return Err(DkgError::Unauthorized(
            "private share sender does not match SourceHub NodeInfo".into(),
        ));
    }
    let expected_id = transport::derive_private_message_id(
        *ceremony_id,
        *attempt_id,
        *from,
        *to,
        share_value,
        nonce,
    );
    if expected_id != *message_id {
        return Err(DkgError::Unauthorized(
            "private share message ID mismatch".into(),
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy)]
struct PrivateShareCompletion {
    attempt: AttemptKey,
    from_node_id: u32,
    should_drive: bool,
}

async fn accept_private_delivery<D>(
    state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    message: &DkgPrivateMessage,
    _sender: &PeerId,
) -> Result<PrivateShareCompletion>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    let DkgPrivateMessage::ShareDelivery {
        ceremony_id,
        attempt_id,
        message_id,
        from,
        to,
        share_value,
        nonce,
        report_evidence,
        ..
    } = message.clone()
    else {
        return Err(DkgError::ProtocolError(
            "expected private ShareDelivery".into(),
        ));
    };
    let should_drive = DkgCoordinator::with_routes(state, routes)
        .accept_transport_share(
            AttemptKey::new(ceremony_id, attempt_id),
            message_id,
            from.node_id,
            to.node_id,
            share_value,
            nonce,
            report_evidence.map(|evidence| *evidence),
        )
        .await?;
    Ok(PrivateShareCompletion {
        attempt: AttemptKey::new(ceremony_id, attempt_id),
        from_node_id: from.node_id,
        should_drive,
    })
}

async fn drive_private_completion<D>(
    state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    completion: PrivateShareCompletion,
) -> Result<()>
where
    D: CoordinatorDkg,
{
    if completion.should_drive {
        drive_accepted_share(
            &DkgCoordinator::with_routes(state, routes),
            completion.attempt,
            completion.from_node_id,
        )
        .await?;
    }
    Ok(())
}

/// Return a retry delay that is stable for one pair/attempt but changes for the
/// next retry. Busy responses are treated as a minimum wait, while the growing
/// local backoff supplies a widening jitter window. This prevents a committee
/// burst from repeatedly hitting the same recipient in synchronized waves.
fn private_retry_delay(
    message_id: MessageId,
    retry_attempt: u32,
    backoff: Duration,
    busy_retry_after: Option<Duration>,
    remaining: Duration,
) -> Duration {
    let (floor, ceiling) = if let Some(retry_after) = busy_retry_after {
        let floor = retry_after.min(DKG_MAX_REPAIR_BACKOFF);
        (
            floor,
            floor.saturating_add(backoff).min(DKG_MAX_REPAIR_BACKOFF),
        )
    } else {
        (backoff / 2, backoff)
    };
    let floor_ms = floor.as_millis() as u64;
    let ceiling_ms = ceiling.as_millis() as u64;
    let spread_ms = ceiling_ms.saturating_sub(floor_ms);

    let mut seed_bytes = [0_u8; 8];
    seed_bytes.copy_from_slice(&message_id.0[..8]);
    let mut value = u64::from_le_bytes(seed_bytes)
        ^ u64::from(retry_attempt).wrapping_mul(0x9e37_79b9_7f4a_7c15);
    // SplitMix64 gives a deterministic, well-distributed word without adding a
    // random generator to the hot path or making retry tests nondeterministic.
    value = value.wrapping_add(0x9e37_79b9_7f4a_7c15);
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^= value >> 31;

    let jitter_ms = if spread_ms == 0 {
        0
    } else {
        value % (spread_ms + 1)
    };
    Duration::from_millis(floor_ms.saturating_add(jitter_ms)).min(remaining)
}

async fn open_private_pair_hello<D>(
    state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    peer: String,
    ceremony_id: CeremonyId,
    attempt_id: AttemptId,
    opener: ParticipantRef,
    responder: ParticipantRef,
) -> Result<()>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    let pair_id = transport::derive_pair_hello_id(ceremony_id, attempt_id, opener, responder);
    let hello = DkgPrivateMessage::PairHello {
        ceremony_id,
        attempt_id,
        pair_id,
        opener,
        responder,
    };
    let exact_hello = transport::encode(&hello).map_err(DkgError::Serialization)?;
    let deadline: Instant = state
        .dkg_session_state
        .transport_hard_deadline(&ceremony_id.0, attempt_id)
        .await
        .ok_or_else(|| DkgError::InvalidState("transport hard deadline is missing".into()))?
        .into();
    let mut backoff = INITIAL_PRIVATE_RETRY_BACKOFF;
    let mut retry_attempt = 0_u32;
    loop {
        if Instant::now() >= deadline {
            return Err(DkgError::NetworkCommunication(format!(
                "responder-only private pair exchange with {peer} exceeded hard attempt deadline"
            )));
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        let permit = timeout(
            remaining,
            state.dkg_private_exchange_permits.clone().acquire_owned(),
        )
        .await
        .map_err(|_| DkgError::NetworkCommunication("private pair permit timed out".into()))?
        .map_err(|_| DkgError::InvalidState("private exchange semaphore closed".into()))?;
        let attempt_timeout = PEER_RESPONSE_TIMEOUT.min(remaining);
        let mut busy_retry_after = None;
        let mut attempt_connection = None;
        let exchange = timeout(attempt_timeout, async {
            let (stream, parent) = state
                .peer_connection_pool
                .open_stream_with_connection(&state.network, &peer, routes.dkg_private_alpn)
                .await
                .map_err(|error| DkgError::NetworkConnection(error.to_string()))?;
            attempt_connection = Some(parent);
            stream
                .send(Message::new(
                    exact_hello.clone(),
                    routes.dkg_private_alpn.to_vec(),
                ))
                .await
                .map_err(|error| DkgError::NetworkCommunication(error.to_string()))?;
            let response = recv_private(&*stream)
                .await
                .map_err(|error| DkgError::NetworkCommunication(error.to_string()))?;
            if let DkgPrivateMessage::Busy {
                ceremony_id: busy_ceremony,
                attempt_id: busy_attempt,
                retry_after_ms,
            } = response
            {
                if busy_ceremony != ceremony_id || busy_attempt != attempt_id {
                    return Err(DkgError::ProtocolError(
                        "private Busy response did not match PairHello attempt".into(),
                    ));
                }
                busy_retry_after = Some(Duration::from_millis(retry_after_ms.max(1)));
                return Err(DkgError::NetworkCommunication("private peer busy".into()));
            }
            validate_private_delivery(&state, &response, stream.peer_id()).await?;
            let DkgPrivateMessage::ShareDelivery { from, to, .. } = response.clone() else {
                return Err(DkgError::ProtocolError(
                    "PairHello responder did not return ShareDelivery".into(),
                ));
            };
            if from != responder || to != opener {
                return Err(DkgError::Unauthorized(
                    "PairHello responder returned the wrong directional obligation".into(),
                ));
            }
            let completion =
                accept_private_delivery(state.clone(), routes, &response, stream.peer_id()).await?;
            let ack = share_ack_for(&response).map_err(DkgError::ProtocolError)?;
            send_private(&*stream, routes.dkg_private_alpn, &ack)
                .await
                .map_err(|error| DkgError::NetworkCommunication(error.to_string()))?;
            Ok(completion)
        })
        .await
        .unwrap_or_else(|_| {
            Err(DkgError::NetworkCommunication(format!(
                "responder-only private pair exchange with {peer} timed out"
            )))
        });
        drop(permit);
        match exchange {
            Ok(completion) => {
                drive_private_completion(state.clone(), routes, completion).await?;
                crate::metrics::record_dkg_transport_event("private", "pair_completed");
                return Ok(());
            }
            Err(error) => {
                if busy_retry_after.is_none() {
                    if let Some(connection) = attempt_connection.as_ref() {
                        state
                            .peer_connection_pool
                            .invalidate_if_same(&peer, routes.dkg_private_alpn, connection)
                            .await;
                    }
                }
                crate::metrics::record_dkg_transport_event("private", "retry");
                let remaining = deadline.saturating_duration_since(Instant::now());
                let delay = private_retry_delay(
                    pair_id,
                    retry_attempt,
                    backoff,
                    busy_retry_after,
                    remaining,
                );
                tracing::debug!(%peer, %error, "retrying responder-only private pair exchange");
                sleep(delay).await;
                retry_attempt = retry_attempt.saturating_add(1);
                backoff = (backoff * 2).min(DKG_MAX_REPAIR_BACKOFF);
            }
        }
    }
}

fn spawn_reshare_receiver_pair_openers<D>(
    state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    attempt: AttemptKey,
) where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    tokio::spawn(async move {
        let session_id = attempt.session_id();
        let Ok((committees, active_dealers)) = state
            .dkg_session_state
            .with_attempt_state(attempt, |session| {
                (
                    session.transport.committees.clone(),
                    session.transport.active_dealers.clone(),
                )
            })
            .await
        else {
            return;
        };
        let Some(committees) = committees else {
            return;
        };
        let Some(next) = committees.next.as_ref() else {
            return;
        };
        let Some(local_receiver) = next.participant(CommitteeScope::Next, &state.node_key) else {
            return;
        };
        let attempt_id = attempt.attempt_id;
        let mut tasks = FuturesUnordered::new();
        for dealer in active_dealers {
            if committees.canonical_pair_opener(local_receiver, dealer) != Some(local_receiver) {
                continue;
            }
            let Some(peer) = committees.route(dealer).map(str::to_string) else {
                continue;
            };
            let state = state.clone();
            tasks.push(async move {
                open_private_pair_hello(
                    state,
                    routes,
                    peer,
                    attempt.ceremony_id,
                    attempt_id,
                    local_receiver,
                    dealer,
                )
                .await
            });
        }
        while let Some(result) = tasks.next().await {
            if let Err(error) = result {
                tracing::warn!(session_id, %error, "reshare responder-only pair exchange failed");
            }
        }
    });
}

async fn open_private_pair<D>(
    state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    peer: String,
    outgoing_bytes: Vec<u8>,
) -> Result<()>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    let outgoing: DkgPrivateMessage = transport::decode(&outgoing_bytes, MAX_CONTROL_MESSAGE_BYTES)
        .map_err(DkgError::Deserialization)?;
    let DkgPrivateMessage::ShareDelivery {
        ceremony_id,
        attempt_id,
        message_id,
        ..
    } = outgoing.clone()
    else {
        return Err(DkgError::InvalidState(
            "cached private message is not a share".into(),
        ));
    };
    let deadline: Instant = state
        .dkg_session_state
        .transport_hard_deadline(&ceremony_id.0, attempt_id)
        .await
        .ok_or_else(|| DkgError::InvalidState("transport hard deadline is missing".into()))?
        .into();
    let mut backoff = INITIAL_PRIVATE_RETRY_BACKOFF;
    let mut retry_attempt = 0_u32;
    loop {
        if Instant::now() >= deadline {
            return Err(DkgError::NetworkCommunication(format!(
                "private pair exchange with {peer} exceeded hard attempt deadline"
            )));
        }
        let semaphore = state.dkg_private_exchange_permits.clone();
        let remaining = deadline.saturating_duration_since(Instant::now());
        let permit = timeout(remaining, semaphore.acquire_owned())
            .await
            .map_err(|_| {
                DkgError::NetworkCommunication(format!(
                    "private pair exchange with {peer} exceeded hard attempt deadline"
                ))
            })?
            .map_err(|_| DkgError::InvalidState("private exchange semaphore closed".into()))?;
        let pair_metrics = PrivatePairMetricsGuard::new();
        tracing::info!(
            session_id = ceremony_id.0,
            %peer,
            "opening private DKG pair exchange"
        );
        // A connect or response can disappear without producing an I/O error.  Bound
        // each individual stream attempt so the cached share is retried long before
        // the ceremony's hard deadline.  The outer loop retains the exact serialized
        // bytes and exponential backoff, so a retry never regenerates crypto material.
        let attempt_timeout =
            PEER_RESPONSE_TIMEOUT.min(deadline.saturating_duration_since(Instant::now()));
        let mut busy_retry_after = None;
        let mut attempt_connection = None;
        let exchange = timeout(attempt_timeout, async {
            let (stream, parent_connection) = state
                .peer_connection_pool
                .open_stream_with_connection(&state.network, &peer, routes.dkg_private_alpn)
                .await
                .map_err(|error| DkgError::NetworkConnection(error.to_string()))?;
            attempt_connection = Some(parent_connection);
            let remote = stream.peer_id().clone();
            stream
                .send(Message::new(
                    outgoing_bytes.clone(),
                    routes.dkg_private_alpn.to_vec(),
                ))
                .await
                .map_err(|error| DkgError::NetworkCommunication(error.to_string()))?;
            let response = recv_private(&*stream)
                .await
                .map_err(|error| DkgError::NetworkCommunication(error.to_string()))?;
            if let DkgPrivateMessage::Busy {
                ceremony_id: busy_ceremony_id,
                attempt_id: busy_attempt_id,
                retry_after_ms,
            } = response
            {
                if busy_ceremony_id != ceremony_id || busy_attempt_id != attempt_id {
                    return Err(DkgError::ProtocolError(
                        "private Busy response did not match the active attempt".into(),
                    ));
                }
                busy_retry_after = Some(Duration::from_millis(retry_after_ms.max(1)));
                return Err(DkgError::NetworkCommunication("private peer busy".into()));
            }
            if let DkgPrivateMessage::ShareAck { .. } = response {
                validate_share_ack(&outgoing, &response).map_err(DkgError::ProtocolError)?;
                state
                    .dkg_session_state
                    .acknowledge_private_message(&ceremony_id.0, attempt_id, message_id)
                    .await;
                return Ok(None);
            }
            validate_private_delivery(&state, &response, &remote).await?;
            let completion =
                accept_private_delivery(state.clone(), routes, &response, &remote).await?;
            let ack = share_ack_for(&response).map_err(DkgError::ProtocolError)?;
            send_private(&*stream, routes.dkg_private_alpn, &ack)
                .await
                .map_err(|error| DkgError::NetworkCommunication(error.to_string()))?;
            let final_ack = recv_private(&*stream)
                .await
                .map_err(|error| DkgError::NetworkCommunication(error.to_string()))?;
            validate_share_ack(&outgoing, &final_ack).map_err(DkgError::ProtocolError)?;
            state
                .dkg_session_state
                .acknowledge_private_message(&ceremony_id.0, attempt_id, message_id)
                .await;
            Ok(Some(completion))
        })
        .await
        .unwrap_or_else(|_| {
            Err(DkgError::NetworkCommunication(format!(
                "private pair exchange with {peer} timed out after {}ms",
                attempt_timeout.as_millis()
            )))
        });
        drop(permit);
        match exchange {
            Ok(completion) => {
                pair_metrics.complete();
                crate::metrics::record_dkg_transport_event("private", "pair_completed");
                tracing::info!(
                    session_id = ceremony_id.0,
                    %peer,
                    "private DKG pair exchange completed"
                );
                if let Some(completion) = completion {
                    drive_private_completion(state.clone(), routes, completion).await?;
                }
                return Ok(());
            }
            Err(error) => {
                drop(pair_metrics);
                // `open_stream` may succeed on a cached QUIC connection whose
                // subsequent request/response path is no longer making progress.
                // Never retain that connection across a timeout: Iroh can otherwise
                // keep returning new streams on it until its much longer path-health
                // transition expires. A valid Busy response proves the transport is
                // live and intentionally retains the connection.
                if busy_retry_after.is_none() {
                    if let Some(connection) = attempt_connection.as_ref() {
                        if state
                            .peer_connection_pool
                            .invalidate_if_same(&peer, routes.dkg_private_alpn, connection)
                            .await
                        {
                            crate::metrics::record_dkg_transport_event(
                                "private",
                                "connection_invalidated",
                            );
                            tracing::warn!(
                                session_id = ceremony_id.0,
                                %peer,
                                %error,
                                "invalidated stalled private DKG connection"
                            );
                        }
                    }
                }
                crate::metrics::record_dkg_transport_event("private", "retry");
                let remaining = deadline.saturating_duration_since(Instant::now());
                let retry_delay = private_retry_delay(
                    message_id,
                    retry_attempt,
                    backoff,
                    busy_retry_after,
                    remaining,
                );
                tracing::debug!(%peer, %error, backoff_ms = backoff.as_millis(),
                    retry_delay_ms = retry_delay.as_millis(),
                    retry_attempt,
                    "retrying private pair exchange with identical cached share");
                sleep(retry_delay).await;
                retry_attempt = retry_attempt.saturating_add(1);
                backoff = (backoff * 2).min(DKG_MAX_REPAIR_BACKOFF);
            }
        }
    }
}

/// Exchange every cached recipient-specific share through one deterministic
/// bidirectional stream per unordered pair. The lower node ID opens the stream;
/// both directions are digest-acknowledged before the stream closes.
pub(crate) async fn exchange_private_shares<D>(
    coord: &DkgCoordinator<D>,
    attempt: AttemptKey,
    outgoing: Vec<(u32, String, MessageId, Vec<u8>)>,
) -> Result<()>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    let (local_node_id, committees, deadline) = coord
        .app_state
        .dkg_session_state
        .with_attempt_state(attempt, |session| {
            (
                session.node.node_id(),
                session.transport.committees.clone(),
                session.transport.hard_deadline,
            )
        })
        .await
        .map_err(|error| crate::dkg::v0::coordinator::attempt_state_error(attempt, error))?;
    let committees = committees.ok_or_else(|| {
        DkgError::InvalidState("ceremony committee configuration is missing".into())
    })?;
    let deadline = deadline
        .ok_or_else(|| DkgError::InvalidState("transport hard deadline is missing".into()))?;
    let mut openers = FuturesUnordered::new();
    let all_message_ids: Vec<_> = outgoing.iter().map(|(_, _, id, _)| *id).collect();
    for (to_node_id, peer, _, bytes) in outgoing {
        let decoded = transport::decode::<DkgPrivateMessage>(&bytes, MAX_CONTROL_MESSAGE_BYTES)
            .map_err(DkgError::Deserialization)?;
        let should_open = match decoded {
            DkgPrivateMessage::ShareDelivery { from, to, .. }
                if to.scope == CommitteeScope::Next =>
            {
                committees.canonical_pair_opener(from, to) == Some(from)
            }
            DkgPrivateMessage::ShareDelivery { .. } => {
                transport::is_canonical_pair_opener(local_node_id, to_node_id)
            }
            _ => false,
        };
        if should_open {
            let state = coord.app_state.clone();
            let routes = coord.routes;
            openers.push(async move { open_private_pair(state, routes, peer, bytes).await });
        }
    }
    while let Some(result) = openers.next().await {
        result?;
    }
    loop {
        let mut missing = 0usize;
        for message_id in &all_message_ids {
            if !coord
                .app_state
                .dkg_session_state
                .private_message_acknowledged_for_attempt(attempt, *message_id)
                .await
                .map_err(|error| crate::dkg::v0::coordinator::attempt_state_error(attempt, error))?
            {
                missing += 1;
            }
        }
        if missing == 0 {
            return Ok(());
        }
        if Instant::now() >= deadline.into() {
            return Err(DkgError::NetworkCommunication(format!(
                "{missing} private pair exchanges were not acknowledged before hard deadline"
            )));
        }
        sleep(Duration::from_millis(100)).await;
    }
}

#[cfg(test)]
mod stability_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct ScriptedBroadcastTopic {
        id: network::TopicId,
        calls: AtomicUsize,
        fail_on_calls: BTreeSet<usize>,
        observed: tokio::sync::Mutex<Vec<Bytes>>,
    }

    impl ScriptedBroadcastTopic {
        fn new(fail_on_calls: impl IntoIterator<Item = usize>) -> Self {
            Self {
                id: network::TopicId::new([42; 32]),
                calls: AtomicUsize::new(0),
                fail_on_calls: fail_on_calls.into_iter().collect(),
                observed: tokio::sync::Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait]
    impl Topic for ScriptedBroadcastTopic {
        fn id(&self) -> network::TopicId {
            self.id
        }

        async fn broadcast(&self, data: Bytes) -> network::Result<()> {
            let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
            self.observed.lock().await.push(data);
            if self.fail_on_calls.contains(&call) {
                return Err(network::NetworkError::Connection(format!(
                    "scripted broadcast failure on call {call}"
                )));
            }
            Ok(())
        }

        async fn recv(&self) -> network::Result<PubSubEvent> {
            std::future::pending().await
        }
    }

    #[tokio::test]
    async fn partial_publication_failure_replays_the_exact_batch_from_manifest() {
        let topic = ScriptedBroadcastTopic::new([2]);
        let batch = PreparedPublicBatch {
            root: [7; 32],
            contribution_count: 1,
            messages: vec![
                Bytes::from_static(b"manifest"),
                Bytes::from_static(b"chunk-0"),
                Bytes::from_static(b"chunk-1"),
            ],
        };

        assert!(
            broadcast_public_batches(&topic, std::slice::from_ref(&batch))
                .await
                .is_err()
        );
        broadcast_public_batches(&topic, &[batch])
            .await
            .expect("the retry should restart with the identical manifest");

        assert_eq!(
            topic.observed.lock().await.as_slice(),
            [
                Bytes::from_static(b"manifest"),
                Bytes::from_static(b"chunk-0"),
                Bytes::from_static(b"manifest"),
                Bytes::from_static(b"chunk-0"),
                Bytes::from_static(b"chunk-1"),
            ]
        );
    }

    fn pending_reshare_ring() -> RingPayload {
        RingPayload {
            upgrade_info: Default::default(),
            ring_pk: "authoritative-ring-key".to_string(),
            peer_node_keys: vec!["current-b".to_string(), "current-a".to_string()],
            new_peer_node_keys: Some(vec!["next-b".to_string(), "next-a".to_string()]),
            new_threshold: Some(2),
            threshold: 2,
            pss_interval: 60,
            block_number_nonce: 0,
            policy_id: None,
            reporting: Default::default(),
        }
    }

    #[test]
    fn reshare_start_rejects_stale_ring_key_before_leader_selection() {
        let error = pending_reshare_parameters(&pending_reshare_ring(), "stale-ring-key")
            .expect_err("a stale scheduler observation must not start reshare");
        assert!(matches!(error, DkgError::InvalidState(_)));
        assert!(error.to_string().contains("differs from SourceHub state"));
    }

    #[test]
    fn threshold_only_reshare_uses_current_committee_as_next() {
        let mut ring = pending_reshare_ring();
        ring.new_peer_node_keys = None;
        ring.new_threshold = Some(1);
        let (next_keys, next_threshold) =
            pending_reshare_parameters(&ring, "authoritative-ring-key").unwrap();
        assert_eq!(next_keys, ring.peer_node_keys);
        assert_eq!(next_threshold, 1);
        assert_eq!(transport::canonical_leader(&next_keys), Some("current-a"));
    }

    fn resolved_next_routes() -> Vec<NodeRoute> {
        vec![
            NodeRoute {
                node_key: "next-b".to_string(),
                peer_id: format!("{}@127.0.0.1:9002", "bb".repeat(32)),
            },
            NodeRoute {
                node_key: "next-a".to_string(),
                peer_id: format!("{}@127.0.0.1:9001", "aa".repeat(32)),
            },
        ]
    }

    fn valid_next_transport_committee() -> CommitteeConfig {
        let resolved = resolved_next_routes();
        CommitteeConfig {
            // Transport order need not match SourceHub order, but each route
            // must remain bound to its node key.
            node_keys: vec!["next-a".to_string(), "next-b".to_string()],
            peer_routes: vec![resolved[1].peer_id.clone(), resolved[0].peer_id.clone()],
            node_id_assignments: HashMap::from([
                ("next-a".to_string(), 1),
                ("next-b".to_string(), 2),
            ]),
            threshold: 2,
        }
    }

    #[test]
    fn reshare_next_transport_routes_accept_reordering_with_exact_key_bindings() {
        validate_reshare_next_transport_committee(
            &valid_next_transport_committee(),
            &["next-b".to_string(), "next-a".to_string()],
            2,
            &resolved_next_routes(),
        )
        .expect("equivalent orderings with authoritative key-route bindings must validate");
    }

    #[test]
    fn reshare_next_transport_routes_reject_altered_or_swapped_routes() {
        let expected_keys = ["next-b".to_string(), "next-a".to_string()];
        let resolved = resolved_next_routes();

        let mut altered = valid_next_transport_committee();
        altered.peer_routes[0] = format!("{}@127.0.0.1:9999", "aa".repeat(32));
        let error =
            validate_reshare_next_transport_committee(&altered, &expected_keys, 2, &resolved)
                .expect_err("an altered direct address must be rejected");
        assert!(matches!(error, DkgError::Unauthorized(_)));
        assert!(error.to_string().contains("SourceHub NodeInfo routes"));

        let mut swapped = valid_next_transport_committee();
        swapped.peer_routes.swap(0, 1);
        let error =
            validate_reshare_next_transport_committee(&swapped, &expected_keys, 2, &resolved)
                .expect_err("a route set bound to the wrong node keys must be rejected");
        assert!(matches!(error, DkgError::Unauthorized(_)));
        assert!(error.to_string().contains("SourceHub NodeInfo routes"));
    }

    #[test]
    fn reshare_next_transport_rejects_membership_threshold_and_assignment_mismatches() {
        let expected_keys = ["next-b".to_string(), "next-a".to_string()];
        let resolved = resolved_next_routes();

        let mut wrong_member = valid_next_transport_committee();
        wrong_member.node_keys[0] = "next-c".to_string();
        let error =
            validate_reshare_next_transport_committee(&wrong_member, &expected_keys, 2, &resolved)
                .expect_err("a different transport member must be rejected");
        assert!(matches!(error, DkgError::Unauthorized(_)));
        assert!(error.to_string().contains("announced next committee"));

        let mut wrong_threshold = valid_next_transport_committee();
        wrong_threshold.threshold = 1;
        let error = validate_reshare_next_transport_committee(
            &wrong_threshold,
            &expected_keys,
            2,
            &resolved,
        )
        .expect_err("a different transport threshold must be rejected");
        assert!(matches!(error, DkgError::Unauthorized(_)));
        assert!(error.to_string().contains("announced threshold"));

        let mut wrong_assignments = valid_next_transport_committee();
        wrong_assignments
            .node_id_assignments
            .insert("next-a".to_string(), 2);
        wrong_assignments
            .node_id_assignments
            .insert("next-b".to_string(), 1);
        let error = validate_reshare_next_transport_committee(
            &wrong_assignments,
            &expected_keys,
            2,
            &resolved,
        )
        .expect_err("noncanonical next transport assignments must be rejected");
        assert!(matches!(error, DkgError::Unauthorized(_)));
        assert!(error.to_string().contains("not canonical"));
    }

    #[test]
    fn neighbor_churn_only_schedules_rejoin_after_sustained_full_isolation() {
        let peer_a = PeerId::from_bytes(b"peer-a");
        let peer_b = PeerId::from_bytes(b"peer-b");
        let now = Instant::now();
        let mut tracker = GossipNeighborTracker::default();

        tracker.neighbor_up(&peer_a);
        tracker.neighbor_up(&peer_b);
        assert!(tracker.neighbor_down(&peer_a, now));
        assert_eq!(tracker.neighbor_count(), 1);
        assert_eq!(tracker.isolation_deadline(), None);

        assert!(tracker.neighbor_down(&peer_b, now));
        assert!(tracker.is_isolated());
        assert_eq!(
            tracker.isolation_deadline(),
            Some(now + DKG_GOSSIP_ISOLATION_GRACE)
        );

        tracker.neighbor_up(&peer_a);
        assert!(!tracker.is_isolated());
        assert_eq!(tracker.isolation_deadline(), None);
    }

    #[test]
    fn rejoin_reset_does_not_treat_initial_empty_topic_as_isolated() {
        let peer = PeerId::from_bytes(b"peer");
        let mut tracker = GossipNeighborTracker::default();
        tracker.neighbor_up(&peer);
        tracker.neighbor_down(&peer, Instant::now());
        assert!(tracker.is_isolated());

        tracker.reset_after_rejoin();
        assert!(!tracker.is_isolated());
        assert_eq!(tracker.neighbor_count(), 0);
        assert_eq!(tracker.isolation_deadline(), None);
    }

    #[test]
    fn control_timeout_includes_operation_peer_and_attempt_scope() {
        let request = DkgControlMessage::TopologyProbeAck {
            ceremony_id: CeremonyId(42),
            attempt_id: AttemptId([7; 32]),
            nonce: [9; 32],
        };
        let message = control_timeout_message(
            "0123456789abcdef@127.0.0.1:9000",
            &request,
            PEER_RESPONSE_TIMEOUT,
        );
        assert!(message.contains("topology-probe-ack"));
        assert!(message.contains("0123456789ab"));
        assert!(message.contains("ceremony=42"));
        assert!(message.contains("attempt=070707070707"));
    }

    #[test]
    fn reshare_preparation_only_fails_for_nonretryable_next_member_errors() {
        let retryable = DkgError::NetworkCommunication("timed out".into());
        let nonretryable = DkgError::Unauthorized("configuration mismatch".into());

        assert_eq!(
            reshare_preparation_error_action(false, &retryable),
            ResharePreparationErrorAction::Retry
        );
        assert_eq!(
            reshare_preparation_error_action(false, &nonretryable),
            ResharePreparationErrorAction::ExcludeOld
        );
        assert_eq!(
            reshare_preparation_error_action(true, &nonretryable),
            ResharePreparationErrorAction::Fail
        );
    }

    #[test]
    fn follower_bootstrap_preserves_the_authoritative_direct_route() {
        let leader_bytes = [7u8; 32];
        let route = format!("{}@127.0.0.1:9000", hex::encode(leader_bytes));

        let bootstrap = leader_bootstrap("follower-key", "leader-key", &route).unwrap();

        assert_eq!(bootstrap.len(), 1);
        assert_eq!(bootstrap[0].as_bytes(), route.as_bytes());
    }

    #[test]
    fn follower_bootstrap_accepts_an_id_only_discovery_route() {
        let route = hex::encode([7u8; 32]);

        let bootstrap = leader_bootstrap("follower-key", "leader-key", &route).unwrap();

        assert_eq!(bootstrap.len(), 1);
        assert_eq!(bootstrap[0].as_bytes(), route.as_bytes());
    }

    #[test]
    fn follower_bootstrap_preserves_hostname_and_ipv6_routes() {
        let node_id = hex::encode([7u8; 32]);
        for route in [
            format!("{node_id}@leader.example.com:9000"),
            format!("{node_id}@[::1]:9000"),
        ] {
            let bootstrap = leader_bootstrap("follower-key", "leader-key", &route).unwrap();
            assert_eq!(bootstrap[0].as_bytes(), route.as_bytes());
        }
    }

    #[test]
    fn follower_bootstrap_rejects_malformed_leader_route() {
        let error = leader_bootstrap("follower-key", "leader-key", "not-hex@127.0.0.1:9000")
            .expect_err("malformed leader node IDs must be rejected before Gossip subscribe");

        assert!(matches!(error, DkgError::InvalidInput(_)));
        assert!(error.to_string().contains("invalid leader route"));

        let node_id = hex::encode([7u8; 32]);
        let error = leader_bootstrap(
            "follower-key",
            "leader-key",
            &format!("{node_id}@not a valid address"),
        )
        .expect_err("malformed direct addresses must be rejected before Gossip subscribe");

        assert!(matches!(error, DkgError::InvalidInput(_)));
        assert!(error.to_string().contains("invalid leader route"));
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn follower_bootstrap_joins_gossip_with_discovery_and_relays_disabled() {
        use network::Network as _;

        let leader = network::NetworkImpl::builder()
            .bind_addr_v4("127.0.0.1:0".parse().unwrap())
            .private_routes_only()
            .build()
            .await
            .expect("build leader network");
        let follower = network::NetworkImpl::builder()
            .bind_addr_v4("127.0.0.1:0".parse().unwrap())
            .private_routes_only()
            .build()
            .await
            .expect("build follower network");
        let leader_router = leader
            .create_router_builder()
            .unwrap()
            .spawn()
            .expect("spawn leader Gossip router");
        let follower_router = follower
            .create_router_builder()
            .unwrap()
            .spawn()
            .expect("spawn follower Gossip router");

        let topic_id = network::TopicId::new([23; 32]);
        let leader_topic = leader
            .pubsub()
            .expect("leader pub-sub")
            .subscribe(topic_id, Vec::new())
            .await
            .expect("leader creates topic");
        let leader_route = format!(
            "{}@{}",
            hex::encode(leader.local_peer_id().as_bytes()),
            leader
                .bound_addresses()
                .into_iter()
                .next()
                .expect("leader bound address")
        );
        let bootstrap = leader_bootstrap("follower-key", "leader-key", &leader_route).unwrap();
        let follower_topic = follower
            .pubsub()
            .expect("follower pub-sub")
            .subscribe(topic_id, bootstrap)
            .await
            .expect("follower joins through the direct leader route");

        timeout(Duration::from_secs(10), async {
            loop {
                if matches!(
                    leader_topic.recv().await.expect("leader topic event"),
                    PubSubEvent::NeighborUp(_)
                ) {
                    break;
                }
            }
        })
        .await
        .expect("leader and follower should become Gossip neighbors");

        leader_topic
            .broadcast(Bytes::from_static(b"direct-route-bootstrap"))
            .await
            .expect("leader broadcasts after direct join");
        let received = timeout(Duration::from_secs(10), async {
            loop {
                if let PubSubEvent::Received(message) =
                    follower_topic.recv().await.expect("follower topic event")
                {
                    return message;
                }
            }
        })
        .await
        .expect("follower receives over the direct Gossip route");
        assert_eq!(&received.data[..], b"direct-route-bootstrap");
        assert_eq!(received.origin, leader.local_peer_id());

        leader_router.shutdown().await.unwrap();
        follower_router.shutdown().await.unwrap();
    }

    #[test]
    fn leader_does_not_bootstrap_through_its_own_route() {
        assert!(leader_bootstrap("leader-key", "leader-key", "not-needed")
            .unwrap()
            .is_empty());
    }

    #[test]
    fn missing_topology_members_are_exact_and_prefixes_are_bounded() {
        let expected = BTreeSet::from([
            "aaaaaaaaaaaaaaaa".to_string(),
            "bbbbbbbbbbbbbbbb".to_string(),
            "cccccccccccccccc".to_string(),
        ]);
        let acknowledged = BTreeSet::from([
            "aaaaaaaaaaaaaaaa".to_string(),
            "cccccccccccccccc".to_string(),
        ]);
        let missing = missing_topology_peers(&expected, &acknowledged);
        assert_eq!(missing, vec!["bbbbbbbbbbbbbbbb"]);
        assert_eq!(missing_topology_peer_prefixes(&missing), "bbbbbbbbbbbb");
    }

    #[tokio::test]
    async fn ceremony_start_lock_is_removed_after_the_last_waiter_releases_it() {
        let state = Arc::new(create_test_app_state_default("ceremony_start_lock_cleanup").await);
        let ceremony = CeremonyId(91);
        let first = lock_ceremony_start(&state, ceremony).await;
        assert!(state
            .dkg_ceremony_start_locks
            .lock()
            .await
            .contains_key(&ceremony.0));

        let waiter_state = state.clone();
        let waiter =
            tokio::spawn(async move { lock_ceremony_start(&waiter_state, ceremony).await });
        timeout(Duration::from_secs(1), async {
            loop {
                let references = {
                    let locks = state.dkg_ceremony_start_locks.lock().await;
                    Arc::strong_count(locks.get(&ceremony.0).expect("lock entry must exist"))
                };
                if references >= 3 {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("waiter should retain the existing lock");

        drop(first);
        let second = waiter.await.expect("waiter task should complete");
        assert!(state
            .dkg_ceremony_start_locks
            .lock()
            .await
            .contains_key(&ceremony.0));
        drop(second);

        timeout(Duration::from_secs(1), async {
            loop {
                if !state
                    .dkg_ceremony_start_locks
                    .lock()
                    .await
                    .contains_key(&ceremony.0)
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("last guard should remove the ceremony lock entry");
    }

    #[test]
    fn private_busy_retries_honor_hint_and_desynchronize_pairs() {
        let backoff = Duration::from_secs(1);
        let busy_hint = Duration::from_millis(250);
        let remaining = Duration::from_secs(30);
        let first = private_retry_delay(MessageId([1; 32]), 0, backoff, Some(busy_hint), remaining);
        let second_pair =
            private_retry_delay(MessageId([2; 32]), 0, backoff, Some(busy_hint), remaining);
        let next_attempt =
            private_retry_delay(MessageId([1; 32]), 1, backoff, Some(busy_hint), remaining);

        assert!(first >= busy_hint);
        assert!(first <= busy_hint + backoff);
        assert_ne!(first, second_pair);
        assert_ne!(first, next_attempt);
    }

    #[test]
    fn private_retry_delay_never_exceeds_deadline_or_global_cap() {
        let remaining = Duration::from_millis(17);
        assert_eq!(
            private_retry_delay(
                MessageId([3; 32]),
                99,
                DKG_MAX_REPAIR_BACKOFF,
                Some(Duration::from_secs(300)),
                remaining,
            ),
            remaining
        );
    }

    // =========================================================================
    // GossipNeighborTracker
    // =========================================================================

    fn tracker_peer(byte: u8) -> PeerId {
        PeerId::from_bytes(&[byte; 32])
    }

    #[test]
    fn gossip_neighbor_tracker_is_not_isolated_before_any_neighbor() {
        let mut tracker = GossipNeighborTracker::default();
        assert!(!tracker.is_isolated());
        assert_eq!(tracker.neighbor_count(), 0);
        // A down event for a peer that was never a neighbor is a no-op and
        // must not arm isolation before any neighbor was ever seen.
        assert!(!tracker.neighbor_down(&tracker_peer(1), Instant::now()));
        assert!(!tracker.is_isolated());
        assert!(tracker.isolation_deadline().is_none());
    }

    #[test]
    fn gossip_neighbor_tracker_arms_isolation_only_after_last_neighbor_leaves() {
        let mut tracker = GossipNeighborTracker::default();
        let peer_a = tracker_peer(1);
        let peer_b = tracker_peer(2);

        tracker.neighbor_up(&peer_a);
        tracker.neighbor_up(&peer_b);
        assert_eq!(tracker.neighbor_count(), 2);
        assert!(!tracker.is_isolated());

        // One neighbor leaving while another remains must not arm isolation.
        assert!(tracker.neighbor_down(&peer_a, Instant::now()));
        assert_eq!(tracker.neighbor_count(), 1);
        assert!(!tracker.is_isolated());
        assert!(tracker.isolation_deadline().is_none());

        // The last neighbor leaving arms isolation with a grace deadline.
        let now = Instant::now();
        assert!(tracker.neighbor_down(&peer_b, now));
        assert_eq!(tracker.neighbor_count(), 0);
        assert!(tracker.is_isolated());
        let deadline = tracker
            .isolation_deadline()
            .expect("isolation deadline must be armed once every neighbor is gone");
        assert!(deadline >= now);
    }

    #[test]
    fn gossip_neighbor_tracker_rejoin_clears_isolation() {
        let mut tracker = GossipNeighborTracker::default();
        let peer_a = tracker_peer(1);

        tracker.neighbor_up(&peer_a);
        tracker.neighbor_down(&peer_a, Instant::now());
        assert!(tracker.is_isolated());
        assert!(tracker.isolation_deadline().is_some());

        // A fresh neighbor coming up must clear isolation immediately.
        tracker.neighbor_up(&tracker_peer(2));
        assert!(!tracker.is_isolated());
        assert!(tracker.isolation_deadline().is_none());
    }

    #[test]
    fn gossip_neighbor_tracker_reset_after_rejoin_returns_to_initial_state() {
        let mut tracker = GossipNeighborTracker::default();
        let peer_a = tracker_peer(1);
        tracker.neighbor_up(&peer_a);
        tracker.neighbor_down(&peer_a, Instant::now());
        assert!(tracker.is_isolated());

        tracker.reset_after_rejoin();
        assert!(!tracker.is_isolated());
        assert_eq!(tracker.neighbor_count(), 0);
        assert!(tracker.isolation_deadline().is_none());
        // A subsequent down-event on an unrelated peer must not arm
        // isolation, exactly like the pre-any-neighbor state, since
        // `ever_had_neighbor` was cleared by the reset.
        assert!(!tracker.neighbor_down(&tracker_peer(3), Instant::now()));
        assert!(!tracker.is_isolated());
    }

    // =========================================================================
    // verify_signed_contribution — per-phase/scope authorization matrix
    // =========================================================================

    /// Build a single-node test `AppState` with a session pre-configured as if
    /// `configure_transport`/`activate_transport` had already run, then sign a
    /// contribution from `origin` using that same node's own endpoint identity
    /// so `verify_signed_contribution`'s route-authentication step succeeds
    /// and only the phase/scope authorization matrix is under test.
    async fn contribution_test_state(
        db_name: &str,
        session_id: u128,
        kind: SessionKind,
        active_dealers: Vec<ParticipantRef>,
        origin: ParticipantRef,
    ) -> (
        Arc<AppState<crypto::DkgImpl>>,
        CeremonyId,
        AttemptId,
        [u8; 32],
    ) {
        let state = Arc::new(create_test_app_state_default(db_name).await);
        let node = *{
            use crypto::r#trait::Dkg as _;
            crypto::DkgImpl::new(1, 2, 3, 0, crypto::r#trait::DkgRole::Standard)
                .expect("construct DkgImpl for test session")
        };
        assert_eq!(
            state
                .dkg_session_state
                .create_session(session_id, node, 3, |_| {})
                .await,
            CreateSessionOutcome::Created
        );

        let ceremony_id = CeremonyId(session_id);
        let attempt_id = AttemptId([9u8; 32]);
        let committee_digest = [3u8; 32];
        let local_peer_hex = hex::encode(state.network.local_peer_id().as_bytes());

        {
            let mut states = state.dkg_session_state.states.write().await;
            let session = states
                .get_mut(&session_id)
                .expect("session was just created");
            session.kind = kind;
            session.transport.ceremony_id = Some(ceremony_id);
            session.transport.attempt_id = Some(attempt_id);
            session.transport.committee_digest = Some(committee_digest);
            session.transport.leader_node_key = Some("test-leader".to_string());
            session.transport.active_dealers = active_dealers;
            session.routing.ring_id = "test-ring-post".to_string();
            session
                .routing
                .node_id_to_peer_id
                .insert(origin.node_id, local_peer_hex.clone());
            session
                .routing
                .reshare_new_node_id_to_peer_id
                .insert(origin.node_id, local_peer_hex);
        }

        (state, ceremony_id, attempt_id, committee_digest)
    }

    async fn sign_contribution(
        state: &Arc<AppState<crypto::DkgImpl>>,
        ceremony_id: CeremonyId,
        attempt_id: AttemptId,
        committee_digest: [u8; 32],
        origin: ParticipantRef,
        payload: DkgPublicPayload,
    ) -> network::SignedPayload {
        let contribution = DkgPublicContribution::new(
            ceremony_id,
            attempt_id,
            "test-ring-post".to_string(),
            committee_digest,
            origin,
            payload,
        )
        .expect("construct contribution");
        let encoded = transport::encode(&contribution).expect("encode contribution");
        state
            .network
            .pubsub()
            .expect("pubsub enabled")
            .sign(PUBLIC_CONTRIBUTION_SIGNING_DOMAIN, encoded.into())
            .await
            .expect("sign contribution with local endpoint identity")
    }

    fn repair_test_prepare(
        ceremony_id: CeremonyId,
        attempt_id: AttemptId,
        member_count: u32,
    ) -> PrepareSession {
        let node_keys: Vec<_> = (1..=member_count)
            .map(|node_id| format!("repair-node-{node_id}"))
            .collect();
        let peer_routes: Vec<_> = (1..=member_count)
            .map(|node_id| format!("repair-route-{node_id}"))
            .collect();
        let node_id_assignments = node_keys
            .iter()
            .enumerate()
            .map(|(index, key)| (key.clone(), index as u32 + 1))
            .collect();
        PrepareSession {
            ceremony_id,
            attempt_id,
            config_digest: [4; 32],
            topic_id: [5; 32],
            leader_node_key: node_keys[0].clone(),
            committees: CeremonyConfig {
                current: CommitteeConfig {
                    node_keys,
                    peer_routes,
                    node_id_assignments,
                    threshold: 1,
                },
                next: None,
            },
            token_string: String::new(),
            kind: SessionKind::Refresh {
                ring_pk_hex: "test-ring".to_string(),
            },
            pss_interval: 0,
            policy_id: None,
            ring_id: "test-ring-post".to_string(),
        }
    }

    fn refresh_health_payload(session_id: u128) -> DkgPublicPayload {
        DkgPublicPayload::RefreshHealthCheckResult {
            statement: crate::sign::v0::messages::RefreshHealthCheckStatement {
                domain: crate::sign::v0::messages::REFRESH_HEALTH_CHECK_DOMAIN.to_string(),
                session_id,
                ring_pk: "test-ring".to_string(),
                public_polynomial_sha256: "00".repeat(32),
                peer_node_keys_sha256: "11".repeat(32),
                threshold: 1,
                total_participants: 2,
            },
            signature: None,
        }
    }

    async fn bind_test_origin_to_local_peer(
        state: &Arc<AppState<crypto::DkgImpl>>,
        session_id: u128,
        origin: ParticipantRef,
    ) {
        let local_peer_hex = hex::encode(state.network.local_peer_id().as_bytes());
        let mut states = state.dkg_session_state.states.write().await;
        let session = states.get_mut(&session_id).expect("repair test session");
        match origin.scope {
            CommitteeScope::Current => {
                session
                    .routing
                    .node_id_to_peer_id
                    .insert(origin.node_id, local_peer_hex);
            }
            CommitteeScope::Next => {
                session
                    .routing
                    .reshare_new_node_id_to_peer_id
                    .insert(origin.node_id, local_peer_hex);
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn complete_phase_is_marked_published_only_after_retry_succeeds() {
        let origin = ParticipantRef::current(1);
        let (state, ceremony_id, attempt_id, _) = contribution_test_state(
            "complete_publication_commits_after_retry",
            4249,
            SessionKind::Fresh,
            Vec::new(),
            origin,
        )
        .await;
        let topic = Arc::new(ScriptedBroadcastTopic::new([2]));
        {
            let mut states = state.dkg_session_state.states.write().await;
            let transport = &mut states
                .get_mut(&ceremony_id.0)
                .expect("publication test session")
                .transport;
            transport.topic = Some(topic.clone());
            transport.hard_deadline =
                Some(std::time::Instant::now() + std::time::Duration::from_secs(60));
            transport.public_contributions.insert(
                PublicPhase::Commitments,
                (1..=3)
                    .map(|node_id| {
                        (
                            ParticipantRef::current(node_id),
                            SignedPayload {
                                origin: vec![node_id as u8],
                                signature: vec![node_id as u8; 32],
                                data: vec![node_id as u8; 32],
                            },
                        )
                    })
                    .collect(),
            );
        }

        publish_phase_if_complete(
            state.clone(),
            &network::V0,
            ceremony_id.0,
            attempt_id,
            PublicPhase::Commitments,
        )
        .await
        .expect("a transient Gossip failure should schedule publication retry");
        assert_eq!(
            state
                .dkg_session_state
                .with_state(&ceremony_id.0, |session| (
                    session
                        .transport
                        .publishing_public_phases
                        .contains(&PublicPhase::Commitments),
                    session
                        .transport
                        .published_public_phases
                        .contains(&PublicPhase::Commitments),
                ))
                .await,
            Some((true, false)),
            "a partial send must remain in-flight, not published"
        );

        tokio::task::yield_now().await;
        tokio::time::advance(INITIAL_CONTROL_RETRY_BACKOFF).await;
        for _ in 0..4 {
            tokio::task::yield_now().await;
        }

        assert_eq!(
            state
                .dkg_session_state
                .with_state(&ceremony_id.0, |session| (
                    session
                        .transport
                        .publishing_public_phases
                        .contains(&PublicPhase::Commitments),
                    session
                        .transport
                        .published_public_phases
                        .contains(&PublicPhase::Commitments),
                ))
                .await,
            Some((false, true)),
            "the full successful retry must atomically commit publication"
        );
        let observed = topic.observed.lock().await;
        assert_eq!(observed.len(), 4, "manifest and chunk should be retried");
        assert_eq!(observed[0], observed[2]);
        assert_eq!(observed[1], observed[3]);
    }

    struct ScriptedPublicRepairRequester {
        responses: tokio::sync::Mutex<
            HashMap<String, std::collections::VecDeque<Result<DkgControlMessage>>>,
        >,
        requests: tokio::sync::Mutex<Vec<(String, &'static str)>>,
    }

    impl ScriptedPublicRepairRequester {
        fn new(
            responses: HashMap<String, std::collections::VecDeque<Result<DkgControlMessage>>>,
        ) -> Self {
            Self {
                responses: tokio::sync::Mutex::new(responses),
                requests: tokio::sync::Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait]
    impl PublicRepairRequester for ScriptedPublicRepairRequester {
        async fn request(
            &self,
            peer: &str,
            request: DkgControlMessage,
        ) -> Result<DkgControlMessage> {
            self.requests
                .lock()
                .await
                .push((peer.to_string(), request.metric_label()));
            self.responses
                .lock()
                .await
                .get_mut(peer)
                .and_then(std::collections::VecDeque::pop_front)
                .unwrap_or_else(|| {
                    Err(DkgError::NetworkConnection(format!(
                        "script has no response for {peer}"
                    )))
                })
        }
    }

    #[test]
    fn public_repair_control_errors_separate_availability_from_malformed_bytes() {
        assert!(retryable_public_repair_control_error(
            &DkgError::NetworkConnection("offline".into())
        ));
        assert!(retryable_public_repair_control_error(
            &DkgError::NetworkCommunication("stream reset".into())
        ));
        assert!(retryable_public_repair_control_error(
            &DkgError::ProtocolError("explicit peer error".into())
        ));
        assert!(!retryable_public_repair_control_error(
            &DkgError::Deserialization("malformed peer bytes".into())
        ));
        assert!(!retryable_public_repair_control_error(
            &DkgError::Serialization("local encoding failure".into())
        ));
    }

    #[tokio::test]
    async fn leader_unavailability_enters_direct_origin_repair() {
        let origin = ParticipantRef::current(1);
        let (state, ceremony_id, attempt_id, committee_digest) = contribution_test_state(
            "leader_unavailability_enters_origin_repair",
            4250,
            SessionKind::Refresh {
                ring_pk_hex: "test-ring".to_string(),
            },
            Vec::new(),
            origin,
        )
        .await;
        let prepare = repair_test_prepare(ceremony_id, attempt_id, 1);
        let signed = sign_contribution(
            &state,
            ceremony_id,
            attempt_id,
            committee_digest,
            origin,
            refresh_health_payload(ceremony_id.0),
        )
        .await;
        let requester = ScriptedPublicRepairRequester::new(HashMap::from([(
            "repair-route-1".to_string(),
            std::collections::VecDeque::from([
                Err(DkgError::NetworkConnection("leader unavailable".into())),
                Ok(DkgControlMessage::PublicContributionResponse {
                    ceremony_id,
                    attempt_id,
                    contribution: Some(signed),
                }),
            ]),
        )]));

        repair_public_phase_claimed(
            &state,
            &network::V0,
            &requester,
            &prepare,
            PublicPhase::RefreshHealthCheck,
        )
        .await
        .expect("origin repair should replace the unavailable leader repair path");

        let retained = state
            .dkg_session_state
            .public_contributions(&ceremony_id.0, attempt_id, PublicPhase::RefreshHealthCheck)
            .await
            .expect("active repair attempt");
        assert_eq!(retained.keys().copied().collect::<Vec<_>>(), vec![origin]);
        assert_eq!(
            requester.requests.lock().await.as_slice(),
            [
                ("repair-route-1".to_string(), "get_public_phase"),
                ("repair-route-1".to_string(), "get_public_contribution"),
            ]
        );
    }

    #[tokio::test]
    async fn commitment_audit_leader_failure_does_not_create_origin_fanout() {
        let origin = ParticipantRef::current(1);
        let (state, ceremony_id, attempt_id, _) = contribution_test_state(
            "commitment_audit_repair_remains_best_effort",
            4255,
            SessionKind::Refresh {
                ring_pk_hex: "test-ring".to_string(),
            },
            Vec::new(),
            origin,
        )
        .await;
        let prepare = repair_test_prepare(ceremony_id, attempt_id, 2);
        let requester = ScriptedPublicRepairRequester::new(HashMap::from([(
            "repair-route-1".to_string(),
            std::collections::VecDeque::from([Err(DkgError::ProtocolError(
                "leader no longer retains diagnostic audits".into(),
            ))]),
        )]));

        repair_public_phase_claimed(
            &state,
            &network::V0,
            &requester,
            &prepare,
            PublicPhase::CommitmentAudit,
        )
        .await
        .expect("commitment-audit repair is optional diagnostics");

        assert_eq!(
            requester.requests.lock().await.as_slice(),
            [("repair-route-1".to_string(), "get_public_phase")]
        );
    }

    #[tokio::test]
    async fn later_leader_page_failure_preserves_pages_then_uses_origins() {
        let first = ParticipantRef::current(1);
        let second = ParticipantRef::current(2);
        let (state, ceremony_id, attempt_id, committee_digest) = contribution_test_state(
            "later_leader_page_failure_uses_origins",
            4251,
            SessionKind::Fresh,
            Vec::new(),
            first,
        )
        .await;
        bind_test_origin_to_local_peer(&state, ceremony_id.0, second).await;
        let prepare = repair_test_prepare(ceremony_id, attempt_id, 2);
        let first_signed = sign_contribution(
            &state,
            ceremony_id,
            attempt_id,
            committee_digest,
            first,
            DkgPublicPayload::CommitmentHash {
                commitment_hash: [1; 32],
            },
        )
        .await;
        let second_signed = sign_contribution(
            &state,
            ceremony_id,
            attempt_id,
            committee_digest,
            second,
            DkgPublicPayload::CommitmentHash {
                commitment_hash: [2; 32],
            },
        )
        .await;
        let requester = ScriptedPublicRepairRequester::new(HashMap::from([
            (
                "repair-route-1".to_string(),
                std::collections::VecDeque::from([
                    Ok(DkgControlMessage::PublicPhaseResponse {
                        ceremony_id,
                        attempt_id,
                        phase: PublicPhase::CommitmentHashes,
                        contributions: vec![first_signed],
                        next_cursor: Some(first),
                    }),
                    Err(DkgError::NetworkCommunication(
                        "leader failed on the second page".into(),
                    )),
                ]),
            ),
            (
                "repair-route-2".to_string(),
                std::collections::VecDeque::from([Ok(
                    DkgControlMessage::PublicContributionResponse {
                        ceremony_id,
                        attempt_id,
                        contribution: Some(second_signed),
                    },
                )]),
            ),
        ]));
        let expected = BTreeSet::from([first, second]);

        let outcome = collect_public_phase_from_leader(
            &state,
            &network::V0,
            &requester,
            &prepare,
            PublicPhase::CommitmentHashes,
            &expected,
        )
        .await
        .expect("a later leader availability failure must be recoverable");
        assert!(matches!(
            outcome,
            LeaderPublicRepairOutcome::Unavailable { retained: 1, .. }
        ));
        collect_public_phase_from_origins(
            &state,
            &network::V0,
            &requester,
            &prepare,
            PublicPhase::CommitmentHashes,
            &expected,
        )
        .await
        .expect("the missing second origin should complete repair");

        let retained = state
            .dkg_session_state
            .public_contributions(&ceremony_id.0, attempt_id, PublicPhase::CommitmentHashes)
            .await
            .expect("active repair attempt");
        assert_eq!(
            retained.keys().copied().collect::<Vec<_>>(),
            vec![first, second]
        );
    }

    #[tokio::test]
    async fn unavailable_origin_does_not_block_other_origin_responses() {
        let first = ParticipantRef::current(1);
        let second = ParticipantRef::current(2);
        let (state, ceremony_id, attempt_id, committee_digest) = contribution_test_state(
            "unavailable_origin_does_not_block_others",
            4252,
            SessionKind::Fresh,
            Vec::new(),
            first,
        )
        .await;
        bind_test_origin_to_local_peer(&state, ceremony_id.0, second).await;
        let prepare = repair_test_prepare(ceremony_id, attempt_id, 2);
        let second_signed = sign_contribution(
            &state,
            ceremony_id,
            attempt_id,
            committee_digest,
            second,
            DkgPublicPayload::CommitmentHash {
                commitment_hash: [2; 32],
            },
        )
        .await;
        let requester = ScriptedPublicRepairRequester::new(HashMap::from([
            (
                "repair-route-1".to_string(),
                std::collections::VecDeque::from([Err(DkgError::NetworkConnection(
                    "first origin unavailable".into(),
                ))]),
            ),
            (
                "repair-route-2".to_string(),
                std::collections::VecDeque::from([Ok(
                    DkgControlMessage::PublicContributionResponse {
                        ceremony_id,
                        attempt_id,
                        contribution: Some(second_signed),
                    },
                )]),
            ),
        ]));

        collect_public_phase_from_origins(
            &state,
            &network::V0,
            &requester,
            &prepare,
            PublicPhase::CommitmentHashes,
            &BTreeSet::from([first, second]),
        )
        .await
        .expect("one unavailable origin must not short-circuit the repair round");

        let retained = state
            .dkg_session_state
            .public_contributions(&ceremony_id.0, attempt_id, PublicPhase::CommitmentHashes)
            .await
            .expect("active repair attempt");
        assert!(!retained.contains_key(&first));
        assert!(retained.contains_key(&second));
    }

    #[tokio::test]
    async fn malformed_origin_response_preflights_before_any_origin_is_applied() {
        let first = ParticipantRef::current(1);
        let second = ParticipantRef::current(2);
        let (state, ceremony_id, attempt_id, committee_digest) = contribution_test_state(
            "malformed_origin_response_is_atomic",
            4253,
            SessionKind::Refresh {
                ring_pk_hex: "test-ring".to_string(),
            },
            Vec::new(),
            first,
        )
        .await;
        bind_test_origin_to_local_peer(&state, ceremony_id.0, second).await;
        let prepare = repair_test_prepare(ceremony_id, attempt_id, 2);
        let second_signed = sign_contribution(
            &state,
            ceremony_id,
            attempt_id,
            committee_digest,
            second,
            refresh_health_payload(ceremony_id.0),
        )
        .await;
        let requester = ScriptedPublicRepairRequester::new(HashMap::from([
            (
                "repair-route-1".to_string(),
                std::collections::VecDeque::from([Ok(DkgControlMessage::Begun {
                    ceremony_id,
                    attempt_id,
                    activation_digest: [8; 32],
                })]),
            ),
            (
                "repair-route-2".to_string(),
                std::collections::VecDeque::from([Ok(
                    DkgControlMessage::PublicContributionResponse {
                        ceremony_id,
                        attempt_id,
                        contribution: Some(second_signed),
                    },
                )]),
            ),
        ]));

        let error = collect_public_phase_from_origins(
            &state,
            &network::V0,
            &requester,
            &prepare,
            PublicPhase::RefreshHealthCheck,
            &BTreeSet::from([first, second]),
        )
        .await
        .expect_err("an authenticated malformed origin response must fail fast");
        assert!(matches!(
            error,
            PublicRepairFailure::Violation(PublicProtocolViolation {
                kind: PublicProtocolViolationKind::MalformedOriginMessage,
                accused: PublicViolationAccused::Origin(origin),
                ..
            }) if origin == first
        ));
        assert!(
            state
                .dkg_session_state
                .public_contributions(&ceremony_id.0, attempt_id, PublicPhase::RefreshHealthCheck,)
                .await
                .expect("active repair attempt")
                .is_empty(),
            "origin responses must be preflighted before any valid subset is recorded"
        );
    }

    fn fresh_commitment_bytes(origin_node_id: u32, session_id: u128) -> Vec<u8> {
        use crypto::r#trait::{Dkg as _, DkgMode, DkgRole};

        let mut sender = *crypto::DkgImpl::new(origin_node_id, 2, 3, session_id, DkgRole::Standard)
            .expect("construct fresh commitment sender");
        sender
            .generate_polynomial(DkgMode::Fresh)
            .expect("generate fresh commitment");
        crate::dkg::v0::helpers::serialize_commitment_coefficients(
            &sender.commitment().coefficients,
        )
        .expect("serialize fresh commitment")
    }

    fn verified_test_contribution(
        ceremony_id: CeremonyId,
        attempt_id: AttemptId,
        committee_digest: [u8; 32],
        origin: ParticipantRef,
        payload: DkgPublicPayload,
    ) -> VerifiedPublicContribution {
        let contribution = DkgPublicContribution::new(
            ceremony_id,
            attempt_id,
            "test-ring-post".to_string(),
            committee_digest,
            origin,
            payload,
        )
        .expect("construct test contribution");
        VerifiedPublicContribution {
            signed: SignedPayload {
                origin: vec![origin.node_id as u8; 32],
                signature: vec![origin.node_id as u8; 64],
                data: transport::encode(&contribution).expect("encode test contribution"),
            },
            contribution,
        }
    }

    #[tokio::test]
    async fn repair_payload_preflight_is_atomic_before_retention_or_crypto_mutation() {
        let first = ParticipantRef::current(2);
        let second = ParticipantRef::current(3);
        let (state, ceremony_id, attempt_id, committee_digest) = contribution_test_state(
            "repair_payload_preflight_is_atomic",
            4255,
            SessionKind::Fresh,
            Vec::new(),
            first,
        )
        .await;
        bind_test_origin_to_local_peer(&state, ceremony_id.0, second).await;
        let prepare = repair_test_prepare(ceremony_id, attempt_id, 3);

        let valid_commitment = fresh_commitment_bytes(first.node_id, ceremony_id.0);
        let mut invalid_commitment = fresh_commitment_bytes(second.node_id, ceremony_id.0);
        invalid_commitment[..crypto::GROUP_POINT_SIZE].fill(0xff);
        {
            let mut states = state.dkg_session_state.states.write().await;
            let session = states.get_mut(&ceremony_id.0).expect("repair test session");
            session.commit_reveal.received_hashes.insert(
                first.node_id,
                crate::dkg::v0::helpers::fresh_commitment_hash(
                    ceremony_id.0,
                    first.node_id,
                    &valid_commitment,
                ),
            );
            session.commit_reveal.received_hashes.insert(
                second.node_id,
                crate::dkg::v0::helpers::fresh_commitment_hash(
                    ceremony_id.0,
                    second.node_id,
                    &invalid_commitment,
                ),
            );
        }

        let valid = verified_test_contribution(
            ceremony_id,
            attempt_id,
            committee_digest,
            first,
            DkgPublicPayload::Commitment {
                commitment: valid_commitment,
                report_evidence: None,
            },
        );
        let invalid = verified_test_contribution(
            ceremony_id,
            attempt_id,
            committee_digest,
            second,
            DkgPublicPayload::Commitment {
                commitment: invalid_commitment,
                report_evidence: None,
            },
        );

        let error = apply_repair_contributions(
            &state,
            &network::V0,
            &prepare,
            PublicPhase::Commitments,
            vec![valid, invalid],
            RepairContributionSource::Origin,
        )
        .await
        .expect_err("a crypto-invalid direct-origin contribution must fail preflight");
        assert!(matches!(
            error,
            PublicRepairFailure::Violation(PublicProtocolViolation {
                kind: PublicProtocolViolationKind::InvalidContribution,
                accused: PublicViolationAccused::Origin(origin),
                ..
            }) if origin == second
        ));

        let retained = state
            .dkg_session_state
            .public_contributions(&ceremony_id.0, attempt_id, PublicPhase::Commitments)
            .await
            .expect("active repair attempt");
        assert!(
            retained.is_empty(),
            "a failed payload preflight must retain none of the repair batch"
        );
        assert_eq!(
            state
                .dkg_session_state
                .with_state(&ceremony_id.0, |session| session.commitments_received)
                .await,
            Some(0),
            "a failed payload preflight must not apply the valid batch prefix"
        );
    }

    #[tokio::test]
    async fn direct_origin_payload_is_preflighted_before_leader_relay() {
        let origin = ParticipantRef::current(2);
        let (state, ceremony_id, attempt_id, committee_digest) = contribution_test_state(
            "direct_origin_preflight_before_relay",
            4256,
            SessionKind::Fresh,
            Vec::new(),
            origin,
        )
        .await;
        let topic = Arc::new(ScriptedBroadcastTopic::new([]));
        let mut invalid_commitment = fresh_commitment_bytes(origin.node_id, ceremony_id.0);
        invalid_commitment[..crypto::GROUP_POINT_SIZE].fill(0xff);
        let signed = sign_contribution(
            &state,
            ceremony_id,
            attempt_id,
            committee_digest,
            origin,
            DkgPublicPayload::Commitment {
                commitment: invalid_commitment.clone(),
                report_evidence: None,
            },
        )
        .await;

        let first = verified_test_contribution(
            ceremony_id,
            attempt_id,
            committee_digest,
            ParticipantRef::current(1),
            DkgPublicPayload::Commitment {
                commitment: fresh_commitment_bytes(1, ceremony_id.0),
                report_evidence: None,
            },
        );
        let third = verified_test_contribution(
            ceremony_id,
            attempt_id,
            committee_digest,
            ParticipantRef::current(3),
            DkgPublicPayload::Commitment {
                commitment: fresh_commitment_bytes(3, ceremony_id.0),
                report_evidence: None,
            },
        );
        {
            let mut states = state.dkg_session_state.states.write().await;
            let session = states
                .get_mut(&ceremony_id.0)
                .expect("direct contribution test session");
            session.transport.leader_node_key = Some(state.node_key.clone());
            session.transport.topic = Some(topic.clone());
            session.transport.hard_deadline =
                Some(std::time::Instant::now() + std::time::Duration::from_secs(30));
            session.transport.public_contributions.insert(
                PublicPhase::Commitments,
                BTreeMap::from([
                    (first.contribution.origin, first.signed),
                    (third.contribution.origin, third.signed),
                ]),
            );
            session.commit_reveal.received_hashes.insert(
                origin.node_id,
                crate::dkg::v0::helpers::fresh_commitment_hash(
                    ceremony_id.0,
                    origin.node_id,
                    &invalid_commitment,
                ),
            );
        }
        let sender = state.network.local_peer_id().clone();

        let error = handle_control(
            state.clone(),
            &network::V0,
            DkgControlMessage::PublicContribution(signed),
            &sender,
        )
        .await
        .expect_err("the leader must reject a crypto-invalid direct contribution");

        assert!(matches!(error, DkgError::Deserialization(_)));
        assert_eq!(
            topic.calls.load(Ordering::SeqCst),
            0,
            "the invalid contribution must not complete and relay the phase batch"
        );
        assert_eq!(
            state
                .dkg_session_state
                .transport_attempt(&ceremony_id.0)
                .await,
            None,
            "an attributable direct-origin violation must abort the exact attempt"
        );
    }

    #[tokio::test]
    async fn malformed_leader_repair_is_attributable_but_stale_abort_is_attempt_scoped() {
        let origin = ParticipantRef::current(1);
        let (state, ceremony_id, attempt_id, _) = contribution_test_state(
            "malformed_leader_repair_is_attempt_scoped",
            4254,
            SessionKind::Refresh {
                ring_pk_hex: "test-ring".to_string(),
            },
            Vec::new(),
            origin,
        )
        .await;
        let prepare = repair_test_prepare(ceremony_id, attempt_id, 1);
        let requester = ScriptedPublicRepairRequester::new(HashMap::from([(
            "repair-route-1".to_string(),
            std::collections::VecDeque::from([Ok(DkgControlMessage::Begun {
                ceremony_id,
                attempt_id,
                activation_digest: [7; 32],
            })]),
        )]));

        let violation = match collect_public_phase_from_leader(
            &state,
            &network::V0,
            &requester,
            &prepare,
            PublicPhase::RefreshHealthCheck,
            &BTreeSet::from([origin]),
        )
        .await
        .expect_err("an authenticated unexpected leader response must be attributable")
        {
            PublicRepairFailure::Violation(violation) => violation,
            other => panic!("expected typed protocol violation, got {other:?}"),
        };
        assert_eq!(
            violation.kind,
            PublicProtocolViolationKind::MalformedLeaderMessage
        );
        assert_eq!(violation.accused, PublicViolationAccused::Leader);

        let newer_attempt = AttemptId([attempt_id.0[0].wrapping_add(1); 32]);
        {
            let mut states = state.dkg_session_state.states.write().await;
            states
                .get_mut(&ceremony_id.0)
                .expect("repair test session")
                .transport
                .attempt_id = Some(newer_attempt);
        }
        abort_public_protocol_violation(&state, &prepare, &violation, TopicTaskDisposition::Abort)
            .await;
        assert_eq!(
            state
                .dkg_session_state
                .transport_attempt(&ceremony_id.0)
                .await,
            Some(newer_attempt),
            "a stale attributable response must not remove a newer attempt"
        );
    }

    #[tokio::test]
    async fn recording_a_stale_public_contribution_is_not_equivocation() {
        let origin = ParticipantRef::current(1);
        let (state, ceremony_id, active_attempt, committee_digest) = contribution_test_state(
            "record_stale_public_contribution",
            4241,
            SessionKind::Fresh,
            Vec::new(),
            origin,
        )
        .await;
        let stale_attempt = AttemptId([active_attempt.0[0].wrapping_add(1); 32]);
        let contribution = DkgPublicContribution::new(
            ceremony_id,
            stale_attempt,
            "test-ring-post".to_string(),
            committee_digest,
            origin,
            DkgPublicPayload::CommitmentHash {
                commitment_hash: [1; 32],
            },
        )
        .unwrap();
        let signed = SignedPayload {
            origin: vec![1; 32],
            signature: vec![2; 64],
            data: vec![3; 16],
        };

        let error = record_public_contribution(&state, signed, &contribution)
            .await
            .expect_err("stale contribution must be rejected");

        assert!(
            matches!(error, DkgError::ProtocolError(ref message) if message.contains("stale attempt"))
        );
    }

    #[tokio::test]
    async fn verify_signed_contribution_rejects_reshare_commitment_from_non_dealer() {
        let origin = ParticipantRef::current(1);
        let (state, ceremony_id, attempt_id, committee_digest) = contribution_test_state(
            "verify_signed_contribution_rejects_non_dealer",
            4242,
            SessionKind::Reshare {
                ring_pk_hex: "test-ring".to_string(),
                new_peer_node_keys: vec!["node-a".to_string()],
                new_threshold: 1,
                bulletin_post_id: "test-ring-post".to_string(),
            },
            vec![ParticipantRef::current(2)], // origin (node 1) is deliberately not a dealer
            origin,
        )
        .await;

        let signed = sign_contribution(
            &state,
            ceremony_id,
            attempt_id,
            committee_digest,
            origin,
            DkgPublicPayload::Commitment {
                commitment: vec![1, 2, 3],
                report_evidence: None,
            },
        )
        .await;

        let error = verify_signed_contribution(&state, &signed)
            .await
            .expect_err(
            "a non-dealer origin must not be allowed to submit a reshare Commitments contribution",
        );
        assert!(matches!(error, DkgError::Unauthorized(_)));
    }

    #[tokio::test]
    async fn verify_signed_contribution_accepts_reshare_commitment_from_active_dealer() {
        let origin = ParticipantRef::current(1);
        let (state, ceremony_id, attempt_id, committee_digest) = contribution_test_state(
            "verify_signed_contribution_accepts_active_dealer",
            4243,
            SessionKind::Reshare {
                ring_pk_hex: "test-ring".to_string(),
                new_peer_node_keys: vec!["node-a".to_string()],
                new_threshold: 1,
                bulletin_post_id: "test-ring-post".to_string(),
            },
            vec![origin], // origin is an active dealer this time
            origin,
        )
        .await;

        let signed = sign_contribution(
            &state,
            ceremony_id,
            attempt_id,
            committee_digest,
            origin,
            DkgPublicPayload::Commitment {
                commitment: vec![1, 2, 3],
                report_evidence: None,
            },
        )
        .await;

        verify_signed_contribution(&state, &signed).await.expect(
            "an active dealer must be allowed to submit a reshare Commitments contribution",
        );
    }

    #[tokio::test]
    async fn verify_signed_contribution_rejects_foreign_ring_id() {
        let origin = ParticipantRef::current(1);
        let (state, ceremony_id, attempt_id, committee_digest) = contribution_test_state(
            "verify_signed_contribution_rejects_foreign_ring",
            4245,
            SessionKind::Fresh,
            Vec::new(),
            origin,
        )
        .await;
        let contribution = DkgPublicContribution::new(
            ceremony_id,
            attempt_id,
            "different-ring".to_string(),
            committee_digest,
            origin,
            DkgPublicPayload::CommitmentHash {
                commitment_hash: [7; 32],
            },
        )
        .unwrap();
        let signed = state
            .network
            .pubsub()
            .expect("pubsub enabled")
            .sign(
                PUBLIC_CONTRIBUTION_SIGNING_DOMAIN,
                transport::encode(&contribution).unwrap().into(),
            )
            .await
            .unwrap();

        let error = verify_signed_contribution(&state, &signed)
            .await
            .expect_err("the signed contribution must be bound to the active ring");
        assert!(matches!(error, DkgError::Unauthorized(_)));
    }

    #[tokio::test]
    async fn verify_signed_contribution_rejects_next_scope_origin_during_refresh() {
        // Refresh has no "next" committee at all — a contribution whose origin
        // claims `CommitteeScope::Next` must be rejected regardless of phase.
        let origin = ParticipantRef::next(1);
        let (state, ceremony_id, attempt_id, committee_digest) = contribution_test_state(
            "verify_signed_contribution_rejects_next_scope_refresh",
            4244,
            SessionKind::Refresh {
                ring_pk_hex: "test-ring".to_string(),
            },
            Vec::new(),
            origin,
        )
        .await;

        let signed = sign_contribution(
            &state,
            ceremony_id,
            attempt_id,
            committee_digest,
            origin,
            DkgPublicPayload::Commitment {
                commitment: vec![1, 2, 3],
                report_evidence: None,
            },
        )
        .await;

        let error = verify_signed_contribution(&state, &signed)
            .await
            .expect_err("a Next-scope origin must never be accepted during a Refresh ceremony");
        assert!(matches!(error, DkgError::Unauthorized(_)));
    }

    fn assembled_contribution(
        origin: ParticipantRef,
        message_byte: u8,
    ) -> VerifiedPublicContribution {
        let message_id = MessageId([message_byte; 32]);
        let contribution = DkgPublicContribution {
            ceremony_id: CeremonyId(900),
            attempt_id: AttemptId([9; 32]),
            ring_id: "batch-test-ring".into(),
            committee_digest: [8; 32],
            origin,
            message_id,
            payload: DkgPublicPayload::Commitment {
                commitment: vec![message_byte],
                report_evidence: None,
            },
        };
        VerifiedPublicContribution {
            signed: SignedPayload {
                origin: vec![origin.node_id as u8; 32],
                signature: vec![message_byte; 64],
                data: vec![message_byte; 8],
            },
            contribution,
        }
    }

    fn assembled_manifest(
        contributions: &[VerifiedPublicContribution],
        chunk_count: u32,
        complete: bool,
    ) -> PhaseManifest {
        let ids = contributions
            .iter()
            .map(|verified| {
                (
                    verified.contribution.origin,
                    verified.contribution.message_id,
                )
            })
            .collect();
        PhaseManifest {
            ceremony_id: CeremonyId(900),
            attempt_id: AttemptId([9; 32]),
            phase: PublicPhase::Commitments,
            phase_root: transport::phase_root(
                CeremonyId(900),
                AttemptId([9; 32]),
                PublicPhase::Commitments,
                &ids,
            ),
            contribution_ids: ids,
            chunk_count,
            complete,
        }
    }

    #[test]
    fn public_batch_waits_for_manifest_and_every_chunk() {
        let first = assembled_contribution(ParticipantRef::current(1), 1);
        let second = assembled_contribution(ParticipantRef::current(2), 2);
        let manifest = assembled_manifest(&[first.clone(), second.clone()], 2, true);
        let expected = BTreeSet::from([ParticipantRef::current(1), ParticipantRef::current(2)]);
        let mut assembler = PublicBatchAssembler::default();

        assert!(matches!(
            assembler
                .insert_chunk(
                    PublicBatchMode::Complete,
                    PublicPhase::Commitments,
                    manifest.phase_root,
                    1,
                    vec![second],
                    [2; 32],
                    expected.len(),
                )
                .unwrap(),
            PublicBatchAssembly::Pending { .. }
        ));
        assert!(matches!(
            assembler
                .insert_manifest(
                    PublicBatchMode::Complete,
                    manifest.clone(),
                    [3; 32],
                    &expected,
                )
                .unwrap(),
            PublicBatchAssembly::Pending {
                manifest_added: true
            }
        ));
        let complete = assembler
            .insert_chunk(
                PublicBatchMode::Complete,
                PublicPhase::Commitments,
                manifest.phase_root,
                0,
                vec![first],
                [1; 32],
                expected.len(),
            )
            .unwrap();
        let PublicBatchAssembly::Complete { contributions, .. } = complete else {
            panic!("batch must complete only after manifest and both chunks");
        };
        assert_eq!(
            contributions
                .iter()
                .map(|verified| verified.contribution.origin)
                .collect::<Vec<_>>(),
            vec![ParticipantRef::current(1), ParticipantRef::current(2)]
        );
    }

    #[test]
    fn manifest_repair_schedule_coalesces_without_extending_deadline() {
        let now = Instant::now();
        let first_deadline = now + DKG_REPAIR_STALL_INTERVAL;
        let later_deadline = first_deadline + DKG_REPAIR_STALL_INTERVAL;
        let mut schedule = ManifestRepairSchedule::default();

        assert!(schedule.arm(PublicPhase::Commitments, first_deadline));
        assert!(
            !schedule.arm(PublicPhase::Commitments, later_deadline),
            "another incremental root must not create work or postpone repair"
        );
        assert_eq!(schedule.next_deadline(), Some(first_deadline));
        assert!(schedule
            .take_due(first_deadline - Duration::from_nanos(1))
            .is_empty());
        assert_eq!(
            schedule.take_due(first_deadline),
            vec![PublicPhase::Commitments]
        );
        assert_eq!(schedule.next_deadline(), None);
    }

    #[test]
    fn manifest_repair_schedule_tracks_phases_independently_and_cancels_complete_phase() {
        let now = Instant::now();
        let first_deadline = now + DKG_REPAIR_STALL_INTERVAL;
        let second_deadline = first_deadline + Duration::from_secs(1);
        let mut schedule = ManifestRepairSchedule::default();

        assert!(schedule.arm(PublicPhase::Commitments, second_deadline));
        assert!(schedule.arm(PublicPhase::CommitmentHashes, first_deadline));
        assert_eq!(schedule.next_deadline(), Some(first_deadline));
        assert_eq!(
            schedule.take_due(first_deadline),
            vec![PublicPhase::CommitmentHashes]
        );
        assert_eq!(schedule.next_deadline(), Some(second_deadline));

        assert!(schedule.cancel(PublicPhase::Commitments));
        assert!(!schedule.cancel(PublicPhase::Commitments));
        assert_eq!(schedule.next_deadline(), None);
    }

    #[test]
    fn public_batch_accepts_only_identical_retransmissions() {
        let contribution = assembled_contribution(ParticipantRef::current(1), 1);
        let manifest = assembled_manifest(std::slice::from_ref(&contribution), 1, true);
        let expected = BTreeSet::from([ParticipantRef::current(1)]);
        let mut assembler = PublicBatchAssembler::default();
        assert!(matches!(
            assembler
                .insert_manifest(
                    PublicBatchMode::Complete,
                    manifest.clone(),
                    [1; 32],
                    &expected,
                )
                .unwrap(),
            PublicBatchAssembly::Pending { .. }
        ));
        assert!(matches!(
            assembler
                .insert_manifest(
                    PublicBatchMode::Complete,
                    manifest.clone(),
                    [1; 32],
                    &expected,
                )
                .unwrap(),
            PublicBatchAssembly::Duplicate
        ));
        let error = assembler
            .insert_manifest(
                PublicBatchMode::Complete,
                manifest.clone(),
                [9; 32],
                &expected,
            )
            .expect_err("a semantically equal manifest with different bytes must conflict");
        assert_eq!(error.kind, PublicProtocolViolationKind::ConflictingManifest);
        assert!(matches!(
            assembler
                .insert_chunk(
                    PublicBatchMode::Complete,
                    PublicPhase::Commitments,
                    manifest.phase_root,
                    0,
                    vec![contribution.clone()],
                    [2; 32],
                    expected.len(),
                )
                .unwrap(),
            PublicBatchAssembly::Complete { .. }
        ));
        assert!(matches!(
            assembler
                .insert_chunk(
                    PublicBatchMode::Complete,
                    PublicPhase::Commitments,
                    manifest.phase_root,
                    0,
                    vec![contribution],
                    [2; 32],
                    expected.len(),
                )
                .unwrap(),
            PublicBatchAssembly::Duplicate
        ));
        let error = assembler
            .insert_chunk(
                PublicBatchMode::Complete,
                PublicPhase::Commitments,
                manifest.phase_root,
                0,
                vec![assembled_contribution(ParticipantRef::current(1), 1)],
                [8; 32],
                expected.len(),
            )
            .expect_err("a semantically equal chunk with different bytes must conflict");
        assert_eq!(error.kind, PublicProtocolViolationKind::ConflictingChunk);
    }

    #[test]
    fn public_batch_rejects_invalid_or_conflicting_complete_roots() {
        let contribution = assembled_contribution(ParticipantRef::current(1), 1);
        let mut invalid = assembled_manifest(std::slice::from_ref(&contribution), 1, true);
        invalid.phase_root = [99; 32];
        let expected = BTreeSet::from([ParticipantRef::current(1)]);
        let mut assembler = PublicBatchAssembler::default();
        let error = assembler
            .insert_manifest(PublicBatchMode::Complete, invalid, [1; 32], &expected)
            .expect_err("an internally invalid root must fail");
        assert_eq!(error.kind, PublicProtocolViolationKind::InvalidManifest);

        let first_root = [1; 32];
        let second_root = [2; 32];
        assembler
            .insert_chunk(
                PublicBatchMode::Complete,
                PublicPhase::Commitments,
                first_root,
                0,
                vec![contribution.clone()],
                [2; 32],
                expected.len(),
            )
            .unwrap();
        let error = assembler
            .insert_chunk(
                PublicBatchMode::Complete,
                PublicPhase::Commitments,
                second_root,
                0,
                vec![assembled_contribution(ParticipantRef::current(1), 2)],
                [3; 32],
                expected.len(),
            )
            .expect_err("a complete phase cannot advertise two roots");
        assert_eq!(error.kind, PublicProtocolViolationKind::ConflictingManifest);
    }

    #[test]
    fn public_batch_rejects_conflicting_chunks_and_noncanonical_contents() {
        let first = assembled_contribution(ParticipantRef::current(1), 1);
        let second = assembled_contribution(ParticipantRef::current(2), 2);
        let manifest = assembled_manifest(&[first.clone(), second.clone()], 1, true);
        let expected = BTreeSet::from([ParticipantRef::current(1), ParticipantRef::current(2)]);
        let mut assembler = PublicBatchAssembler::default();
        assembler
            .insert_manifest(
                PublicBatchMode::Complete,
                manifest.clone(),
                [1; 32],
                &expected,
            )
            .unwrap();
        let error = assembler
            .insert_chunk(
                PublicBatchMode::Complete,
                PublicPhase::Commitments,
                manifest.phase_root,
                0,
                vec![second, first],
                [2; 32],
                expected.len(),
            )
            .expect_err("manifest contents must retain canonical origin order");
        assert_eq!(error.kind, PublicProtocolViolationKind::BatchMismatch);

        let contribution = assembled_contribution(ParticipantRef::current(1), 3);
        let mut assembler = PublicBatchAssembler::default();
        assembler
            .insert_chunk(
                PublicBatchMode::Complete,
                PublicPhase::Commitments,
                [3; 32],
                0,
                vec![contribution.clone()],
                [3; 32],
                2,
            )
            .unwrap();
        let error = assembler
            .insert_chunk(
                PublicBatchMode::Complete,
                PublicPhase::Commitments,
                [3; 32],
                0,
                vec![assembled_contribution(ParticipantRef::current(2), 4)],
                [4; 32],
                2,
            )
            .expect_err("the same chunk index cannot change contents");
        assert_eq!(error.kind, PublicProtocolViolationKind::ConflictingChunk);
    }

    #[test]
    fn incremental_batches_allow_multiple_roots_but_reject_origin_equivocation() {
        let first = assembled_contribution(ParticipantRef::current(1), 1);
        let second = assembled_contribution(ParticipantRef::current(2), 2);
        let first_manifest = assembled_manifest(std::slice::from_ref(&first), 1, false);
        let second_manifest = assembled_manifest(std::slice::from_ref(&second), 1, false);
        let expected = BTreeSet::from([ParticipantRef::current(1), ParticipantRef::current(2)]);
        let mut assembler = PublicBatchAssembler::default();
        for (manifest, contribution) in [(first_manifest, first.clone()), (second_manifest, second)]
        {
            assembler
                .insert_manifest(
                    PublicBatchMode::Incremental,
                    manifest.clone(),
                    [contribution.contribution.origin.node_id as u8; 32],
                    &expected,
                )
                .unwrap();
            assert!(matches!(
                assembler
                    .insert_chunk(
                        PublicBatchMode::Incremental,
                        PublicPhase::Commitments,
                        manifest.phase_root,
                        0,
                        vec![contribution],
                        [manifest.contribution_ids.len() as u8; 32],
                        expected.len(),
                    )
                    .unwrap(),
                PublicBatchAssembly::Complete { .. }
            ));
        }

        let error = assembler
            .insert_chunk(
                PublicBatchMode::Incremental,
                PublicPhase::Commitments,
                [7; 32],
                0,
                vec![assembled_contribution(ParticipantRef::current(1), 9)],
                [9; 32],
                expected.len(),
            )
            .expect_err("one origin cannot sign two messages for a public phase");
        assert_eq!(error.kind, PublicProtocolViolationKind::OriginEquivocation);
        assert_eq!(
            error.accused,
            PublicViolationAccused::Origin(ParticipantRef::current(1))
        );
    }

    #[test]
    fn incremental_batch_buffers_are_origin_bounded() {
        let first = assembled_contribution(ParticipantRef::current(1), 1);
        let second = assembled_contribution(ParticipantRef::current(2), 2);
        let expected = BTreeSet::from([ParticipantRef::current(1), ParticipantRef::current(2)]);
        let mut assembler = PublicBatchAssembler::default();

        assembler
            .insert_chunk(
                PublicBatchMode::Incremental,
                PublicPhase::Commitments,
                [1; 32],
                0,
                vec![first.clone()],
                [1; 32],
                expected.len(),
            )
            .unwrap();
        let error = assembler
            .insert_chunk(
                PublicBatchMode::Incremental,
                PublicPhase::Commitments,
                [2; 32],
                0,
                vec![first],
                [2; 32],
                expected.len(),
            )
            .expect_err("a leader cannot retain one contribution under multiple roots");
        assert_eq!(error.kind, PublicProtocolViolationKind::BatchMismatch);

        let mut assembler = PublicBatchAssembler::default();
        let first = assembled_contribution(ParticipantRef::current(1), 1);
        let one_origin = assembled_manifest(std::slice::from_ref(&first), 1, false);
        let overlapping = assembled_manifest(&[first, second], 1, false);
        assembler
            .insert_manifest(PublicBatchMode::Incremental, one_origin, [3; 32], &expected)
            .unwrap();
        let error = assembler
            .insert_manifest(
                PublicBatchMode::Incremental,
                overlapping,
                [4; 32],
                &expected,
            )
            .expect_err("pending manifest entries must remain committee-bounded");
        assert_eq!(error.kind, PublicProtocolViolationKind::BufferLimit);
    }

    fn retained_repair_contribution(node_id: u8, data_len: usize) -> SignedPayload {
        SignedPayload {
            origin: vec![node_id; 32],
            signature: vec![node_id; 64],
            data: vec![255; data_len],
        }
    }

    #[test]
    fn public_phase_repair_pages_are_bounded_complete_and_canonical() {
        let retained: BTreeMap<_, _> = (1u8..=MAX_DKG_COMMITTEE_SIZE as u8)
            .rev()
            .map(|node_id| {
                (
                    ParticipantRef::current(node_id as u32),
                    retained_repair_contribution(node_id, 30_000),
                )
            })
            .collect();
        let ceremony_id = CeremonyId(777);
        let attempt_id = AttemptId([8; 32]);
        let mut after = None;
        let mut received = Vec::new();
        let mut page_count = 0;

        loop {
            let response = public_phase_response_page(
                ceremony_id,
                attempt_id,
                PublicPhase::Commitments,
                &retained,
                after,
            )
            .unwrap();
            assert!(transport::encode(&response).unwrap().len() <= MAX_PUBLIC_REPAIR_PAGE_BYTES);
            let DkgControlMessage::PublicPhaseResponse {
                contributions,
                next_cursor,
                ..
            } = response
            else {
                panic!("repair helper returned the wrong response type");
            };
            page_count += 1;
            received.extend(contributions.into_iter().map(|signed| signed.origin[0]));
            let Some(cursor) = next_cursor else {
                break;
            };
            assert!(after.is_none_or(|previous| cursor > previous));
            after = Some(cursor);
        }

        assert!(page_count > 1);
        assert!(page_count <= MAX_DKG_COMMITTEE_SIZE);
        assert_eq!(
            received,
            (1u8..=MAX_DKG_COMMITTEE_SIZE as u8).collect::<Vec<_>>()
        );

        let terminal = public_phase_response_page(
            ceremony_id,
            attempt_id,
            PublicPhase::Commitments,
            &retained,
            Some(ParticipantRef::current(MAX_DKG_COMMITTEE_SIZE as u32)),
        )
        .unwrap();
        assert!(matches!(
            terminal,
            DkgControlMessage::PublicPhaseResponse {
                contributions,
                next_cursor: None,
                ..
            } if contributions.is_empty()
        ));
    }

    #[test]
    fn public_phase_repair_rejects_one_oversized_contribution() {
        let retained = BTreeMap::from([(
            ParticipantRef::current(1),
            retained_repair_contribution(1, MAX_PUBLIC_REPAIR_PAGE_BYTES / 2),
        )]);
        let error = public_phase_response_page(
            CeremonyId(778),
            AttemptId([9; 32]),
            PublicPhase::Commitments,
            &retained,
            None,
        )
        .expect_err("one contribution cannot exceed the repair page limit");
        assert!(matches!(error, DkgError::ProtocolError(_)));
    }

    #[test]
    fn public_repair_page_progress_rejects_cursor_and_origin_contradictions() {
        let empty = BTreeSet::new();
        assert!(validate_public_repair_page_progress(
            Some(ParticipantRef::current(1)),
            &[ParticipantRef::current(2), ParticipantRef::current(3)],
            Some(ParticipantRef::current(3)),
            &empty,
        )
        .is_ok());
        assert!(validate_public_repair_page_progress(
            None,
            &[],
            Some(ParticipantRef::current(1)),
            &empty,
        )
        .is_err());
        assert!(validate_public_repair_page_progress(
            Some(ParticipantRef::current(2)),
            &[ParticipantRef::current(2)],
            None,
            &empty,
        )
        .is_err());
        assert!(validate_public_repair_page_progress(
            None,
            &[ParticipantRef::current(2), ParticipantRef::current(1)],
            None,
            &empty,
        )
        .is_err());
        assert!(validate_public_repair_page_progress(
            None,
            &[ParticipantRef::current(1), ParticipantRef::current(2)],
            Some(ParticipantRef::current(1)),
            &empty,
        )
        .is_err());
        assert!(validate_public_repair_page_progress(
            Some(ParticipantRef::current(1)),
            &[ParticipantRef::current(2)],
            None,
            &BTreeSet::from([ParticipantRef::current(2)]),
        )
        .is_err());
    }
}
