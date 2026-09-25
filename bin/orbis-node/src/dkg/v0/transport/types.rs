//! Wire types: ceremony/attempt identity, committee config, and the three
//! DKG message enums (public, control, private).

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};

use super::digest::{
    canonical_leader, ceremony_committee_digest, derive_message_id, encode, phase_root,
};
use crate::constants::MAX_DKG_COMMITTEE_SIZE;
use crate::dkg::v0::messages::{
    ControlSignature, SessionKind, SignedDkgCommitment, SignedDkgShare,
};
use crate::sign::v0::messages::RefreshHealthCheckStatement;

pub const PUBLIC_CONTRIBUTION_SIGNING_DOMAIN: &[u8] = b"orbis-dkg-public-contribution-v1";
pub const MAX_PUBLIC_CHUNK_BYTES: usize = 256 * 1024;
pub const MAX_PUBLIC_ORIGIN_EVIDENCE_BYTES: usize = 2 * 1024 * 1024;
/// Keep repair pages comfortably below Iroh's current 1 MiB message ceiling.
/// `pub` (not `network.rs`-local) so the reporting registry can
/// independently re-derive whether a signed repair page genuinely exceeds
/// this bound.
pub const MAX_PUBLIC_REPAIR_PAGE_BYTES: usize = 512 * 1024;

/// Stable logical ceremony identity. Existing session IDs remain its source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CeremonyId(pub u128);

/// Unique identity for one actual attempt of a logical ceremony.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AttemptId(pub [u8; 32]);

/// Internal identity for one concrete execution of a deterministic ceremony.
///
/// `CeremonyId` is intentionally reusable across retries, so active protocol
/// work must carry both fields whenever it reads, mutates, or removes session
/// state. This type is not serialized on the wire; messages continue to encode
/// the two existing fields independently.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct AttemptKey {
    pub ceremony_id: CeremonyId,
    pub attempt_id: AttemptId,
}

impl AttemptKey {
    pub(crate) const fn new(ceremony_id: CeremonyId, attempt_id: AttemptId) -> Self {
        Self {
            ceremony_id,
            attempt_id,
        }
    }

    pub(crate) const fn session_id(self) -> u128 {
        self.ceremony_id.0
    }

    #[cfg(test)]
    pub(crate) const fn test(session_id: u128) -> Self {
        Self::new(CeremonyId(session_id), AttemptId([0xA5; 32]))
    }
}

impl AttemptId {
    pub fn random() -> Self {
        Self(rand::random())
    }
}

/// Content-bound identifier used for idempotency and acknowledgements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct MessageId(pub [u8; 32]);

/// Bounded attribution label for a peer-specific PSS transport failure.
///
/// These values are deliberately coarse: they are safe to put on the wire and
/// use as metric labels, while raw transport errors remain local log data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PssOfflineStage {
    StartForward,
    Prepare,
    TopologyProbe,
    TopologyAck,
    Activate,
    Begin,
    PublicContribution,
    RefreshResultStage,
    RefreshResultCommit,
    PublicRepairLeader,
    PublicRepairOrigin,
    ReshareShareAck,
    PrivatePair,
    PrivateInbound,
}

impl PssOfflineStage {
    pub const fn as_metric_label(self) -> &'static str {
        match self {
            Self::StartForward => "start_forward",
            Self::Prepare => "prepare",
            Self::TopologyProbe => "topology_probe",
            Self::TopologyAck => "topology_ack",
            Self::Activate => "activate",
            Self::Begin => "begin",
            Self::PublicContribution => "public_contribution",
            Self::RefreshResultStage => "refresh_result_stage",
            Self::RefreshResultCommit => "refresh_result_commit",
            Self::PublicRepairLeader => "public_repair_leader",
            Self::PublicRepairOrigin => "public_repair_origin",
            Self::ReshareShareAck => "reshare_share_ack",
            Self::PrivatePair => "private_pair",
            Self::PrivateInbound => "private_inbound",
        }
    }

    /// Stages observed only by the attempt's canonical leader.
    pub const fn requires_canonical_leader(self) -> bool {
        matches!(
            self,
            Self::Prepare
                | Self::TopologyProbe
                | Self::Activate
                | Self::Begin
                | Self::RefreshResultStage
                | Self::RefreshResultCommit
        )
    }
}

/// Identifies which side of a committee transition owns a numeric node ID.
/// Numeric IDs are only unique inside one scope during reshare.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitteeScope {
    Current,
    Next,
}

/// Wire status value for `GetSessionStatus`/`SessionStatusResponse`. Deliberately independent
/// of `session_state::DkgFailureStage`/`DkgPhase` — this module cannot depend on
/// `session_state` (the dependency runs the other way), and this is a coarser, purely
/// client-facing status than either of those internal types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DkgSessionStatusValue {
    InProgress,
    Completed,
    Failed,
    NotFound,
}

/// Attempt-scoped participant identity used by message IDs and deduplication.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ParticipantRef {
    pub scope: CommitteeScope,
    pub node_id: u32,
}

impl ParticipantRef {
    pub const fn current(node_id: u32) -> Self {
        Self {
            scope: CommitteeScope::Current,
            node_id,
        }
    }

    pub const fn next(node_id: u32) -> Self {
        Self {
            scope: CommitteeScope::Next,
            node_id,
        }
    }
}

impl Serialize for ParticipantRef {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let scope = match self.scope {
            CommitteeScope::Current => "current",
            CommitteeScope::Next => "next",
        };
        serializer.serialize_str(&format!("{scope}:{}", self.node_id))
    }
}

impl<'de> Deserialize<'de> for ParticipantRef {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        let (scope, node_id) = encoded
            .split_once(':')
            .ok_or_else(|| serde::de::Error::custom("participant must be '<scope>:<node_id>'"))?;
        let scope = match scope {
            "current" => CommitteeScope::Current,
            "next" => CommitteeScope::Next,
            _ => {
                return Err(serde::de::Error::custom(format!(
                    "unknown participant scope '{scope}'"
                )))
            }
        };
        let node_id = node_id
            .parse::<u32>()
            .map_err(|_| serde::de::Error::custom("participant node ID is not a u32"))?;
        if node_id == 0 {
            return Err(serde::de::Error::custom(
                "participant node ID must be greater than zero",
            ));
        }
        Ok(Self { scope, node_id })
    }
}

/// One committee's authenticated routes and canonical node-ID assignments.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CommitteeConfig {
    pub node_keys: Vec<String>,
    pub peer_routes: Vec<String>,
    pub node_id_assignments: HashMap<String, u32>,
    pub threshold: u32,
}

impl CommitteeConfig {
    pub fn len(&self) -> usize {
        self.node_keys.len()
    }

    #[allow(dead_code)] // API symmetry with `len` (clippy::len_without_is_empty); no caller yet.
    pub fn is_empty(&self) -> bool {
        self.node_keys.is_empty()
    }

    pub fn participant(&self, scope: CommitteeScope, node_key: &str) -> Option<ParticipantRef> {
        self.node_id_assignments
            .get(node_key)
            .copied()
            .map(|node_id| ParticipantRef { scope, node_id })
    }

    pub fn validate(&self, label: &str) -> Result<(), String> {
        if self.node_keys.is_empty() {
            return Err(format!("{label} committee is empty"));
        }
        if self.node_keys.len() > MAX_DKG_COMMITTEE_SIZE {
            return Err(format!(
                "{label} committee has {} members, maximum is {MAX_DKG_COMMITTEE_SIZE}",
                self.node_keys.len()
            ));
        }
        if self.node_keys.len() != self.peer_routes.len()
            || self.node_keys.len() != self.node_id_assignments.len()
        {
            return Err(format!(
                "{label} committee keys, routes, and assignments have different lengths"
            ));
        }
        if self.threshold == 0 || self.threshold as usize > self.node_keys.len() {
            return Err(format!("{label} committee threshold is outside 1..=size"));
        }
        let expected: BTreeSet<u32> = (1..=self.node_keys.len() as u32).collect();
        let actual: BTreeSet<u32> = self.node_id_assignments.values().copied().collect();
        if expected != actual
            || self
                .node_keys
                .iter()
                .any(|key| !self.node_id_assignments.contains_key(key))
        {
            return Err(format!(
                "{label} committee node-ID assignments are not canonical and complete"
            ));
        }
        Ok(())
    }
}

/// Base ceremony configuration. Reshare carries both committees; fresh and
/// refresh carry only `current`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CeremonyConfig {
    pub current: CommitteeConfig,
    pub next: Option<CommitteeConfig>,
}

impl CeremonyConfig {
    pub fn validate(&self) -> Result<(), String> {
        self.current.validate("current")?;
        if let Some(next) = &self.next {
            next.validate("next")?;
        }
        Ok(())
    }

    /// Deduplicated union keyed by canonical node key. A key present in both
    /// committees has one transport route and may carry two scoped identities.
    pub fn union_routes(&self) -> BTreeMap<String, String> {
        let mut union = BTreeMap::new();
        for (key, route) in self.current.node_keys.iter().zip(&self.current.peer_routes) {
            union.insert(key.clone(), route.clone());
        }
        if let Some(next) = &self.next {
            for (key, route) in next.node_keys.iter().zip(&next.peer_routes) {
                union.entry(key.clone()).or_insert_with(|| route.clone());
            }
        }
        union
    }

    pub fn committee(&self, scope: CommitteeScope) -> Option<&CommitteeConfig> {
        match scope {
            CommitteeScope::Current => Some(&self.current),
            CommitteeScope::Next => self.next.as_ref(),
        }
    }

    pub fn node_key(&self, participant: ParticipantRef) -> Option<&str> {
        let committee = self.committee(participant.scope)?;
        committee
            .node_id_assignments
            .iter()
            .find_map(|(key, node_id)| (*node_id == participant.node_id).then_some(key.as_str()))
    }

    pub fn route(&self, participant: ParticipantRef) -> Option<&str> {
        let committee = self.committee(participant.scope)?;
        let key = self.node_key(participant)?;
        committee
            .node_keys
            .iter()
            .position(|candidate| candidate == key)
            .and_then(|index| committee.peer_routes.get(index))
            .map(String::as_str)
    }

    pub fn canonical_pair_opener(
        &self,
        first: ParticipantRef,
        second: ParticipantRef,
    ) -> Option<ParticipantRef> {
        let first_key = self.node_key(first)?;
        let second_key = self.node_key(second)?;
        match first_key.cmp(second_key) {
            std::cmp::Ordering::Less => Some(first),
            std::cmp::Ordering::Greater => Some(second),
            std::cmp::Ordering::Equal => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicPhase {
    CommitmentHashes,
    Commitments,
    CommitmentAudit,
    RefreshHealthCheck,
    ReshareParticipantSet,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DkgPublicPayload {
    CommitmentHash {
        commitment_hash: [u8; 32],
    },
    Commitment {
        commitment: Vec<u8>,
        report_evidence: Option<Box<SignedDkgCommitment>>,
    },
    CommitmentAudit {
        revealed: Vec<SignedDkgCommitment>,
    },
    RefreshHealthCheckResult {
        statement: RefreshHealthCheckStatement,
        signature: Option<String>,
    },
    ReshareParticipantSet {
        selected_dealers: Vec<ParticipantRef>,
    },
}

impl DkgPublicPayload {
    pub fn phase(&self) -> PublicPhase {
        match self {
            Self::CommitmentHash { .. } => PublicPhase::CommitmentHashes,
            Self::Commitment { .. } => PublicPhase::Commitments,
            Self::CommitmentAudit { .. } => PublicPhase::CommitmentAudit,
            Self::RefreshHealthCheckResult { .. } => PublicPhase::RefreshHealthCheck,
            Self::ReshareParticipantSet { .. } => PublicPhase::ReshareParticipantSet,
        }
    }
}

impl PublicPhase {
    pub fn as_metric_label(self) -> &'static str {
        match self {
            Self::CommitmentHashes => "commitment_hashes",
            Self::Commitments => "commitments",
            Self::CommitmentAudit => "commitment_audit",
            Self::RefreshHealthCheck => "refresh_health_check",
            Self::ReshareParticipantSet => "reshare_participant_set",
        }
    }
}

/// Contribution signed by its originating Iroh endpoint before it is relayed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DkgPublicContribution {
    pub ceremony_id: CeremonyId,
    pub attempt_id: AttemptId,
    pub ring_id: String,
    pub committee_digest: [u8; 32],
    pub origin: ParticipantRef,
    /// Unix timestamp covered by the endpoint signature. Public-origin fault
    /// reports pin their validity window to this value so one signed bad
    /// contribution cannot be re-reported after chain deduplication expires.
    pub signed_at: u64,
    pub message_id: MessageId,
    pub payload: DkgPublicPayload,
}

impl DkgPublicContribution {
    pub fn new(
        ceremony_id: CeremonyId,
        attempt_id: AttemptId,
        ring_id: String,
        committee_digest: [u8; 32],
        origin: ParticipantRef,
        payload: DkgPublicPayload,
    ) -> Result<Self, String> {
        let signed_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|error| format!("failed to get public contribution timestamp: {error}"))?
            .as_secs();
        Self::new_at(
            ceremony_id,
            attempt_id,
            ring_id,
            committee_digest,
            origin,
            signed_at,
            payload,
        )
    }

    pub fn new_at(
        ceremony_id: CeremonyId,
        attempt_id: AttemptId,
        ring_id: String,
        committee_digest: [u8; 32],
        origin: ParticipantRef,
        signed_at: u64,
        payload: DkgPublicPayload,
    ) -> Result<Self, String> {
        let message_id = derive_message_id(
            ceremony_id,
            attempt_id,
            payload.phase(),
            origin,
            None,
            &(signed_at, &payload),
        )?;
        Ok(Self {
            ceremony_id,
            attempt_id,
            ring_id,
            committee_digest,
            origin,
            signed_at,
            message_id,
            payload,
        })
    }

    pub fn validate_message_id(&self) -> Result<(), String> {
        let expected = derive_message_id(
            self.ceremony_id,
            self.attempt_id,
            self.payload.phase(),
            self.origin,
            None,
            &(self.signed_at, &self.payload),
        )?;
        if expected != self.message_id {
            return Err("public contribution message_id does not match its payload".to_string());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PhaseManifest {
    pub ceremony_id: CeremonyId,
    pub attempt_id: AttemptId,
    pub phase: PublicPhase,
    pub phase_root: [u8; 32],
    pub contribution_ids: BTreeMap<ParticipantRef, MessageId>,
    pub chunk_count: u32,
    /// Complete phases name every expected origin. Incremental reshare batches
    /// name a non-empty subset and are independently rooted.
    pub complete: bool,
    /// When the leader constructed this manifest. A self-reported claim, but
    /// authenticated for free by the enclosing Gossip delivery signature
    /// (`AuthenticatedMessage.signature`) — the same signature `dkg_leader_
    /// equivocation`/`dkg_leader_batch_mismatch`/`dkg_leader_public_fault`
    /// evidence already relies on. Lets fault evidence anchor to when the
    /// leader actually broadcast this, instead of report-construction time.
    pub signed_at: u64,
}

impl PhaseManifest {
    /// Validate that a leader manifest names exactly the expected origins and
    /// commits to their canonical message-id ordering.
    pub fn validate(&self, expected_origins: &BTreeSet<ParticipantRef>) -> Result<(), String> {
        let actual_origins: BTreeSet<_> = self.contribution_ids.keys().copied().collect();
        if (self.complete && &actual_origins != expected_origins)
            || (!self.complete
                && (actual_origins.is_empty() || !actual_origins.is_subset(expected_origins)))
        {
            return Err(format!(
                "public phase manifest origins do not match committee: expected {expected_origins:?}, got {actual_origins:?}"
            ));
        }
        if self.chunk_count == 0 {
            return Err("public phase manifest has no chunks".to_string());
        }
        if self.chunk_count as usize > self.contribution_ids.len() {
            return Err(format!(
                "public phase manifest has {} chunks for only {} contributions",
                self.chunk_count,
                self.contribution_ids.len()
            ));
        }
        let expected_root = phase_root(
            self.ceremony_id,
            self.attempt_id,
            self.phase,
            &self.contribution_ids,
        );
        if self.phase_root != expected_root {
            return Err("public phase manifest has an invalid canonical phase root".to_string());
        }
        Ok(())
    }
}

/// Public topic messages. The payload type excludes all secret-bearing variants.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DkgPublicMessage {
    TopologyProbe {
        ceremony_id: CeremonyId,
        attempt_id: AttemptId,
        nonce: [u8; 32],
    },
    Manifest(PhaseManifest),
    Chunk {
        ceremony_id: CeremonyId,
        attempt_id: AttemptId,
        phase: PublicPhase,
        phase_root: [u8; 32],
        index: u32,
        contributions: Vec<network::SignedPayload>,
        /// See `PhaseManifest::signed_at` — same meaning, same authentication
        /// (the enclosing Gossip delivery signature), set once per batch and
        /// shared by the manifest and every one of its chunks.
        signed_at: u64,
    },
}

/// Split a canonical origin-keyed contribution set into public Gossip chunks,
/// enforcing the byte cap against the exact serialized envelope rather than a
/// raw-payload estimate. This matters for JSON's byte-array expansion.
pub fn chunk_public_contributions(
    ceremony_id: CeremonyId,
    attempt_id: AttemptId,
    phase: PublicPhase,
    phase_root: [u8; 32],
    contributions: BTreeMap<ParticipantRef, network::SignedPayload>,
    signed_at: u64,
) -> Result<Vec<DkgPublicMessage>, String> {
    chunk_public_contributions_with_limit(
        ceremony_id,
        attempt_id,
        phase,
        phase_root,
        contributions,
        signed_at,
        MAX_PUBLIC_CHUNK_BYTES,
    )
}

pub(super) fn chunk_public_contributions_with_limit(
    ceremony_id: CeremonyId,
    attempt_id: AttemptId,
    phase: PublicPhase,
    phase_root: [u8; 32],
    contributions: BTreeMap<ParticipantRef, network::SignedPayload>,
    signed_at: u64,
    max_bytes: usize,
) -> Result<Vec<DkgPublicMessage>, String> {
    let mut chunks: Vec<Vec<network::SignedPayload>> = Vec::new();
    let mut current = Vec::new();

    for contribution in contributions.into_values() {
        current.push(contribution);
        let candidate = DkgPublicMessage::Chunk {
            ceremony_id,
            attempt_id,
            phase,
            phase_root,
            index: chunks.len() as u32,
            contributions: current.clone(),
            signed_at,
        };
        if encode(&candidate)?.len() <= max_bytes {
            continue;
        }

        let last = current
            .pop()
            .expect("the contribution pushed immediately above is present");
        if current.is_empty() {
            return Err(format!(
                "one signed public contribution exceeds the {max_bytes}-byte chunk limit"
            ));
        }
        chunks.push(std::mem::take(&mut current));
        current.push(last);

        let next = DkgPublicMessage::Chunk {
            ceremony_id,
            attempt_id,
            phase,
            phase_root,
            index: chunks.len() as u32,
            contributions: current.clone(),
            signed_at,
        };
        if encode(&next)?.len() > max_bytes {
            return Err(format!(
                "one signed public contribution exceeds the {max_bytes}-byte chunk limit"
            ));
        }
    }
    if !current.is_empty() {
        chunks.push(current);
    }

    chunks
        .into_iter()
        .enumerate()
        .map(|(index, contributions)| {
            Ok(DkgPublicMessage::Chunk {
                ceremony_id,
                attempt_id,
                phase,
                phase_root,
                index: index as u32,
                signed_at,
                contributions,
            })
        })
        .collect()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PrepareSession {
    pub ceremony_id: CeremonyId,
    pub attempt_id: AttemptId,
    pub config_digest: [u8; 32],
    pub topic_id: [u8; 32],
    pub leader_node_key: String,
    pub committees: CeremonyConfig,
    pub kind: SessionKind,
    pub pss_interval: u64,
    pub policy_id: Option<String>,
    pub ring_id: String,
    /// Node-key signature over `config_digest`, binding the sender to this
    /// exact committee/config claim so a noncanonical-leader impersonation
    /// attempt or a route/digest claim contradicting Vera stays
    /// provable after the fact. Every real construction site always signs
    /// (Fresh DKG included — it's the target of a `leader_prepare_fault`
    /// report the same as Refresh/Reshare); `Option` exists only because
    /// nothing at the protocol layer requires it to be `Some` — a sender
    /// could send `None` or a garbage signature and the message is still
    /// accepted and processed normally (`verify_control_signature` is only
    /// ever called from the fault-*reporting* path, never from message
    /// acceptance). This is a deliberate, accepted tradeoff, not an
    /// oversight — see `reporting/README.md`'s `ControlSignature`
    /// attribution-evasion note for the reasoning.
    pub report_signature: Option<ControlSignature>,
}

impl PrepareSession {
    pub fn participant_routes(&self) -> Vec<String> {
        self.committees.union_routes().into_values().collect()
    }

    pub fn leader_route(&self) -> Option<&str> {
        let committee = self.leader_committee()?;
        committee
            .node_keys
            .iter()
            .position(|key| key == &self.leader_node_key)
            .and_then(|index| committee.peer_routes.get(index))
            .map(String::as_str)
    }

    pub fn leader_committee(&self) -> Option<&CommitteeConfig> {
        match self.kind {
            SessionKind::Reshare { .. } => self.committees.next.as_ref(),
            SessionKind::Fresh | SessionKind::FreshPet { .. } | SessionKind::Refresh { .. } => {
                Some(&self.committees.current)
            }
        }
    }

    pub fn canonical_leader_node_key(&self) -> Option<&str> {
        canonical_leader(&self.leader_committee()?.node_keys)
    }

    pub fn current_participant(&self, node_key: &str) -> Option<ParticipantRef> {
        self.committees
            .current
            .participant(CommitteeScope::Current, node_key)
    }

    pub fn committee_digest(&self) -> [u8; 32] {
        ceremony_committee_digest(
            &self.committees.current.node_keys,
            self.committees
                .next
                .as_ref()
                .map(|next| next.node_keys.as_slice()),
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DkgControlMessage {
    StartFresh {
        ring_id: String,
    },
    /// Internally triggered by this node's own coordinator once its main-key
    /// `Fresh` ceremony completes locally on a `requires_pet` ring — never an
    /// external API request like `StartFresh`. Forwarded to the canonical
    /// leader exactly like `StartFresh` (the leader for a ring's committee is
    /// the same for both ceremonies, since it's a pure function of
    /// `peer_node_keys`).
    StartFreshPet {
        ring_id: String,
    },
    StartAccepted {
        ceremony_id: CeremonyId,
        attempt_id: AttemptId,
    },
    /// Fresh-DKG-only. Forwarded to the canonical leader exactly like `StartFresh`, since only
    /// the leader ever observes a barrier-phase failure (followers just sit "prepared" waiting
    /// for the next control message) and only the leader writes/reads the failure record.
    GetSessionStatus {
        ring_id: String,
    },
    SessionStatusResponse {
        session_id: Option<u128>,
        status: DkgSessionStatusValue,
        /// Empty unless `status == Failed`. One of "preparing" |
        /// "commitment_hashes" | "commitments" | "share_exchange" | "unknown".
        stage: String,
        missing: Vec<(u32, String)>,
        reason: String,
        /// Unix seconds; `None` unless `status == Failed`.
        failed_at: Option<i64>,
    },
    StartReshare {
        ring_id: String,
        expected_ring_pk: String,
    },
    ReshareStartAccepted {
        ceremony_id: CeremonyId,
        attempt_id: AttemptId,
    },
    /// Ask the canonical current-committee leader to coordinate a due refresh.
    /// The requester key lets the receiver authenticate only the sender's
    /// Vera route instead of resolving the entire committee.
    StartRefresh {
        ring_id: String,
        expected_ring_pk: String,
        requester_node_key: String,
    },
    RefreshStartAccepted {
        ceremony_id: CeremonyId,
        attempt_id: AttemptId,
    },
    /// The receiver independently re-checked and refresh is no longer due
    /// (e.g. another attempt already completed). Distinct from an error so
    /// the caller stops retrying the canonical leader cleanly.
    RefreshNotDue,
    Prepare(Box<PrepareSession>),
    Prepared {
        ceremony_id: CeremonyId,
        attempt_id: AttemptId,
        config_digest: [u8; 32],
        /// Node-key signature over (ceremony_id, attempt_id, "prepared",
        /// config_digest) — see `ControlSignature`.
        report_signature: Option<ControlSignature>,
    },
    TopologyProbeAck {
        ceremony_id: CeremonyId,
        attempt_id: AttemptId,
        nonce: [u8; 32],
    },
    Activate {
        ceremony_id: CeremonyId,
        attempt_id: AttemptId,
        activation_digest: [u8; 32],
        active_dealers: Vec<ParticipantRef>,
        /// Node-key signature over (ceremony_id, attempt_id, "activate",
        /// activation_digest) — see `ControlSignature`.
        report_signature: Option<ControlSignature>,
    },
    Activated {
        ceremony_id: CeremonyId,
        attempt_id: AttemptId,
        activation_digest: [u8; 32],
        /// Node-key signature over (ceremony_id, attempt_id, "activated",
        /// activation_digest) — see `ControlSignature`.
        report_signature: Option<ControlSignature>,
    },
    Begin {
        ceremony_id: CeremonyId,
        attempt_id: AttemptId,
        activation_digest: [u8; 32],
        /// Node-key signature over (ceremony_id, attempt_id, "begin",
        /// activation_digest) — see `ControlSignature`.
        report_signature: Option<ControlSignature>,
    },
    Begun {
        ceremony_id: CeremonyId,
        attempt_id: AttemptId,
        activation_digest: [u8; 32],
        /// Node-key signature over (ceremony_id, attempt_id, "begun",
        /// activation_digest) — see `ControlSignature`.
        report_signature: Option<ControlSignature>,
    },
    Abort {
        ceremony_id: CeremonyId,
        attempt_id: AttemptId,
        reason: String,
    },
    PublicContribution(network::SignedPayload),
    PublicContributionAck {
        ceremony_id: CeremonyId,
        attempt_id: AttemptId,
        message_id: MessageId,
    },
    /// Retain the leader's exact signed refresh result before it is announced
    /// on Gossip. This is the direct-repair half of the public-plane delivery
    /// barrier; it deliberately does not promote the staged share.
    StageRefreshResult(network::SignedPayload),
    /// Apply a previously staged refresh result. The receiver records a short
    /// lived receipt so a lost response can be acknowledged idempotently after
    /// the DKG session itself has been removed.
    CommitRefreshResult {
        ceremony_id: CeremonyId,
        attempt_id: AttemptId,
        message_id: MessageId,
    },
    ReshareShareAck {
        ceremony_id: CeremonyId,
        attempt_id: AttemptId,
        idempotency_key: MessageId,
        receiver: ParticipantRef,
        dealer: ParticipantRef,
    },
    ReshareShareAcked {
        ceremony_id: CeremonyId,
        attempt_id: AttemptId,
        idempotency_key: MessageId,
    },
    RelayInvalidShareEvidence {
        ceremony_id: CeremonyId,
        attempt_id: AttemptId,
        idempotency_key: MessageId,
        evidence: SignedDkgShare,
    },
    RelayInvalidCommitmentEvidence {
        ceremony_id: CeremonyId,
        attempt_id: AttemptId,
        idempotency_key: MessageId,
        commitment_a: SignedDkgCommitment,
        commitment_b: SignedDkgCommitment,
    },
    RelayPublicOriginFaultEvidence {
        ceremony_id: CeremonyId,
        attempt_id: AttemptId,
        idempotency_key: MessageId,
        fault_kind: crate::reporting::v0::types::DkgPublicOriginFaultKind,
        contribution_a: network::SignedPayload,
        contribution_b: Option<network::SignedPayload>,
    },
    /// Relay two conflicting endpoint-signed leader deliveries (a manifest,
    /// or a chunk) proving the canonical leader equivocated. `delivery_id`
    /// is the per-broadcast randomized ID mixed into each delivery's
    /// Gossip-frame signing domain — required alongside the `SignedPayload`
    /// to independently re-verify the endpoint signature later.
    RelayLeaderEquivocationEvidence {
        ceremony_id: CeremonyId,
        attempt_id: AttemptId,
        idempotency_key: MessageId,
        delivery_id_a: [u8; 16],
        delivery_a: network::SignedPayload,
        delivery_id_b: [u8; 16],
        delivery_b: network::SignedPayload,
    },
    /// Relay two leader-signed Gossip deliveries (any combination of
    /// manifest and chunk) that each reference the same origin under two
    /// different phase roots — same shape as `RelayLeaderEquivocationEvidence`,
    /// different fault predicate (see `DkgLeaderBatchMismatchStatement`).
    RelayLeaderBatchMismatchEvidence {
        ceremony_id: CeremonyId,
        attempt_id: AttemptId,
        idempotency_key: MessageId,
        delivery_id_a: [u8; 16],
        delivery_a: network::SignedPayload,
        delivery_id_b: [u8; 16],
        delivery_b: network::SignedPayload,
    },
    /// Relay a single leader-signed Gossip delivery (a manifest or chunk)
    /// that is independently provable as invalid on its own — see
    /// `DkgLeaderPublicFaultKind` for the covered fault kinds.
    RelayLeaderPublicFaultEvidence {
        ceremony_id: CeremonyId,
        attempt_id: AttemptId,
        idempotency_key: MessageId,
        fault_kind: crate::reporting::v0::types::DkgLeaderPublicFaultKind,
        delivery_id: [u8; 16],
        delivery: network::SignedPayload,
    },
    /// Relay a node-key-signed control-handshake fault (a bad `Prepare`, or
    /// a follower's conflicting `Prepared`/`Activated`/`Begun` acks) from a
    /// pure pending-new reshare member to a current-committee signer.
    RelayControlMessageFaultEvidence {
        ceremony_id: CeremonyId,
        attempt_id: AttemptId,
        idempotency_key: MessageId,
        accused_node_key: String,
        message_kind: String,
        fault_kind: crate::reporting::v0::types::DkgControlMessageFaultKind,
        artifact_a: crate::reporting::v0::types::ControlMessageArtifact,
        artifact_b: Option<crate::reporting::v0::types::ControlMessageArtifact>,
    },
    EvidenceAccepted {
        ceremony_id: CeremonyId,
        attempt_id: AttemptId,
        idempotency_key: MessageId,
    },
    /// Relay an availability observation from a pending-new reshare member
    /// that does not yet own a usable report-signing share to the current
    /// committee. The receiver independently validates the active attempt,
    /// authenticated observer, stage entitlement, and accused participants.
    RelayOfflineCandidates {
        ceremony_id: CeremonyId,
        attempt_id: AttemptId,
        idempotency_key: MessageId,
        stage: PssOfflineStage,
        accused: Vec<ParticipantRef>,
    },
    OfflineCandidatesAccepted {
        ceremony_id: CeremonyId,
        attempt_id: AttemptId,
        idempotency_key: MessageId,
    },
    GetPublicContribution {
        ceremony_id: CeremonyId,
        attempt_id: AttemptId,
        phase: PublicPhase,
        origin: ParticipantRef,
    },
    PublicContributionResponse {
        ceremony_id: CeremonyId,
        attempt_id: AttemptId,
        contribution: Option<network::SignedPayload>,
    },
    GetPublicPhase {
        ceremony_id: CeremonyId,
        attempt_id: AttemptId,
        phase: PublicPhase,
        after: Option<ParticipantRef>,
    },
    PublicPhaseResponse {
        ceremony_id: CeremonyId,
        attempt_id: AttemptId,
        phase: PublicPhase,
        contributions: Vec<network::SignedPayload>,
        next_cursor: Option<ParticipantRef>,
        /// `public_repair_page_digest` over this message's other fields —
        /// what `report_signature` actually covers. Lets a leader-served
        /// direct-QUIC repair page be attributed the same way
        /// `Prepare`/`Prepared`/etc. are, since (unlike Gossip broadcasts)
        /// this message has no transport-layer signature to reclaim.
        page_digest: [u8; 32],
        /// Node-key signature over `page_digest`, binding the leader to this
        /// exact repair-page content — see `ControlSignature`. Signed
        /// unconditionally at the one real construction site
        /// (`sign_public_phase_response`, Fresh DKG included); `Option`
        /// exists only because nothing at the protocol layer requires it to
        /// be `Some` before the response is accepted — same deliberate,
        /// accepted tradeoff as `PrepareSession.report_signature`.
        report_signature: Option<ControlSignature>,
    },
    Error {
        ceremony_id: Option<CeremonyId>,
        attempt_id: Option<AttemptId>,
        message: String,
    },
}

impl DkgControlMessage {
    pub fn metric_label(&self) -> &'static str {
        match self {
            Self::StartFresh { .. } => "start_fresh",
            Self::StartFreshPet { .. } => "start_fresh_pet",
            Self::StartAccepted { .. } => "start_accepted",
            Self::GetSessionStatus { .. } => "get_session_status",
            Self::SessionStatusResponse { .. } => "session_status_response",
            Self::StartReshare { .. } => "start_reshare",
            Self::ReshareStartAccepted { .. } => "reshare_start_accepted",
            Self::StartRefresh { .. } => "start_refresh",
            Self::RefreshStartAccepted { .. } => "refresh_start_accepted",
            Self::RefreshNotDue => "refresh_not_due",
            Self::Prepare(_) => "prepare",
            Self::Prepared { .. } => "prepared",
            Self::TopologyProbeAck { .. } => "topology_probe_ack",
            Self::Activate { .. } => "activate",
            Self::Activated { .. } => "activated",
            Self::Begin { .. } => "begin",
            Self::Begun { .. } => "begun",
            Self::Abort { .. } => "abort",
            Self::PublicContribution(_) => "public_contribution",
            Self::PublicContributionAck { .. } => "public_contribution_ack",
            Self::StageRefreshResult(_) => "stage_refresh_result",
            Self::CommitRefreshResult { .. } => "commit_refresh_result",
            Self::ReshareShareAck { .. } => "reshare_share_ack",
            Self::ReshareShareAcked { .. } => "reshare_share_acked",
            Self::RelayInvalidShareEvidence { .. } => "relay_invalid_share_evidence",
            Self::RelayInvalidCommitmentEvidence { .. } => "relay_invalid_commitment_evidence",
            Self::RelayPublicOriginFaultEvidence { .. } => "relay_public_origin_fault_evidence",
            Self::RelayLeaderEquivocationEvidence { .. } => "relay_leader_equivocation_evidence",
            Self::RelayLeaderBatchMismatchEvidence { .. } => "relay_leader_batch_mismatch_evidence",
            Self::RelayLeaderPublicFaultEvidence { .. } => "relay_leader_public_fault_evidence",
            Self::RelayControlMessageFaultEvidence { .. } => "relay_control_message_fault_evidence",
            Self::EvidenceAccepted { .. } => "evidence_accepted",
            Self::RelayOfflineCandidates { .. } => "relay_offline_candidates",
            Self::OfflineCandidatesAccepted { .. } => "offline_candidates_accepted",
            Self::GetPublicContribution { .. } => "get_public_contribution",
            Self::PublicContributionResponse { .. } => "public_contribution_response",
            Self::GetPublicPhase { .. } => "get_public_phase",
            Self::PublicPhaseResponse { .. } => "public_phase_response",
            Self::Error { .. } => "error",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DkgPrivateMessage {
    PairHello {
        ceremony_id: CeremonyId,
        attempt_id: AttemptId,
        pair_id: MessageId,
        opener: ParticipantRef,
        responder: ParticipantRef,
    },
    ShareDelivery {
        ceremony_id: CeremonyId,
        attempt_id: AttemptId,
        message_id: MessageId,
        from: ParticipantRef,
        to: ParticipantRef,
        share_value: Vec<u8>,
        nonce: [u8; 16],
        report_evidence: Option<Box<SignedDkgShare>>,
    },
    ShareAck {
        ceremony_id: CeremonyId,
        attempt_id: AttemptId,
        message_id: MessageId,
        share_digest: [u8; 32],
    },
    Busy {
        ceremony_id: CeremonyId,
        attempt_id: AttemptId,
        retry_after_ms: u64,
    },
}

impl DkgPrivateMessage {
    pub fn metric_label(&self) -> &'static str {
        match self {
            Self::PairHello { .. } => "pair_hello",
            Self::ShareDelivery { .. } => "share_delivery",
            Self::ShareAck { .. } => "share_ack",
            Self::Busy { .. } => "busy",
        }
    }
}
