//! Typed transport contract for every DKG-backed ceremony.
//!
//! The three enums in this module are the complete DKG wire surface. Public
//! messages cannot represent credentials, secret shares, or private evidence.

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};

use crate::dkg::v0::messages::{SessionKind, SignedDkgCommitment, SignedDkgShare};
use crate::sign::v0::messages::RefreshHealthCheckStatement;

pub const PUBLIC_CONTRIBUTION_SIGNING_DOMAIN: &[u8] = b"orbis-dkg-public-contribution-v1";
pub const MAX_PUBLIC_CHUNK_BYTES: usize = 256 * 1024;

/// Stable logical ceremony identity. Existing session IDs remain its source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CeremonyId(pub u128);

/// Unique identity for one actual attempt of a logical ceremony.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AttemptId(pub [u8; 32]);

impl AttemptId {
    pub fn random() -> Self {
        Self(rand::random())
    }
}

/// Content-bound identifier used for idempotency and acknowledgements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct MessageId(pub [u8; 32]);

/// Identifies which side of a committee transition owns a numeric node ID.
/// Numeric IDs are only unique inside one scope during reshare.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitteeScope {
    Current,
    Next,
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
        report_evidence: Option<SignedDkgCommitment>,
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
        let message_id = derive_message_id(
            ceremony_id,
            attempt_id,
            payload.phase(),
            origin,
            None,
            &payload,
        )?;
        Ok(Self {
            ceremony_id,
            attempt_id,
            ring_id,
            committee_digest,
            origin,
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
            &self.payload,
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
        if self.chunk_count == 0 && !self.contribution_ids.is_empty() {
            return Err("non-empty public phase manifest has no chunks".to_string());
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
) -> Result<Vec<DkgPublicMessage>, String> {
    chunk_public_contributions_with_limit(
        ceremony_id,
        attempt_id,
        phase,
        phase_root,
        contributions,
        MAX_PUBLIC_CHUNK_BYTES,
    )
}

fn chunk_public_contributions_with_limit(
    ceremony_id: CeremonyId,
    attempt_id: AttemptId,
    phase: PublicPhase,
    phase_root: [u8; 32],
    contributions: BTreeMap<ParticipantRef, network::SignedPayload>,
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
    pub token_string: String,
    pub kind: SessionKind,
    pub pss_interval: u64,
    pub policy_id: Option<String>,
    pub ring_id: String,
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
            SessionKind::Fresh | SessionKind::Refresh { .. } => Some(&self.committees.current),
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
        token_string: String,
    },
    StartAccepted {
        ceremony_id: CeremonyId,
        attempt_id: AttemptId,
    },
    StartReshare {
        ring_id: String,
        expected_ring_pk: String,
    },
    ReshareStartAccepted {
        ceremony_id: CeremonyId,
        attempt_id: AttemptId,
    },
    /// Ask the receiver to lead a due refresh. Sent by any current-committee
    /// member walking `canonical_leader_candidates` in order; the receiver
    /// independently re-validates the sender and the ring state rather than
    /// trusting the request.
    StartRefresh {
        ring_id: String,
        expected_ring_pk: String,
    },
    RefreshStartAccepted {
        ceremony_id: CeremonyId,
        attempt_id: AttemptId,
    },
    /// The receiver independently re-checked and refresh is no longer due
    /// (e.g. another attempt already completed). Distinct from an error so
    /// the forward-chain walk stops cleanly instead of trying the next
    /// candidate.
    RefreshNotDue,
    Prepare(Box<PrepareSession>),
    Prepared {
        ceremony_id: CeremonyId,
        attempt_id: AttemptId,
        config_digest: [u8; 32],
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
    },
    Activated {
        ceremony_id: CeremonyId,
        attempt_id: AttemptId,
        activation_digest: [u8; 32],
    },
    Begin {
        ceremony_id: CeremonyId,
        attempt_id: AttemptId,
        activation_digest: [u8; 32],
    },
    Begun {
        ceremony_id: CeremonyId,
        attempt_id: AttemptId,
        activation_digest: [u8; 32],
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
    EvidenceAccepted {
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
    },
    PublicPhaseResponse {
        ceremony_id: CeremonyId,
        attempt_id: AttemptId,
        phase: PublicPhase,
        contributions: Vec<network::SignedPayload>,
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
            Self::StartAccepted { .. } => "start_accepted",
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
            Self::EvidenceAccepted { .. } => "evidence_accepted",
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
        report_evidence: Option<SignedDkgShare>,
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

pub fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    serde_json::to_vec(value).map_err(|error| error.to_string())
}

pub fn decode<T: DeserializeOwned>(bytes: &[u8], max_bytes: usize) -> Result<T, String> {
    if bytes.len() > max_bytes {
        return Err(format!(
            "encoded DKG transport message is {} bytes, maximum is {}",
            bytes.len(),
            max_bytes
        ));
    }
    serde_json::from_slice(bytes).map_err(|error| error.to_string())
}

pub fn canonical_leader(peer_node_keys: &[String]) -> Option<&str> {
    peer_node_keys.iter().map(String::as_str).min()
}

/// Deterministic committee ordering used to walk refresh-leader candidates in
/// a fixed sequence every current member agrees on without communicating.
/// Rank 0 matches `canonical_leader`.
pub fn canonical_leader_candidates(peer_node_keys: &[String]) -> Vec<&str> {
    let mut candidates: Vec<&str> = peer_node_keys.iter().map(String::as_str).collect();
    candidates.sort_unstable();
    candidates
}

/// The lower canonical node ID opens the one stream for an unordered pair.
pub fn is_canonical_pair_opener(local_node_id: u32, remote_node_id: u32) -> bool {
    local_node_id < remote_node_id
}

pub fn derive_pair_hello_id(
    ceremony_id: CeremonyId,
    attempt_id: AttemptId,
    opener: ParticipantRef,
    responder: ParticipantRef,
) -> MessageId {
    let mut hasher = Sha256::new();
    hasher.update(b"orbis-dkg-private-pair-hello-v1");
    hasher.update(ceremony_id.0.to_be_bytes());
    hasher.update(attempt_id.0);
    hasher.update(encode(&opener).expect("participant serialization is infallible"));
    hasher.update(encode(&responder).expect("participant serialization is infallible"));
    MessageId(hasher.finalize().into())
}

pub fn committee_digest(peer_node_keys: &[String]) -> [u8; 32] {
    let mut keys = peer_node_keys.to_vec();
    keys.sort();
    let mut hasher = Sha256::new();
    hasher.update(b"orbis-dkg-committee-v1");
    hasher.update((keys.len() as u64).to_be_bytes());
    for key in keys {
        hasher.update((key.len() as u64).to_be_bytes());
        hasher.update(key.as_bytes());
    }
    hasher.finalize().into()
}

/// Digest a current committee and optional next committee without collapsing
/// identical numeric node IDs across scopes.
pub fn ceremony_committee_digest(current: &[String], next: Option<&[String]>) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"orbis-dkg-ceremony-committees-v1");
    hasher.update(committee_digest(current));
    match next {
        Some(next) => {
            hasher.update([1]);
            hasher.update(committee_digest(next));
        }
        None => hasher.update([0]),
    }
    hasher.finalize().into()
}

pub fn config_digest(prepare: &PrepareSession) -> Result<[u8; 32], String> {
    let mut hasher = Sha256::new();
    hasher.update(b"orbis-dkg-config-v2");
    hasher.update(prepare.ceremony_id.0.to_be_bytes());
    hasher.update(prepare.attempt_id.0);
    hasher.update(prepare.topic_id);
    hash_string(&mut hasher, &prepare.leader_node_key);
    prepare.committees.validate()?;
    hash_committee_config(&mut hasher, &prepare.committees.current)?;
    match &prepare.committees.next {
        Some(next) => {
            hasher.update([1]);
            hash_committee_config(&mut hasher, next)?;
        }
        None => hasher.update([0]),
    }
    hasher.update(encode(&prepare.kind)?);
    hasher.update(prepare.pss_interval.to_be_bytes());
    match &prepare.policy_id {
        Some(policy_id) => {
            hasher.update([1]);
            hash_string(&mut hasher, policy_id);
        }
        None => hasher.update([0]),
    }
    hash_string(&mut hasher, &prepare.ring_id);
    Ok(hasher.finalize().into())
}

/// Hash one committee without relying on `HashMap` iteration order.
///
/// `PrepareSession` crosses a serialization boundary before followers verify
/// its digest. Deserializing `node_id_assignments` creates a map with a fresh
/// randomized iteration order, so hashing the container's serialized bytes is
/// not deterministic. The ordered node-key and route vectors are the canonical
/// traversal, and each assignment is looked up by key.
fn hash_committee_config(hasher: &mut Sha256, committee: &CommitteeConfig) -> Result<(), String> {
    hasher.update((committee.node_keys.len() as u64).to_be_bytes());
    for (node_key, peer_route) in committee.node_keys.iter().zip(&committee.peer_routes) {
        hash_string(hasher, node_key);
        hash_string(hasher, peer_route);
        let node_id = committee
            .node_id_assignments
            .get(node_key)
            .ok_or_else(|| format!("committee assignment missing node key {node_key}"))?;
        hasher.update(node_id.to_be_bytes());
    }
    hasher.update(committee.threshold.to_be_bytes());
    Ok(())
}

pub fn activation_digest(
    config_digest: [u8; 32],
    active_dealers: &[ParticipantRef],
) -> Result<[u8; 32], String> {
    let mut canonical = active_dealers.to_vec();
    canonical.sort();
    canonical.dedup();
    if canonical.len() != active_dealers.len()
        || canonical
            .iter()
            .any(|participant| participant.scope != CommitteeScope::Current)
    {
        return Err(
            "activation dealer set must contain unique current-committee participants".into(),
        );
    }
    let mut hasher = Sha256::new();
    hasher.update(b"orbis-dkg-activation-v1");
    hasher.update(config_digest);
    hasher.update(encode(&canonical)?);
    Ok(hasher.finalize().into())
}

fn hash_string(hasher: &mut Sha256, value: &str) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value.as_bytes());
}

pub fn derive_topic_id(
    chain_id: &str,
    ring_id: &str,
    committee_digest: &[u8; 32],
    ceremony_id: CeremonyId,
    attempt_id: AttemptId,
) -> network::TopicId {
    let mut hasher = Sha256::new();
    hasher.update(b"orbis-dkg-topic-v1");
    hasher.update((chain_id.len() as u64).to_be_bytes());
    hasher.update(chain_id.as_bytes());
    hasher.update((ring_id.len() as u64).to_be_bytes());
    hasher.update(ring_id.as_bytes());
    hasher.update(committee_digest);
    hasher.update(ceremony_id.0.to_be_bytes());
    hasher.update(attempt_id.0);
    network::TopicId::new(hasher.finalize().into())
}

pub fn derive_message_id<T: Serialize>(
    ceremony_id: CeremonyId,
    attempt_id: AttemptId,
    phase: PublicPhase,
    origin: ParticipantRef,
    recipient: Option<ParticipantRef>,
    payload: &T,
) -> Result<MessageId, String> {
    let payload = encode(payload)?;
    let mut hasher = Sha256::new();
    hasher.update(b"orbis-dkg-message-v1");
    hasher.update(ceremony_id.0.to_be_bytes());
    hasher.update(attempt_id.0);
    hasher.update(encode(&phase)?);
    hasher.update(encode(&origin)?);
    hasher.update(encode(&recipient)?);
    hasher.update((payload.len() as u64).to_be_bytes());
    hasher.update(payload);
    Ok(MessageId(hasher.finalize().into()))
}

pub fn phase_root(
    ceremony_id: CeremonyId,
    attempt_id: AttemptId,
    phase: PublicPhase,
    contributions: &BTreeMap<ParticipantRef, MessageId>,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"orbis-dkg-phase-root-v1");
    hasher.update(ceremony_id.0.to_be_bytes());
    hasher.update(attempt_id.0);
    hasher.update(encode(&phase).expect("public phase serialization is infallible"));
    hasher.update((contributions.len() as u64).to_be_bytes());
    for (origin, message_id) in contributions {
        hasher.update(encode(origin).expect("participant serialization is infallible"));
        hasher.update(message_id.0);
    }
    hasher.finalize().into()
}

pub fn share_digest(
    ceremony_id: CeremonyId,
    attempt_id: AttemptId,
    from: ParticipantRef,
    to: ParticipantRef,
    share_value: &[u8],
    nonce: &[u8; 16],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"orbis-dkg-private-share-v1");
    hasher.update(ceremony_id.0.to_be_bytes());
    hasher.update(attempt_id.0);
    hasher.update(encode(&from).expect("participant serialization is infallible"));
    hasher.update(encode(&to).expect("participant serialization is infallible"));
    hasher.update((share_value.len() as u64).to_be_bytes());
    hasher.update(share_value);
    hasher.update(nonce);
    hasher.finalize().into()
}

pub fn derive_private_message_id(
    ceremony_id: CeremonyId,
    attempt_id: AttemptId,
    from: ParticipantRef,
    to: ParticipantRef,
    share_value: &[u8],
    nonce: &[u8; 16],
) -> MessageId {
    let digest = share_digest(ceremony_id, attempt_id, from, to, share_value, nonce);
    let mut hasher = Sha256::new();
    hasher.update(b"orbis-dkg-private-message-v1");
    hasher.update(ceremony_id.0.to_be_bytes());
    hasher.update(attempt_id.0);
    hasher.update(encode(&from).expect("participant serialization is infallible"));
    hasher.update(encode(&to).expect("participant serialization is infallible"));
    hasher.update(digest);
    MessageId(hasher.finalize().into())
}

pub fn derive_control_message_id<T: Serialize>(
    ceremony_id: CeremonyId,
    attempt_id: AttemptId,
    message_kind: &str,
    origin: ParticipantRef,
    recipient: ParticipantRef,
    payload: &T,
) -> Result<MessageId, String> {
    let mut hasher = Sha256::new();
    hasher.update(b"orbis-dkg-control-message-v1");
    hasher.update(ceremony_id.0.to_be_bytes());
    hasher.update(attempt_id.0);
    hash_string(&mut hasher, message_kind);
    hasher.update(encode(&origin)?);
    hasher.update(encode(&recipient)?);
    hasher.update(encode(payload)?);
    Ok(MessageId(hasher.finalize().into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn committee(entries: &[(&str, &str, u32)], threshold: u32) -> CommitteeConfig {
        CommitteeConfig {
            node_keys: entries
                .iter()
                .map(|(key, _, _)| (*key).to_string())
                .collect(),
            peer_routes: entries
                .iter()
                .map(|(_, route, _)| (*route).to_string())
                .collect(),
            node_id_assignments: entries
                .iter()
                .map(|(key, _, node_id)| ((*key).to_string(), *node_id))
                .collect(),
            threshold,
        }
    }

    #[test]
    fn canonical_leader_candidates_are_fully_ordered_and_match_canonical_leader() {
        let keys: Vec<String> = ["node-c", "node-a", "node-b"]
            .into_iter()
            .map(String::from)
            .collect();
        let candidates = canonical_leader_candidates(&keys);
        assert_eq!(candidates, vec!["node-a", "node-b", "node-c"]);
        assert_eq!(candidates.first().copied(), canonical_leader(&keys));

        let single = vec!["only-node".to_string()];
        assert_eq!(canonical_leader_candidates(&single), vec!["only-node"]);

        let empty: Vec<String> = Vec::new();
        assert!(canonical_leader_candidates(&empty).is_empty());
    }

    #[test]
    fn scoped_participants_do_not_collapse_equal_node_ids() {
        let config = CeremonyConfig {
            current: committee(&[("old-a", "peer-old-a", 1), ("overlap", "peer-o", 2)], 1),
            next: Some(committee(
                &[("new-a", "peer-new-a", 1), ("overlap", "peer-o", 2)],
                1,
            )),
        };
        assert_ne!(ParticipantRef::current(1), ParticipantRef::next(1));
        assert_eq!(config.node_key(ParticipantRef::current(1)), Some("old-a"));
        assert_eq!(config.node_key(ParticipantRef::next(1)), Some("new-a"));
        assert_eq!(
            config.union_routes().len(),
            3,
            "overlap must deduplicate by node key"
        );
    }

    #[test]
    fn activation_digest_binds_frozen_current_dealers() {
        let base = [7; 32];
        let first = activation_digest(
            base,
            &[ParticipantRef::current(1), ParticipantRef::current(2)],
        )
        .unwrap();
        let reordered = activation_digest(
            base,
            &[ParticipantRef::current(2), ParticipantRef::current(1)],
        )
        .unwrap();
        let different = activation_digest(base, &[ParticipantRef::current(1)]).unwrap();
        assert_eq!(first, reordered);
        assert_ne!(first, different);
        assert!(activation_digest(base, &[ParticipantRef::next(1)]).is_err());
    }

    #[test]
    fn configuration_digest_survives_a_fifty_member_wire_round_trip() {
        let node_keys: Vec<String> = (0..50).map(|index| format!("node-{index:02}")).collect();
        let peer_routes: Vec<String> = (0..50).map(|index| format!("peer-{index:02}")).collect();
        let node_id_assignments: HashMap<String, u32> = node_keys
            .iter()
            .rev()
            .enumerate()
            .map(|(index, key)| (key.clone(), 50 - index as u32))
            .collect();
        let mut prepare = PrepareSession {
            ceremony_id: CeremonyId(99),
            attempt_id: AttemptId([7; 32]),
            config_digest: [0; 32],
            topic_id: [8; 32],
            leader_node_key: node_keys[0].clone(),
            committees: CeremonyConfig {
                current: CommitteeConfig {
                    node_keys,
                    peer_routes,
                    node_id_assignments,
                    threshold: 34,
                },
                next: None,
            },
            token_string: "credential".into(),
            kind: SessionKind::Fresh,
            pss_interval: 60,
            policy_id: Some("policy".into()),
            ring_id: "ring".into(),
        };
        prepare.config_digest = config_digest(&prepare).unwrap();

        let wire = encode(&prepare).unwrap();
        let decoded: PrepareSession = decode(&wire, wire.len()).unwrap();

        assert_eq!(config_digest(&decoded).unwrap(), prepare.config_digest);
    }

    #[test]
    fn reshare_pair_owner_uses_node_keys_and_pair_hello_is_scoped() {
        let config = CeremonyConfig {
            current: committee(&[("z-dealer", "peer-z", 1)], 1),
            next: Some(committee(&[("a-receiver", "peer-a", 1)], 1)),
        };
        let dealer = ParticipantRef::current(1);
        let receiver = ParticipantRef::next(1);
        assert_eq!(
            config.canonical_pair_opener(dealer, receiver),
            Some(receiver),
            "numeric node IDs must not choose a reshare opener"
        );
        let ceremony = CeremonyId(4);
        let attempt = AttemptId([5; 32]);
        let pair_id = derive_pair_hello_id(ceremony, attempt, receiver, dealer);
        assert_eq!(
            pair_id,
            derive_pair_hello_id(ceremony, attempt, receiver, dealer)
        );
        assert_ne!(
            pair_id,
            derive_pair_hello_id(ceremony, attempt, dealer, receiver)
        );
    }

    #[test]
    fn committee_and_leader_are_order_independent() {
        let a = vec!["node-c".into(), "node-a".into(), "node-b".into()];
        let b = vec!["node-b".into(), "node-c".into(), "node-a".into()];
        assert_eq!(canonical_leader(&a), Some("node-a"));
        assert_eq!(committee_digest(&a), committee_digest(&b));
    }

    #[test]
    fn reshare_leader_is_canonical_next_receiver_and_is_digest_bound() {
        let mut prepare = PrepareSession {
            ceremony_id: CeremonyId(42),
            attempt_id: AttemptId([3; 32]),
            config_digest: [0; 32],
            topic_id: [4; 32],
            leader_node_key: "new-a".into(),
            committees: CeremonyConfig {
                current: committee(&[("old-a", "peer-old-a", 1), ("old-b", "peer-old-b", 2)], 2),
                next: Some(committee(
                    &[("new-b", "peer-new-b", 2), ("new-a", "peer-new-a", 1)],
                    2,
                )),
            },
            token_string: String::new(),
            kind: SessionKind::Reshare {
                ring_pk_hex: "ring-pk".into(),
                new_peer_node_keys: vec!["new-a".into(), "new-b".into()],
                new_threshold: 2,
                bulletin_post_id: "ring".into(),
            },
            pss_interval: 60,
            policy_id: Some("policy".into()),
            ring_id: "ring".into(),
        };
        assert_eq!(prepare.canonical_leader_node_key(), Some("new-a"));
        assert_eq!(prepare.leader_route(), Some("peer-new-a"));

        let next_leader_digest = config_digest(&prepare).unwrap();
        prepare.leader_node_key = "old-a".into();
        assert_ne!(config_digest(&prepare).unwrap(), next_leader_digest);
        assert_ne!(
            prepare.canonical_leader_node_key(),
            Some(prepare.leader_node_key.as_str())
        );
    }

    #[test]
    fn topic_and_message_ids_isolate_attempts() {
        let committee = committee_digest(&["node-a".into(), "node-b".into()]);
        let ceremony = CeremonyId(7);
        let first = AttemptId([1; 32]);
        let second = AttemptId([2; 32]);
        assert_ne!(
            derive_topic_id("chain", "ring", &committee, ceremony, first),
            derive_topic_id("chain", "ring", &committee, ceremony, second)
        );
        let payload = DkgPublicPayload::CommitmentHash {
            commitment_hash: [9; 32],
        };
        let origin = ParticipantRef::current(1);
        assert_ne!(
            derive_message_id(
                ceremony,
                first,
                PublicPhase::CommitmentHashes,
                origin,
                None,
                &payload
            )
            .unwrap(),
            derive_message_id(
                ceremony,
                second,
                PublicPhase::CommitmentHashes,
                origin,
                None,
                &payload
            )
            .unwrap()
        );
    }

    #[test]
    fn public_message_type_cannot_encode_a_share() {
        let message = DkgPublicMessage::TopologyProbe {
            ceremony_id: CeremonyId(1),
            attempt_id: AttemptId([2; 32]),
            nonce: [3; 32],
        };
        let encoded = encode(&message).unwrap();
        let decoded: DkgPublicMessage = decode(&encoded, 1024).unwrap();
        assert_eq!(message, decoded);

        let private = DkgPrivateMessage::Busy {
            ceremony_id: CeremonyId(1),
            attempt_id: AttemptId([2; 32]),
            retry_after_ms: 100,
        };
        let encoded_private = encode(&private).unwrap();
        assert!(decode::<DkgPublicMessage>(&encoded_private, 1024).is_err());
    }

    #[test]
    fn lower_node_id_is_the_only_pair_opener() {
        assert!(is_canonical_pair_opener(1, 2));
        assert!(!is_canonical_pair_opener(2, 1));
        assert!(!is_canonical_pair_opener(2, 2));
    }

    #[test]
    fn contribution_rejects_payload_mutation() {
        let mut contribution = DkgPublicContribution::new(
            CeremonyId(1),
            AttemptId([2; 32]),
            "ring".into(),
            [3; 32],
            ParticipantRef::current(4),
            DkgPublicPayload::CommitmentHash {
                commitment_hash: [5; 32],
            },
        )
        .unwrap();
        contribution.payload = DkgPublicPayload::CommitmentHash {
            commitment_hash: [6; 32],
        };
        assert!(contribution.validate_message_id().is_err());
    }

    #[test]
    fn phase_root_is_canonical_and_attempt_scoped() {
        let ceremony = CeremonyId(11);
        let attempt = AttemptId([12; 32]);
        let first = BTreeMap::from([
            (ParticipantRef::current(2), MessageId([2; 32])),
            (ParticipantRef::current(1), MessageId([1; 32])),
        ]);
        let second = BTreeMap::from([
            (ParticipantRef::current(1), MessageId([1; 32])),
            (ParticipantRef::current(2), MessageId([2; 32])),
        ]);
        assert_eq!(
            phase_root(ceremony, attempt, PublicPhase::Commitments, &first),
            phase_root(ceremony, attempt, PublicPhase::Commitments, &second)
        );
        assert_ne!(
            phase_root(ceremony, attempt, PublicPhase::Commitments, &first),
            phase_root(
                ceremony,
                AttemptId([13; 32]),
                PublicPhase::Commitments,
                &first
            )
        );
    }

    #[test]
    fn scoped_participant_map_keys_round_trip_on_the_json_wire() {
        let ceremony = CeremonyId(14);
        let attempt = AttemptId([15; 32]);
        let contribution_ids = BTreeMap::from([
            (ParticipantRef::current(1), MessageId([1; 32])),
            (ParticipantRef::next(1), MessageId([2; 32])),
        ]);
        let message = DkgPublicMessage::Manifest(PhaseManifest {
            ceremony_id: ceremony,
            attempt_id: attempt,
            phase: PublicPhase::Commitments,
            phase_root: phase_root(
                ceremony,
                attempt,
                PublicPhase::Commitments,
                &contribution_ids,
            ),
            contribution_ids,
            chunk_count: 1,
            complete: true,
        });

        let encoded = encode(&message).unwrap();
        let decoded: DkgPublicMessage = decode(&encoded, encoded.len()).unwrap();

        assert_eq!(decoded, message);
        let text = String::from_utf8(encoded).unwrap();
        assert!(text.contains("current:1"));
        assert!(text.contains("next:1"));
    }

    #[test]
    fn manifest_rejects_omission_and_invalid_root() {
        let ceremony = CeremonyId(21);
        let attempt = AttemptId([22; 32]);
        let ids = BTreeMap::from([
            (ParticipantRef::current(1), MessageId([1; 32])),
            (ParticipantRef::current(2), MessageId([2; 32])),
        ]);
        let mut manifest = PhaseManifest {
            ceremony_id: ceremony,
            attempt_id: attempt,
            phase: PublicPhase::Commitments,
            phase_root: phase_root(ceremony, attempt, PublicPhase::Commitments, &ids),
            contribution_ids: ids,
            chunk_count: 1,
            complete: true,
        };
        let committee = BTreeSet::from([ParticipantRef::current(1), ParticipantRef::current(2)]);
        assert!(manifest.validate(&committee).is_ok());

        manifest
            .contribution_ids
            .remove(&ParticipantRef::current(2));
        assert!(manifest.validate(&committee).is_err());
        manifest
            .contribution_ids
            .insert(ParticipantRef::current(2), MessageId([2; 32]));
        manifest.phase_root = [99; 32];
        assert!(manifest.validate(&committee).is_err());
    }

    #[test]
    fn chunks_use_canonical_order_and_actual_encoded_limit() {
        let contributions = BTreeMap::from([
            (
                ParticipantRef::current(3),
                network::SignedPayload {
                    origin: vec![3],
                    signature: vec![3; 64],
                    data: vec![3; 256],
                },
            ),
            (
                ParticipantRef::current(1),
                network::SignedPayload {
                    origin: vec![1],
                    signature: vec![1; 64],
                    data: vec![1; 256],
                },
            ),
            (
                ParticipantRef::current(2),
                network::SignedPayload {
                    origin: vec![2],
                    signature: vec![2; 64],
                    data: vec![2; 256],
                },
            ),
        ]);
        let limit = 1_500;
        let chunks = chunk_public_contributions_with_limit(
            CeremonyId(1),
            AttemptId([2; 32]),
            PublicPhase::Commitments,
            [3; 32],
            contributions,
            limit,
        )
        .unwrap();

        assert!(chunks.len() > 1);
        let mut origins = Vec::new();
        for (expected_index, chunk) in chunks.iter().enumerate() {
            assert!(encode(chunk).unwrap().len() <= limit);
            let DkgPublicMessage::Chunk {
                index,
                contributions,
                ..
            } = chunk
            else {
                panic!("chunk helper returned a non-chunk message");
            };
            assert_eq!(*index, expected_index as u32);
            origins.extend(contributions.iter().map(|signed| signed.origin[0]));
        }
        assert_eq!(origins, vec![1, 2, 3]);
    }

    #[test]
    fn private_message_id_binds_recipient_and_exact_share() {
        let ceremony = CeremonyId(1);
        let attempt = AttemptId([2; 32]);
        let nonce = [3; 16];
        let from = ParticipantRef::current(1);
        let to = ParticipantRef::current(2);
        let original = derive_private_message_id(ceremony, attempt, from, to, &[4, 5], &nonce);
        assert_eq!(
            original,
            derive_private_message_id(ceremony, attempt, from, to, &[4, 5], &nonce)
        );
        assert_ne!(
            original,
            derive_private_message_id(
                ceremony,
                attempt,
                from,
                ParticipantRef::current(3),
                &[4, 5],
                &nonce,
            )
        );
        assert_ne!(
            original,
            derive_private_message_id(ceremony, attempt, from, to, &[4, 6], &nonce)
        );
    }
}
