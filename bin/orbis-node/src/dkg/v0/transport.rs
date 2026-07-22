//! Typed transport contract for DKG-backed ceremonies.
//!
//! Public messages intentionally cannot represent credentials or secret shares.
//! Reshare continues to use the legacy direct `DkgMessage` path in v1 of this
//! transport refactor.

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicPhase {
    CommitmentHashes,
    Commitments,
    CommitmentAudit,
    RefreshHealthCheck,
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
}

impl DkgPublicPayload {
    pub fn phase(&self) -> PublicPhase {
        match self {
            Self::CommitmentHash { .. } => PublicPhase::CommitmentHashes,
            Self::Commitment { .. } => PublicPhase::Commitments,
            Self::CommitmentAudit { .. } => PublicPhase::CommitmentAudit,
            Self::RefreshHealthCheckResult { .. } => PublicPhase::RefreshHealthCheck,
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
    pub origin_node_id: u32,
    pub message_id: MessageId,
    pub payload: DkgPublicPayload,
}

impl DkgPublicContribution {
    pub fn new(
        ceremony_id: CeremonyId,
        attempt_id: AttemptId,
        ring_id: String,
        committee_digest: [u8; 32],
        origin_node_id: u32,
        payload: DkgPublicPayload,
    ) -> Result<Self, String> {
        let message_id = derive_message_id(
            ceremony_id,
            attempt_id,
            payload.phase(),
            origin_node_id,
            None,
            &payload,
        )?;
        Ok(Self {
            ceremony_id,
            attempt_id,
            ring_id,
            committee_digest,
            origin_node_id,
            message_id,
            payload,
        })
    }

    pub fn validate_message_id(&self) -> Result<(), String> {
        let expected = derive_message_id(
            self.ceremony_id,
            self.attempt_id,
            self.payload.phase(),
            self.origin_node_id,
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
    pub contribution_ids: BTreeMap<u32, MessageId>,
    pub chunk_count: u32,
}

impl PhaseManifest {
    /// Validate that a leader manifest names exactly the expected origins and
    /// commits to their canonical message-id ordering.
    pub fn validate(&self, expected_origins: &BTreeSet<u32>) -> Result<(), String> {
        let actual_origins: BTreeSet<_> = self.contribution_ids.keys().copied().collect();
        if &actual_origins != expected_origins {
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
    contributions: BTreeMap<u32, network::SignedPayload>,
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
    contributions: BTreeMap<u32, network::SignedPayload>,
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
    pub threshold: u32,
    pub total_participants: u32,
    pub peer_ids: Vec<String>,
    pub peer_node_keys: Vec<String>,
    pub node_id_assignments: HashMap<String, u32>,
    pub token_string: String,
    pub kind: SessionKind,
    pub pss_interval: u64,
    pub policy_id: Option<String>,
    pub ring_id: String,
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
    TopologyProbeStatus {
        ceremony_id: CeremonyId,
        attempt_id: AttemptId,
        nonce: [u8; 32],
    },
    TopologyProbeStatusResponse {
        ceremony_id: CeremonyId,
        attempt_id: AttemptId,
        nonce: [u8; 32],
        seen: bool,
    },
    Activate {
        ceremony_id: CeremonyId,
        attempt_id: AttemptId,
    },
    Activated {
        ceremony_id: CeremonyId,
        attempt_id: AttemptId,
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
    GetPublicContribution {
        ceremony_id: CeremonyId,
        attempt_id: AttemptId,
        phase: PublicPhase,
        origin_node_id: u32,
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DkgPrivateMessage {
    PairHello {
        ceremony_id: CeremonyId,
        attempt_id: AttemptId,
    },
    ShareDelivery {
        ceremony_id: CeremonyId,
        attempt_id: AttemptId,
        message_id: MessageId,
        from_node_id: u32,
        to_node_id: u32,
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

/// The lower canonical node ID opens the one stream for an unordered pair.
pub fn is_canonical_pair_opener(local_node_id: u32, remote_node_id: u32) -> bool {
    local_node_id < remote_node_id
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

pub fn config_digest(prepare: &PrepareSession) -> Result<[u8; 32], String> {
    let mut hasher = Sha256::new();
    hasher.update(b"orbis-dkg-config-v1");
    hasher.update(prepare.ceremony_id.0.to_be_bytes());
    hasher.update(prepare.attempt_id.0);
    hasher.update(prepare.topic_id);
    hash_string(&mut hasher, &prepare.leader_node_key);
    hasher.update(prepare.threshold.to_be_bytes());
    hasher.update(prepare.total_participants.to_be_bytes());
    let mut routes: Vec<_> = prepare
        .peer_node_keys
        .iter()
        .zip(prepare.peer_ids.iter())
        .collect();
    routes.sort_by(|(left, _), (right, _)| left.cmp(right));
    hasher.update((routes.len() as u64).to_be_bytes());
    for (node_key, peer_id) in routes {
        hash_string(&mut hasher, node_key);
        hash_string(&mut hasher, peer_id);
    }
    let assignments: BTreeMap<_, _> = prepare.node_id_assignments.iter().collect();
    hasher.update((assignments.len() as u64).to_be_bytes());
    for (node_key, node_id) in assignments {
        hash_string(&mut hasher, node_key);
        hasher.update(node_id.to_be_bytes());
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
    origin_node_id: u32,
    recipient_node_id: Option<u32>,
    payload: &T,
) -> Result<MessageId, String> {
    let payload = encode(payload)?;
    let mut hasher = Sha256::new();
    hasher.update(b"orbis-dkg-message-v1");
    hasher.update(ceremony_id.0.to_be_bytes());
    hasher.update(attempt_id.0);
    hasher.update(encode(&phase)?);
    hasher.update(origin_node_id.to_be_bytes());
    hasher.update(recipient_node_id.unwrap_or(0).to_be_bytes());
    hasher.update((payload.len() as u64).to_be_bytes());
    hasher.update(payload);
    Ok(MessageId(hasher.finalize().into()))
}

pub fn phase_root(
    ceremony_id: CeremonyId,
    attempt_id: AttemptId,
    phase: PublicPhase,
    contributions: &BTreeMap<u32, MessageId>,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"orbis-dkg-phase-root-v1");
    hasher.update(ceremony_id.0.to_be_bytes());
    hasher.update(attempt_id.0);
    hasher.update(encode(&phase).expect("public phase serialization is infallible"));
    hasher.update((contributions.len() as u64).to_be_bytes());
    for (origin, message_id) in contributions {
        hasher.update(origin.to_be_bytes());
        hasher.update(message_id.0);
    }
    hasher.finalize().into()
}

pub fn share_digest(
    ceremony_id: CeremonyId,
    attempt_id: AttemptId,
    from_node_id: u32,
    to_node_id: u32,
    share_value: &[u8],
    nonce: &[u8; 16],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"orbis-dkg-private-share-v1");
    hasher.update(ceremony_id.0.to_be_bytes());
    hasher.update(attempt_id.0);
    hasher.update(from_node_id.to_be_bytes());
    hasher.update(to_node_id.to_be_bytes());
    hasher.update((share_value.len() as u64).to_be_bytes());
    hasher.update(share_value);
    hasher.update(nonce);
    hasher.finalize().into()
}

pub fn derive_private_message_id(
    ceremony_id: CeremonyId,
    attempt_id: AttemptId,
    from_node_id: u32,
    to_node_id: u32,
    share_value: &[u8],
    nonce: &[u8; 16],
) -> MessageId {
    let digest = share_digest(
        ceremony_id,
        attempt_id,
        from_node_id,
        to_node_id,
        share_value,
        nonce,
    );
    let mut hasher = Sha256::new();
    hasher.update(b"orbis-dkg-private-message-v1");
    hasher.update(ceremony_id.0.to_be_bytes());
    hasher.update(attempt_id.0);
    hasher.update(from_node_id.to_be_bytes());
    hasher.update(to_node_id.to_be_bytes());
    hasher.update(digest);
    MessageId(hasher.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn committee_and_leader_are_order_independent() {
        let a = vec!["node-c".into(), "node-a".into(), "node-b".into()];
        let b = vec!["node-b".into(), "node-c".into(), "node-a".into()];
        assert_eq!(canonical_leader(&a), Some("node-a"));
        assert_eq!(committee_digest(&a), committee_digest(&b));
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
        assert_ne!(
            derive_message_id(
                ceremony,
                first,
                PublicPhase::CommitmentHashes,
                1,
                None,
                &payload
            )
            .unwrap(),
            derive_message_id(
                ceremony,
                second,
                PublicPhase::CommitmentHashes,
                1,
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
            4,
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
        let first = BTreeMap::from([(2, MessageId([2; 32])), (1, MessageId([1; 32]))]);
        let second = BTreeMap::from([(1, MessageId([1; 32])), (2, MessageId([2; 32]))]);
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
    fn manifest_rejects_omission_and_invalid_root() {
        let ceremony = CeremonyId(21);
        let attempt = AttemptId([22; 32]);
        let ids = BTreeMap::from([(1, MessageId([1; 32])), (2, MessageId([2; 32]))]);
        let mut manifest = PhaseManifest {
            ceremony_id: ceremony,
            attempt_id: attempt,
            phase: PublicPhase::Commitments,
            phase_root: phase_root(ceremony, attempt, PublicPhase::Commitments, &ids),
            contribution_ids: ids,
            chunk_count: 1,
        };
        let committee = BTreeSet::from([1, 2]);
        assert!(manifest.validate(&committee).is_ok());

        manifest.contribution_ids.remove(&2);
        assert!(manifest.validate(&committee).is_err());
        manifest.contribution_ids.insert(2, MessageId([2; 32]));
        manifest.phase_root = [99; 32];
        assert!(manifest.validate(&committee).is_err());
    }

    #[test]
    fn chunks_use_canonical_order_and_actual_encoded_limit() {
        let contributions = BTreeMap::from([
            (
                3,
                network::SignedPayload {
                    origin: vec![3],
                    signature: vec![3; 64],
                    data: vec![3; 256],
                },
            ),
            (
                1,
                network::SignedPayload {
                    origin: vec![1],
                    signature: vec![1; 64],
                    data: vec![1; 256],
                },
            ),
            (
                2,
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
        let original = derive_private_message_id(ceremony, attempt, 1, 2, &[4, 5], &nonce);
        assert_eq!(
            original,
            derive_private_message_id(ceremony, attempt, 1, 2, &[4, 5], &nonce)
        );
        assert_ne!(
            original,
            derive_private_message_id(ceremony, attempt, 1, 3, &[4, 5], &nonce)
        );
        assert_ne!(
            original,
            derive_private_message_id(ceremony, attempt, 1, 2, &[4, 6], &nonce)
        );
    }
}
