//! Canonical encode/decode and digest/ID-derivation for the DKG wire types.

use serde::{de::DeserializeOwned, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

use super::types::{
    AttemptId, CeremonyId, CommitteeConfig, CommitteeScope, MessageId, ParticipantRef,
    PrepareSession, PssOfflineStage, PublicPhase,
};

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
///
/// Comparing raw numeric IDs like this is only valid for an ordinary
/// same-scope pair. For a reshare pair, `Current` and `Next` identities are
/// assigned independently and may share the same numeric ID for different
/// physical nodes, so this function cannot disambiguate them — reshare
/// callers must use [`super::types::CeremonyConfig::canonical_pair_opener`], which compares
/// by node key instead.
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

/// What a leader's `ControlSignature` on a `PublicPhaseResponse` actually
/// covers — every field of the response except the digest/signature
/// themselves. Independently re-derivable by any co-signer from a retained
/// copy of the response, the same way `config_digest` is for `Prepare`.
pub fn public_repair_page_digest(
    ceremony_id: CeremonyId,
    attempt_id: AttemptId,
    phase: PublicPhase,
    contributions: &[network::SignedPayload],
    next_cursor: Option<ParticipantRef>,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"orbis-dkg-public-repair-page-v1");
    hasher.update(ceremony_id.0.to_be_bytes());
    hasher.update(attempt_id.0);
    hasher.update(encode(&phase).expect("public phase serialization is infallible"));
    hasher.update((contributions.len() as u64).to_be_bytes());
    for signed in contributions {
        hasher.update((signed.origin.len() as u64).to_be_bytes());
        hasher.update(&signed.origin);
        hasher.update((signed.signature.len() as u64).to_be_bytes());
        hasher.update(&signed.signature);
        hasher.update((signed.data.len() as u64).to_be_bytes());
        hasher.update(&signed.data);
    }
    hasher.update(encode(&next_cursor).expect("optional participant serialization is infallible"));
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

/// Canonical bytes signed by `ControlSignature` for one control-handshake
/// message. `digest` is that message's own existing `config_digest` or
/// `activation_digest` field — reused rather than re-derived, so signing
/// adds no new hashing surface beyond binding it to
/// (ceremony_id, attempt_id, message_kind). `signed_at` is bound in too —
/// otherwise it's a self-reported, unauthenticated claim that a signer could
/// forge without invalidating their own signature (see `ControlSignature`'s
/// own doc comment for why that matters for fault-evidence anchoring).
pub fn control_ack_signing_bytes(
    ceremony_id: CeremonyId,
    attempt_id: AttemptId,
    message_kind: &str,
    digest: [u8; 32],
    signed_at: u64,
) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(b"orbis-dkg-control-ack-v1");
    hasher.update(ceremony_id.0.to_be_bytes());
    hasher.update(attempt_id.0);
    hash_string(&mut hasher, message_kind);
    hasher.update(digest);
    hasher.update(signed_at.to_be_bytes());
    hasher.finalize().to_vec()
}

/// Derive one recipient-independent identity for an offline-candidate relay.
/// Every current-committee recipient therefore claims and acknowledges the
/// same logical observation, while the authenticated sender remains bound into
/// the ID so another participant cannot replay it as its own observation.
pub fn derive_offline_candidates_id(
    ceremony_id: CeremonyId,
    attempt_id: AttemptId,
    sender_peer: &[u8],
    stage: PssOfflineStage,
    accused: &[ParticipantRef],
) -> Result<MessageId, String> {
    let mut accused = accused.to_vec();
    accused.sort_unstable();
    accused.dedup();
    let mut hasher = Sha256::new();
    hasher.update(b"orbis-dkg-offline-candidates-v1");
    hasher.update(ceremony_id.0.to_be_bytes());
    hasher.update(attempt_id.0);
    hasher.update((sender_peer.len() as u64).to_be_bytes());
    hasher.update(sender_peer);
    hasher.update(encode(&stage)?);
    hasher.update(encode(&accused)?);
    Ok(MessageId(hasher.finalize().into()))
}
