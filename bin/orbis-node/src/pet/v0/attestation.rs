//! Signed evidence that a specific ring committee member genuinely computed
//! a given threshold PET-check contribution.
//!
//! Every PET check the initiator runs is only ever seen directly by the
//! initiator itself — a PRE peer gating its own reencryption share release
//! (see `pre::v0::coordinator::handlers::handle_reencrypt_request`) never
//! participated in that fan-out and has no authenticated channel to the
//! responders who computed it. A [`PetShareAttestation`] makes each
//! contribution portable: signed by the contributing node's own identity
//! key, it can be forwarded through the initiator and verified by any third
//! party against `ring_payload.peer_node_keys`, without that party trusting
//! the initiator's word or re-running the threshold fan-out itself.
//!
//! Reuses the same node-identity signing primitives as
//! `reporting::v0::relay_binding`'s `RelayRequestStatement` —
//! `common::blockchain::{sign_node_message_with_hex_key, verify_node_message}`
//! over each node's `LocalStorageKeys::NodeSigningKey` (secp256k1), already
//! verifiable by any other node via `ring_payload.peer_node_keys`.

use serde::{Deserialize, Serialize};

/// Domain-separates a PET-share signature from every other signed message
/// this codebase produces with the same node key (e.g. `RelayRequestStatement`).
const PET_SHARE_ATTESTATION_DOMAIN: &[u8] = b"orbis-pet-check-share-v0";

/// The exact bytes a committee member signs over its own threshold PET
/// contribution. Binding `tag_proof_digest` (the same transcript digest
/// `Pet::verify_tag_knowledge` checks) ties the signature to one specific
/// document/tag/ring/policy combination, so it can never be replayed
/// against a different document — even by the signer itself. Binding
/// `from_node_id` prevents a forwarder from relabeling whose contribution
/// this is; binding `partial` ties the signature to these exact bytes, so a
/// verifier trusts them outright rather than recomputing anything.
pub(crate) fn pet_share_signing_bytes(
    tag_proof_digest: &[u8; 32],
    from_node_id: u32,
    partial: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(PET_SHARE_ATTESTATION_DOMAIN.len() + 32 + 4 + partial.len());
    out.extend_from_slice(PET_SHARE_ATTESTATION_DOMAIN);
    out.extend_from_slice(tag_proof_digest);
    out.extend_from_slice(&from_node_id.to_be_bytes());
    out.extend_from_slice(partial);
    out
}

/// A single committee member's signed threshold PET-check contribution.
/// Forwarded alongside a `ReencryptRequest` (see
/// `pre::v0::messages::PreRequestContext::pet_attestations`) so a PRE peer
/// can verify a genuine PET check passed before releasing its share.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PetShareAttestation {
    pub from_node_id: u32,
    /// Serialized `Pet::PublicKey` — this node's `share_i * R`.
    pub partial: Vec<u8>,
    /// Signature over `pet_share_signing_bytes(tag_proof_digest, from_node_id, partial)`,
    /// verifiable against `ring_payload.peer_node_keys[from_node_id - 1]`
    /// (see `helpers::identity::node_key_for_id`) via
    /// `common::blockchain::verify_node_message`.
    pub signature: Vec<u8>,
}
