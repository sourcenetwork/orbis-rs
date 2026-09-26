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
//! **One canonical statement, not two.** The signature covers exactly one
//! `PetCheckResponseStatement` (`reporting::v0::types::pet`) — the same type
//! reused verbatim as `InvalidCryptoResponse::Pet` report evidence when a
//! contribution fails verification. Every verifier (the live collector in
//! `coordinator::initiator`, the PRE-peer re-check in
//! `coordinator::verification::verify_pet_admission`, and a report
//! co-signer in `reporting::v0::registry::invalid_crypto::pet`) reconstructs
//! the identical statement from a mix of its own already-trusted context
//! (chain id, ring state, request id, ...) and these thin wire fields, then
//! checks the signature against that reconstruction — mirroring exactly how
//! PRE has one `PreReencryptResponseStatement` used the same way across its
//! live response path and its report evidence. Maintaining two
//! independently-designed signed messages here (one for live use, one for
//! reporting) would risk them drifting out of sync; this doesn't have that
//! problem because there is only one.
//!
//! Reuses the same node-identity signing primitives as
//! `reporting::v0::relay_binding`'s `RelayRequestStatement` —
//! `common::blockchain::{sign_node_message_with_hex_key, verify_node_message}`
//! over each node's `LocalStorageKeys::NodeSigningKey` (secp256k1), already
//! verifiable by any other node via `ring_payload.peer_node_keys`.

use crate::reporting::v0::observation::InvalidCryptoResponseObservation;
use crate::reporting::v0::types::{
    InvalidCryptoResponse, PetCheckResponseStatement, ReportedDocumentEvidence,
    CHAIN_BLOCK_GRACE_SECS, PET_CHECK_RESPONSE_DOMAIN,
};
use serde::{Deserialize, Serialize};

/// A single committee member's signed threshold PET-check contribution.
/// Forwarded alongside a `ReencryptRequest` (see
/// `pre::v0::messages::PreRequestContext::pet_attestations`) so a PRE peer
/// can verify a genuine PET check passed before releasing its share.
///
/// Thin on the wire by design: every field a verifier can already derive
/// from its own trusted context (chain id, ring state, request id, salt,
/// object id, crypto backend, ...) is *not* repeated here — see
/// [`PetCheckStatementContext::statement_for`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PetShareAttestation {
    /// The PET-check round this contribution was computed for — bound into
    /// the signed statement so a stale attestation from an unrelated round
    /// can't silently be mixed in; carried per-attestation (rather than
    /// assumed shared) since a verifier reconstructing this from a forwarded
    /// list has no other source for it.
    pub request_id: String,
    pub from_node_id: u32,
    /// Serialized `Pet::PublicKey` — this node's `share_i * R`.
    pub partial: Vec<u8>,
    /// Serialized `Pet::ShareValue` — the per-share DLEQ proof's Fiat-Shamir
    /// challenge.
    pub challenge: Vec<u8>,
    /// Serialized `Pet::ShareValue` — the per-share DLEQ proof's response.
    pub proof: Vec<u8>,
    /// Unix seconds at which the responder produced and signed `signature`.
    pub signed_at: u64,
    /// Signature over `PetCheckResponseStatement::canonical_bytes()`,
    /// verifiable against `ring_payload.peer_node_keys[from_node_id - 1]`
    /// (see `helpers::identity::node_key_for_id`) via
    /// `common::blockchain::verify_node_message`.
    pub signature: Vec<u8>,
}

/// Everything needed to reconstruct a [`PetCheckResponseStatement`] except
/// the per-contribution fields (`request_id`/`from_node_id`/`partial`/
/// `challenge`/`proof`/`signed_at`/`responder_node_key`) — built once per
/// verifying context (the round being run live, or a PRE peer's independent
/// re-check) by whoever holds the authoritative ring/document context (the
/// initiator in `coordinator::initiator`, the responder in
/// `coordinator::handlers`, the PRE peer in `coordinator::verification`),
/// then reused for every contribution checked in that context.
pub(crate) struct PetCheckStatementContext {
    pub chain_id: String,
    pub ring_id: String,
    pub ring_pk: String,
    pub ring_state_sha256: String,
    pub protocol_version: u64,
    pub object_id: String,
    pub salt: Option<String>,
    pub crypto_backend: String,
    pub document_inline: bool,
}

impl PetCheckStatementContext {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn statement_for(
        &self,
        responder_node_key: String,
        request_id: String,
        signed_at: u64,
        from_node_id: u32,
        partial: Vec<u8>,
        challenge: Vec<u8>,
        proof: Vec<u8>,
    ) -> PetCheckResponseStatement {
        PetCheckResponseStatement {
            domain: PET_CHECK_RESPONSE_DOMAIN.to_string(),
            chain_id: self.chain_id.clone(),
            ring_id: self.ring_id.clone(),
            ring_pk: self.ring_pk.clone(),
            ring_state_sha256: self.ring_state_sha256.clone(),
            protocol_version: self.protocol_version,
            request_id,
            signed_at,
            responder_node_key,
            origin_protocol: "pet".to_string(),
            object_id: self.object_id.clone(),
            salt: self.salt.clone(),
            from_node_id,
            partial,
            challenge,
            proof,
            crypto_backend: self.crypto_backend.clone(),
            document_inline: self.document_inline,
        }
    }
}

/// Build the `InvalidCryptoResponseObservation` for a PET contribution whose
/// per-share DLEQ proof failed verification — shared by the live collector
/// (`coordinator::initiator`) and the PRE-peer admission re-check
/// (`coordinator::verification::verify_pet_admission`), which differ only in
/// how they resolve `accused_peer_id` (a live connection's own peer id vs. a
/// bulletin `NodeInfo` lookup, since admission re-checking has no live
/// connection to the accused node — mirrors
/// `reporting::v0::relay_binding::queue_unauthorized_request_report`'s same
/// resolution for the same reason).
///
/// `observed_at` is pinned to `statement.signed_at - CHAIN_BLOCK_GRACE_SECS`,
/// matching every other invalid-crypto-response observation in this
/// codebase, so the envelope anchors to the evidence timestamp rather than
/// to whenever this node happened to notice the failure.
pub(crate) fn invalid_pet_response_observation(
    ring_id: String,
    accused_node_key: String,
    accused_peer_id: String,
    statement: PetCheckResponseStatement,
    response_signature: Vec<u8>,
    inline_document: Option<ReportedDocumentEvidence>,
) -> InvalidCryptoResponseObservation {
    let observed_at = statement.signed_at.saturating_sub(CHAIN_BLOCK_GRACE_SECS);
    InvalidCryptoResponseObservation {
        ring_id,
        accused_node_key,
        accused_peer_id,
        observed_at,
        evidence: InvalidCryptoResponse::Pet {
            statement,
            response_signature,
        },
        inline_document,
    }
}
