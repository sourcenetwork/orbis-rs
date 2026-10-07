//! Shared context construction and reporting glue for the PET blind
//! equality test — the multi-round blinded check protocol (commit a
//! blinded candidate set, reveal a selected subset, prove decryption
//! against each node's own blinded share) that replaced PET's original
//! single-round check, which leaked information about the plaintext
//! fingerprint across repeated checks.
//!
//! [`build_pet_blind_context`] builds the one canonical
//! [`PetBlindContext`] every participant in a given attempt independently
//! recomputes from its own verified inputs — never trusted as a bare digest
//! from the coordinator. It is used identically by the initiator's own local
//! contribution, every incoming commit/reveal/decrypt handler, and PRE
//! admission's independent re-check, mirroring the role
//! `PetCheckStatementContext` played for the old single-round protocol
//! (still used for evidence-verification bookkeeping only, see this file's
//! git history for that superseded protocol's shape).

use crate::pet::v0::messages::PetCheckContext;
use crate::reporting::v0::observation::InvalidCryptoResponseObservation;
use crate::reporting::v0::types::{
    ring_state_sha256, InvalidCryptoResponse, PetBlindCertificate, PetBlindContext,
    PetBlindDecryptStatement, PetBlindRevealStatement, PetBlindSignedDecrypt,
    ReportedDocumentEvidence, CHAIN_BLOCK_GRACE_SECS,
};
use serde::{Deserialize, Serialize};

/// The portable result of a completed blind equality test: the fully
/// verified round-2 certificate plus at least `threshold` signed round-3
/// decrypt responses, forwarded to every PRE peer (via
/// `pre::v0::messages::PreRequestContext::pet_evidence`) so each one can
/// independently verify the check passed before releasing its reencryption
/// share — see `coordinator::verification::verify_pet_admission`.
///
/// `coordinator_node_key` is this attempt's coordinator (the node that ran
/// `initiate_pet_check`) — unauthenticated as a bare wire claim, but
/// self-correcting: it feeds `PetBlindContext::coordinator_node_key`, and a
/// wrong claim fails admission's independently recomputed `context_digest`
/// comparison against the certificate's own signed contents.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PetBlindEvidence {
    pub certificate: PetBlindCertificate,
    pub decrypt_responses: Vec<PetBlindSignedDecrypt>,
    pub coordinator_node_key: String,
}

/// Build the canonical [`PetBlindContext`] for one attempt from independently
/// verified inputs. `pet_pk_hex`/`ring_payload` must come from a live
/// bulletin read (never a caller-supplied value); `coordinator_node_key` must
/// be either this node's own identity (when it is itself the coordinator) or
/// resolved from an authenticated transport peer id against the ring
/// committee (never taken from an unauthenticated request field) — see
/// `coordinator::verification::resolve_coordinator_node_key`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_pet_blind_context(
    chain_id: String,
    ring_payload: &bulletin::r#trait::RingPayload,
    pet_pk_hex: &str,
    protocol_version: u64,
    crypto_backend: String,
    ctx: &PetCheckContext,
    actor_id: String,
    coordinator_node_key: String,
    attempt_id: String,
) -> PetBlindContext {
    PetBlindContext {
        chain_id,
        protocol_version,
        crypto_backend,
        ring_id: ctx.document.ring_id.clone(),
        ring_pk: ring_payload.ring_pk.clone(),
        ring_state_sha256: ring_state_sha256(ring_payload),
        pet_pk: pet_pk_hex.to_string(),
        public_polynomial_digest: crate::reporting::v0::types::pet_public_polynomial_digest(
            &ctx.public_polynomial,
        ),
        object_id: ctx.object_id.clone(),
        salt: ctx.salt.clone(),
        timestamp: ctx.document.timestamp,
        document_inline: ctx.document_inline,
        audit_target_object_id: ctx.audit_target_object_id.clone(),
        actor_id,
        valid_window_start: ctx.valid_window.as_ref().map(|window| window.start),
        valid_window_end: ctx.valid_window.as_ref().map(|window| window.end),
        coordinator_node_key,
        attempt_id,
    }
}

/// Build the `InvalidCryptoResponseObservation` for a reveal-phase
/// contribution whose blinding-correctness proof failed verification, or
/// which did not open its own committed commitment — shared by the live
/// collector (`coordinator::initiator`) and the PRE-peer admission re-check
/// (`coordinator::verification::verify_pet_admission`), which differ only in
/// how they resolve `accused_peer_id` — mirrors
/// `reporting::v0::relay_binding::queue_unauthorized_request_report`'s same
/// resolution for the same reason.
///
/// `observed_at` is pinned to `statement.signed_at - CHAIN_BLOCK_GRACE_SECS`,
/// matching every other invalid-crypto-response observation in this
/// codebase, so the envelope anchors to the evidence timestamp rather than
/// to whenever this node happened to notice the failure.
#[allow(clippy::too_many_arguments)]
pub(crate) fn invalid_pet_blind_reveal_observation(
    ring_id: String,
    accused_node_key: String,
    accused_peer_id: String,
    context: PetBlindContext,
    statement: PetBlindRevealStatement,
    response_signature: Vec<u8>,
    inline_document: Option<ReportedDocumentEvidence>,
) -> InvalidCryptoResponseObservation {
    let observed_at = statement.signed_at.saturating_sub(CHAIN_BLOCK_GRACE_SECS);
    InvalidCryptoResponseObservation {
        ring_id,
        accused_node_key,
        accused_peer_id,
        observed_at,
        evidence: InvalidCryptoResponse::PetBlindReveal {
            statement,
            response_signature,
        },
        inline_document,
        pet_blind_context: Some(context),
        pet_blind_certificate: None,
    }
}

/// Same as [`invalid_pet_blind_reveal_observation`], for a decrypt-phase
/// contribution whose decryption DLEQ proof failed verification against
/// `Z·R` (the certificate's reconstructed aggregate ephemeral point, not the
/// old protocol's bare `R`).
#[allow(clippy::too_many_arguments)]
pub(crate) fn invalid_pet_blind_decrypt_observation(
    ring_id: String,
    accused_node_key: String,
    accused_peer_id: String,
    context: PetBlindContext,
    statement: PetBlindDecryptStatement,
    response_signature: Vec<u8>,
    inline_document: Option<ReportedDocumentEvidence>,
    certificate: PetBlindCertificate,
) -> InvalidCryptoResponseObservation {
    let observed_at = statement.signed_at.saturating_sub(CHAIN_BLOCK_GRACE_SECS);
    InvalidCryptoResponseObservation {
        ring_id,
        accused_node_key,
        accused_peer_id,
        observed_at,
        evidence: InvalidCryptoResponse::PetBlindDecrypt {
            statement,
            response_signature,
        },
        inline_document,
        pet_blind_context: Some(context),
        pet_blind_certificate: Some(certificate),
    }
}
