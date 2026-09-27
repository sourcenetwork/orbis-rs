//! PET Protocol Messages
//!
//! Wire messages for peer-to-peer threshold PET-check coordination between
//! orbis nodes. Never exposed externally — the only caller is PRE's own
//! `start_pre` pipeline, gated on a ring's `requires_pet`.

use authz::vera::ValidWindow;
use bulletin::r#trait::DocumentPayload;
use serde::{Deserialize, Serialize};

/// Everything a responder needs to independently verify a PET-check request
/// and compute its own threshold contribution — mirrors PRE's own
/// `PreRequestContext`: every peer re-derives and re-verifies this from
/// primary sources, never trusting the initiator's word.
///
/// Deliberately does *not* carry the audit target: computing a threshold
/// contribution (`share_i * R`) doesn't need to know which owner it will
/// ultimately be checked against — only the initiator needs the target, to
/// do the one final comparison after combining every contribution (see
/// `coordinator::initiator`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PetCheckContext {
    /// The full document payload — carries the tag, its knowledge proof, and
    /// everything `crypto::pet_context::tag_proof_digest` needs to rebuild
    /// the transcript digest independently. `ring_payload` is never carried
    /// on the wire — every responder reads it live from the bulletin by
    /// `document.ring_id`, exactly like PRE's own `resolve_document_and_ring_payloads`.
    pub document: DocumentPayload,
    /// The salt the requester supplied, needed to rebuild the exact
    /// `CiphertextContext` the payload's own encryption proof (and, in turn,
    /// the tag) was bound to. Not stored on `DocumentPayload` itself — mirrors
    /// `PreRequestContext::salt`.
    pub salt: Option<String>,
    /// The underlying PRE request's bulletin object id — bound into every
    /// responder's signed `PetCheckResponseStatement` (see
    /// `attestation::PetCheckStatementContext`) so a report co-signer that
    /// never saw this live round can still locate the same document.
    pub object_id: String,
    /// Whether the underlying PRE request's document was supplied inline
    /// rather than read from the bulletin — mirrors `PetCheckResponseStatement::document_inline`.
    pub document_inline: bool,
    /// Raw JWT authorizing this specific audit request (the same token the
    /// underlying PRE request was authorized with — a PET check never runs
    /// standalone). `handle_check_request` — the one entry point reachable
    /// from a raw wire message with no other upstream authentication —
    /// independently re-verifies it and binds it to `object_id`/`salt`
    /// before this node's secret share is ever touched, exactly like PRE's
    /// own responders re-verify `PreRequestContext::token_string`. Without
    /// this, a direct peer request could obtain a genuine contribution (and,
    /// combined with every other peer's, an equality oracle) for any
    /// document/target without ever going through the ACP-gated normal PRE
    /// entry point — see the PET audit fix checklist, finding #3.
    pub token_string: String,
    /// The plaintext owner identity being audited — not an ACP handle to
    /// resolve, see `pet::README.md`'s "no ACP identity-resolution step"
    /// invariant and `pre::v0::messages::PreRequestContext::audit_target_object_id`'s
    /// identical reasoning: this travels as a plain field because ACP
    /// itself (via `check_pet_permission`) is what protects it, not
    /// cryptographic binding to `token_string` — naming a target gets a
    /// caller nowhere without `token_string`'s authenticated actor genuinely
    /// holding permission on that exact object.
    pub audit_target_object_id: String,
    /// Time-bounded ACP validity window, forwarded from the same JWT-backed
    /// request that authorized the underlying PRE round.
    pub valid_window: Option<ValidWindow>,
}

/// Wire message sent from the coordinator to each ring node requesting this
/// node's threshold PET-check contribution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PetCheckRequest {
    pub request_id: String,
    pub from_node_id: u32,
    pub context: PetCheckContext,
}

/// PET protocol message types.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PetMessage {
    /// Request from coordinator to ring node for a threshold PET-check share.
    /// Boxed because the embedded document makes this the largest variant.
    CheckRequest(Box<PetCheckRequest>),
    /// Response from ring node to coordinator with its threshold contribution.
    CheckResponse {
        request_id: String,
        from_node_id: u32,
        /// Serialized `Pet::PublicKey` — this node's `share_i * R`.
        partial: Vec<u8>,
        /// Serialized `Pet::ShareValue` — the per-share DLEQ proof's
        /// Fiat-Shamir challenge.
        challenge: Vec<u8>,
        /// Serialized `Pet::ShareValue` — the per-share DLEQ proof's
        /// response.
        proof: Vec<u8>,
        /// Unix seconds at which this node produced and signed
        /// `signature` — part of the signed `PetCheckResponseStatement`.
        signed_at: u64,
        /// Signature over `PetCheckResponseStatement::canonical_bytes()`, so
        /// this contribution can be forwarded to and independently verified
        /// by a PRE peer that never received it directly — see
        /// `attestation::PetShareAttestation`.
        signature: Vec<u8>,
    },
    /// Error message.
    Error { request_id: String, error: String },
}

impl PetMessage {
    /// Get the request ID from any message.
    pub fn request_id(&self) -> &str {
        match self {
            PetMessage::CheckRequest(req) => &req.request_id,
            PetMessage::CheckResponse { request_id, .. } => request_id,
            PetMessage::Error { request_id, .. } => request_id,
        }
    }

    /// Get the from_node_id for response messages (used for deduplication).
    pub fn sender_node_id(&self) -> Option<u32> {
        match self {
            PetMessage::CheckResponse { from_node_id, .. } => Some(*from_node_id),
            _ => None,
        }
    }
}
