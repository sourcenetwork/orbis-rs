//! PET Protocol Messages
//!
//! Wire messages for peer-to-peer threshold PET-check coordination between
//! orbis nodes. Never exposed externally — the only caller is PRE's own
//! `start_pre` pipeline, gated on a ring's `requires_pet`.

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
        /// Signature over `attestation::pet_share_signing_bytes(digest, from_node_id, partial)`,
        /// so this contribution can be forwarded to and independently
        /// verified by a PRE peer that never received it directly — see
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
