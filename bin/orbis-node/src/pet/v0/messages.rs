//! PET Protocol Messages
//!
//! Wire messages for the peer-to-peer threshold PET blind-equality-test
//! (commit/reveal/decrypt) between orbis nodes. Never exposed externally —
//! the only caller is PRE's own `start_pre` pipeline, gated on a ring's
//! `requires_pet`.
//!
//! Replaces the old single-round `CheckRequest`/`CheckResponse` entirely:
//! that protocol exposed the raw combined `x*R` to whoever ran the check,
//! letting them recover the owner's deterministic fingerprint on every
//! check regardless of match/mismatch.

use authz::request::ValidWindow;
use bulletin::r#trait::DocumentPayload;
use serde::{Deserialize, Serialize};

use crate::reporting::v0::types::PetBlindCertificate;

/// Everything a responder needs to independently verify a PET-check request
/// and compute its own contribution — mirrors PRE's own `PreRequestContext`:
/// every peer re-derives and re-verifies this from primary sources, never
/// trusting the initiator's word. Carried unchanged in every one of the
/// three phases' requests, and independently re-authenticated/re-authorized
/// at each one: each phase arrives as its own request, potentially relayed
/// by a different node than the last, so trusting an earlier phase's
/// approval would mean trusting that relay not to have tampered with
/// anything in between.
///
/// Deliberately does *not* carry the audit target's resolution beyond
/// `audit_target_object_id` itself: computing a blinding contribution needs
/// the target's fingerprint (to form `D = T - Y`), so unlike the old
/// protocol, every phase here *does* need this field — see this file's
/// module doc comment and `pet::README.md`'s "no ACP identity-resolution
/// step" invariant for why that's still safe.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PetCheckContext {
    /// Certified ring snapshot used to start this attempt.
    pub ring_state_sha256: String,
    /// Exact canonical PET polynomial fixed for this attempt.
    pub public_polynomial: Vec<u8>,
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
    /// responder's signed statements so a report co-signer that never saw
    /// this live round can still locate the same document.
    pub object_id: String,
    /// Whether the underlying PRE request's document was supplied inline
    /// rather than read from the bulletin.
    pub document_inline: bool,
    /// Raw JWT authorizing this specific audit request (the same token the
    /// underlying PRE request was authorized with — a PET check never runs
    /// standalone). Every phase's handler independently re-verifies it and
    /// binds it to `object_id`/`salt` before this node's secret share is
    /// ever touched, exactly like PRE's own responders re-verify
    /// `PreRequestContext::token_string`. Without this, a direct peer
    /// request could obtain a genuine contribution for any document/target
    /// without ever going through the ACP-gated normal PRE entry point.
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

/// Round 1 (Commit): request for a hiding commitment to a fresh blinding
/// contribution. Over-asked to every ring member; exactly `threshold` of the
/// responders are selected before anything sensitive is revealed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitRequest {
    /// Phase-specific transport id (`format!("commit-{attempt_id}")`).
    pub request_id: String,
    /// Stable across all three phases of this comparison — distinct from
    /// the outer PRE request id.
    pub attempt_id: String,
    pub from_node_id: u32,
    pub context: PetCheckContext,
}

/// Round 2 (Reveal): request that only the exact `threshold` participants
/// selected after round 1 ever receive. No substitution — a shortfall here
/// discards the whole attempt rather than swapping in a different blinder,
/// which would mix state across attempts in exactly the way the blinding
/// scheme's cancellation-attack protection depends on not happening.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevealRequest {
    pub request_id: String,
    pub attempt_id: String,
    pub from_node_id: u32,
    /// The exact, sorted selected list — `(node_id, commitment)` pairs, not
    /// every over-asked round-1 candidate.
    pub all_commitments: Vec<(u32, Vec<u8>)>,
    pub context: PetCheckContext,
}

/// Round 3 (Decrypt): request to thresh­old-decrypt the certificate's
/// aggregate points. Independent of round 2's participant set — over-asked
/// again, freely substitutable, exactly like ordinary threshold decryption.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptRequest {
    pub request_id: String,
    pub attempt_id: String,
    pub from_node_id: u32,
    /// The complete, independently verifiable round-2 output — never just a
    /// bare list of point pairs.
    pub certificate: PetBlindCertificate,
    pub context: PetCheckContext,
}

/// PET protocol message types.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PetMessage {
    /// Boxed like the other two request variants: the embedded document
    /// makes `PetCheckContext` the largest field in every one of them.
    CommitRequest(Box<CommitRequest>),
    CommitResponse {
        request_id: String,
        attempt_id: String,
        /// Recomputed independently by the receiver, never trusted as-is —
        /// carried so a decode/mismatch can be attributed without a second
        /// round trip.
        context_digest: [u8; 32],
        from_node_id: u32,
        /// `C_i` — see `reporting::v0::types::pet_blind_commit_hash`.
        commitment: Vec<u8>,
    },
    RevealRequest(Box<RevealRequest>),
    RevealResponse {
        request_id: String,
        attempt_id: String,
        context_digest: [u8; 32],
        selection_digest: [u8; 32],
        from_node_id: u32,
        /// This node's own `C_i`, re-endorsed.
        commitment: Vec<u8>,
        /// Serialized `Pet::PublicKey` — `A_i = z_i·R`.
        blinded_r: Vec<u8>,
        /// Serialized `Pet::PublicKey` — `B_i = z_i·(T-Y)`. May legitimately
        /// be the identity point (an exact pre-blinding match).
        blinded_diff: Vec<u8>,
        /// Opens `commitment`; never `z_i` itself.
        commit_salt: [u8; 32],
        /// Serialized `Pet::ShareValue` — the blinding-correctness proof's
        /// Fiat-Shamir challenge.
        challenge: Vec<u8>,
        /// Serialized `Pet::ShareValue` — the blinding-correctness proof's
        /// response.
        proof: Vec<u8>,
        signed_at: u64,
        /// Signature over `PetBlindRevealStatement::canonical_bytes()`.
        response_signature: Vec<u8>,
    },
    DecryptRequest(Box<DecryptRequest>),
    DecryptResponse {
        request_id: String,
        attempt_id: String,
        context_digest: [u8; 32],
        certificate_digest: [u8; 32],
        from_node_id: u32,
        /// Serialized `Pet::PublicKey` — reconstructed `Z·R`.
        aggregate_r: Vec<u8>,
        /// Serialized `Pet::PublicKey` — reconstructed `Z·(T-Y)`.
        aggregate_diff: Vec<u8>,
        /// Serialized `Pet::PublicKey` — this node's `share_i·(Z·R)`.
        partial: Vec<u8>,
        /// Serialized `Pet::ShareValue` — the existing per-share decryption
        /// DLEQ's Fiat-Shamir challenge, run against `Z·R` in place of the
        /// old protocol's `R`.
        challenge: Vec<u8>,
        /// Serialized `Pet::ShareValue` — the decryption DLEQ's response.
        proof: Vec<u8>,
        signed_at: u64,
        /// Serialized `Pet::PubPoly` — the exact polynomial `partial` was
        /// computed against. Lets any verifier (live round or later report
        /// validation) authenticate this against the ring's known `pet_pk`
        /// regardless of which generation it is.
        public_polynomial: Vec<u8>,
        /// Signature over `PetBlindDecryptStatement::canonical_bytes()`.
        response_signature: Vec<u8>,
    },
    /// The peer has a different local generation; start a fresh attempt after convergence.
    GenerationMismatch {
        request_id: String,
    },
    /// Error message.
    Error {
        request_id: String,
        error: String,
    },
}

impl PetMessage {
    /// Get the request ID from any message.
    pub fn request_id(&self) -> &str {
        match self {
            PetMessage::CommitRequest(req) => &req.request_id,
            PetMessage::CommitResponse { request_id, .. } => request_id,
            PetMessage::RevealRequest(req) => &req.request_id,
            PetMessage::RevealResponse { request_id, .. } => request_id,
            PetMessage::DecryptRequest(req) => &req.request_id,
            PetMessage::DecryptResponse { request_id, .. } => request_id,
            PetMessage::Error { request_id, .. }
            | PetMessage::GenerationMismatch { request_id } => request_id,
        }
    }

    /// Get the from_node_id for response messages (used for deduplication).
    pub fn sender_node_id(&self) -> Option<u32> {
        match self {
            PetMessage::CommitResponse { from_node_id, .. }
            | PetMessage::RevealResponse { from_node_id, .. }
            | PetMessage::DecryptResponse { from_node_id, .. } => Some(*from_node_id),
            _ => None,
        }
    }
}
