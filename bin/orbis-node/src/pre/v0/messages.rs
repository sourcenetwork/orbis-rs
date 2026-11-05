//! PRE Protocol Messages
//!
//! This module defines the message types used for PRE (Proxy Re-Encryption)
//! protocol communication between nodes over the iroh network.

use crate::pet::v0::attestation::PetBlindEvidence;
use authz::request::ValidWindow;
use crypto::r#trait::ReaderAuthorizationSignature;
use orbis_reporting::codec::{write_bytes, write_string, write_u32, write_u64};
use pre_share::DefraLocator;
use serde::{Deserialize, Serialize};

/// All parameters specific to a reencryption request.
///
/// Mirrors the role of `SignContext` in the sign protocol — groups the auth,
/// object identity, and crypto material that travel together through the PRE
/// coordinator call chain and are forwarded to each ring node in the network
/// message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreRequestContext {
    /// Serialized reader public key (G1Affine)
    pub rdr_pk_bytes: Vec<u8>,
    /// Signature of knowledge of `rdr_pk_bytes`'s discrete log, bound to this
    /// request's [`crypto::context::ReaderAuthorizationContext`]. Verified by
    /// every responder inside `ThresholdDealer::reencrypt` against its own
    /// independently rebuilt context, not only the ingress node — without it,
    /// a caller authorized for one ciphertext can redirect PRE toward an
    /// unrelated one under the same ring key by submitting a difference of
    /// two published commitments as `rdr_pk`, and without the request-binding
    /// half, a valid signature from one request could be replayed into a
    /// different one.
    pub rdr_pk_signature: ReaderAuthorizationSignature,
    /// Object ID of the encrypted document on the bulletin
    pub object_id: String,
    /// Raw JWT string issued by the caller
    pub token_string: String,
    /// Optional key derivation bytes
    pub derivation: Option<Vec<u8>>,
    /// Optional salt for policy metadata binding
    pub salt: Option<String>,
    /// Optional valid window for time-bounded authz checks
    pub valid_window: Option<ValidWindow>,
    /// The relayer's signed record of this request, so a peer whose ACP re-check fails can attribute
    /// the relaying node via an `unauthorized_request` report. Always set on the live relay path,
    /// including the inline-document path (the statement carries the inline document's evidence so
    /// it can be re-verified without reading the bulletin); `None` only in unit tests that construct
    /// the context directly.
    pub relay_statement: Option<crate::reporting::v0::types::RelayRequestStatement>,
    pub relay_signature: Vec<u8>,
    /// Present only when the caller supplied the document inline instead of posting it to the
    /// bulletin first. Every node (leader and cascaded committee members) uses this directly and
    /// independently re-verifies it via `check_document_id_binding` — mirrors the existing
    /// pattern where each node independently re-does `check_policy_access`/`verify_encryption_binding`
    /// rather than trusting the relay's word. `None` means the document is read from the bulletin
    /// by `object_id`, exactly as before this field existed.
    pub document: Option<bulletin::r#trait::DocumentPayload>,
    /// The plaintext owner identity being audited, present only for a `requires_pet` ring — not
    /// an ACP handle to resolve, see `pet::README.md`'s "no ACP identity-resolution step"
    /// invariant. Every committee member independently re-checks `check_pet_permission` and
    /// re-verifies the PET match itself against this value (see
    /// `pet::v0::coordinator::verification::verify_pet_admission`) rather than trusting this
    /// node's word that the check passed — that independent verification is only meaningful if
    /// the verifier knows what it's checking, so unlike every other PET-internal message, this
    /// deliberately exposes the audit target to the whole ring committee, not just the initiator.
    pub audit_target_object_id: Option<String>,
    /// Signed, portable evidence that a genuine PET blind equality test passed for this document
    /// — see `PetBlindEvidence`. `None` for a ring that doesn't require PET; always `Some` otherwise,
    /// since `check_pet_if_required` already aborted `start_pre` on any failure or shortfall before
    /// a `ReencryptRequest` is ever built.
    pub pet_evidence: Option<PetBlindEvidence>,
    /// Hex-encoded public polynomial of the PSS generation the coordinator pinned this request
    /// to, read from the exact same atomic local-storage snapshot used for the coordinator's own
    /// local share and for verifying every peer's response (see
    /// `coordinator::initiator::resolve_reencryption_material`) — never set any earlier, since an
    /// earlier read could disagree with that snapshot if a PSS ceremony completes in between. Each
    /// responder (`coordinator::handlers::handle_reencrypt_request`) rejects when its own local
    /// `RingShareBundle.public_polynomial` doesn't match this value, instead of silently serving a
    /// share from the wrong generation. Left empty by the stage that first constructs this context
    /// (`service::stages::prepare_pre_relay`) and overwritten with the real value in
    /// `initiate_reencryption_inner` right before dispatch.
    pub pinned_public_polynomial: String,
}

/// Wire message sent from the coordinator to each ring node requesting a reencryption share.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReencryptRequest {
    pub request_id: String,
    pub from_node_id: u32,
    pub context: PreRequestContext,
}

/// Stored-delivery acknowledgement a responder returns to the relayer in place of
/// `PreMessage::ReencryptResponse` when the ring's `pre_share_endpoints` configures Defra
/// storage (the branch itself is wired in a later step). The relayer only ever validates this
/// ack's identity and context — that it genuinely came from this responder, for this exact
/// request, under the pinned generation — never the cryptographic validity of the stored share;
/// that's left entirely to the reader, against the fetched, signed envelope
/// (`pre_share::SignedStoredShareEnvelope`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredShareAck {
    pub request_id: String,
    pub from_node_id: u32,
    /// Where the signed envelope landed. Opaque for now — Step 3 (the Defra storage client)
    /// decides the real addressing scheme.
    pub defra_locator: DefraLocator,
    /// SHA-256 digest of the signed envelope's serialized bytes — binds this ack to the exact
    /// envelope produced, without the relayer fetching from Defra just to bookkeep.
    pub envelope_sha256: Vec<u8>,
    /// Echoed from `PreRequestContext::pinned_public_polynomial` so the relayer can confirm
    /// every ack it counts pinned the same generation without inspecting envelope contents.
    pub pinned_public_polynomial: String,
    /// Unix seconds when the responder signed this ack; covered by `ack_signature`, so it
    /// cannot be forged after the fact.
    pub signed_at: u64,
    pub ack_signature: Vec<u8>,
}

impl StoredShareAck {
    /// Field order is the canonical wire contract for `ack_signature` — same pattern as
    /// `PreReencryptResponseStatement::canonical_bytes` (`orbis_reporting`).
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        write_string(&mut out, &self.request_id);
        write_u32(&mut out, self.from_node_id);
        write_string(&mut out, &self.defra_locator.0);
        write_bytes(&mut out, &self.envelope_sha256);
        write_string(&mut out, &self.pinned_public_polynomial);
        write_u64(&mut out, self.signed_at);
        out
    }
}

/// PRE protocol message types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PreMessage {
    /// Request from coordinator to ring node for reencryption.
    /// Boxed because the relay statement makes this the largest variant.
    ReencryptRequest(Box<ReencryptRequest>),
    /// Response from ring node to coordinator with reencryption share
    ReencryptResponse {
        request_id: String,
        from_node_id: u32,
        share: Vec<u8>,     // Serialized PubShare<G1Affine>
        challenge: Vec<u8>, // Serialized Fr (for NIZK proof)
        proof: Vec<u8>,     // Serialized Fr (for NIZK proof)
        /// Unix seconds when the responder signed the response statement;
        /// covered by `response_signature`, so it cannot be forged after the fact.
        signed_at: u64,
        response_signature: Vec<u8>,
    },
    /// Response from a ring node that stored its share in Defra instead of returning it
    /// directly — the `pre_share_endpoints` delivery mode. See `StoredShareAck`.
    ReencryptStored(StoredShareAck),
    /// Error message
    Error { request_id: String, error: String },
}

impl PreMessage {
    /// Get the request ID from any message
    pub fn request_id(&self) -> &str {
        match self {
            PreMessage::ReencryptRequest(req) => &req.request_id,
            PreMessage::ReencryptResponse { request_id, .. } => request_id,
            PreMessage::ReencryptStored(ack) => &ack.request_id,
            PreMessage::Error { request_id, .. } => request_id,
        }
    }

    /// Get the from_node_id for response messages (used for deduplication)
    pub fn sender_node_id(&self) -> Option<u32> {
        match self {
            PreMessage::ReencryptResponse { from_node_id, .. } => Some(*from_node_id),
            PreMessage::ReencryptStored(ack) => Some(ack.from_node_id),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::blockchain::{sign_node_message_with_hex_key, verify_node_message};

    const SIGNING_KEY_HEX: &str =
        "c4a48e2fce1481cd3294b4490f6678090ea98d3d0e5cd984558ab0968741b104";
    const PUBLIC_KEY_HEX: &str =
        "024f4e2ad99c34d60b9ba6283c9431a8418af8673212961f97a77b6377fcd05b62";

    fn sample_ack() -> StoredShareAck {
        let mut ack = StoredShareAck {
            request_id: "req-1".to_string(),
            from_node_id: 1,
            defra_locator: DefraLocator("doc-1".to_string()),
            envelope_sha256: vec![1, 2, 3],
            pinned_public_polynomial: "poly-gen-1".to_string(),
            signed_at: 1_700_000_000,
            ack_signature: Vec::new(),
        };
        ack.ack_signature =
            sign_node_message_with_hex_key(SIGNING_KEY_HEX, &ack.canonical_bytes()).unwrap();
        ack
    }

    #[test]
    fn ack_signature_round_trips() {
        let ack = sample_ack();
        verify_node_message(PUBLIC_KEY_HEX, &ack.canonical_bytes(), &ack.ack_signature)
            .expect("verify ack signature");
    }

    #[test]
    fn ack_signature_rejects_tampered_locator() {
        let mut ack = sample_ack();
        ack.defra_locator = DefraLocator("doc-evil".to_string());
        assert!(
            verify_node_message(PUBLIC_KEY_HEX, &ack.canonical_bytes(), &ack.ack_signature)
                .is_err()
        );
    }

    #[test]
    fn ack_signature_rejects_tampered_pinned_polynomial() {
        let mut ack = sample_ack();
        ack.pinned_public_polynomial = "poly-gen-2".to_string();
        assert!(
            verify_node_message(PUBLIC_KEY_HEX, &ack.canonical_bytes(), &ack.ack_signature)
                .is_err()
        );
    }

    #[test]
    fn pre_message_dispatches_stored_ack_by_request_id_and_node_id() {
        let message = PreMessage::ReencryptStored(sample_ack());
        assert_eq!(message.request_id(), "req-1");
        assert_eq!(message.sender_node_id(), Some(1));
    }
}
