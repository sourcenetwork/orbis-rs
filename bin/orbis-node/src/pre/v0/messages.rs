//! PRE Protocol Messages
//!
//! This module defines the message types used for PRE (Proxy Re-Encryption)
//! protocol communication between nodes over the iroh network.

use authz::sourcehub::ValidWindow;
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
    /// the relaying node via an `unauthorized_request` report. Always set on the live relay path;
    /// `None` only in unit tests that construct the context directly.
    pub relay_statement: Option<crate::reporting::v0::types::RelayRequestStatement>,
    pub relay_signature: Vec<u8>,
}

/// Wire message sent from the coordinator to each ring node requesting a reencryption share.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReencryptRequest {
    pub request_id: String,
    pub from_node_id: u32,
    pub context: PreRequestContext,
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
    /// Error message
    Error { request_id: String, error: String },
}

impl PreMessage {
    /// Get the request ID from any message
    pub fn request_id(&self) -> &str {
        match self {
            PreMessage::ReencryptRequest(req) => &req.request_id,
            PreMessage::ReencryptResponse { request_id, .. } => request_id,
            PreMessage::Error { request_id, .. } => request_id,
        }
    }

    /// Get the from_node_id for response messages (used for deduplication)
    pub fn sender_node_id(&self) -> Option<u32> {
        match self {
            PreMessage::ReencryptResponse { from_node_id, .. } => Some(*from_node_id),
            _ => None,
        }
    }
}
