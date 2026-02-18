//! Sign Protocol Messages
//!
//! This module defines the message types used for threshold BLS signing
//! protocol communication between nodes over the network.

use serde::{Deserialize, Serialize};

/// Verification strategy for sign requests.
///
/// Determines how responder nodes verify that a message should be signed.
/// The initiator sets this based on the signing context (store_secret vs utility service).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SignVerification {
    /// Verify message exists on bulletin (store_secret path).
    /// Responder deserializes message as BulletinPost, reads from bulletin, verifies payload match.
    Bulletin,
    /// Message was authenticated at the gRPC layer (utility service path).
    /// Responder trusts that the initiator verified the JWT. Ring routing comes from ring_id field.
    Authenticated,
}

/// Sign protocol message types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SignMessage {
    /// Request from coordinator to ring node for nonce commitments (FROST Round 1)
    NonceRequest {
        request_id: String,
        from_node_id: u32,
        /// Serialized ring public key (used to look up DKG share)
        ring_pk: Vec<u8>,
    },
    /// Response with nonce commitment (FROST Round 1)
    NonceResponse {
        request_id: String,
        from_node_id: u32,
        /// Serialized NonceCommitment
        nonce_commitment: Vec<u8>,
    },
    /// Request from coordinator to ring node for signing
    SignRequest {
        request_id: String,
        from_node_id: u32,
        /// Raw message to sign (will be hashed internally using hash-to-curve)
        message: Vec<u8>,
        /// Serialized list of (node_id, commitment_bytes) for FROST; empty for BLS
        all_commitments: Vec<u8>,
        /// Ring ID for routing (used to look up ring info on bulletin)
        ring_id: String,
        /// How responders should verify this message before signing
        verification: SignVerification,
    },
    /// Response from ring node to coordinator with signature share
    SignResponse {
        request_id: String,
        from_node_id: u32,
        /// Serialized signature share
        sig_share: Vec<u8>,
    },
    /// Error message
    Error { request_id: String, error: String },
}

impl SignMessage {
    /// Get the request ID from any message
    pub fn request_id(&self) -> &str {
        match self {
            SignMessage::NonceRequest { request_id, .. } => request_id,
            SignMessage::NonceResponse { request_id, .. } => request_id,
            SignMessage::SignRequest { request_id, .. } => request_id,
            SignMessage::SignResponse { request_id, .. } => request_id,
            SignMessage::Error { request_id, .. } => request_id,
        }
    }

    /// Get the from_node_id for response messages (used for deduplication)
    pub fn from_node_id(&self) -> Option<u32> {
        match self {
            SignMessage::NonceResponse { from_node_id, .. } => Some(*from_node_id),
            SignMessage::SignResponse { from_node_id, .. } => Some(*from_node_id),
            _ => None,
        }
    }
}
