//! Sign Protocol Messages
//!
//! This module defines the message types used for threshold BLS signing
//! protocol communication between nodes over the network.

use serde::{Deserialize, Serialize};

/// Sign protocol message types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SignMessage {
    /// Request from coordinator to ring node for signing
    SignRequest {
        request_id: String,
        from_node_id: u32,
        /// Raw message to sign (will be hashed internally using hash-to-curve)
        message: Vec<u8>,
    },
    /// Response from ring node to coordinator with signature share
    SignResponse {
        request_id: String,
        from_node_id: u32,
        /// Serialized signature share (G2Point)
        sig_share: Vec<u8>,
    },
    /// Error message
    Error { request_id: String, error: String },
}

impl SignMessage {
    /// Get the request ID from any message
    pub fn request_id(&self) -> &str {
        match self {
            SignMessage::SignRequest { request_id, .. } => request_id,
            SignMessage::SignResponse { request_id, .. } => request_id,
            SignMessage::Error { request_id, .. } => request_id,
        }
    }
}
