//! PRE Protocol Messages
//!
//! This module defines the message types used for PRE (Proxy Re-Encryption)
//! protocol communication between nodes over the iroh network.

use serde::{Deserialize, Serialize};

/// PRE protocol message types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PreMessage {
    /// Request from coordinator to ring node for reencryption
    ReencryptRequest {
        request_id: String,
        from_node_id: u32,
        secret: Vec<u8>,  // Serialized Secret
        rdr_pk: Vec<u8>,  // Serialized reader public key (G1Affine)
        ring_pk: Vec<u8>, // Ring's aggregate public key (for identifying DKG session)
        policy_id: String,
        resource: String,
        object_id: String,
        permission: String,
        token_string: String, // Client's token passed to ring nodes for auth
    },
    /// Response from ring node to coordinator with reencryption share
    ReencryptResponse {
        request_id: String,
        from_node_id: u32,
        share: Vec<u8>,     // Serialized PubShare<G1Affine>
        challenge: Vec<u8>, // Serialized Fr (for NIZK proof)
        proof: Vec<u8>,     // Serialized Fr (for NIZK proof)
    },
    /// Error message
    Error { request_id: String, error: String },
}

impl PreMessage {
    /// Get the request ID from any message
    pub fn request_id(&self) -> &str {
        match self {
            PreMessage::ReencryptRequest { request_id, .. } => request_id,
            PreMessage::ReencryptResponse { request_id, .. } => request_id,
            PreMessage::Error { request_id, .. } => request_id,
        }
    }
}
