//! Sign Protocol Messages
//!
//! This module defines the message types used for threshold BLS signing
//! protocol communication between nodes over the network.

use authz::sourcehub::ValidWindow;
use bulletin::r#trait::KeyDerivation;
use serde::{Deserialize, Serialize};

/// Distinguishes the two signing pathways.
///
/// - `Bulletin`: message is a serialized `BulletinPost`; authorization is its existence on chain.
///   Signs from the root key (no derivation, no metadata).
/// - `Policy`: policy-authorized derivation signing with JWT auth, mirrors the PRE flow.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SignContext {
    /// Message bytes are a serialized `BulletinPost` verified against the chain.
    /// No derivation or metadata — signs from the root key.
    Bulletin,
    /// Policy-authorized signing: JWT token is validated and policy access is checked.
    /// The derivation path is stored on the bulletin in the `KeyDerivation` entry and is
    /// NOT passed by the client — it is fetched from the chain and used directly.
    Policy {
        /// Raw JWT string issued by the caller
        token_string: String,
        /// Namespace of the key derivation object on the bulletin
        namespace: String,
        /// Object ID of the key derivation entry
        derivation_id: String,
        /// Optional valid window for time-bounded authz checks
        valid_window: Option<ValidWindow>,
        /// Key derivation payload fetched from the bulletin by the coordinator.
        /// Carried here to avoid a redundant bulletin for the coordinator
        /// Peer nodes always re-fetch independently.
        key_derivation: KeyDerivation,
    },
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
        /// Auth context — responder validates auth here before generating the nonce,
        /// so nonces are never burned for unauthorized requests.
        context: SignContext,
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
        /// Signing pathway and auth context
        context: SignContext,
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
