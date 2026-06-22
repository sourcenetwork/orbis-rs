//! Sign Protocol Messages
//!
//! This module defines the message types used for threshold BLS signing
//! protocol communication between nodes over the network.

use authz::sourcehub::ValidWindow;
use bulletin::r#trait::KeyDerivation;
use common::blockchain::orbis::RING_RESHARE_FINALIZE_SIGN_DOC_DOMAIN;
use serde::{Deserialize, Serialize};

/// Domain separator for signed ring reshare bulletin updates.
pub const RING_RESHARE_UPDATE_DOMAIN: &str = RING_RESHARE_FINALIZE_SIGN_DOC_DOMAIN;
/// Domain separator for discarded post-refresh diagnostic signatures.
pub const REFRESH_HEALTH_CHECK_DOMAIN: &str = "orbis-pss-refresh-healthcheck-v1";

/// Payload for the `Policy` variant of [`SignContext`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyContext {
    /// Raw JWT string issued by the caller
    pub token_string: String,
    /// Object ID of the key derivation entry
    pub derivation_id: String,
    /// Optional valid window for time-bounded authz checks
    pub valid_window: Option<ValidWindow>,
    /// Key derivation payload fetched from the bulletin by the coordinator.
    /// Carried here to avoid a redundant bulletin lookup for the coordinator;
    /// peer nodes always re-fetch independently.
    pub key_derivation: KeyDerivation,
}

/// Canonical message signed by the new committee before a reshare bulletin update.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RingReshareUpdateStatement {
    /// Domain separator, must equal [`RING_RESHARE_UPDATE_DOMAIN`].
    pub domain: String,
    /// DKG/PSS reshare session that produced the new shares.
    pub session_id: u128,
    /// SourceHub chain ID that will verify the signature.
    pub chain_id: String,
    /// Hex-encoded ring public key. Reshare preserves this key.
    pub ring_pk: String,
    /// Ring ID of the ring being updated.
    pub ring_id: String,
    /// SHA-256 hex of the current ring state (proto-encoded for SourceHub).
    pub current_ring_sha256: String,
    /// SHA-256 hex of the finalized ring state after reshare.
    pub finalized_ring_sha256: String,
    /// Current payload block-number nonce used for replay protection.
    pub block_number_nonce: u64,
}

/// Payload for reshare-update signing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RingReshareUpdateContext {
    pub statement: RingReshareUpdateStatement,
}

/// Canonical message signed as a post-refresh smoke test.
///
/// This signature is never posted or persisted. It exists only to prove that at
/// least a threshold subset can sign using the refreshed active public polynomial.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshHealthCheckStatement {
    /// Domain separator, must equal [`REFRESH_HEALTH_CHECK_DOMAIN`].
    pub domain: String,
    /// DKG/PSS refresh session that produced the current refreshed shares.
    pub session_id: u128,
    /// Hex-encoded ring public key. Refresh preserves this key.
    pub ring_pk: String,
    /// SHA-256 hex of the refreshed public polynomial bytes.
    pub public_polynomial_sha256: String,
    /// SHA-256 hex of the canonical sorted peer node key list.
    pub peer_node_keys_sha256: String,
    /// Current ring threshold.
    pub threshold: u32,
    /// Current ring committee size.
    pub total_participants: u32,
}

/// Payload for refresh health-check signing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshHealthCheckContext {
    pub statement: RefreshHealthCheckStatement,
}

/// Distinguishes the two signing pathways.
///
/// - `Bulletin`: message is a serialized `BulletinPost`; authorization is its existence on chain.
///   Signs from the root key (no derivation, no metadata).
/// - `Policy`: policy-authorized derivation signing with JWT auth, mirrors the PRE flow.
/// - `RingReshareUpdate`: new-committee signing for an in-place ring bulletin update.
/// - `RefreshHealthCheck`: post-refresh diagnostic signing with no persisted result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SignContext {
    /// Message bytes are a serialized `BulletinPost` verified against the chain.
    /// The object ID lets nonce responders resolve and gate the authoritative ring.
    Bulletin { object_id: String },
    /// Policy-authorized signing: JWT token is validated and policy access is checked.
    /// The derivation path is stored on the bulletin in the `KeyDerivation` entry and is
    /// NOT passed by the client — it is fetched from the chain and used directly.
    Policy(Box<PolicyContext>),
    /// Reshare bulletin update signing. Responders validate the announced transition
    /// and sign the canonical statement from the new shares.
    RingReshareUpdate(Box<RingReshareUpdateContext>),
    /// PSS refresh health check. Responders validate the canonical statement
    /// against their staged refreshed bundle and sign only this domain.
    RefreshHealthCheck(Box<RefreshHealthCheckContext>),
}

/// Wire message sent from the coordinator to each ring node requesting a nonce commitment
/// (FROST Round 1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NonceRequest {
    pub request_id: String,
    pub from_node_id: u32,
    /// Serialized ring public key (used to look up DKG share)
    pub ring_pk: Vec<u8>,
    /// Auth context — responder validates auth here before generating the nonce,
    /// so nonces are never burned for unauthorized requests.
    pub context: SignContext,
}

/// Wire message sent from the coordinator to each ring node requesting a signature share.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignRequest {
    pub request_id: String,
    pub from_node_id: u32,
    /// Raw message to sign (will be hashed internally using hash-to-curve)
    pub message: Vec<u8>,
    /// Serialized list of (node_id, commitment_bytes) for FROST; empty for BLS
    pub all_commitments: Vec<u8>,
    /// Signing pathway and auth context
    pub context: SignContext,
}

/// Sign protocol message types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SignMessage {
    /// Request from coordinator to ring node for nonce commitments (FROST Round 1)
    NonceRequest(NonceRequest),
    /// Response with nonce commitment (FROST Round 1)
    NonceResponse {
        request_id: String,
        from_node_id: u32,
        /// Serialized NonceCommitment
        nonce_commitment: Vec<u8>,
    },
    /// Request from coordinator to ring node for signing
    SignRequest(SignRequest),
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
            SignMessage::NonceRequest(req) => &req.request_id,
            SignMessage::NonceResponse { request_id, .. } => request_id,
            SignMessage::SignRequest(req) => &req.request_id,
            SignMessage::SignResponse { request_id, .. } => request_id,
            SignMessage::Error { request_id, .. } => request_id,
        }
    }

    /// Get the from_node_id for response messages (used for deduplication)
    pub fn sender_node_id(&self) -> Option<u32> {
        match self {
            SignMessage::NonceResponse { from_node_id, .. } => Some(*from_node_id),
            SignMessage::SignResponse { from_node_id, .. } => Some(*from_node_id),
            _ => None,
        }
    }
}
