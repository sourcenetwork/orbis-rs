//! Ring-reshare finalize sign doc for x/bulletin.
//!
//! NOTE: as of this split, nothing in this crate or the workspace calls
//! [`ring_reshare_finalize_sign_bytes_from_hashes`] — ring reshare finalization
//! now goes through `x/orbis`'s own `ring_reshare_finalize_sign_bytes` (see
//! `crate::blockchain::orbis::ids`), which has an active caller. This looks like
//! a leftover from before ring lifecycle moved off bulletin posts; kept as-is
//! (moved, not deleted) since removing it is a behavior decision, not a
//! readability one.

use crate::blockchain::{BlockchainError, Result};
use prost::Message;

pub const RING_RESHARE_FINALIZE_SIGN_DOC_DOMAIN: &str = "orbis-ring-reshare-finalize";

/// Canonical sign document for finalizing a ring reshare.
/// Canonical sign-doc field numbers:
/// - 1: domain (string)
/// - 2: chain_id (string)
/// - 3: namespace (string)
/// - 4: post_id (string)
/// - 5: ring_pk (string)
/// - 6: current_payload_sha256 (bytes)
/// - 7: finalized_payload_sha256 (bytes)
/// - 8: block_number_nonce (uint64)
#[derive(Clone, Message)]
pub struct RingReshareFinalizeSignDoc {
    #[prost(string, tag = "1")]
    pub domain: String,
    #[prost(string, tag = "2")]
    pub chain_id: String,
    #[prost(string, tag = "3")]
    pub namespace: String,
    #[prost(string, tag = "4")]
    pub post_id: String,
    #[prost(string, tag = "5")]
    pub ring_pk: String,
    #[prost(bytes = "vec", tag = "6")]
    pub current_payload_sha256: Vec<u8>,
    #[prost(bytes = "vec", tag = "7")]
    pub finalized_payload_sha256: Vec<u8>,
    #[prost(uint64, tag = "8")]
    pub block_number_nonce: u64,
}

/// Build Vera-compatible sign bytes for a ring reshare finalization.
pub fn ring_reshare_finalize_sign_bytes_from_hashes(
    chain_id: &str,
    namespace: &str,
    post_id: &str,
    ring_pk: &str,
    current_payload_sha256: Vec<u8>,
    finalized_payload_sha256: Vec<u8>,
    block_number_nonce: u64,
) -> Result<Vec<u8>> {
    if current_payload_sha256.len() != 32 {
        return Err(BlockchainError::Serialization(format!(
            "current_payload_sha256 must be 32 bytes, got {}",
            current_payload_sha256.len()
        )));
    }
    if finalized_payload_sha256.len() != 32 {
        return Err(BlockchainError::Serialization(format!(
            "finalized_payload_sha256 must be 32 bytes, got {}",
            finalized_payload_sha256.len()
        )));
    }

    Ok(RingReshareFinalizeSignDoc {
        domain: RING_RESHARE_FINALIZE_SIGN_DOC_DOMAIN.to_string(),
        chain_id: chain_id.to_string(),
        namespace: namespace.to_string(),
        post_id: post_id.to_string(),
        ring_pk: ring_pk.to_string(),
        current_payload_sha256,
        finalized_payload_sha256,
        block_number_nonce,
    }
    .encode_to_vec())
}
