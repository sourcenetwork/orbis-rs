//! Deterministic DKG/PSS session-ID derivation.

use super::commitment::{hash_labeled_bytes, hash_labeled_str, hash_sorted_strings};
use crate::dkg::v0::error::{DkgError, Result};
use sha2::{Digest, Sha256};

const PSS_SESSION_ID_DOMAIN: &[u8] = b"orbis-pss-session-v1";

/// Returns a `SessionNotFound` error for the given session_id.
pub fn session_not_found(session_id: u128) -> DkgError {
    DkgError::SessionNotFound(format!("DKG session {} not found", session_id))
}

/// Derive a deterministic refresh session ID from the ring's current generation state.
pub fn derive_refresh_session_id(
    ring_pk_hex: &str,
    peer_node_keys: &[String],
    threshold: u32,
    public_polynomial_hex: &str,
) -> Result<u128> {
    let mut hasher = Sha256::new();
    hasher.update(PSS_SESSION_ID_DOMAIN);
    hash_labeled_str(&mut hasher, b"kind", "refresh");
    hash_labeled_str(&mut hasher, b"ring_pk", ring_pk_hex);
    hash_sorted_strings(&mut hasher, b"peer_node_keys", peer_node_keys);
    hash_labeled_bytes(&mut hasher, b"threshold", &threshold.to_le_bytes());
    hash_labeled_str(&mut hasher, b"public_polynomial", public_polynomial_hex);
    let digest = hasher.finalize();
    Ok(u128::from_le_bytes(digest[..16].try_into()?))
}

/// Derive a deterministic session ID for a fresh DKG from the ring's on-chain ID.
///
/// Using a deterministic ID means concurrent `start_dkg` calls for the same ring
/// produce the same session_id and the second call hits `SessionAlreadyExists`
/// instead of launching a parallel ceremony that would deadlock finalization.
pub fn derive_fresh_dkg_session_id(ring_id: &str) -> Result<u128> {
    let mut hasher = Sha256::new();
    hasher.update(PSS_SESSION_ID_DOMAIN);
    hash_labeled_str(&mut hasher, b"kind", "fresh");
    hash_labeled_str(&mut hasher, b"ring_id", ring_id);
    let digest = hasher.finalize();
    Ok(u128::from_le_bytes(digest[..16].try_into()?))
}

/// Derive a deterministic session ID for a ring's PET checking-key fresh DKG.
///
/// A distinct `"fresh-pet"` kind label (not a suffix or variant of `"fresh"`)
/// guarantees this never collides with the ring's own main-key session ID,
/// which uses the same `ring_id` input under the `"fresh"` label.
pub fn derive_fresh_pet_dkg_session_id(ring_id: &str) -> Result<u128> {
    let mut hasher = Sha256::new();
    hasher.update(PSS_SESSION_ID_DOMAIN);
    hash_labeled_str(&mut hasher, b"kind", "fresh-pet");
    hash_labeled_str(&mut hasher, b"ring_id", ring_id);
    let digest = hasher.finalize();
    Ok(u128::from_le_bytes(digest[..16].try_into()?))
}

/// Derive a deterministic reshare session ID from the ring's current generation state
/// and the authoritative transition announced on the bulletin.
pub fn derive_reshare_session_id(
    ring_pk_hex: &str,
    bulletin_post_id: &str,
    old_peer_node_keys: &[String],
    new_peer_node_keys: &[String],
    new_threshold: u32,
) -> Result<u128> {
    let mut hasher = Sha256::new();
    hasher.update(PSS_SESSION_ID_DOMAIN);
    hash_labeled_str(&mut hasher, b"kind", "reshare");
    hash_labeled_str(&mut hasher, b"ring_pk", ring_pk_hex);
    hash_labeled_str(&mut hasher, b"bulletin_post_id", bulletin_post_id);
    hash_sorted_strings(&mut hasher, b"old_peer_node_keys", old_peer_node_keys);
    hash_sorted_strings(&mut hasher, b"new_peer_node_keys", new_peer_node_keys);
    hash_labeled_bytes(&mut hasher, b"new_threshold", &new_threshold.to_le_bytes());
    let digest = hasher.finalize();
    Ok(u128::from_le_bytes(digest[..16].try_into()?))
}
