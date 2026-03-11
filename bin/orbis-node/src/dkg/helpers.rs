use crate::dkg::error::{DkgError, Result};
use crate::helpers::helpers::extract_node_part;
use authn::{BearerToken, DkgClaims};
use bulletin::r#trait::RingPayload;
use crypto::{CryptoSerialize, GroupAffine as G1Affine};
use local_storage::r#trait::{LocalStorage, LocalStorageKeys};
use std::time::{SystemTime, UNIX_EPOCH};

/// Returns a `SessionNotFound` error for the given session_id.
pub fn session_not_found(session_id: u64) -> DkgError {
    DkgError::SessionNotFound(format!("DKG session {} not found", session_id))
}

/// Serializes a slice of G1Affine commitment coefficients to a flat byte buffer.
pub fn serialize_commitment_coefficients(coefficients: &[G1Affine]) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    for coeff in coefficients {
        let coeff_bytes = CryptoSerialize::to_bytes(coeff).map_err(|e| {
            DkgError::Serialization(format!("Failed to serialize commitment coefficient: {}", e))
        })?;
        bytes.extend_from_slice(&coeff_bytes);
    }
    Ok(bytes)
}

/// Validates an incoming PSS refresh `SessionInit` message.
///
/// Checks (in order):
/// 1. The ring is known (`RingPkMapping` present in local storage).
/// 2. The sender's peer ID is a current member of that ring.
/// 3. Enough time has elapsed since the last refresh (`reshare_interval_secs`).
///
/// The caller is responsible for the atomic in-progress flag
/// (`try_mark_ring_refreshing`) after this returns `Ok`.
pub fn validate_refresh_session_init<S: LocalStorage>(
    ring_pk_hex: &str,
    sender_hex: &str,
    local_storage: &S,
    reshare_interval_secs: u64,
) -> Result<()> {
    // 1. Load the cached RingPayload (written during fresh DKG Phase 4).
    let ring_payload_bytes = local_storage
        .get(LocalStorageKeys::RingPkMapping(ring_pk_hex.to_string()))
        .map_err(|e| DkgError::Storage(format!("Failed to read RingPkMapping: {}", e)))?
        .ok_or_else(|| DkgError::Unauthorized(format!("Unknown ring: {}", ring_pk_hex)))?;
    let ring_payload: RingPayload = serde_json::from_slice(&ring_payload_bytes)
        .map_err(|e| DkgError::Deserialization(format!("Bad cached ring payload: {}", e)))?;

    // 2. Verify the sender is a current ring member.
    let sender_in_ring = ring_payload
        .peer_ids
        .iter()
        .any(|pid| extract_node_part(pid) == sender_hex);
    if !sender_in_ring {
        return Err(DkgError::Unauthorized(format!(
            "Refresh initiator {} is not a member of ring {}",
            sender_hex, ring_pk_hex
        )));
    }

    // 3. Verify enough time has elapsed since the last refresh/DKG.
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| DkgError::Generic(format!("Failed to get timestamp: {}", e)))?
        .as_secs();
    let last_refresh_bytes = local_storage
        .get(LocalStorageKeys::RingLastRefresh(ring_pk_hex.to_string()))
        .map_err(|e| DkgError::Storage(format!("Failed to read last refresh time: {}", e)))?
        .ok_or_else(|| {
            DkgError::Unauthorized(
                "Ring has no refresh timestamp; cannot accept refresh".to_string(),
            )
        })?;
    let last_refresh_arr: [u8; 8] = last_refresh_bytes
        .try_into()
        .map_err(|_| DkgError::Deserialization("Invalid last refresh timestamp bytes".to_string()))?;
    let elapsed = now_secs.saturating_sub(u64::from_le_bytes(last_refresh_arr));
    if elapsed < reshare_interval_secs {
        return Err(DkgError::Unauthorized(format!(
            "Refresh too soon: {}s elapsed, minimum is {}s",
            elapsed, reshare_interval_secs
        )));
    }

    Ok(())
}

/// Validates JWT claims against the DKG request.
pub fn validate_dkg_claims(
    token: &BearerToken<DkgClaims>,
    threshold: u32,
    peer_ids: &[String],
) -> Result<()> {
    // Validate threshold matches
    if token.claims.threshold != threshold {
        return Err(DkgError::Unauthorized(format!(
            "Token threshold ({}) does not match request threshold ({})",
            token.claims.threshold, threshold
        )));
    }

    // Validate peer_ids match (order-independent)
    if token.claims.peer_ids.len() != peer_ids.len() {
        return Err(DkgError::Unauthorized(format!(
            "Token peer_ids count ({}) does not match request peer_ids count ({})",
            token.claims.peer_ids.len(),
            peer_ids.len()
        )));
    }

    let mut sorted_token: Vec<&str> = token.claims.peer_ids.iter().map(|s| s.as_str()).collect();
    let mut sorted_req: Vec<&str> = peer_ids.iter().map(|s| s.as_str()).collect();
    sorted_token.sort();
    sorted_req.sort();

    if sorted_token != sorted_req {
        return Err(DkgError::Unauthorized(
            "Token peer_ids do not match request peer_ids".to_string(),
        ));
    }

    Ok(())
}
