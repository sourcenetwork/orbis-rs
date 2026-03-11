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
    let last_refresh_arr: [u8; 8] = last_refresh_bytes.try_into().map_err(|_| {
        DkgError::Deserialization("Invalid last refresh timestamp bytes".to_string())
    })?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::helpers::test_helpers::{cleanup_db, test_db_path};
    use bulletin::r#trait::RingPayload;
    use local_storage::{r#trait::LocalStorage, LocalStorageImpl};

    fn make_storage(db_name: &str) -> (LocalStorageImpl, String) {
        let db_path = test_db_path(db_name);
        let storage = LocalStorageImpl::new(None, db_path.clone()).expect("create storage");
        (storage, db_path)
    }

    fn write_ring(storage: &LocalStorageImpl, ring_pk_hex: &str, peer_ids: Vec<String>) {
        let payload = RingPayload {
            ring_pk: ring_pk_hex.to_string(),
            peer_ids,
            threshold: 1,
            public_polynomial: "poly".to_string(),
        };
        let bytes = serde_json::to_vec(&payload).unwrap();
        storage
            .set(
                LocalStorageKeys::RingPkMapping(ring_pk_hex.to_string()),
                bytes,
            )
            .unwrap();
    }

    fn write_last_refresh(storage: &LocalStorageImpl, ring_pk_hex: &str, secs: u64) {
        storage
            .set(
                LocalStorageKeys::RingLastRefresh(ring_pk_hex.to_string()),
                secs.to_le_bytes().to_vec(),
            )
            .unwrap();
    }

    #[test]
    fn test_unknown_ring() {
        let (storage, db_path) = make_storage("helpers_unknown_ring");
        let result = validate_refresh_session_init("some_pk", "sender", &storage, 86400);
        assert!(
            matches!(result, Err(DkgError::Unauthorized(_))),
            "Expected Unauthorized for unknown ring, got: {:?}",
            result
        );
        cleanup_db(&db_path);
    }

    #[test]
    fn test_corrupt_ring_payload() {
        let (storage, db_path) = make_storage("helpers_corrupt_payload");
        storage
            .set(
                LocalStorageKeys::RingPkMapping("pk".to_string()),
                b"not valid json".to_vec(),
            )
            .unwrap();
        let result = validate_refresh_session_init("pk", "sender", &storage, 86400);
        assert!(
            matches!(result, Err(DkgError::Deserialization(_))),
            "Expected Deserialization error for corrupt payload, got: {:?}",
            result
        );
        cleanup_db(&db_path);
    }

    #[test]
    fn test_sender_not_in_ring() {
        let (storage, db_path) = make_storage("helpers_sender_not_in_ring");
        let ring_pk = "ring_pk_abc";
        write_ring(
            &storage,
            ring_pk,
            vec!["aabbccdd".to_string(), "eeff0011".to_string()],
        );
        write_last_refresh(&storage, ring_pk, 0);
        let result = validate_refresh_session_init(ring_pk, "deadbeef00000000", &storage, 86400);
        assert!(
            matches!(result, Err(DkgError::Unauthorized(_))),
            "Expected Unauthorized for sender not in ring, got: {:?}",
            result
        );
        cleanup_db(&db_path);
    }

    #[test]
    fn test_no_last_refresh_timestamp() {
        let (storage, db_path) = make_storage("helpers_no_timestamp");
        let ring_pk = "ring_pk_def";
        write_ring(&storage, ring_pk, vec!["aabbccdd".to_string()]);
        // Intentionally do not write RingLastRefresh
        let result = validate_refresh_session_init(ring_pk, "aabbccdd", &storage, 86400);
        assert!(
            matches!(result, Err(DkgError::Unauthorized(_))),
            "Expected Unauthorized for missing timestamp, got: {:?}",
            result
        );
        if let Err(DkgError::Unauthorized(msg)) = result {
            assert!(
                msg.contains("no refresh timestamp"),
                "Expected 'no refresh timestamp' message, got: {}",
                msg
            );
        }
        cleanup_db(&db_path);
    }

    #[test]
    fn test_refresh_too_soon() {
        let (storage, db_path) = make_storage("helpers_too_soon");
        let ring_pk = "ring_pk_ghi";
        write_ring(&storage, ring_pk, vec!["aabbccdd".to_string()]);
        // Set last refresh to now — elapsed will be ~0s
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        write_last_refresh(&storage, ring_pk, now);
        let result = validate_refresh_session_init(ring_pk, "aabbccdd", &storage, 86400);
        assert!(
            matches!(result, Err(DkgError::Unauthorized(_))),
            "Expected Unauthorized for too soon, got: {:?}",
            result
        );
        if let Err(DkgError::Unauthorized(msg)) = result {
            assert!(
                msg.contains("too soon"),
                "Expected 'too soon' message, got: {}",
                msg
            );
        }
        cleanup_db(&db_path);
    }

    #[test]
    fn test_refresh_succeeds() {
        let (storage, db_path) = make_storage("helpers_success");
        let ring_pk = "ring_pk_jkl";
        write_ring(&storage, ring_pk, vec!["aabbccdd".to_string()]);
        // Timestamp at epoch — elapsed >> interval
        write_last_refresh(&storage, ring_pk, 0);
        let result = validate_refresh_session_init(ring_pk, "aabbccdd", &storage, 86400);
        assert!(
            result.is_ok(),
            "Expected Ok for valid refresh, got: {:?}",
            result
        );
        cleanup_db(&db_path);
    }
}
