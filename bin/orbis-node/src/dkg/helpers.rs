use crate::dkg::error::{DkgError, Result};
use crate::helpers::helpers::extract_node_part;
use crate::ring_state::RingShareBundle;
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
/// 3. Enough time has elapsed since the last refresh (`ring_payload.pss_interval`).
///    If `pss_interval` is `None` the time check is skipped (any time is acceptable).
///
/// The caller is responsible for the atomic in-progress flag
/// (`try_mark_ring_refreshing`) after this returns `Ok`.
pub fn validate_refresh_session_init<S: LocalStorage>(
    ring_pk_hex: &str,
    sender_hex: &str,
    local_storage: &S,
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
    //    Only enforced when the ring has a `pss_interval` set.
    if let Some(pss_interval_secs) = ring_payload.pss_interval {
        if pss_interval_secs > 0 {
            let now_secs = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| DkgError::Generic(format!("Failed to get timestamp: {}", e)))?
                .as_secs();
            // `ring_pk_hex` is aggregate_pk.to_string() — same key the bundle is stored under.
            // A missing bundle means the ring hasn't completed DKG yet.
            let last_refresh_secs = RingShareBundle::load_by_ring_key(local_storage, ring_pk_hex)
                .map(|b| b.refreshed_at)
                .map_err(|_| {
                    DkgError::Unauthorized(
                        "Ring has no refresh timestamp; cannot accept refresh".to_string(),
                    )
                })?;
            let elapsed = now_secs.saturating_sub(last_refresh_secs);
            if elapsed < pss_interval_secs {
                return Err(DkgError::Unauthorized(format!(
                    "Refresh too soon: {}s elapsed, minimum is {}s",
                    elapsed, pss_interval_secs
                )));
            }
        }
    }

    Ok(())
}

/// Validates JWT claims against the DKG request.
pub fn validate_dkg_claims(
    token: &BearerToken<DkgClaims>,
    threshold: u32,
    peer_ids: &[String],
    pss_interval: Option<u64>,
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

    // Validate pss_interval matches. Normalize both sides: 0 and None both mean "disabled".
    let normalize = |v: Option<u64>| v.filter(|&x| x > 0);
    if normalize(token.claims.pss_interval) != normalize(pss_interval) {
        return Err(DkgError::Unauthorized(format!(
            "Token pss_interval ({:?}) does not match request pss_interval ({:?})",
            token.claims.pss_interval, pss_interval
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::helpers::test_helpers::{cleanup_db, test_db_path};
    use crate::ring_state::RingShareBundle;
    use bulletin::r#trait::RingPayload;
    use local_storage::{r#trait::LocalStorage, LocalStorageImpl};

    fn make_storage(db_name: &str) -> (LocalStorageImpl, String) {
        let db_path = test_db_path(db_name);
        let storage = LocalStorageImpl::new(None, db_path.clone()).expect("create storage");
        (storage, db_path)
    }

    fn write_ring(
        storage: &LocalStorageImpl,
        ring_pk_hex: &str,
        peer_ids: Vec<String>,
        pss_interval: Option<u64>,
    ) {
        let payload = RingPayload {
            ring_pk: ring_pk_hex.to_string(),
            peer_ids,
            threshold: 1,
            pss_interval,
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
        // `ring_pk_hex` is aggregate_pk.to_string() — same key the bundle is stored under.
        let bundle = RingShareBundle {
            share_bytes: vec![],
            public_polynomial: String::new(),
            refreshed_at: secs,
        };
        bundle.save_by_ring_key(storage, ring_pk_hex).unwrap();
    }

    #[test]
    fn test_unknown_ring() {
        let (storage, db_path) = make_storage("helpers_unknown_ring");
        let result = validate_refresh_session_init("some_pk", "sender", &storage);
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
        let result = validate_refresh_session_init("pk", "sender", &storage);
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
            None, // membership check fires before any time check
        );
        let result = validate_refresh_session_init(ring_pk, "deadbeef00000000", &storage);
        assert!(
            matches!(result, Err(DkgError::Unauthorized(_))),
            "Expected Unauthorized for sender not in ring, got: {:?}",
            result
        );
        cleanup_db(&db_path);
    }

    #[test]
    fn test_no_last_refresh_timestamp() {
        // When pss_interval is set, a missing bundle (no DKG yet) must be rejected.
        let (storage, db_path) = make_storage("helpers_no_timestamp");
        let ring_pk = "ring_pk_def";
        write_ring(&storage, ring_pk, vec!["aabbccdd".to_string()], Some(86400));
        // Intentionally do not write a RingShareBundle
        let result = validate_refresh_session_init(ring_pk, "aabbccdd", &storage);
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
        write_ring(&storage, ring_pk, vec!["aabbccdd".to_string()], Some(86400));
        // Set last refresh to now — elapsed will be ~0s
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        write_last_refresh(&storage, ring_pk, now);
        let result = validate_refresh_session_init(ring_pk, "aabbccdd", &storage);
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
        write_ring(&storage, ring_pk, vec!["aabbccdd".to_string()], Some(86400));
        // Timestamp at epoch — elapsed >> interval
        write_last_refresh(&storage, ring_pk, 0);
        let result = validate_refresh_session_init(ring_pk, "aabbccdd", &storage);
        assert!(
            result.is_ok(),
            "Expected Ok for valid refresh, got: {:?}",
            result
        );
        cleanup_db(&db_path);
    }

    #[test]
    fn test_no_pss_interval_skips_time_check() {
        // When pss_interval is None, time check is skipped — refresh always allowed.
        let (storage, db_path) = make_storage("helpers_no_interval");
        let ring_pk = "ring_pk_mno";
        write_ring(&storage, ring_pk, vec!["aabbccdd".to_string()], None);
        // No RingShareBundle written — would fail if the time check ran.
        let result = validate_refresh_session_init(ring_pk, "aabbccdd", &storage);
        assert!(
            result.is_ok(),
            "Expected Ok when pss_interval is None (no time check), got: {:?}",
            result
        );
        cleanup_db(&db_path);
    }
}
