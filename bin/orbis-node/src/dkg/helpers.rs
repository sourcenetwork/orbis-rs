use crate::constants::BULLETIN_RING_NAMESPACE;
use crate::dkg::error::{DkgError, Result};
use crate::dkg::messages::SessionKind;
use crate::helpers::helpers::extract_node_part;
use crate::ring_state::{RingIndexEntry, RingShareBundle};
use zeroize::Zeroizing;
use authn::{BearerToken, DkgClaims};
use bulletin::r#trait::{Bulletin, RingPayload};
use crypto::r#trait::{CryptoDeserialize, PriShare};
use crypto::{CryptoSerialize, GroupAffine as G1Affine, ScalarField as Fr};
use local_storage::r#trait::{LocalStorage, LocalStorageKeys};
use std::sync::Arc;
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

/// Validates an incoming reshare `SessionInit` message.
///
/// Checks (in order):
/// 0. Fast structural checks: `next_peer_ids` non-empty, `new_threshold` in `[1, n]`.
/// 1. Resolve the bulletin post: use `RingIndex` when this node has an entry for
///    `ring_pk_hex`, otherwise use `bulletin_post_id` from the `SessionInit` (needed for
///    pure Receiver nodes that were never on the old committee).
/// 2. The deserialized `RingPayload::ring_pk` must equal `ring_pk_hex` (binds the read to
///    the intended ring when the post ID came from the wire).
/// 3. The sender's peer ID is a current member of that ring's OLD committee.
/// 4. `ring_payload.next_peer_ids` must be set and must match the proposed list
///    (order-independent).  A missing bulletin field is also rejected — the ring must have
///    been prepared for reshare on-chain before any node may initiate one.
/// 5. `ring_payload.new_threshold` must be set and must match the proposed value.
///    Same rationale: absent means not yet authorised.
///
/// No time-based check is performed — reshare is triggered by membership change, not interval.
///
/// ## Bulletin trust model
///
/// This function treats the bulletin as the authoritative source of truth for reshare
/// parameters.  Both `next_peer_ids` and `new_threshold` **must** be pre-announced on-chain
/// (e.g. via a governance transaction on SourceHub) before any node will accept a reshare
/// `SessionInit`.  An old-committee member that sends a `SessionInit` without a matching
/// bulletin entry — or with parameters that differ from the bulletin — is rejected.  This
/// ensures that reshares cannot be unilaterally redirected to an arbitrary new committee by
/// a single old-committee member.
pub async fn validate_reshare_session_init<S: LocalStorage>(
    ring_pk_hex: &str,
    sender_hex: &str,
    proposed_next_peer_ids: &[String],
    proposed_new_threshold: u32,
    bulletin_post_id: &str,
    local_storage: &S,
    bulletin: &Arc<dyn Bulletin + Send + Sync>,
) -> Result<()> {
    // 0. Fast-fail on structurally invalid parameters before hitting the bulletin.
    if proposed_next_peer_ids.is_empty() {
        return Err(DkgError::InvalidInput(
            "Reshare next_peer_ids cannot be empty".to_string(),
        ));
    }
    if proposed_new_threshold < 1 || proposed_new_threshold as usize > proposed_next_peer_ids.len()
    {
        return Err(DkgError::InvalidInput(format!(
            "Reshare new_threshold {} is invalid for a committee of {} nodes (must be 1..=n)",
            proposed_new_threshold,
            proposed_next_peer_ids.len()
        )));
    }

    // Look up the bulletin post ID from the local index.  Pure Receiver nodes have no
    // local entry for this ring (they were never members), so fall back to the post ID
    // carried in the SessionInit message — the bulletin is the source of truth either way.
    let ring_index: Vec<RingIndexEntry> = local_storage
        .get(LocalStorageKeys::RingIndex)
        .map_err(|e| DkgError::Storage(format!("Failed to read RingIndex: {}", e)))?
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();
    let resolved_post_id = ring_index
        .iter()
        .find(|e| e.ring_pk_str == ring_pk_hex)
        .map(|e| e.bulletin_post_id.as_str())
        .unwrap_or(bulletin_post_id);

    let bulletin_post = bulletin
        .read(
            BULLETIN_RING_NAMESPACE.to_string(),
            resolved_post_id.to_string(),
        )
        .await
        .map_err(|e| {
            DkgError::Unauthorized(format!("Ring {} not found in bulletin: {}", ring_pk_hex, e))
        })?;
    let ring_payload: RingPayload = serde_json::from_slice(&bulletin_post.payload)
        .map_err(|e| DkgError::Deserialization(format!("Bad ring payload: {}", e)))?;

    if ring_payload.ring_pk != ring_pk_hex {
        return Err(DkgError::Unauthorized(format!(
            "Bulletin ring_pk does not match session ring for {}",
            ring_pk_hex
        )));
    }

    // 3. Sender must be in the old committee.
    let sender_in_ring = ring_payload
        .peer_ids
        .iter()
        .any(|pid| extract_node_part(pid) == sender_hex);
    if !sender_in_ring {
        return Err(DkgError::Unauthorized(format!(
            "Reshare initiator {} is not a member of ring {}",
            sender_hex, ring_pk_hex
        )));
    }

    // 4. The bulletin must pre-announce the new committee, and the proposed list must match.
    //    A missing `next_peer_ids` means the ring has not been prepared for reshare on-chain.
    let announced = ring_payload.next_peer_ids.as_ref().ok_or_else(|| {
        DkgError::Unauthorized(format!(
            "Ring {} has no bulletin-announced next_peer_ids; reshare not authorised",
            ring_pk_hex
        ))
    })?;
    let mut sorted_announced: Vec<&str> = announced.iter().map(|s| s.as_str()).collect();
    sorted_announced.sort();
    let mut sorted_proposed: Vec<&str> =
        proposed_next_peer_ids.iter().map(|s| s.as_str()).collect();
    sorted_proposed.sort();
    if sorted_announced != sorted_proposed {
        return Err(DkgError::Unauthorized(format!(
            "Reshare next_peer_ids do not match bulletin-announced committee for ring {}",
            ring_pk_hex
        )));
    }

    // 5. The bulletin must pre-announce the new threshold, and the proposed value must match.
    //    A missing `new_threshold` means the ring has not been prepared for reshare on-chain.
    let announced_threshold = ring_payload.new_threshold.ok_or_else(|| {
        DkgError::Unauthorized(format!(
            "Ring {} has no bulletin-announced new_threshold; reshare not authorised",
            ring_pk_hex
        ))
    })?;
    if proposed_new_threshold != announced_threshold {
        return Err(DkgError::Unauthorized(format!(
            "Reshare new_threshold {} does not match bulletin-announced threshold {} for ring {}",
            proposed_new_threshold, announced_threshold, ring_pk_hex
        )));
    }

    Ok(())
}

/// Validates an incoming PSS refresh `SessionInit` message.
///
/// Checks (in order):
/// 1. The ring is known (an entry with `ring_pk_str == ring_pk_hex` exists in `RingIndex`).
/// 2. The sender's peer ID is a current member of that ring (from the bulletin RingPayload).
/// 3. Enough time has elapsed since the last refresh (`ring_payload.pss_interval`).
///    If `pss_interval` is `None` the time check is skipped (any time is acceptable).
///
/// The caller is responsible for the atomic in-progress flag
/// (`try_mark_ring_pss`) after this returns `Ok`.
pub async fn validate_refresh_session_init<S: LocalStorage>(
    ring_pk_hex: &str,
    sender_hex: &str,
    local_storage: &S,
    bulletin: &Arc<dyn Bulletin + Send + Sync>,
) -> Result<()> {
    // 1. Look up the bulletin post_id for this ring from the local RingIndex.
    let ring_index: Vec<RingIndexEntry> = local_storage
        .get(LocalStorageKeys::RingIndex)
        .map_err(|e| DkgError::Storage(format!("Failed to read RingIndex: {}", e)))?
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();
    let entry = ring_index
        .iter()
        .find(|e| e.ring_pk_str == ring_pk_hex)
        .ok_or_else(|| DkgError::Unauthorized(format!("Unknown ring: {}", ring_pk_hex)))?;
    let post_id = &entry.bulletin_post_id;

    // Fetch the canonical RingPayload from the bulletin — it is the source of truth.
    let bulletin_post = bulletin
        .read(BULLETIN_RING_NAMESPACE.to_string(), post_id.to_string())
        .await
        .map_err(|e| {
            DkgError::Unauthorized(format!("Ring {} not found in bulletin: {}", ring_pk_hex, e))
        })?;
    let ring_payload: RingPayload = serde_json::from_slice(&bulletin_post.payload)
        .map_err(|e| DkgError::Deserialization(format!("Bad ring payload from bulletin: {}", e)))?;

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
                .map(|b| b.last_pss)
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

/// Writes the `RingShareBundle` (share + polynomial) after a completed DKG, PSS refresh,
/// or reshare.
///
/// - `Fresh`   — write directly under `aggregate_pk`.
/// - `Refresh` — load old bundle, fold in the delta share and polynomial, write back
///               under the original ring key.
/// - `Reshare` — write a fresh bundle under the old ring key (the new share replaces
///               the old one; the ring public key is unchanged).
///
/// `combine_pub_poly` encapsulates curve-specific polynomial combination (Refresh only).
pub fn persist_ring_bundle<S: LocalStorage>(
    storage: &S,
    kind: &SessionKind,
    final_share_bytes: &[u8],
    pub_poly_bytes: &[u8],
    aggregate_pk: &G1Affine,
    now_secs: u64,
    session_id: u64,
    combine_pub_poly: impl Fn(&[u8], &[u8]) -> std::result::Result<Vec<u8>, String>,
) -> Result<()> {
    match kind {
        SessionKind::Fresh => {
            // Fresh DKG: single atomic write of share + polynomial.
            // Use now_secs so the PSS scheduler waits a full pss_interval before the
            // first refresh rather than treating the ring as immediately overdue.
            let bundle = RingShareBundle {
                share_bytes: Zeroizing::new(final_share_bytes.to_vec()),
                public_polynomial: hex::encode(pub_poly_bytes),
                last_pss: now_secs,
            };
            bundle
                .save(storage, aggregate_pk)
                .map_err(|e| DkgError::Storage(format!("Failed to store share bundle: {}", e)))?;
        }
        SessionKind::Refresh { ring_pk_hex } => {
            // PSS Refresh: load old bundle, add delta share + polynomial, write back.
            let old_bundle =
                RingShareBundle::load_by_ring_key(storage, ring_pk_hex).map_err(|e| {
                    DkgError::Storage(format!("Refresh: failed to load old share bundle: {}", e))
                })?;

            let old_pri = old_bundle.pri_share().map_err(|e| {
                DkgError::Deserialization(format!(
                    "Refresh: failed to deserialize old share: {}",
                    e
                ))
            })?;
            let delta_pri = PriShare::<Fr>::from_bytes(final_share_bytes).map_err(|e| {
                DkgError::Deserialization(format!(
                    "Refresh: failed to deserialize delta share: {}",
                    e
                ))
            })?;
            let new_pri = PriShare {
                i: old_pri.i,
                v: old_pri.v + delta_pri.v,
            };
            let new_share_bytes = CryptoSerialize::to_bytes(&new_pri).map_err(|e| {
                DkgError::Serialization(format!(
                    "Refresh: failed to serialize combined share: {}",
                    e
                ))
            })?;

            let old_poly_bytes = hex::decode(&old_bundle.public_polynomial).map_err(|e| {
                DkgError::Deserialization(format!(
                    "Refresh: failed to decode old polynomial hex: {}",
                    e
                ))
            })?;
            let new_poly_bytes =
                combine_pub_poly(&old_poly_bytes, pub_poly_bytes).map_err(|e| {
                    DkgError::Crypto(format!("Refresh: failed to combine polynomials: {}", e))
                })?;

            let new_bundle = RingShareBundle {
                share_bytes: Zeroizing::new(new_share_bytes),
                public_polynomial: hex::encode(&new_poly_bytes),
                last_pss: now_secs,
            };
            new_bundle
                .save_by_ring_key(storage, ring_pk_hex)
                .map_err(|e| {
                    DkgError::Storage(format!("Refresh: failed to store new bundle: {}", e))
                })?;

            tracing::info!(
                session_id = session_id,
                ring_key = %ring_pk_hex,
                "Refresh: Phase 4 complete — RingShareBundle updated atomically"
            );
        }
        SessionKind::Reshare { ring_pk_hex, .. } => {
            // Reshare: the computed share is the full new share (not a delta).
            // Write it under the old ring key — the ring public key is unchanged.
            let bundle = RingShareBundle {
                share_bytes: Zeroizing::new(final_share_bytes.to_vec()),
                public_polynomial: hex::encode(pub_poly_bytes),
                last_pss: now_secs,
            };
            bundle.save_by_ring_key(storage, ring_pk_hex).map_err(|e| {
                DkgError::Storage(format!("Reshare: failed to store share bundle: {}", e))
            })?;

            tracing::info!(
                session_id = session_id,
                ring_key = %ring_pk_hex,
                "Reshare: Phase 4 complete — RingShareBundle written under old ring key"
            );
        }
    }
    Ok(())
}

/// Returns `true` if `our_node_part` appears as the node portion of any peer ID in
/// `committee` (sorted or unsorted — membership check is order-independent).
///
/// Used during reshare `SessionInit` handling to decide whether this node is in the
/// old committee, the new committee, or both.
pub fn in_committee(committee: &[String], our_node_part: &str) -> bool {
    committee
        .iter()
        .any(|p| extract_node_part(p) == our_node_part)
}

/// Returns the 1-based node index of `our_node_part` in `sorted_committee`.
///
/// `sorted_committee` must already be sorted so that all nodes derive the same
/// index for the same peer.  Panics if not found — callers must confirm membership
/// with `in_committee` before calling this.
pub fn node_index_in(sorted_committee: &[String], our_node_part: &str) -> u32 {
    sorted_committee
        .iter()
        .position(|p| extract_node_part(p) == our_node_part)
        .map(|i| (i + 1) as u32)
        .expect("node not found in committee — check in_committee() first")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::BULLETIN_RING_NAMESPACE;
    use crate::helpers::test_helpers::{cleanup_db, test_db_path, write_ring_to_bulletin};
    use crate::ring_state::{RingIndexEntry, RingShareBundle};
    use bulletin::dummy::DummyBulletin;
    use bulletin::r#trait::Bulletin;
    use local_storage::{r#trait::LocalStorage, LocalStorageImpl};
    use std::sync::Arc;

    fn make_storage(db_name: &str) -> (LocalStorageImpl, String) {
        let db_path = test_db_path(db_name);
        let storage = LocalStorageImpl::new(None, db_path.clone()).expect("create storage");
        (storage, db_path)
    }

    fn write_last_refresh(storage: &LocalStorageImpl, ring_pk: &str, secs: u64) {
        let bundle = RingShareBundle {
            share_bytes: vec![],
            public_polynomial: String::new(),
            last_pss: secs,
        };
        bundle.save_by_ring_key(storage, ring_pk).unwrap();
    }

    #[tokio::test]
    async fn test_unknown_ring() {
        let (storage, db_path) = make_storage("helpers_unknown_ring");
        let bulletin: Arc<dyn Bulletin + Send + Sync> =
            Arc::new(DummyBulletin::new().await.expect("DummyBulletin::new"));
        // No RingIndex written — ring is unknown.
        let result = validate_refresh_session_init("some_pk", "sender", &storage, &bulletin).await;
        assert!(
            matches!(result, Err(DkgError::Unauthorized(_))),
            "Expected Unauthorized for unknown ring, got: {:?}",
            result
        );
        cleanup_db(&db_path);
    }

    #[tokio::test]
    async fn test_corrupt_ring_payload() {
        let (storage, db_path) = make_storage("helpers_corrupt_payload");
        let bulletin: Arc<dyn Bulletin + Send + Sync> =
            Arc::new(DummyBulletin::new().await.expect("DummyBulletin::new"));
        // Post garbage bytes to the bulletin and point RingIndex at them.
        let garbage = b"not valid json".to_vec();
        bulletin
            .post(
                BULLETIN_RING_NAMESPACE.to_string(),
                garbage.clone(),
                vec![],
                None,
            )
            .await
            .unwrap();
        let post_id = bulletin
            .get_post_id(BULLETIN_RING_NAMESPACE, &garbage)
            .unwrap();
        storage
            .set(
                LocalStorageKeys::RingIndex,
                serde_json::to_vec(&vec![RingIndexEntry {
                    ring_pk_str: "pk".to_string(),
                    bulletin_post_id: post_id,
                }])
                .unwrap(),
            )
            .unwrap();
        let result = validate_refresh_session_init("pk", "sender", &storage, &bulletin).await;
        assert!(
            matches!(result, Err(DkgError::Deserialization(_))),
            "Expected Deserialization error for corrupt payload, got: {:?}",
            result
        );
        cleanup_db(&db_path);
    }

    #[tokio::test]
    async fn test_sender_not_in_ring() {
        let (storage, db_path) = make_storage("helpers_sender_not_in_ring");
        let bulletin: Arc<dyn Bulletin + Send + Sync> =
            Arc::new(DummyBulletin::new().await.expect("DummyBulletin::new"));
        let ring_pk = "ring_pk_abc";
        write_ring_to_bulletin(
            &storage,
            &bulletin,
            ring_pk,
            vec!["aabbccdd".to_string(), "eeff0011".to_string()],
            None,
        )
        .await;
        let result =
            validate_refresh_session_init(ring_pk, "deadbeef00000000", &storage, &bulletin).await;
        assert!(
            matches!(result, Err(DkgError::Unauthorized(_))),
            "Expected Unauthorized for sender not in ring, got: {:?}",
            result
        );
        cleanup_db(&db_path);
    }

    #[tokio::test]
    async fn test_no_last_refresh_timestamp() {
        // When pss_interval is set, a missing bundle (no DKG yet) must be rejected.
        let (storage, db_path) = make_storage("helpers_no_timestamp");
        let bulletin: Arc<dyn Bulletin + Send + Sync> =
            Arc::new(DummyBulletin::new().await.expect("DummyBulletin::new"));
        let ring_pk = "ring_pk_def";
        write_ring_to_bulletin(
            &storage,
            &bulletin,
            ring_pk,
            vec!["aabbccdd".to_string()],
            Some(86400),
        )
        .await;
        // Intentionally do not write a RingShareBundle.
        let result = validate_refresh_session_init(ring_pk, "aabbccdd", &storage, &bulletin).await;
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

    #[tokio::test]
    async fn test_refresh_too_soon() {
        let (storage, db_path) = make_storage("helpers_too_soon");
        let bulletin: Arc<dyn Bulletin + Send + Sync> =
            Arc::new(DummyBulletin::new().await.expect("DummyBulletin::new"));
        let ring_pk = "ring_pk_ghi";
        write_ring_to_bulletin(
            &storage,
            &bulletin,
            ring_pk,
            vec!["aabbccdd".to_string()],
            Some(86400),
        )
        .await;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        write_last_refresh(&storage, ring_pk, now);
        let result = validate_refresh_session_init(ring_pk, "aabbccdd", &storage, &bulletin).await;
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

    #[tokio::test]
    async fn test_refresh_succeeds() {
        let (storage, db_path) = make_storage("helpers_success");
        let bulletin: Arc<dyn Bulletin + Send + Sync> =
            Arc::new(DummyBulletin::new().await.expect("DummyBulletin::new"));
        let ring_pk = "ring_pk_jkl";
        write_ring_to_bulletin(
            &storage,
            &bulletin,
            ring_pk,
            vec!["aabbccdd".to_string()],
            Some(86400),
        )
        .await;
        // Timestamp at epoch — elapsed >> interval.
        write_last_refresh(&storage, ring_pk, 0);
        let result = validate_refresh_session_init(ring_pk, "aabbccdd", &storage, &bulletin).await;
        assert!(
            result.is_ok(),
            "Expected Ok for valid refresh, got: {:?}",
            result
        );
        cleanup_db(&db_path);
    }

    #[tokio::test]
    async fn test_no_pss_interval_skips_time_check() {
        // When pss_interval is None, time check is skipped — refresh always allowed.
        let (storage, db_path) = make_storage("helpers_no_interval");
        let bulletin: Arc<dyn Bulletin + Send + Sync> =
            Arc::new(DummyBulletin::new().await.expect("DummyBulletin::new"));
        let ring_pk = "ring_pk_mno";
        write_ring_to_bulletin(
            &storage,
            &bulletin,
            ring_pk,
            vec!["aabbccdd".to_string()],
            None,
        )
        .await;
        // No RingShareBundle written — would fail if the time check ran.
        let result = validate_refresh_session_init(ring_pk, "aabbccdd", &storage, &bulletin).await;
        assert!(
            result.is_ok(),
            "Expected Ok when pss_interval is None (no time check), got: {:?}",
            result
        );
        cleanup_db(&db_path);
    }
}
