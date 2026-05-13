use crate::dkg::error::DkgError;
use crate::helpers::helpers::extract_node_part;
use crate::helpers::test_helpers::BULLETIN_RING_NAMESPACE;
use crate::helpers::test_helpers::{cleanup_db, create_test_app_state_with_bulletin, test_db_path};
use crate::ring_state::RingIndexEntry;
use bulletin::{
    dummy::DummyBulletin,
    r#trait::{Bulletin, RingPayload},
};
use local_storage::r#trait::{LocalStorage, LocalStorageKeys};
use std::sync::Arc;
use std::time::Duration;

use crypto::DkgImpl;

// ──────────────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────────────

/// Build an AppState with `ring_payload` posted to the bulletin.
///
/// Seeds `RingIndex` with a `RingIndexEntry` so the PSS scheduler can find the ring.
/// Returns `(app_state, ring_index_entry, db_path)`.
async fn make_state_with_ring(
    db_name: &str,
    ring_payload: &RingPayload,
) -> (crate::app_state::AppState<DkgImpl>, RingIndexEntry, String) {
    let bulletin: Arc<dyn Bulletin + Send + Sync> =
        Arc::new(DummyBulletin::new().await.expect("DummyBulletin::new"));
    let db_path = test_db_path(db_name);
    let app_state = create_test_app_state_with_bulletin(
        Some("127.0.0.1:0".to_string()),
        true,
        bulletin,
        db_name,
    )
    .await;

    // Post RingPayload to the bulletin and derive the post_id.
    let payload_bytes = serde_json::to_vec(ring_payload).expect("serialize RingPayload");
    app_state
        .bulletin
        .post(
            BULLETIN_RING_NAMESPACE.to_string(),
            payload_bytes.clone(),
            None,
        )
        .await
        .expect("post RingPayload to bulletin");
    let post_id = app_state
        .bulletin
        .get_post_id(BULLETIN_RING_NAMESPACE, &payload_bytes)
        .expect("compute post_id");

    // Seed RingIndex with the entry.
    let entry = RingIndexEntry {
        ring_pk_str: ring_payload.ring_pk.clone(),
        bulletin_post_id: post_id,
        bulletin_namespace: BULLETIN_RING_NAMESPACE.to_string(),
    };
    let index_bytes = serde_json::to_vec(&vec![&entry]).expect("serialize RingIndex");
    app_state
        .local_storage
        .set(LocalStorageKeys::RingIndex, index_bytes)
        .expect("write RingIndex");

    (app_state, entry, db_path)
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

/// A zero interval should disable the scheduler immediately without spawning any work.
#[tokio::test]
async fn test_scheduler_zero_interval_is_noop() {
    let db_name = "pss_noop_scheduler";
    let db_path = test_db_path(db_name);

    let bulletin: Arc<dyn Bulletin + Send + Sync> =
        Arc::new(DummyBulletin::new().await.expect("DummyBulletin::new"));
    let app_state = create_test_app_state_with_bulletin(
        Some("127.0.0.1:0".to_string()),
        true,
        bulletin,
        db_name,
    )
    .await;

    let state = Arc::new(app_state);
    // Should return immediately without spawning
    super::spawn_pss_scheduler(state.clone(), Duration::ZERO);

    // Give the event loop a chance to run any spawned tasks
    tokio::time::sleep(Duration::from_millis(50)).await;

    // No DKG sessions should have been created
    assert_eq!(
        state.dkg_session_state.session_count().await,
        0,
        "No sessions should be created when interval is zero"
    );

    cleanup_db(&db_path);
}

/// When the ring index is empty (fresh node, no DKG completed yet),
/// `refresh_all_rings` should return Ok(()) silently.
#[tokio::test]
async fn test_refresh_all_rings_empty_index() {
    let db_name = "pss_empty_index";
    let db_path = test_db_path(db_name);

    let bulletin: Arc<dyn Bulletin + Send + Sync> =
        Arc::new(DummyBulletin::new().await.expect("DummyBulletin::new"));
    let app_state = create_test_app_state_with_bulletin(
        Some("127.0.0.1:0".to_string()),
        true,
        bulletin,
        db_name,
    )
    .await;

    // Local storage has no RingIndex entry
    let result = super::pss_all_rings(&Arc::new(app_state)).await;
    assert!(result.is_ok(), "Should succeed with empty ring index");

    cleanup_db(&db_path);
}

/// When the ring index lists a ring that has no matching entry in the bulletin,
/// `refresh_all_rings` should still return Ok(()) — per-ring errors are logged
/// and swallowed so other rings are not affected.
#[tokio::test]
async fn test_refresh_all_rings_bulletin_miss_does_not_propagate() {
    let db_name = "pss_bulletin_miss";
    let db_path = test_db_path(db_name);

    let bulletin: Arc<dyn Bulletin + Send + Sync> =
        Arc::new(DummyBulletin::new().await.expect("DummyBulletin::new"));
    let app_state = create_test_app_state_with_bulletin(
        Some("127.0.0.1:0".to_string()),
        true,
        bulletin,
        db_name,
    )
    .await;

    // Seed ring index with a nonexistent ring
    let ring_index = vec![RingIndexEntry {
        ring_pk_str: "nonexistent_ring".to_string(),
        bulletin_post_id: "nonexistent_ring_id".to_string(),
        bulletin_namespace: BULLETIN_RING_NAMESPACE.to_string(),
    }];
    let index_bytes = serde_json::to_vec(&ring_index).expect("serialize ring index");
    app_state
        .local_storage
        .set(LocalStorageKeys::RingIndex, index_bytes)
        .expect("set RingIndex");

    // pss_all_rings absorbs per-ring errors; should still be Ok(())
    let result = super::pss_all_rings(&Arc::new(app_state)).await;
    assert!(
        result.is_ok(),
        "refresh_all_rings should not propagate per-ring bulletin errors"
    );

    cleanup_db(&db_path);
}

/// When the ring's peer list does not include this node at all, `pss_ring`
/// should reject the refresh/reshare attempt instead of silently standing down.
#[tokio::test]
async fn test_refresh_ring_rejects_non_member() {
    let db_name = "pss_non_member";

    // Two fake peer IDs that sort before any real random peer ID.
    // They are 64-char hex strings (all zeroes / ones) — valid format.
    let fake_peer_1 = "0".repeat(64);
    let fake_peer_2 = "1".repeat(64);

    // ring_pk is not validated on the non-member path because membership is checked
    // first once the payload is deserialized.
    let ring_payload = RingPayload {
        ring_pk: "fake_pk".to_string(),
        peer_ids: vec![fake_peer_1.clone(), fake_peer_2.clone()],
        new_peer_ids: None,
        new_threshold: None,
        threshold: 1,
        pss_interval: Some(86400),
        block_number_nonce: 0,
    };

    let (app_state, entry, db_path) = make_state_with_ring(db_name, &ring_payload).await;

    // Our real peer ID is not one of the fake committee members.
    let our_hex = hex::encode(app_state.network.local_peer_id().as_bytes());
    let our_node_part = extract_node_part(&our_hex);

    // Confirm our peer is absent from the committee (test precondition).
    assert!(
        !ring_payload
            .peer_ids
            .iter()
            .any(|peer_id| extract_node_part(peer_id) == our_node_part),
        "Test setup: our node must not be in the committee for this test to be meaningful"
    );

    let state_arc = Arc::new(app_state);
    let result = super::pss_ring(&state_arc, &entry).await;

    assert!(
        matches!(result, Err(DkgError::Unauthorized(_))),
        "Non-member should be rejected explicitly: {:?}",
        result
    );
    assert_eq!(
        state_arc.dkg_session_state.session_count().await,
        0,
        "No session should be created when this node is not in the committee"
    );

    cleanup_db(&db_path);
}

/// A malformed peer list must not leave the ring marked as in-progress when
/// refresh setup fails before any session is created.
#[tokio::test]
async fn test_refresh_setup_invalid_peer_does_not_wedge_ring_claim() {
    let db_name = "pss_invalid_peer_no_wedge";
    let (app_state, our_hex, db_path) = make_initiator_state(db_name).await;

    let ring_pk = "pss_invalid_peer_ring";
    let ring_payload = RingPayload {
        ring_pk: ring_pk.to_string(),
        peer_ids: vec![our_hex.clone(), "not-a-valid-peer-id".to_string()],
        new_peer_ids: None,
        new_threshold: None,
        threshold: 1,
        pss_interval: Some(1),
        block_number_nonce: 0,
    };

    let entry = post_ring_and_seed_index(&app_state, &ring_payload).await;
    let state_arc = Arc::new(app_state);

    let result = super::pss_ring(&state_arc, &entry).await;
    assert!(
        matches!(result, Err(DkgError::InvalidInput(_))),
        "Expected InvalidInput for malformed peer ID, got: {:?}",
        result
    );
    assert_eq!(
        state_arc.dkg_session_state.session_count().await,
        0,
        "No session should be created when refresh setup rejects invalid peer IDs"
    );
    assert!(
        !state_arc
            .dkg_session_state
            .is_ring_pss_active(ring_pk)
            .await,
        "Refresh setup failure must not leave the ring claimed as in-progress"
    );

    cleanup_db(&db_path);
}

/// When the bulletin has corrupt bytes for a ring's payload,
/// `refresh_ring` should return a deserialization error.
#[tokio::test]
async fn test_refresh_ring_bad_bulletin_payload() {
    let db_name = "pss_bad_payload";
    let ring_pk_str = "test_ring_bad_payload";
    let db_path = test_db_path(db_name);

    let bulletin: Arc<dyn Bulletin + Send + Sync> =
        Arc::new(DummyBulletin::new().await.expect("DummyBulletin::new"));
    let app_state = create_test_app_state_with_bulletin(
        Some("127.0.0.1:0".to_string()),
        true,
        bulletin,
        db_name,
    )
    .await;

    // Post garbage bytes to the bulletin so deserialization of RingPayload fails.
    let garbage = b"not valid json".to_vec();
    app_state
        .bulletin
        .post(BULLETIN_RING_NAMESPACE.to_string(), garbage.clone(), None)
        .await
        .expect("post garbage");
    let post_id = app_state
        .bulletin
        .get_post_id(BULLETIN_RING_NAMESPACE, &garbage)
        .expect("compute post_id");

    let entry = RingIndexEntry {
        ring_pk_str: ring_pk_str.to_string(),
        bulletin_post_id: post_id,
        bulletin_namespace: BULLETIN_RING_NAMESPACE.to_string(),
    };
    app_state
        .local_storage
        .set(
            LocalStorageKeys::RingIndex,
            serde_json::to_vec(&vec![&entry]).expect("serialize"),
        )
        .expect("write RingIndex");

    let result = super::pss_ring(&Arc::new(app_state), &entry).await;
    assert!(
        matches!(result, Err(DkgError::Deserialization(_))),
        "Expected Deserialization error, got: {:?}",
        result
    );

    cleanup_db(&db_path);
}

/// When the ring index points at a bulletin post for a different ring,
/// `pss_ring` must reject it before deriving committee state.
#[tokio::test]
async fn test_refresh_ring_rejects_bulletin_ring_pk_mismatch() {
    let db_name = "pss_ring_pk_mismatch";
    let (app_state, our_hex, db_path) = make_initiator_state(db_name).await;

    let ring_payload = RingPayload {
        ring_pk: "bulletin_ring_pk".to_string(),
        peer_ids: vec![our_hex],
        new_peer_ids: None,
        new_threshold: None,
        threshold: 1,
        pss_interval: Some(1),
        block_number_nonce: 0,
    };

    let payload_bytes = serde_json::to_vec(&ring_payload).expect("serialize RingPayload");
    app_state
        .bulletin
        .post(
            BULLETIN_RING_NAMESPACE.to_string(),
            payload_bytes.clone(),
            None,
        )
        .await
        .expect("post RingPayload");
    let post_id = app_state
        .bulletin
        .get_post_id(BULLETIN_RING_NAMESPACE, &payload_bytes)
        .expect("compute post_id");

    let entry = RingIndexEntry {
        ring_pk_str: "expected_ring_pk".to_string(),
        bulletin_post_id: post_id,
        bulletin_namespace: BULLETIN_RING_NAMESPACE.to_string(),
    };
    app_state
        .local_storage
        .set(
            LocalStorageKeys::RingIndex,
            serde_json::to_vec(&vec![&entry]).expect("serialize RingIndex"),
        )
        .expect("write RingIndex");

    let result = super::pss_ring(&Arc::new(app_state), &entry).await;
    assert!(
        matches!(result, Err(DkgError::Storage(ref msg)) if msg.contains("bulletin post ring_pk mismatch")),
        "Expected Storage error for mismatched ring_pk, got: {:?}",
        result
    );

    cleanup_db(&db_path);
}

// ──────────────────────────────────────────────────────────────────────────────
// Dispatch tests — reshare vs refresh routing
// ──────────────────────────────────────────────────────────────────────────────

/// Set up an AppState and return (app_state, our_hex, db_path).
async fn make_initiator_state(
    db_name: &str,
) -> (crate::app_state::AppState<DkgImpl>, String, String) {
    let db_path = test_db_path(db_name);
    let bulletin: Arc<dyn Bulletin + Send + Sync> =
        Arc::new(DummyBulletin::new().await.expect("DummyBulletin::new"));
    let app_state = create_test_app_state_with_bulletin(
        Some("127.0.0.1:0".to_string()),
        true,
        bulletin,
        db_name,
    )
    .await;
    let our_hex = hex::encode(app_state.network.local_peer_id().as_bytes());
    (app_state, our_hex, db_path)
}

/// Post a RingPayload to the bulletin and seed RingIndex.
async fn post_ring_and_seed_index(
    app_state: &crate::app_state::AppState<DkgImpl>,
    ring_payload: &RingPayload,
) -> RingIndexEntry {
    let payload_bytes = serde_json::to_vec(ring_payload).expect("serialize RingPayload");
    app_state
        .bulletin
        .post(
            BULLETIN_RING_NAMESPACE.to_string(),
            payload_bytes.clone(),
            None,
        )
        .await
        .expect("post RingPayload");
    let post_id = app_state
        .bulletin
        .get_post_id(BULLETIN_RING_NAMESPACE, &payload_bytes)
        .expect("compute post_id");
    let entry = RingIndexEntry {
        ring_pk_str: ring_payload.ring_pk.clone(),
        bulletin_post_id: post_id,
        bulletin_namespace: BULLETIN_RING_NAMESPACE.to_string(),
    };
    app_state
        .local_storage
        .set(
            LocalStorageKeys::RingIndex,
            serde_json::to_vec(&vec![&entry]).expect("serialize RingIndex"),
        )
        .expect("write RingIndex");
    entry
}

/// When `new_peer_ids` is set, `pss_ring` must dispatch to `trigger_reshare`
/// even when `pss_interval` is absent (which would cause a refresh to skip).
///
/// The reshare path loads the old share bundle; since none exists the function
/// returns `Err(Storage(...))`.  That proves we reached `trigger_reshare` rather
/// than silently returning at the interval gate.
#[tokio::test]
async fn test_pss_ring_reshare_bypasses_interval() {
    let db_name = "pss_reshare_bypasses_interval";
    let (app_state, our_hex, db_path) = make_initiator_state(db_name).await;

    let ring_payload = RingPayload {
        ring_pk: "pss_reshare_bypass_pk".to_string(),
        peer_ids: vec![our_hex.clone()],
        new_peer_ids: Some(vec![our_hex.clone()]),
        new_threshold: None,
        threshold: 1,
        pss_interval: None, // no interval — refresh would skip silently
        block_number_nonce: 0,
    };

    let entry = post_ring_and_seed_index(&app_state, &ring_payload).await;
    let result = super::pss_ring(&Arc::new(app_state), &entry).await;

    assert!(
        matches!(result, Err(DkgError::Storage(_))),
        "Expected Storage error: reshare was triggered despite missing pss_interval, \
         then failed to load absent share bundle. Got: {:?}",
        result
    );
    cleanup_db(&db_path);
}

/// When only `new_threshold` is set (and `new_peer_ids` is absent),
/// `pss_ring` must still dispatch to `trigger_reshare`, using the old committee
/// as the fallback for the reshare session's `new_peer_ids`.
#[tokio::test]
async fn test_pss_ring_new_threshold_alone_triggers_reshare() {
    let db_name = "pss_new_threshold_triggers_reshare";
    let (app_state, our_hex, db_path) = make_initiator_state(db_name).await;

    let ring_payload = RingPayload {
        ring_pk: "pss_new_threshold_pk".to_string(),
        peer_ids: vec![our_hex.clone()],
        new_peer_ids: None, // only threshold change, no new members
        new_threshold: Some(1),
        threshold: 1,
        pss_interval: None,
        block_number_nonce: 0,
    };

    let entry = post_ring_and_seed_index(&app_state, &ring_payload).await;
    let result = super::pss_ring(&Arc::new(app_state), &entry).await;

    assert!(
        matches!(result, Err(DkgError::Storage(_))),
        "Expected Storage error: new_threshold alone triggered reshare which tried to load \
         an absent share bundle. Got: {:?}",
        result
    );
    cleanup_db(&db_path);
}

/// When neither `new_peer_ids` nor `new_threshold` is set, and the ring has
/// no `pss_interval`, `pss_ring` must skip silently (Ok(())) even when our
/// node is the initiator.
#[tokio::test]
async fn test_pss_ring_refresh_skips_without_interval() {
    let db_name = "pss_refresh_skips_no_interval";
    let (app_state, our_hex, db_path) = make_initiator_state(db_name).await;

    let ring_payload = RingPayload {
        ring_pk: "pss_no_interval_pk".to_string(),
        peer_ids: vec![our_hex.clone()],
        new_peer_ids: None,
        new_threshold: None,
        threshold: 1,
        pss_interval: None, // refresh requires pss_interval; without it, must skip
        block_number_nonce: 0,
    };

    let entry = post_ring_and_seed_index(&app_state, &ring_payload).await;
    let result = super::pss_ring(&Arc::new(app_state), &entry).await;

    assert!(
        result.is_ok(),
        "Expected Ok(()): refresh with no pss_interval must skip silently. Got: {:?}",
        result
    );
    cleanup_db(&db_path);
}

/// When the ring index lists a ring that has no bulletin entry at all,
/// `pss_ring` should return a Storage error.
#[tokio::test]
async fn test_refresh_ring_missing_from_bulletin() {
    let db_name = "pss_missing_ring";
    let db_path = test_db_path(db_name);

    let bulletin: Arc<dyn Bulletin + Send + Sync> =
        Arc::new(DummyBulletin::new().await.expect("DummyBulletin::new"));
    let app_state = create_test_app_state_with_bulletin(
        Some("127.0.0.1:0".to_string()),
        true,
        bulletin,
        db_name,
    )
    .await;

    let entry = RingIndexEntry {
        ring_pk_str: "ghost_ring".to_string(),
        bulletin_post_id: "ghost_ring".to_string(),
        bulletin_namespace: BULLETIN_RING_NAMESPACE.to_string(),
    };
    let result = super::pss_ring(&Arc::new(app_state), &entry).await;
    assert!(
        matches!(result, Err(DkgError::Storage(_))),
        "Expected Storage error for missing ring, got: {:?}",
        result
    );

    cleanup_db(&db_path);
}
