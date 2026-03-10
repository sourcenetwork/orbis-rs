use crate::constants::BULLETIN_RING_NAMESPACE;
use crate::dkg::error::DkgError;
use crate::helpers::helpers::extract_node_part;
use crate::helpers::test_helpers::{cleanup_db, create_test_app_state_with_bulletin, test_db_path};
use bulletin::{
    dummy::DummyBulletin,
    r#trait::{Bulletin, BulletinPost, RingPayload},
};
use local_storage::r#trait::{LocalStorage, LocalStorageKeys};
use std::sync::Arc;
use std::time::Duration;

use crypto::DkgImpl;

// ──────────────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────────────

/// Build an AppState whose bulletin has `ring_payload` stored under `ring_id`.
///
/// Returns `(app_state, db_path, dummy_bulletin)` so callers can inspect the
/// bulletin and clean up the DB afterwards.
async fn make_state_with_ring(
    db_name: &str,
    ring_id: &str,
    ring_payload: &RingPayload,
) -> (
    crate::app_state::AppState<DkgImpl>,
    String,
    Arc<DummyBulletin>,
) {
    let dummy_bulletin = Arc::new(DummyBulletin::new().await.expect("DummyBulletin::new"));

    let payload_bytes = serde_json::to_vec(ring_payload).expect("serialize RingPayload");
    let post = BulletinPost {
        id: ring_id.to_string(),
        namespace: BULLETIN_RING_NAMESPACE.to_string(),
        payload: payload_bytes,
        proof: vec![],
    };
    dummy_bulletin.set_post(
        BULLETIN_RING_NAMESPACE.to_string(),
        ring_id.to_string(),
        post,
    );

    let shared_bulletin: Arc<dyn Bulletin + Send + Sync> = dummy_bulletin.clone();
    let db_path = test_db_path(db_name);
    let app_state = create_test_app_state_with_bulletin(
        Some("127.0.0.1:0".to_string()),
        true,
        shared_bulletin,
        db_name,
    )
    .await;

    (app_state, db_path, dummy_bulletin)
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
    super::spawn_reshare_scheduler(state.clone(), Duration::ZERO);

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
    let result = super::refresh_all_rings(&Arc::new(app_state)).await;
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
    let ring_index = vec!["nonexistent_ring_id".to_string()];
    let index_bytes = serde_json::to_vec(&ring_index).expect("serialize ring index");
    app_state
        .local_storage
        .set(LocalStorageKeys::RingIndex, index_bytes)
        .expect("set RingIndex");

    // refresh_all_rings absorbs per-ring errors; should still be Ok(())
    let result = super::refresh_all_rings(&Arc::new(app_state)).await;
    assert!(
        result.is_ok(),
        "refresh_all_rings should not propagate per-ring bulletin errors"
    );

    cleanup_db(&db_path);
}

/// When the bulletin returns a ring but our node is not the lexicographically
/// smallest peer, `refresh_ring` should skip gracefully (Ok(())).
#[tokio::test]
async fn test_refresh_ring_not_initiator_skips_silently() {
    let db_name = "pss_not_initiator";
    let ring_id = "test_ring_not_initiator";

    // Two fake peer IDs that sort before any real random peer ID.
    // They are 64-char hex strings (all zeroes / ones) — valid format.
    let fake_peer_1 = "0".repeat(64);
    let fake_peer_2 = "1".repeat(64);

    let ring_payload = RingPayload {
        ring_pk: "fake_pk".to_string(),
        peer_ids: vec![fake_peer_1.clone(), fake_peer_2.clone()],
        threshold: 1,
        public_polynomial: "fake_poly".to_string(),
    };

    let (app_state, db_path, _bulletin) =
        make_state_with_ring(db_name, ring_id, &ring_payload).await;

    // Our real peer ID (random) is almost certainly larger than all-zeroes
    let our_hex = hex::encode(app_state.network.local_peer_id().as_bytes());
    let our_node_part = extract_node_part(&our_hex);

    // Confirm our peer is NOT the smallest (test precondition)
    let mut sorted = vec![fake_peer_1.clone(), fake_peer_2.clone()];
    sorted.sort();
    assert_ne!(
        extract_node_part(&sorted[0]),
        our_node_part,
        "Test setup: our node must not be the smallest peer for this test to be meaningful"
    );

    let state_arc = Arc::new(app_state);
    let result = super::refresh_ring(&state_arc, ring_id).await;

    assert!(
        result.is_ok(),
        "Non-initiator should skip cleanly: {:?}",
        result
    );
    assert_eq!(
        state_arc.dkg_session_state.session_count().await,
        0,
        "No session should be created when this node is not the initiator"
    );

    cleanup_db(&db_path);
}

/// When the bulletin has a ring but the stored payload is corrupt,
/// `refresh_ring` should return a deserialization error.
#[tokio::test]
async fn test_refresh_ring_bad_bulletin_payload() {
    let db_name = "pss_bad_payload";
    let ring_id = "test_ring_bad_payload";
    let db_path = test_db_path(db_name);

    let dummy_bulletin = Arc::new(DummyBulletin::new().await.expect("DummyBulletin::new"));
    // Store garbage bytes under the ring ID
    let bad_post = BulletinPost {
        id: ring_id.to_string(),
        namespace: BULLETIN_RING_NAMESPACE.to_string(),
        payload: b"not valid json".to_vec(),
        proof: vec![],
    };
    dummy_bulletin.set_post(
        BULLETIN_RING_NAMESPACE.to_string(),
        ring_id.to_string(),
        bad_post,
    );

    let shared_bulletin: Arc<dyn Bulletin + Send + Sync> = dummy_bulletin;
    let app_state = create_test_app_state_with_bulletin(
        Some("127.0.0.1:0".to_string()),
        true,
        shared_bulletin,
        db_name,
    )
    .await;

    let result = super::refresh_ring(&Arc::new(app_state), ring_id).await;
    assert!(
        matches!(result, Err(DkgError::Deserialization(_))),
        "Expected Deserialization error, got: {:?}",
        result
    );

    cleanup_db(&db_path);
}

/// When the ring index lists a ring that has no bulletin entry at all,
/// `refresh_ring` should return a Storage error.
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

    let result = super::refresh_ring(&Arc::new(app_state), "ghost_ring").await;
    assert!(
        matches!(result, Err(DkgError::Storage(_))),
        "Expected Storage error for missing ring, got: {:?}",
        result
    );

    cleanup_db(&db_path);
}
