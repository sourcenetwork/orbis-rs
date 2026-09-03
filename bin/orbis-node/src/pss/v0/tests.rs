use crate::dkg::v0::error::DkgError;
use crate::helpers::auth::current_unix_time;
use crate::helpers::test_helpers::{cleanup_db, create_test_app_state_with_bulletin, test_db_path};
use crate::ring_state::{RingIndexEntry, RingShareBundle};
use bulletin::{
    dummy::DummyBulletin,
    error::BulletinError,
    r#trait::{
        Bulletin, BulletinKind, BulletinPost, BulletinWriteKind, NodeInfo, RingCancellationPayload,
        RingPayload,
    },
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
    let bulletin = Arc::new(DummyBulletin::new().await.expect("DummyBulletin::new"));
    let db_path = test_db_path(db_name);
    let app_state = create_test_app_state_with_bulletin(true, bulletin.clone(), db_name).await;

    let post_id = format!("test-pss-ring-{}", ring_payload.ring_pk);
    bulletin
        .set_ring(post_id.clone(), ring_payload.clone())
        .expect("seed RingPayload");

    // Seed RingIndex with the entry.
    let entry = RingIndexEntry {
        ring_pk_str: ring_payload.ring_pk.clone(),
        bulletin_post_id: post_id,
        indexed_at_secs: 0,
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

    let bulletin = Arc::new(DummyBulletin::new().await.expect("DummyBulletin::new"));
    let app_state = create_test_app_state_with_bulletin(true, bulletin, db_name).await;

    let state = Arc::new(app_state);
    // Should return immediately without spawning
    assert!(super::spawn_pss_scheduler(state.clone(), Duration::ZERO).is_none());

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

#[tokio::test]
async fn scheduler_shutdown_interrupts_waiting_tick() {
    let db_name = "pss_scheduler_shutdown";
    let db_path = test_db_path(db_name);
    let bulletin = Arc::new(DummyBulletin::new().await.expect("DummyBulletin::new"));
    let app_state = create_test_app_state_with_bulletin(true, bulletin, db_name).await;

    let handle = super::spawn_pss_scheduler(Arc::new(app_state), Duration::from_secs(60))
        .expect("scheduler should start");
    tokio::time::timeout(Duration::from_millis(250), handle.shutdown())
        .await
        .expect("scheduler shutdown should not wait for the next tick");

    cleanup_db(&db_path);
}

/// When the ring index is empty (fresh node, no DKG completed yet),
/// `refresh_all_rings` should return Ok(()) silently.
#[tokio::test]
async fn test_refresh_all_rings_empty_index() {
    let db_name = "pss_empty_index";
    let db_path = test_db_path(db_name);

    let bulletin = Arc::new(DummyBulletin::new().await.expect("DummyBulletin::new"));
    let app_state = create_test_app_state_with_bulletin(true, bulletin, db_name).await;

    // Local storage has no RingIndex entry
    let result = super::pss_all_rings(&Arc::new(app_state)).await;
    assert!(result.is_ok(), "Should succeed with empty ring index");

    cleanup_db(&db_path);
}

/// A corrupt ring index must surface an error so the scheduler alerts operators
/// instead of silently treating the node as if it manages no rings.
#[tokio::test]
async fn test_refresh_all_rings_rejects_corrupt_index() {
    let db_name = "pss_corrupt_index";
    let db_path = test_db_path(db_name);

    let bulletin = Arc::new(DummyBulletin::new().await.expect("DummyBulletin::new"));
    let app_state = create_test_app_state_with_bulletin(true, bulletin, db_name).await;

    app_state
        .local_storage
        .set(LocalStorageKeys::RingIndex, b"not valid json".to_vec())
        .expect("write corrupt RingIndex");

    let result = super::pss_all_rings(&Arc::new(app_state)).await;
    assert!(
        matches!(
            result,
            Err(DkgError::Storage(ref message))
                if message.contains("failed to deserialize RingIndex")
        ),
        "corrupt RingIndex should be reported, got: {result:?}"
    );

    cleanup_db(&db_path);
}

/// When the ring index lists a ring that has no matching entry in the bulletin,
/// `refresh_all_rings` should still return Ok(()) — per-ring errors are logged
/// and swallowed so other rings are not affected.
#[tokio::test]
async fn test_refresh_all_rings_bulletin_miss_does_not_propagate() {
    let db_name = "pss_bulletin_miss";
    let db_path = test_db_path(db_name);

    let bulletin = Arc::new(DummyBulletin::new().await.expect("DummyBulletin::new"));
    let app_state = create_test_app_state_with_bulletin(true, bulletin, db_name).await;

    // Seed ring index with a nonexistent ring
    let ring_index = vec![RingIndexEntry {
        ring_pk_str: "nonexistent_ring".to_string(),
        bulletin_post_id: "nonexistent_ring_id".to_string(),
        indexed_at_secs: 0,
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

/// When Vera has finalized a committee that excludes this node, the PSS
/// scan must securely remove the stale bundle and ring-index entry.
#[tokio::test]
async fn test_refresh_ring_reconciles_finalized_removed_member() {
    let db_name = "pss_non_member";

    // Two fake peer IDs that sort before any real random peer ID.
    // They are 64-char hex strings (all zeroes / ones) — valid format.
    let fake_node_key_1 = "non-member-node-key-1".to_string();
    let fake_node_key_2 = "non-member-node-key-2".to_string();

    // ring_pk is not validated on the non-member path because membership is checked
    // first once the payload is deserialized.
    let ring_payload = RingPayload {
        upgrade_info: Default::default(),
        ring_pk: "fake_pk".to_string(),
        peer_node_keys: vec![fake_node_key_1.clone(), fake_node_key_2.clone()],
        new_peer_node_keys: None,
        new_threshold: None,
        threshold: 1,
        pss_interval: 86400,
        block_number_nonce: 0,
        policy_id: None,
        trusted_auth_relay_dids: None,
        reporting: Default::default(),
    };

    let (app_state, entry, db_path) = make_state_with_ring(db_name, &ring_payload).await;

    // Confirm our Vera signing identity is absent from the finalized
    // committee, then seed stale secret material left by an offline rotation.
    assert!(
        !ring_payload
            .peer_node_keys
            .iter()
            .any(|node_key| node_key == &app_state.node_key),
        "Test setup: our node must not be in the committee for this test to be meaningful"
    );
    RingShareBundle {
        share_bytes: vec![1, 2, 3].into(),
        public_polynomial: "stale-polynomial".to_string(),
        last_pss: 1,
    }
    .save_by_ring_key(&app_state.local_storage, &entry.ring_pk_str)
    .expect("seed stale finalized ring bundle");

    let state_arc = Arc::new(app_state);
    let result = super::pss_ring(&state_arc, &entry).await;

    assert!(
        result.is_ok(),
        "removed-member reconciliation failed: {result:?}"
    );
    assert_eq!(
        state_arc.dkg_session_state.session_count().await,
        0,
        "reconciliation must not create a DKG session"
    );
    assert!(
        RingShareBundle::load_by_ring_key(&state_arc.local_storage, &entry.ring_pk_str).is_err(),
        "finalized removal must delete stale secret material"
    );
    assert!(
        !ring_index_entries(&state_arc)
            .iter()
            .any(|candidate| candidate.ring_pk_str == entry.ring_pk_str),
        "finalized removal must delete the stale ring-index entry"
    );

    cleanup_db(&db_path);
}

#[tokio::test]
async fn test_removed_member_reconciliation_preserves_an_active_ring() {
    let db_name = "pss_non_member_active";
    let ring_payload = RingPayload {
        upgrade_info: Default::default(),
        ring_pk: "active_fake_pk".to_string(),
        peer_node_keys: vec!["non-member-node-key".to_string()],
        new_peer_node_keys: None,
        new_threshold: None,
        threshold: 1,
        pss_interval: 86400,
        block_number_nonce: 0,
        policy_id: None,
        trusted_auth_relay_dids: None,
        reporting: Default::default(),
    };
    let (app_state, entry, db_path) = make_state_with_ring(db_name, &ring_payload).await;
    RingShareBundle {
        share_bytes: vec![1, 2, 3].into(),
        public_polynomial: "active-polynomial".to_string(),
        last_pss: 1,
    }
    .save_by_ring_key(&app_state.local_storage, &entry.ring_pk_str)
    .expect("seed active ring bundle");
    app_state
        .dkg_session_state
        .claim_ring_pss_session(&entry.ring_pk_str, 7)
        .await;
    let state = Arc::new(app_state);

    super::pss_ring(&state, &entry).await.unwrap();

    assert!(
        RingShareBundle::load_by_ring_key(&state.local_storage, &entry.ring_pk_str).is_ok(),
        "active PSS material must not be reconciled as stale"
    );
    assert!(
        ring_index_entries(&state)
            .iter()
            .any(|candidate| candidate.ring_pk_str == entry.ring_pk_str),
        "active PSS ring-index entry must be preserved"
    );
    state
        .dkg_session_state
        .unmark_ring_pss(&entry.ring_pk_str)
        .await;

    drop(state);
    cleanup_db(&db_path);
}

/// A malformed peer list must not leave the ring marked as in-progress when
/// refresh setup fails before any session is created.
#[tokio::test]
async fn test_refresh_setup_invalid_peer_does_not_wedge_ring_claim() {
    let db_name = "pss_invalid_peer_no_wedge";
    let (app_state, our_node_key, db_path, bulletin) = make_initiator_state(db_name).await;

    let ring_pk = "pss_invalid_peer_ring";
    let ring_payload = RingPayload {
        upgrade_info: Default::default(),
        ring_pk: ring_pk.to_string(),
        peer_node_keys: vec![our_node_key.clone(), "missing-node-info-key".to_string()],
        new_peer_node_keys: None,
        new_threshold: None,
        threshold: 1,
        pss_interval: 1,
        block_number_nonce: 0,
        policy_id: None,
        trusted_auth_relay_dids: None,
        reporting: Default::default(),
    };

    let entry = post_ring_and_seed_index(&app_state, &bulletin, &ring_payload).await;
    RingShareBundle {
        share_bytes: vec![].into(),
        public_polynomial: "malformed-route-test-poly".to_string(),
        last_pss: 0,
    }
    .save_by_ring_key(&app_state.local_storage, ring_pk)
    .expect("store due refresh bundle");
    let state_arc = Arc::new(app_state);

    let result = super::pss_ring(&state_arc, &entry).await;
    assert!(
        matches!(
            result,
            Err(DkgError::InvalidInput(_)) | Err(DkgError::Unauthorized(_))
        ),
        "Expected a route-resolution error for the unresolved node, got: {:?}",
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

/// A follower resolves only the canonical leader when forwarding a refresh.
/// An unavailable canonical route is surfaced without creating a local
/// fallback attempt.
#[tokio::test]
async fn test_refresh_follower_does_not_fall_back_when_canonical_route_is_missing() {
    let db_name = "pss_follower_skips_route_resolution";
    let (app_state, our_node_key, db_path, bulletin) = make_initiator_state(db_name).await;

    let ring_payload = RingPayload {
        upgrade_info: Default::default(),
        ring_pk: "pss_follower_route_ring".to_string(),
        peer_node_keys: vec!["00-missing-canonical-leader".to_string(), our_node_key],
        new_peer_node_keys: None,
        new_threshold: None,
        threshold: 1,
        pss_interval: 0,
        block_number_nonce: 0,
        policy_id: None,
        trusted_auth_relay_dids: None,
        reporting: Default::default(),
    };
    let entry = post_ring_and_seed_index(&app_state, &bulletin, &ring_payload).await;
    let state = Arc::new(app_state);

    let result = super::pss_ring(&state, &entry).await;
    assert!(
        matches!(result, Err(DkgError::Unauthorized(_))),
        "a missing canonical leader route should be an availability error: {result:?}"
    );
    assert_eq!(state.dkg_session_state.session_count().await, 0);

    cleanup_db(&db_path);
}

/// When the bulletin has corrupt bytes for a ring's payload,
/// `refresh_ring` should return a deserialization error.
#[tokio::test]
async fn test_refresh_ring_bad_bulletin_payload() {
    let db_name = "pss_bad_payload";
    let ring_pk_str = "test_ring_bad_payload";
    let db_path = test_db_path(db_name);

    let bulletin = Arc::new(DummyBulletin::new().await.expect("DummyBulletin::new"));
    let app_state = create_test_app_state_with_bulletin(true, bulletin.clone(), db_name).await;

    // Post garbage bytes to the bulletin so deserialization of RingPayload fails.
    let garbage = b"not valid json".to_vec();
    let post_id = "test-bad-ring-payload".to_string();
    bulletin.set_post(
        post_id.clone(),
        BulletinPost {
            id: post_id.clone(),
            payload: garbage,
        },
    );

    let entry = RingIndexEntry {
        ring_pk_str: ring_pk_str.to_string(),
        bulletin_post_id: post_id,
        indexed_at_secs: 0,
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
        matches!(result, Err(DkgError::ProtocolError(_))),
        "Expected ProtocolError, got: {:?}",
        result
    );

    cleanup_db(&db_path);
}

/// When the ring index points at a bulletin post for a different ring,
/// `pss_ring` must reject it before deriving committee state.
#[tokio::test]
async fn test_refresh_ring_rejects_bulletin_ring_pk_mismatch() {
    let db_name = "pss_ring_pk_mismatch";
    let (app_state, our_hex, db_path, bulletin) = make_initiator_state(db_name).await;

    let ring_payload = RingPayload {
        upgrade_info: Default::default(),
        ring_pk: "bulletin_ring_pk".to_string(),
        peer_node_keys: vec![our_hex],
        new_peer_node_keys: None,
        new_threshold: None,
        threshold: 1,
        pss_interval: 1,
        block_number_nonce: 0,
        policy_id: None,
        trusted_auth_relay_dids: None,
        reporting: Default::default(),
    };

    let post_id = "test-pss-ring-pk-mismatch".to_string();
    bulletin
        .set_ring(post_id.clone(), ring_payload)
        .expect("seed RingPayload");

    let entry = RingIndexEntry {
        ring_pk_str: "expected_ring_pk".to_string(),
        bulletin_post_id: post_id,
        indexed_at_secs: 0,
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

#[tokio::test]
async fn test_pending_fresh_dkg_elapsed_interval_cleans_local_state() {
    let db_name = "pss_pending_fresh_cleanup_elapsed";
    let (app_state, our_hex, db_path, bulletin) = make_initiator_state(db_name).await;
    let local_ring_pk = "pending_fresh_elapsed_local_ring_pk";
    let ring_payload = RingPayload {
        upgrade_info: Default::default(),
        ring_pk: String::new(),
        peer_node_keys: vec![our_hex],
        new_peer_node_keys: None,
        new_threshold: None,
        threshold: 1,
        pss_interval: 1,
        block_number_nonce: 0,
        policy_id: None,
        trusted_auth_relay_dids: None,
        reporting: Default::default(),
    };

    let mut entry = post_ring_and_seed_index_with_local_key(
        &app_state,
        &bulletin,
        &ring_payload,
        local_ring_pk,
    )
    .await;
    entry.indexed_at_secs = current_unix_time().expect("system clock").saturating_sub(2);
    app_state
        .local_storage
        .set(
            LocalStorageKeys::RingIndex,
            serde_json::to_vec(&vec![&entry]).expect("serialize RingIndex"),
        )
        .expect("write RingIndex");
    assert!(
        !app_state
            .local_storage
            .contains(LocalStorageKeys::RingKey(local_ring_pk.to_string()))
            .expect("check RingKey presence"),
        "test setup should not store a finalized pending fresh DKG bundle"
    );

    let state_arc = Arc::new(app_state);
    let result = super::pss_ring(&state_arc, &entry).await;

    assert!(
        result.is_ok(),
        "pending fresh cleanup should succeed, got: {:?}",
        result
    );
    assert!(
        !state_arc
            .local_storage
            .contains(LocalStorageKeys::RingKey(local_ring_pk.to_string()))
            .expect("check RingKey deletion"),
        "pending fresh DKG cleanup should tolerate a missing finalized bundle"
    );
    assert!(
        !ring_index_entries(&state_arc)
            .iter()
            .any(|candidate| candidate.ring_pk_str == local_ring_pk),
        "expired pending fresh DKG RingIndex entry should be removed"
    );
    assert!(matches!(
        bulletin
            .read(entry.bulletin_post_id.clone(), BulletinKind::Ring)
            .await,
        Err(BulletinError::NotFound { .. })
    ));

    cleanup_db(&db_path);
}

#[tokio::test]
async fn test_pending_fresh_dkg_cancellation_failure_still_cleans_local_state() {
    let db_name = "pss_pending_fresh_cleanup_chain_failure";
    let (app_state, our_hex, db_path, bulletin) = make_initiator_state(db_name).await;
    let local_ring_pk = "pending_fresh_chain_failure_local_ring_pk";
    let ring_payload = RingPayload {
        upgrade_info: Default::default(),
        ring_pk: String::new(),
        peer_node_keys: vec![our_hex],
        new_peer_node_keys: None,
        new_threshold: None,
        threshold: 1,
        pss_interval: 1,
        block_number_nonce: 0,
        policy_id: None,
        trusted_auth_relay_dids: None,
        reporting: Default::default(),
    };

    let mut entry = post_ring_and_seed_index_with_local_key(
        &app_state,
        &bulletin,
        &ring_payload,
        local_ring_pk,
    )
    .await;
    entry.indexed_at_secs = current_unix_time().expect("system clock").saturating_sub(2);
    app_state
        .local_storage
        .set(
            LocalStorageKeys::RingIndex,
            serde_json::to_vec(&vec![&entry]).expect("serialize RingIndex"),
        )
        .expect("write RingIndex");
    bulletin.set_fail_pending_ring_cancellations(true);

    let state_arc = Arc::new(app_state);
    let result = super::pss_ring(&state_arc, &entry).await;

    assert!(
        result.is_ok(),
        "best-effort cancellation failure should not block local cleanup: {result:?}"
    );
    assert!(
        !ring_index_entries(&state_arc)
            .iter()
            .any(|candidate| candidate.ring_pk_str == local_ring_pk),
        "failed chain cancellation should still remove the local index entry"
    );
    assert!(
        bulletin
            .read(entry.bulletin_post_id.clone(), BulletinKind::Ring)
            .await
            .is_ok(),
        "injected cancellation failure should leave the bulletin ring intact"
    );

    cleanup_db(&db_path);
}

#[tokio::test]
async fn test_pending_fresh_dkg_missing_bulletin_ring_cleans_local_state() {
    let db_name = "pss_pending_fresh_cleanup_missing_ring";
    let (app_state, our_hex, db_path, bulletin) = make_initiator_state(db_name).await;
    let local_ring_pk = "pending_fresh_missing_bulletin_ring_pk";
    let ring_payload = RingPayload {
        upgrade_info: Default::default(),
        ring_pk: String::new(),
        peer_node_keys: vec![our_hex],
        new_peer_node_keys: None,
        new_threshold: None,
        threshold: 1,
        pss_interval: 86_400,
        block_number_nonce: 0,
        policy_id: None,
        trusted_auth_relay_dids: None,
        reporting: Default::default(),
    };
    let entry = post_ring_and_seed_index_with_local_key(
        &app_state,
        &bulletin,
        &ring_payload,
        local_ring_pk,
    )
    .await;

    let cancellation = RingCancellationPayload {
        ring_id: entry.bulletin_post_id.clone(),
    };
    let payload_bytes: Vec<u8> = cancellation.try_into().expect("serialize cancellation");
    bulletin
        .post(BulletinWriteKind::CancelPendingRing, payload_bytes)
        .await
        .expect("simulate another node cancelling the ring");

    let state_arc = Arc::new(app_state);
    let result = super::pss_ring(&state_arc, &entry).await;

    assert!(
        result.is_ok(),
        "an already-missing bulletin ring should reconcile cleanly: {result:?}"
    );
    assert!(
        !ring_index_entries(&state_arc)
            .iter()
            .any(|candidate| candidate.ring_pk_str == local_ring_pk),
        "bundle-less local index should be removed when another node already cancelled"
    );

    cleanup_db(&db_path);
}

#[tokio::test]
async fn test_pending_fresh_dkg_elapsed_interval_preserves_completed_bundle() {
    let db_name = "pss_pending_fresh_preserves_bundle";
    let (app_state, our_hex, db_path, bulletin) = make_initiator_state(db_name).await;
    let local_ring_pk = "pending_fresh_completed_local_ring_pk";
    let ring_payload = RingPayload {
        upgrade_info: Default::default(),
        ring_pk: String::new(),
        peer_node_keys: vec![our_hex],
        new_peer_node_keys: None,
        new_threshold: None,
        threshold: 1,
        pss_interval: 1,
        block_number_nonce: 0,
        policy_id: None,
        trusted_auth_relay_dids: None,
        reporting: Default::default(),
    };

    let mut entry = post_ring_and_seed_index_with_local_key(
        &app_state,
        &bulletin,
        &ring_payload,
        local_ring_pk,
    )
    .await;
    entry.indexed_at_secs = current_unix_time().expect("system clock").saturating_sub(2);
    app_state
        .local_storage
        .set(
            LocalStorageKeys::RingIndex,
            serde_json::to_vec(&vec![&entry]).expect("serialize RingIndex"),
        )
        .expect("write RingIndex");
    RingShareBundle {
        share_bytes: vec![].into(),
        public_polynomial: "completed-public-polynomial".to_string(),
        last_pss: entry.indexed_at_secs,
    }
    .save_by_ring_key(&app_state.local_storage, local_ring_pk)
    .expect("store completed fresh DKG bundle");

    let state_arc = Arc::new(app_state);
    let result = super::pss_ring(&state_arc, &entry).await;

    assert!(
        result.is_ok(),
        "pending fresh reconciliation should preserve completed state, got: {result:?}"
    );
    assert!(
        state_arc
            .local_storage
            .contains(LocalStorageKeys::RingKey(local_ring_pk.to_string()))
            .expect("check RingKey presence"),
        "completed fresh DKG bundle must remain while bulletin finalization is pending"
    );
    assert!(
        ring_index_entries(&state_arc)
            .iter()
            .any(|candidate| candidate.ring_pk_str == local_ring_pk),
        "completed fresh DKG RingIndex entry must remain while bulletin finalization is pending"
    );
    assert!(
        bulletin
            .read(entry.bulletin_post_id.clone(), BulletinKind::Ring)
            .await
            .is_ok(),
        "completed local bundle must prevent bulletin cancellation"
    );

    cleanup_db(&db_path);
}

#[tokio::test]
async fn test_pending_fresh_dkg_before_interval_remains_indexed() {
    let db_name = "pss_pending_fresh_cleanup_not_due";
    let (app_state, our_hex, db_path, bulletin) = make_initiator_state(db_name).await;
    let local_ring_pk = "pending_fresh_not_due_local_ring_pk";
    let ring_payload = RingPayload {
        upgrade_info: Default::default(),
        ring_pk: String::new(),
        peer_node_keys: vec![our_hex],
        new_peer_node_keys: None,
        new_threshold: None,
        threshold: 1,
        pss_interval: 86_400,
        block_number_nonce: 0,
        policy_id: None,
        trusted_auth_relay_dids: None,
        reporting: Default::default(),
    };

    let entry = post_ring_and_seed_index_with_local_key(
        &app_state,
        &bulletin,
        &ring_payload,
        local_ring_pk,
    )
    .await;

    let state_arc = Arc::new(app_state);
    let result = super::pss_ring(&state_arc, &entry).await;

    assert!(
        result.is_ok(),
        "pending fresh DKG before pss_interval should skip cleanup, got: {:?}",
        result
    );
    assert!(
        !state_arc
            .local_storage
            .contains(LocalStorageKeys::RingKey(local_ring_pk.to_string()))
            .expect("check RingKey presence"),
        "pending fresh DKG should not require a finalized bundle before interval"
    );
    assert!(
        ring_index_entries(&state_arc)
            .iter()
            .any(|candidate| candidate.ring_pk_str == local_ring_pk),
        "not-yet-expired pending fresh DKG RingIndex entry should remain"
    );

    cleanup_db(&db_path);
}

// ──────────────────────────────────────────────────────────────────────────────
// Dispatch tests — reshare vs refresh routing
// ──────────────────────────────────────────────────────────────────────────────

/// Set up an AppState with a routed NodeInfo and return (app_state, node_key, db_path).
async fn make_initiator_state(
    db_name: &str,
) -> (
    crate::app_state::AppState<DkgImpl>,
    String,
    String,
    Arc<DummyBulletin>,
) {
    let db_path = test_db_path(db_name);
    let bulletin = Arc::new(DummyBulletin::new().await.expect("DummyBulletin::new"));
    let app_state = create_test_app_state_with_bulletin(true, bulletin.clone(), db_name).await;
    let peer_id = hex::encode(app_state.network.local_peer_id().as_bytes());
    let node_key = app_state.node_key.clone();
    bulletin
        .set_node_info(
            node_key.clone(),
            NodeInfo {
                peer_id,
                controller_key: "test-controller-key".to_string(),
                whitelisted_policy_ids: vec!["test-policy".to_string()],
                whitelisted_ring_ids: vec![],
            },
        )
        .expect("seed self NodeInfo");
    (app_state, node_key, db_path, bulletin)
}

/// Post a RingPayload to the bulletin and seed RingIndex.
async fn post_ring_and_seed_index(
    app_state: &crate::app_state::AppState<DkgImpl>,
    bulletin: &DummyBulletin,
    ring_payload: &RingPayload,
) -> RingIndexEntry {
    post_ring_and_seed_index_with_local_key(
        app_state,
        bulletin,
        ring_payload,
        &ring_payload.ring_pk,
    )
    .await
}

fn seed_routable_node_info(
    bulletin: &DummyBulletin,
    node_key: &str,
    peer_byte: u8,
    allow_test_policy: bool,
) {
    bulletin
        .set_node_info(
            node_key.to_string(),
            NodeInfo {
                peer_id: hex::encode([peer_byte; 32]),
                controller_key: "test-controller-key".to_string(),
                whitelisted_policy_ids: allow_test_policy
                    .then(|| "test-policy".to_string())
                    .into_iter()
                    .collect(),
                whitelisted_ring_ids: vec![],
            },
        )
        .expect("seed routable test NodeInfo");
}

async fn post_ring_and_seed_index_with_local_key(
    app_state: &crate::app_state::AppState<DkgImpl>,
    bulletin: &DummyBulletin,
    ring_payload: &RingPayload,
    local_ring_pk: &str,
) -> RingIndexEntry {
    let post_id = format!("test-pss-ring-{local_ring_pk}");
    bulletin
        .set_ring(post_id.clone(), ring_payload.clone())
        .expect("seed RingPayload");
    let entry = RingIndexEntry {
        ring_pk_str: local_ring_pk.to_string(),
        bulletin_post_id: post_id,
        indexed_at_secs: current_unix_time().expect("system clock"),
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

fn ring_index_entries(app_state: &crate::app_state::AppState<DkgImpl>) -> Vec<RingIndexEntry> {
    app_state
        .local_storage
        .get(LocalStorageKeys::RingIndex)
        .expect("read RingIndex")
        .map(|bytes| serde_json::from_slice(&bytes).expect("parse RingIndex"))
        .unwrap_or_default()
}

/// When `new_peer_node_keys` is set, `pss_ring` must dispatch to `trigger_reshare`
/// even when `pss_interval` has not yet elapsed (which would cause a refresh to skip).
///
/// The reshare path loads the old share bundle; since none exists the function
/// returns `Err(Storage(...))`.  That proves we reached `trigger_reshare` rather
/// than silently returning at the timing gate.
#[tokio::test]
async fn test_pss_ring_reshare_bypasses_interval() {
    let db_name = "pss_reshare_bypasses_interval";
    let (app_state, our_hex, db_path, bulletin) = make_initiator_state(db_name).await;
    let new_member = "zzzz-reshare-bypass-member".to_string();
    seed_routable_node_info(&bulletin, &new_member, 0x91, true);

    let ring_payload = RingPayload {
        upgrade_info: Default::default(),
        ring_pk: "pss_reshare_bypass_pk".to_string(),
        peer_node_keys: vec![our_hex.clone()],
        new_peer_node_keys: Some(vec![our_hex.clone(), new_member]),
        new_threshold: None,
        threshold: 1,
        pss_interval: u64::MAX, // interval far out — refresh would skip, but reshare must not
        block_number_nonce: 0,
        policy_id: Some("test-policy".to_string()),
        trusted_auth_relay_dids: None,
        reporting: Default::default(),
    };

    let entry = post_ring_and_seed_index(&app_state, &bulletin, &ring_payload).await;
    let result = super::pss_ring(&Arc::new(app_state), &entry).await;

    assert!(
        matches!(result, Err(DkgError::Storage(_))),
        "Expected Storage error: reshare was triggered despite missing pss_interval, \
         then failed to load absent share bundle. Got: {:?}",
        result
    );
    cleanup_db(&db_path);
}

/// A local PSS reshare initiation must still honor this node's NodeInfo opt-in
/// when the local node is in the new committee.
#[tokio::test]
async fn test_pss_ring_reshare_rejects_new_committee_node_without_allowlist() {
    let db_name = "pss_reshare_rejects_unauthorized_new_member";
    let (app_state, our_node_key, db_path, bulletin) = make_initiator_state(db_name).await;
    let local_peer_id = hex::encode(app_state.network.local_peer_id().as_bytes());
    bulletin
        .set_node_info(
            our_node_key.clone(),
            NodeInfo {
                peer_id: local_peer_id,
                controller_key: "test-controller-key".to_string(),
                whitelisted_policy_ids: vec![],
                whitelisted_ring_ids: vec![],
            },
        )
        .expect("override self NodeInfo without allowlist");
    let new_member = "zzzz-unauthorized-reshare-member".to_string();
    seed_routable_node_info(&bulletin, &new_member, 0x92, true);

    let ring_payload = RingPayload {
        upgrade_info: Default::default(),
        ring_pk: "pss_reshare_unauthorized_pk".to_string(),
        peer_node_keys: vec![our_node_key.clone()],
        new_peer_node_keys: Some(vec![our_node_key, new_member]),
        new_threshold: Some(1),
        threshold: 1,
        pss_interval: 86400,
        block_number_nonce: 0,
        policy_id: Some("test-policy".to_string()),
        trusted_auth_relay_dids: None,
        reporting: Default::default(),
    };

    let entry = post_ring_and_seed_index(&app_state, &bulletin, &ring_payload).await;
    let result = super::pss_ring(&Arc::new(app_state), &entry).await;

    match result {
        Err(DkgError::Unauthorized(message)) => {
            assert!(
                message.contains("does not allow policy_id"),
                "expected NodeInfo allowlist rejection, got: {}",
                message
            );
        }
        other => panic!(
            "Expected Unauthorized allowlist rejection, got: {:?}",
            other
        ),
    }
    cleanup_db(&db_path);
}

/// When only `new_threshold` is set (and `new_peer_node_keys` is absent),
/// `pss_ring` must still dispatch to `trigger_reshare`, using the old committee
/// as the fallback for the reshare session's `new_peer_node_keys`.
#[tokio::test]
async fn test_pss_ring_new_threshold_alone_triggers_reshare() {
    let db_name = "pss_new_threshold_triggers_reshare";
    let (app_state, our_hex, db_path, bulletin) = make_initiator_state(db_name).await;
    let old_member = "zzzz-threshold-change-member".to_string();
    seed_routable_node_info(&bulletin, &old_member, 0x93, true);

    let ring_payload = RingPayload {
        upgrade_info: Default::default(),
        ring_pk: "pss_new_threshold_pk".to_string(),
        peer_node_keys: vec![our_hex.clone(), old_member],
        new_peer_node_keys: None, // only threshold change, no new members
        new_threshold: Some(2),
        threshold: 1,
        pss_interval: 86400,
        block_number_nonce: 0,
        policy_id: Some("test-policy".to_string()),
        trusted_auth_relay_dids: None,
        reporting: Default::default(),
    };

    let entry = post_ring_and_seed_index(&app_state, &bulletin, &ring_payload).await;
    let result = super::pss_ring(&Arc::new(app_state), &entry).await;

    assert!(
        matches!(result, Err(DkgError::Storage(_))),
        "Expected Storage error: new_threshold alone triggered reshare which tried to load \
         an absent share bundle. Got: {:?}",
        result
    );
    cleanup_db(&db_path);
}

/// When neither `new_peer_node_keys` nor `new_threshold` is set, and the ring's
/// `pss_interval` has not yet elapsed, `pss_ring` must skip refresh silently.
#[tokio::test]
async fn test_pss_ring_refresh_skips_before_interval_elapsed() {
    let db_name = "pss_refresh_skips_not_due";
    let (app_state, our_hex, db_path, bulletin) = make_initiator_state(db_name).await;

    let ring_payload = RingPayload {
        upgrade_info: Default::default(),
        ring_pk: "pss_not_due_pk".to_string(),
        peer_node_keys: vec![our_hex.clone()],
        new_peer_node_keys: None,
        new_threshold: None,
        threshold: 1,
        pss_interval: u64::MAX, // interval far in the future — refresh must skip
        block_number_nonce: 0,
        policy_id: None,
        trusted_auth_relay_dids: None,
        reporting: Default::default(),
    };

    let entry = post_ring_and_seed_index(&app_state, &bulletin, &ring_payload).await;
    // Seed a bundle with a recent last_pss so the elapsed check triggers the skip.
    RingShareBundle {
        share_bytes: vec![].into(),
        public_polynomial: "poly".to_string(),
        last_pss: u64::MAX - 1,
    }
    .save_by_ring_key(&app_state.local_storage, &ring_payload.ring_pk)
    .expect("store bundle");
    let result = super::pss_ring(&Arc::new(app_state), &entry).await;

    assert!(
        result.is_ok(),
        "Expected Ok(()): refresh not yet due must skip silently. Got: {:?}",
        result
    );
    cleanup_db(&db_path);
}

/// `pss_interval = 0` means immediately due — elapsed >= 0 always satisfies the check.
#[tokio::test]
async fn test_pss_ring_refresh_zero_interval_is_due() {
    let db_name = "pss_refresh_zero_interval_due";
    let (app_state, our_hex, db_path, bulletin) = make_initiator_state(db_name).await;

    let ring_payload = RingPayload {
        upgrade_info: Default::default(),
        ring_pk: "pss_zero_interval_pk".to_string(),
        peer_node_keys: vec![our_hex.clone()],
        new_peer_node_keys: None,
        new_threshold: None,
        threshold: 1,
        pss_interval: 0,
        block_number_nonce: 0,
        policy_id: None,
        trusted_auth_relay_dids: None,
        reporting: Default::default(),
    };

    let entry = post_ring_and_seed_index(&app_state, &bulletin, &ring_payload).await;
    let result = super::pss_ring(&Arc::new(app_state), &entry).await;

    assert!(
        matches!(result, Err(DkgError::Storage(_))),
        "Expected Storage error: present zero interval should reach trigger_refresh and fail \
         only because the test has no share bundle. Got: {:?}",
        result
    );
    cleanup_db(&db_path);
}

/// When the ring index lists a bundle-less ring that has no bulletin entry,
/// `pss_ring` should reconcile the dangling local entry successfully.
#[tokio::test]
async fn test_refresh_ring_missing_from_bulletin_reconciles_local_index() {
    let db_name = "pss_missing_ring";
    let db_path = test_db_path(db_name);

    let bulletin = Arc::new(DummyBulletin::new().await.expect("DummyBulletin::new"));
    let app_state = create_test_app_state_with_bulletin(true, bulletin, db_name).await;

    let entry = RingIndexEntry {
        ring_pk_str: "ghost_ring".to_string(),
        bulletin_post_id: "ghost_ring".to_string(),
        indexed_at_secs: 0,
    };
    app_state
        .local_storage
        .set(
            LocalStorageKeys::RingIndex,
            serde_json::to_vec(&vec![&entry]).expect("serialize RingIndex"),
        )
        .expect("write RingIndex");

    let state_arc = Arc::new(app_state);
    let result = super::pss_ring(&state_arc, &entry).await;
    assert!(
        result.is_ok(),
        "missing bundle-less ring should reconcile successfully, got: {:?}",
        result
    );
    assert!(ring_index_entries(&state_arc).is_empty());

    cleanup_db(&db_path);
}

// ──────────────────────────────────────────────────────────────────────────────
// Multi-ring protocol-version divergence warning
// ──────────────────────────────────────────────────────────────────────────────

mod divergence {
    use super::super::{
        classify_divergence, divergence_log_decision, member_ring_versions, DivergenceReport,
        DivergenceReportState,
    };
    use bulletin::r#trait::{RingPayload, UpgradeInfo};

    const NOW: u64 = 1_000_000;

    fn payload(ring_pk: &str, members: &[&str], upgrade_info: UpgradeInfo) -> RingPayload {
        RingPayload {
            ring_pk: ring_pk.to_string(),
            peer_node_keys: members.iter().map(|m| m.to_string()).collect(),
            upgrade_info,
            ..Default::default()
        }
    }

    fn stable(current: u64) -> UpgradeInfo {
        UpgradeInfo {
            current_version: current,
            next_version: None,
            activation_time: None,
        }
    }

    fn scheduled(current: u64, next: u64, activation_time: u64) -> UpgradeInfo {
        UpgradeInfo {
            current_version: current,
            next_version: Some(next),
            activation_time: Some(activation_time),
        }
    }

    fn fresh_state() -> DivergenceReportState {
        DivergenceReportState {
            last_check_secs: 0,
            last_fingerprint: None,
        }
    }

    #[test]
    fn classify_single_or_empty_is_silent() {
        assert_eq!(classify_divergence(&[]), DivergenceReport::Silent);
        assert_eq!(
            classify_divergence(&[("r1".to_string(), 0, None)]),
            DivergenceReport::Silent
        );
    }

    #[test]
    fn classify_two_rings_same_version() {
        assert_eq!(
            classify_divergence(&[("r1".to_string(), 0, None), ("r2".to_string(), 0, None)]),
            DivergenceReport::MultiRingSingleVersion
        );
    }

    #[test]
    fn classify_two_rings_differing_effective_versions() {
        assert_eq!(
            classify_divergence(&[("r1".to_string(), 0, None), ("r2".to_string(), 1, None)]),
            DivergenceReport::Divergent
        );
    }

    #[test]
    fn classify_pending_upgrade_makes_it_divergent() {
        // Both rings are effective v0, but r2 has a scheduled v1.
        assert_eq!(
            classify_divergence(&[("r1".to_string(), 0, None), ("r2".to_string(), 0, Some(1))]),
            DivergenceReport::Divergent
        );
    }

    #[test]
    fn member_ring_versions_filters_non_members_and_unfinalized() {
        let payloads = vec![
            ("r1".to_string(), payload("pk1", &["me", "b"], stable(0))),
            ("r2".to_string(), payload("pk2", &["b", "c"], stable(1))), // not a member
            ("r3".to_string(), payload("", &["me"], stable(0))),        // not finalized
            (
                "r4".to_string(),
                payload("pk4", &["me"], scheduled(0, 2, NOW + 1000)),
            ),
        ];
        assert_eq!(
            member_ring_versions(&payloads, "me", NOW),
            vec![("r1".to_string(), 0, None), ("r4".to_string(), 0, Some(2))]
        );
    }

    #[test]
    fn member_ring_versions_pending_upgrade_past_activation_is_effective() {
        let payloads = vec![(
            "r1".to_string(),
            payload("pk1", &["me"], scheduled(0, 1, NOW - 10)),
        )];
        // activation_time has passed → effective is v1 and nothing is pending.
        assert_eq!(
            member_ring_versions(&payloads, "me", NOW),
            vec![("r1".to_string(), 1, None)]
        );
    }

    #[test]
    fn member_ring_versions_skips_malformed_upgrade_info() {
        // next_version without activation_time → effective_version() errors.
        let malformed = UpgradeInfo {
            current_version: 0,
            next_version: Some(1),
            activation_time: None,
        };
        let payloads = vec![("r1".to_string(), payload("pk1", &["me"], malformed))];
        assert!(member_ring_versions(&payloads, "me", NOW).is_empty());
    }

    #[test]
    fn log_decision_logs_first_then_dedups_until_change() {
        let mut state = fresh_state();
        let rings = vec![("r1".to_string(), 0, None), ("r2".to_string(), 1, None)];

        assert_eq!(
            divergence_log_decision(100, &rings, &mut state),
            Some(DivergenceReport::Divergent)
        );
        assert_eq!(state.last_check_secs, 100);
        assert!(state.last_fingerprint.is_some());

        // Same set again → no repeat, but the check time still advances.
        assert_eq!(divergence_log_decision(200, &rings, &mut state), None);
        assert_eq!(state.last_check_secs, 200);

        // A version flip on r2 → fresh log.
        let changed = vec![("r1".to_string(), 0, None), ("r2".to_string(), 2, None)];
        assert_eq!(
            divergence_log_decision(300, &changed, &mut state),
            Some(DivergenceReport::Divergent)
        );
    }

    #[test]
    fn log_decision_relogs_when_severity_changes() {
        let mut state = fresh_state();
        let same_version = vec![("r1".to_string(), 0, None), ("r2".to_string(), 0, None)];
        assert_eq!(
            divergence_log_decision(100, &same_version, &mut state),
            Some(DivergenceReport::MultiRingSingleVersion)
        );

        let now_divergent = vec![("r1".to_string(), 0, None), ("r2".to_string(), 1, None)];
        assert_eq!(
            divergence_log_decision(200, &now_divergent, &mut state),
            Some(DivergenceReport::Divergent)
        );
    }

    #[test]
    fn log_decision_silent_resets_so_re_entry_relogs() {
        let mut state = fresh_state();
        let divergent = vec![("r1".to_string(), 0, None), ("r2".to_string(), 1, None)];

        assert!(divergence_log_decision(100, &divergent, &mut state).is_some());

        // Drop to a single ring: nothing logged, fingerprint cleared.
        assert_eq!(
            divergence_log_decision(200, &[("r1".to_string(), 0, None)], &mut state),
            None
        );
        assert_eq!(state.last_fingerprint, None);

        // The same divergent set now re-logs because the state was reset.
        assert_eq!(
            divergence_log_decision(300, &divergent, &mut state),
            Some(DivergenceReport::Divergent)
        );
    }

    #[test]
    fn log_decision_advances_check_time_even_when_silent() {
        let mut state = fresh_state();
        assert_eq!(divergence_log_decision(500, &[], &mut state), None);
        assert_eq!(state.last_check_secs, 500);
    }
}
