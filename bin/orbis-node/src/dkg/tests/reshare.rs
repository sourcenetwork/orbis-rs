use crate::dkg::{
    coordinator::DkgCoordinator,
    helpers::derive_reshare_session_id,
    messages::{DkgMessage, SessionKind},
};
use crate::helpers::create_routers::create_router_with_all_handlers;
use crate::helpers::helpers::extract_node_part;
use crate::helpers::test_helpers::{
    cleanup_db, create_authenticated_request, create_test_app_state_default,
    create_test_app_state_with_bulletin, get_test_ring_post, setup_three_node_network,
    test_db_path, write_ring_to_bulletin, TestKeyPair, TestNode,
};
use crate::helpers::test_helpers::{BULLETIN_RING_NAMESPACE, TEST_FRESH_DKG_RING_ID};
use crate::ring_state::{RingIndexEntry, RingShareBundle};
use crate::DkgServiceImpl;
use bulletin::dummy::DummyBulletin;
use bulletin::r#trait::{BulletinKind, RingPayload};
use crypto::r#trait::{CryptoDeserialize, Dkg, DkgRole, PubPoly as PubPolyTrait};
use crypto::CryptoSerialize;
use local_storage::r#trait::{LocalStorage, LocalStorageKeys};
use network::PeerId;
use proto::dkg_service::{dkg_service_server::DkgService, StartDkgRequest};
use std::sync::Arc;
use std::time::Instant;
use tokio::time::{sleep, Duration};
use tracing_subscriber;

// Concrete crypto implementation for tests (selected via crypto crate features)
use crypto::{DkgImpl, PreImpl, SignImpl};

// =============================================================================
// Reshare validation tests
//
// Exercise the reshare code
// path: unknown ring, sender not in old committee, concurrent ceremony blocked.
// Additionally, includes unit tests for the Dealer Phase 4 cleanup path
// (share deletion, ring index removal, PSS flag cleared) and the session-state
// PSS blocking behaviour (ring/session claim idempotency).
// =============================================================================

/// Build a minimal reshare `SessionInit` that the coordinator can inspect.
///
/// `peer_ids` = old committee, `new_peer_ids` = new committee.
fn reshare_session_init(
    ring_pk: &str,
    peer_ids: Vec<String>,
    new_peer_ids: Vec<String>,
    new_threshold: u32,
) -> DkgMessage {
    let mut node_id_assignments = std::collections::HashMap::new();
    for (i, p) in peer_ids.iter().enumerate() {
        node_id_assignments.insert(p.clone(), (i + 1) as u32);
    }
    DkgMessage::SessionInit {
        // Arbitrary non-colliding session ID for reshare validation tests.
        session_id: 99_999_100,
        threshold: 1,
        total_participants: peer_ids.len() as u32,
        peer_ids,
        node_id_assignments,
        token_string: String::new(),
        kind: SessionKind::Reshare {
            ring_pk_hex: ring_pk.to_string(),
            new_peer_ids,
            new_threshold,
            bulletin_post_id: String::new(),
        },
        pss_interval: None,
        policy_id: None,
        namespace: BULLETIN_RING_NAMESPACE.to_string(),
        ring_id: String::new(),
    }
}

/// Write a minimal `RingShareBundle` with the given `last_pss` timestamp.
///
/// Used by Dealer Phase 4 tests that need a persisted bundle before cleanup.
fn write_last_refresh(
    storage: &impl local_storage::r#trait::LocalStorage,
    ring_pk: &str,
    secs: u64,
) {
    let bundle = RingShareBundle {
        share_bytes: vec![].into(),
        public_polynomial: String::new(),
        last_pss: secs,
    };
    bundle.save_by_ring_key(storage, ring_pk).unwrap();
}

/// `claim_ring_pss_session` is idempotent for the same session ID, conflicts for a
/// different session ID, and after unmark the ring can be claimed again.
#[tokio::test]
async fn test_rings_pss_blocks_refresh_and_reshare_equally() {
    use crate::dkg::session_state::{RingPssClaimOutcome, SessionStateManager};
    let manager: SessionStateManager<DkgImpl> = SessionStateManager::new();
    let ring_pk = "ring_pss_idempotent_test";

    assert_eq!(
        manager.claim_ring_pss_session(ring_pk, 11).await,
        RingPssClaimOutcome::Claimed,
        "first claim should succeed"
    );

    assert_eq!(
        manager.claim_ring_pss_session(ring_pk, 11).await,
        RingPssClaimOutcome::AlreadyClaimedBySameSession,
        "same-session claim should be idempotent"
    );

    assert_eq!(
        manager.claim_ring_pss_session(ring_pk, 12).await,
        RingPssClaimOutcome::Conflict {
            active_session_id: 11
        },
        "different-session claim should conflict"
    );

    manager.unmark_ring_pss(ring_pk).await;
    assert_eq!(
        manager.claim_ring_pss_session(ring_pk, 13).await,
        RingPssClaimOutcome::Claimed,
        "claim after unmark should succeed"
    );
}

/// Reshare `SessionInit` for a ring that does not exist in `RingIndex` must be
/// rejected with `Unauthorized`.
#[tokio::test]
async fn test_reshare_session_init_rejects_unknown_ring() {
    let db_name = "test_reshare_rejects_unknown_ring";
    let db_path = test_db_path(db_name);
    let app_state = Arc::new(create_test_app_state_default(db_name).await);
    let coordinator = DkgCoordinator::new(app_state);

    let sender_bytes = hex::decode("aabbccdd").unwrap();
    let sender_peer_id = PeerId::from_bytes(&sender_bytes);

    // "unknown_ring_pk" is not present in RingIndex or the bulletin.
    let msg = reshare_session_init(
        "unknown_ring_pk",
        vec!["aabbccdd".to_string()],
        vec!["00112233".to_string()],
        1,
    );
    let result = coordinator.handle_message(msg, &sender_peer_id).await;
    assert!(
        matches!(result, Err(crate::dkg::error::DkgError::Unauthorized(_))),
        "Expected Unauthorized for unknown ring, got: {:?}",
        result
    );
    cleanup_db(&db_path);
}

/// Bulletin payload `ring_pk` must match `SessionKind::Reshare::ring_pk_hex` so a wrong
/// `bulletin_post_id` cannot be paired with a different ring's session.
#[tokio::test]
async fn test_reshare_session_init_rejects_mismatched_bulletin_ring_pk() {
    let db_name = "test_reshare_rejects_bulletin_ring_pk_mismatch";
    let db_path = test_db_path(db_name);
    let app_state = Arc::new(create_test_app_state_default(db_name).await);

    use local_storage::r#trait::LocalStorageKeys;

    let sender_hex = "aabbccdd";
    let session_ring_pk = "session_ring_hex";
    let payload = RingPayload {
        ring_pk: "payload_ring_pk_other".to_string(),
        peer_ids: vec![sender_hex.to_string()],
        new_peer_ids: Some(vec!["00112233".to_string()]),
        new_threshold: Some(1),
        threshold: 2,
        pss_interval: None,
        block_number_nonce: 0,
        policy_id: None,
    };
    let bytes = serde_json::to_vec(&payload).unwrap();
    app_state
        .bulletin
        .post(
            BULLETIN_RING_NAMESPACE.to_string(),
            BulletinKind::Ring,
            bytes.clone(),
            None,
        )
        .await
        .unwrap();
    let post_id = app_state
        .bulletin
        .get_post_id(BULLETIN_RING_NAMESPACE, &bytes)
        .unwrap();

    let mut ring_index: Vec<RingIndexEntry> = app_state
        .local_storage
        .get(LocalStorageKeys::RingIndex)
        .ok()
        .flatten()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();
    ring_index.push(RingIndexEntry {
        ring_pk_str: session_ring_pk.to_string(),
        bulletin_post_id: post_id,
        bulletin_namespace: BULLETIN_RING_NAMESPACE.to_string(),
    });
    app_state
        .local_storage
        .set(
            LocalStorageKeys::RingIndex,
            serde_json::to_vec(&ring_index).unwrap(),
        )
        .unwrap();

    let sender_bytes = hex::decode(sender_hex).unwrap();
    let sender_peer_id = PeerId::from_bytes(&sender_bytes);
    let coordinator = DkgCoordinator::new(app_state);

    let msg = reshare_session_init(
        session_ring_pk,
        vec![sender_hex.to_string()],
        vec!["00112233".to_string()],
        1,
    );
    let result = coordinator.handle_message(msg, &sender_peer_id).await;
    assert!(
        matches!(result, Err(crate::dkg::error::DkgError::Unauthorized(_))),
        "Expected Unauthorized when bulletin ring_pk != session ring, got: {:?}",
        result
    );
    cleanup_db(&db_path);
}

/// Reshare `SessionInit` where the ring is known but the sender is not listed in
/// the ring's old committee (`RingPayload::peer_ids`) must be rejected.
#[tokio::test]
async fn test_reshare_session_init_rejects_sender_not_in_old_committee() {
    let db_name = "test_reshare_rejects_sender_not_in_committee";
    let db_path = test_db_path(db_name);
    let app_state = Arc::new(create_test_app_state_default(db_name).await);

    let ring_pk = "reshare_ring";
    // Ring contains "aabbccdd"; sender will be "deadbeef" (not a member).
    // Bulletin must pre-announce new_peer_ids and new_threshold so checks 3 & 4
    // pass and the test actually reaches check 2 (sender membership).
    write_ring_with_announced_reshare(
        &app_state,
        ring_pk,
        vec!["aabbccdd".to_string()],
        Some(vec!["00112233".to_string()]),
        Some(1),
    )
    .await;

    let sender_bytes = hex::decode("deadbeef").unwrap();
    let sender_peer_id = PeerId::from_bytes(&sender_bytes);
    let coordinator = DkgCoordinator::new(app_state);
    let msg = reshare_session_init(
        ring_pk,
        vec!["deadbeef".to_string()],
        vec!["00112233".to_string()],
        1,
    );
    let result = coordinator.handle_message(msg, &sender_peer_id).await;
    assert!(
        matches!(result, Err(crate::dkg::error::DkgError::Unauthorized(_))),
        "Expected Unauthorized for sender not in old committee, got: {:?}",
        result
    );
    cleanup_db(&db_path);
}

/// If `try_mark_ring_pss` is already held for a ring, an incoming reshare
/// `SessionInit` for that ring must be rejected with `Unauthorized`.
#[tokio::test]
async fn test_reshare_session_init_blocks_concurrent_ceremony() {
    let db_name = "test_reshare_blocks_concurrent";
    let db_path = test_db_path(db_name);
    let app_state = Arc::new(create_test_app_state_default(db_name).await);

    let ring_pk = "reshare_ring";
    let sender_hex = "aabbccdd";
    // Include this node's own peer ID in the new committee so it is a Receiver
    // and reaches the try_mark_ring_pss check (the (false,false) guard fires before
    // the mark check, so the test node must be in at least one committee).
    let our_hex = hex::encode(app_state.network.local_peer_id().as_bytes());
    // Bulletin must pre-announce new_peer_ids and new_threshold (matching what the
    // message will propose) so checks 3 & 4 pass and the test reaches the PSS flag check.
    write_ring_with_announced_reshare(
        &app_state,
        ring_pk,
        vec![sender_hex.to_string()],
        Some(vec![our_hex.clone()]),
        Some(1),
    )
    .await;

    // Pre-mark the ring so the coordinator treats it as already resharing.
    assert_eq!(
        app_state
            .dkg_session_state
            .claim_ring_pss_session(ring_pk, 42)
            .await,
        crate::dkg::session_state::RingPssClaimOutcome::Claimed,
        "initial conflicting claim should succeed"
    );

    let sender_bytes = hex::decode(sender_hex).unwrap();
    let sender_peer_id = PeerId::from_bytes(&sender_bytes);
    let coordinator = DkgCoordinator::new(app_state);
    let msg = reshare_session_init(ring_pk, vec![sender_hex.to_string()], vec![our_hex], 1);
    let result = coordinator.handle_message(msg, &sender_peer_id).await;
    assert!(
        matches!(result, Err(crate::dkg::error::DkgError::Unauthorized(_))),
        "Expected Unauthorized for already-in-progress reshare, got: {:?}",
        result
    );
    cleanup_db(&db_path);
}

/// After a pure Dealer's Phase 4 completion:
/// - `LocalStorageKeys::RingKey(ring_pk)` must be absent (share deleted).
/// - `RingIndex` must not contain an entry for `ring_pk`.
#[tokio::test]
async fn test_dealer_phase4_deletes_share_and_ring_index_entry() {
    let db_name = "test_dealer_phase4_deletes_share";
    let db_path = test_db_path(db_name);
    let app_state = Arc::new(create_test_app_state_default(db_name).await);

    let ring_pk = "dealer_phase4_ring";
    // Arbitrary non-colliding session ID for Dealer Phase 4 tests.
    let session_id = 88_000_001u64;

    // Pre-populate local storage: share bundle + ring index entry.
    write_last_refresh(&app_state.local_storage, ring_pk, 0);
    write_ring_to_bulletin(
        &app_state.local_storage,
        &app_state.bulletin,
        ring_pk,
        vec!["aabbccdd".to_string()],
        None,
    )
    .await;

    // Create a session where this node acts as a pure Dealer.
    let coordinator = DkgCoordinator::new(app_state.clone());
    coordinator
        .create_session(session_id, 1, 1, 3, DkgRole::Dealer, |_| {})
        .await
        .expect("create_session should succeed");

    app_state
        .dkg_session_state
        .set_session_kind(
            &session_id,
            SessionKind::Reshare {
                ring_pk_hex: ring_pk.to_string(),
                new_peer_ids: vec!["00112233".to_string()],
                new_threshold: 1,
                bulletin_post_id: String::new(),
            },
        )
        .await;

    // Trigger Phase 4 directly — the Dealer path cleans up without any crypto.
    coordinator
        .initiate_phase4_completion(session_id)
        .await
        .expect("phase4 should succeed for Dealer");

    // Share bundle must be gone.
    assert!(
        crate::ring_state::RingShareBundle::load_by_ring_key(&app_state.local_storage, ring_pk)
            .is_err(),
        "share bundle should have been deleted after Dealer Phase 4"
    );

    // RingIndex entry must be removed.
    let ring_index: Vec<crate::ring_state::RingIndexEntry> = app_state
        .local_storage
        .get(local_storage::r#trait::LocalStorageKeys::RingIndex)
        .ok()
        .flatten()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();
    assert!(
        !ring_index.iter().any(|e| e.ring_pk_str == ring_pk),
        "RingIndex should not contain the dealer's ring after Phase 4"
    );

    cleanup_db(&db_path);
}

/// After a pure Dealer's Phase 4 completion, `is_ring_pss_active` must return
/// `false` (the PSS flag is cleared regardless of success or failure path).
#[tokio::test]
async fn test_dealer_phase4_unmarks_ring_pss() {
    let db_name = "test_dealer_phase4_unmarks_pss";
    let db_path = test_db_path(db_name);
    let app_state = Arc::new(create_test_app_state_default(db_name).await);

    let ring_pk = "dealer_phase4_pss_ring";
    // Arbitrary non-colliding session ID for Dealer Phase 4 PSS flag test.
    let session_id = 88_000_002u64;

    write_last_refresh(&app_state.local_storage, ring_pk, 0);
    write_ring_to_bulletin(
        &app_state.local_storage,
        &app_state.bulletin,
        ring_pk,
        vec!["aabbccdd".to_string()],
        None,
    )
    .await;

    let coordinator = DkgCoordinator::new(app_state.clone());
    coordinator
        .create_session(session_id, 1, 1, 3, DkgRole::Dealer, |_| {})
        .await
        .expect("create_session should succeed");

    app_state
        .dkg_session_state
        .set_session_kind(
            &session_id,
            SessionKind::Reshare {
                ring_pk_hex: ring_pk.to_string(),
                new_peer_ids: vec!["00112233".to_string()],
                new_threshold: 1,
                bulletin_post_id: String::new(),
            },
        )
        .await;

    // Mark the ring as having an active PSS ceremony.
    assert_eq!(
        app_state
            .dkg_session_state
            .claim_ring_pss_session(ring_pk, session_id)
            .await,
        crate::dkg::session_state::RingPssClaimOutcome::Claimed,
        "PSS claim should be markable before Phase 4"
    );

    coordinator
        .initiate_phase4_completion(session_id)
        .await
        .expect("phase4 should succeed for Dealer");

    // PSS flag must be cleared.
    assert!(
        !app_state
            .dkg_session_state
            .is_ring_pss_active(ring_pk)
            .await,
        "PSS flag should be cleared after Dealer Phase 4"
    );

    cleanup_db(&db_path);
}

// =============================================================================
// validate_reshare_session_init — bulletin-anchor checks
//
// These tests exercise the two new bulletin-anchor checks added to
// `validate_reshare_session_init`:
//   • proposed `new_peer_ids` must match `RingPayload::new_peer_ids` when set
//   • proposed `new_threshold` must match `RingPayload::new_threshold` when set
// =============================================================================

/// Post a `RingPayload` with caller-supplied `new_peer_ids` / `new_threshold`
/// and seed `RingIndex` so the coordinator can find the ring.
async fn write_ring_with_announced_reshare(
    app_state: &crate::app_state::AppState<crypto::DkgImpl>,
    ring_pk: &str,
    peer_ids: Vec<String>,
    announced_new_peer_ids: Option<Vec<String>>,
    announced_new_threshold: Option<u32>,
) {
    use crate::ring_state::RingIndexEntry;
    use local_storage::r#trait::LocalStorageKeys;

    let payload = RingPayload {
        ring_pk: ring_pk.to_string(),
        peer_ids,
        new_peer_ids: announced_new_peer_ids,
        new_threshold: announced_new_threshold,
        threshold: 2,
        pss_interval: None,
        block_number_nonce: 0,
        policy_id: None,
    };
    let bytes = serde_json::to_vec(&payload).unwrap();
    app_state
        .bulletin
        .post(
            BULLETIN_RING_NAMESPACE.to_string(),
            BulletinKind::Ring,
            bytes.clone(),
            None,
        )
        .await
        .unwrap();
    let post_id = app_state
        .bulletin
        .get_post_id(BULLETIN_RING_NAMESPACE, &bytes)
        .unwrap();
    let mut ring_index: Vec<RingIndexEntry> = app_state
        .local_storage
        .get(LocalStorageKeys::RingIndex)
        .ok()
        .flatten()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();
    ring_index.push(RingIndexEntry {
        ring_pk_str: ring_pk.to_string(),
        bulletin_post_id: post_id,
        bulletin_namespace: BULLETIN_RING_NAMESPACE.to_string(),
    });
    app_state
        .local_storage
        .set(
            LocalStorageKeys::RingIndex,
            serde_json::to_vec(&ring_index).unwrap(),
        )
        .unwrap();
}

/// Reshare `SessionInit` whose `new_peer_ids` differs from the bulletin-announced
/// committee must be rejected with `Unauthorized`.
#[tokio::test]
async fn test_reshare_session_init_rejects_mismatched_new_peer_ids() {
    let db_name = "test_reshare_rejects_mismatch_peers";
    let db_path = test_db_path(db_name);
    let app_state = Arc::new(create_test_app_state_default(db_name).await);

    let ring_pk = "reshare_ring";
    let sender_hex = "aabbccdd";

    // Bulletin pre-announces "11223344" as the only new-committee member, with threshold 1.
    // new_threshold must also be set so check 4 passes and the test reaches check 3.
    write_ring_with_announced_reshare(
        &app_state,
        ring_pk,
        vec![sender_hex.to_string()],
        Some(vec!["11223344".to_string()]),
        Some(1),
    )
    .await;

    let sender_bytes = hex::decode(sender_hex).unwrap();
    let sender_peer_id = PeerId::from_bytes(&sender_bytes);
    let coordinator = DkgCoordinator::new(app_state);

    // Propose a *different* new committee — should be rejected.
    let msg = reshare_session_init(
        ring_pk,
        vec![sender_hex.to_string()],
        vec!["deadbeef".to_string()], // does not match "11223344"
        1,
    );
    let result = coordinator.handle_message(msg, &sender_peer_id).await;
    assert!(
        matches!(result, Err(crate::dkg::error::DkgError::Unauthorized(_))),
        "Expected Unauthorized for mismatched new_peer_ids, got: {:?}",
        result
    );
    cleanup_db(&db_path);
}

/// Reshare `SessionInit` whose `new_threshold` differs from the bulletin-announced
/// value must be rejected with `Unauthorized`.
#[tokio::test]
async fn test_reshare_session_init_rejects_mismatched_new_threshold() {
    let db_name = "test_reshare_rejects_mismatch_threshold";
    let db_path = test_db_path(db_name);
    let app_state = Arc::new(create_test_app_state_default(db_name).await);

    let ring_pk = "reshare_ring";
    let sender_hex = "aabbccdd";

    // Bulletin pre-announces new_threshold = 2, with matching new_peer_ids.
    // new_peer_ids must also be set (matching the proposal) so check 3 passes
    // and the test actually reaches check 4 (the threshold mismatch).
    write_ring_with_announced_reshare(
        &app_state,
        ring_pk,
        vec![sender_hex.to_string()],
        Some(vec!["00112233".to_string()]),
        Some(2),
    )
    .await;

    let sender_bytes = hex::decode(sender_hex).unwrap();
    let sender_peer_id = PeerId::from_bytes(&sender_bytes);
    let coordinator = DkgCoordinator::new(app_state);

    // Propose new_threshold = 1 — does not match announced 2.
    let msg = reshare_session_init(
        ring_pk,
        vec![sender_hex.to_string()],
        vec!["00112233".to_string()],
        1, // does not match announced 2
    );
    let result = coordinator.handle_message(msg, &sender_peer_id).await;
    assert!(
        matches!(result, Err(crate::dkg::error::DkgError::Unauthorized(_))),
        "Expected Unauthorized for mismatched new_threshold, got: {:?}",
        result
    );
    cleanup_db(&db_path);
}

// =============================================================================
// validate_reshare_session_init — structural parameter checks
//
// These tests exercise the fast-fail checks added to validate_reshare_session_init
// before the bulletin is consulted:
//   • new_peer_ids must be non-empty
//   • new_threshold must be in [1, len(new_peer_ids)]
// No bulletin entry is needed because the checks fire before the bulletin lookup.
// =============================================================================

/// When neither bulletin field is set, the fallback authoritative values are the
/// current `peer_ids` and `threshold`.  Proposing a different committee is still
/// rejected — absent fields mean "keep current", not "accept anything".
#[tokio::test]
async fn test_reshare_session_init_rejects_no_bulletin_announcement() {
    let db_name = "test_reshare_rejects_no_announcement";
    let db_path = test_db_path(db_name);
    let app_state = Arc::new(create_test_app_state_default(db_name).await);

    let ring_pk = "reshare_ring";
    let sender_hex = "aabbccdd";
    // Bulletin has neither field; fallback committee = peer_ids = ["aabbccdd"].
    write_ring_with_announced_reshare(
        &app_state,
        ring_pk,
        vec![sender_hex.to_string()],
        None,
        None,
    )
    .await;

    let sender_bytes = hex::decode(sender_hex).unwrap();
    let sender_peer_id = PeerId::from_bytes(&sender_bytes);
    let coordinator = DkgCoordinator::new(app_state);
    // Propose a *different* committee — must be rejected even though no field is announced.
    let msg = reshare_session_init(
        ring_pk,
        vec![sender_hex.to_string()],
        vec!["00112233".to_string()], // differs from fallback = ["aabbccdd"]
        1,
    );
    let result = coordinator.handle_message(msg, &sender_peer_id).await;
    assert!(
        matches!(result, Err(crate::dkg::error::DkgError::Unauthorized(_))),
        "Expected Unauthorized when proposed peers differ from fallback committee, got: {:?}",
        result
    );
    cleanup_db(&db_path);
}

/// Reshare `SessionInit` with an empty `new_peer_ids` must be rejected with
/// `InvalidInput` before any bulletin lookup occurs.
#[tokio::test]
async fn test_reshare_session_init_rejects_empty_new_committee() {
    let db_name = "test_reshare_rejects_empty_committee";
    let db_path = test_db_path(db_name);
    let app_state = Arc::new(create_test_app_state_default(db_name).await);
    let coordinator = DkgCoordinator::new(app_state);

    let sender_bytes = hex::decode("aabbccdd").unwrap();
    let sender_peer_id = PeerId::from_bytes(&sender_bytes);

    let msg = reshare_session_init(
        "some_ring",
        vec!["aabbccdd".to_string()],
        vec![], // empty new committee
        0,      // threshold irrelevant — empty check fires first
    );
    let result = coordinator.handle_message(msg, &sender_peer_id).await;
    assert!(
        matches!(result, Err(crate::dkg::error::DkgError::InvalidInput(_))),
        "Expected InvalidInput for empty new_peer_ids, got: {:?}",
        result
    );
    cleanup_db(&db_path);
}

/// Reshare `SessionInit` with `new_threshold > len(new_peer_ids)` must be
/// rejected with `InvalidInput` before any bulletin lookup occurs.
#[tokio::test]
async fn test_reshare_session_init_rejects_threshold_exceeds_committee_size() {
    let db_name = "test_reshare_rejects_threshold_too_high";
    let db_path = test_db_path(db_name);
    let app_state = Arc::new(create_test_app_state_default(db_name).await);
    let coordinator = DkgCoordinator::new(app_state);

    let sender_bytes = hex::decode("aabbccdd").unwrap();
    let sender_peer_id = PeerId::from_bytes(&sender_bytes);

    // new_threshold = 3 with only 1 new-committee member — structurally impossible.
    let msg = reshare_session_init(
        "some_ring",
        vec!["aabbccdd".to_string()],
        vec!["00112233".to_string()],
        3, // exceeds committee size of 1
    );
    let result = coordinator.handle_message(msg, &sender_peer_id).await;
    assert!(
        matches!(result, Err(crate::dkg::error::DkgError::InvalidInput(_))),
        "Expected InvalidInput for new_threshold > committee size, got: {:?}",
        result
    );
    cleanup_db(&db_path);
}

/// Reshare `SessionInit` with `new_threshold = 0` must be rejected with
/// `InvalidInput` (threshold must be at least 1).
#[tokio::test]
async fn test_reshare_session_init_rejects_zero_threshold() {
    let db_name = "test_reshare_rejects_zero_threshold";
    let db_path = test_db_path(db_name);
    let app_state = Arc::new(create_test_app_state_default(db_name).await);
    let coordinator = DkgCoordinator::new(app_state);

    let sender_bytes = hex::decode("aabbccdd").unwrap();
    let sender_peer_id = PeerId::from_bytes(&sender_bytes);

    let msg = reshare_session_init(
        "some_ring",
        vec!["aabbccdd".to_string()],
        vec!["00112233".to_string()],
        0, // threshold of zero is never valid
    );
    let result = coordinator.handle_message(msg, &sender_peer_id).await;
    assert!(
        matches!(result, Err(crate::dkg::error::DkgError::InvalidInput(_))),
        "Expected InvalidInput for new_threshold = 0, got: {:?}",
        result
    );
    cleanup_db(&db_path);
}

// =============================================================================
// validate_reshare_session_init — fallback semantics
//
// When a bulletin field is absent the authoritative value falls back to the
// current ring state rather than rejecting outright:
//   • new_peer_ids absent → authoritative = ring_payload.peer_ids
//   • new_threshold absent → authoritative = ring_payload.threshold
// The tests below call validate_reshare_session_init directly so that committee
// membership of the receiving node is not a factor.
// =============================================================================

/// Build and post a RingPayload with configurable threshold and reshare fields,
/// seeding RingIndex so validate_reshare_session_init can locate the ring.
async fn post_ring_for_validation(
    app_state: &crate::app_state::AppState<crypto::DkgImpl>,
    ring_pk: &str,
    peer_ids: Vec<String>,
    threshold: u32,
    new_peer_ids: Option<Vec<String>>,
    new_threshold: Option<u32>,
) {
    use crate::ring_state::RingIndexEntry;
    use local_storage::r#trait::LocalStorageKeys;

    let payload = RingPayload {
        ring_pk: ring_pk.to_string(),
        peer_ids,
        new_peer_ids,
        new_threshold,
        threshold,
        pss_interval: None,
        block_number_nonce: 0,
        policy_id: None,
    };
    let bytes = serde_json::to_vec(&payload).unwrap();
    app_state
        .bulletin
        .post(
            BULLETIN_RING_NAMESPACE.to_string(),
            BulletinKind::Ring,
            bytes.clone(),
            None,
        )
        .await
        .unwrap();
    let post_id = app_state
        .bulletin
        .get_post_id(BULLETIN_RING_NAMESPACE, &bytes)
        .unwrap();
    let mut ring_index: Vec<RingIndexEntry> = app_state
        .local_storage
        .get(LocalStorageKeys::RingIndex)
        .ok()
        .flatten()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();
    ring_index.push(RingIndexEntry {
        ring_pk_str: ring_pk.to_string(),
        bulletin_post_id: post_id,
        bulletin_namespace: BULLETIN_RING_NAMESPACE.to_string(),
    });
    app_state
        .local_storage
        .set(
            LocalStorageKeys::RingIndex,
            serde_json::to_vec(&ring_index).unwrap(),
        )
        .unwrap();
}

/// When `new_peer_ids` is absent and proposed committee equals current `peer_ids`,
/// validation must succeed (fallback = keep current committee).
#[tokio::test]
async fn test_validate_reshare_accepts_new_peer_ids_fallback_to_current() {
    use crate::dkg::helpers::validate_reshare_session_init;

    let db_name = "validate_reshare_fallback_accepts_peers";
    let db_path = test_db_path(db_name);
    let app_state = create_test_app_state_default(db_name).await;

    let ring_pk = "fallback_peers_ring";
    let sender_hex = "aabbccdd";

    // Only new_threshold is announced; new_peer_ids absent → fallback = peer_ids.
    post_ring_for_validation(
        &app_state,
        ring_pk,
        vec![sender_hex.to_string()],
        1,
        None, // absent → fallback = peer_ids = [sender_hex]
        Some(1),
    )
    .await;

    let result = validate_reshare_session_init(
        ring_pk,
        sender_hex,
        &[sender_hex.to_string()], // matches fallback = peer_ids
        1,
        "",
        BULLETIN_RING_NAMESPACE,
        &app_state.local_storage,
        &app_state.bulletin,
    )
    .await;
    assert!(
        result.is_ok(),
        "Expected Ok when proposed peers match current peer_ids (fallback): {:?}",
        result
    );
    cleanup_db(&db_path);
}

/// When `new_threshold` is absent and proposed threshold equals current `threshold`,
/// validation must succeed (fallback = keep current threshold).
#[tokio::test]
async fn test_validate_reshare_accepts_new_threshold_fallback_to_current() {
    use crate::dkg::helpers::validate_reshare_session_init;

    let db_name = "validate_reshare_fallback_accepts_threshold";
    let db_path = test_db_path(db_name);
    let app_state = create_test_app_state_default(db_name).await;

    let ring_pk = "fallback_threshold_ring";
    let sender_hex = "aabbccdd";
    let new_peer = "00112233";

    // Only new_peer_ids is announced; new_threshold absent → fallback = threshold = 1.
    post_ring_for_validation(
        &app_state,
        ring_pk,
        vec![sender_hex.to_string()],
        1, // current threshold
        Some(vec![new_peer.to_string()]),
        None, // absent → fallback = 1
    )
    .await;

    let result = validate_reshare_session_init(
        ring_pk,
        sender_hex,
        &[new_peer.to_string()],
        1, // matches fallback = current threshold
        "",
        BULLETIN_RING_NAMESPACE,
        &app_state.local_storage,
        &app_state.bulletin,
    )
    .await;
    assert!(
        result.is_ok(),
        "Expected Ok when proposed threshold matches current threshold (fallback): {:?}",
        result
    );
    cleanup_db(&db_path);
}

/// When `new_peer_ids` is absent and proposed committee differs from current `peer_ids`,
/// validation must reject — absent does not mean "accept any committee".
#[tokio::test]
async fn test_validate_reshare_rejects_when_peers_differ_from_fallback() {
    use crate::dkg::helpers::validate_reshare_session_init;

    let db_name = "validate_reshare_fallback_rejects_peers";
    let db_path = test_db_path(db_name);
    let app_state = create_test_app_state_default(db_name).await;

    let ring_pk = "fallback_reject_peers_ring";
    let sender_hex = "aabbccdd";

    // new_peer_ids absent → fallback = peer_ids = ["aabbccdd"].
    post_ring_for_validation(
        &app_state,
        ring_pk,
        vec![sender_hex.to_string()],
        1,
        None,
        Some(1),
    )
    .await;

    let result = validate_reshare_session_init(
        ring_pk,
        sender_hex,
        &["00112233".to_string()], // differs from fallback = ["aabbccdd"]
        1,
        "",
        BULLETIN_RING_NAMESPACE,
        &app_state.local_storage,
        &app_state.bulletin,
    )
    .await;
    assert!(
        matches!(result, Err(crate::dkg::error::DkgError::Unauthorized(_))),
        "Expected Unauthorized when proposed peers differ from fallback: {:?}",
        result
    );
    cleanup_db(&db_path);
}

/// When `new_threshold` is absent and proposed threshold differs from current `threshold`,
/// validation must reject — absent does not mean "accept any threshold".
#[tokio::test]
async fn test_validate_reshare_rejects_when_threshold_differs_from_fallback() {
    use crate::dkg::helpers::validate_reshare_session_init;

    let db_name = "validate_reshare_fallback_rejects_threshold";
    let db_path = test_db_path(db_name);
    let app_state = create_test_app_state_default(db_name).await;

    let ring_pk = "fallback_reject_threshold_ring";
    let sender_hex = "aabbccdd";
    let new_peer_1 = "00112233";
    let new_peer_2 = "11223344";

    // new_threshold absent → fallback = threshold = 2.
    post_ring_for_validation(
        &app_state,
        ring_pk,
        vec![sender_hex.to_string()],
        2,                                                          // current threshold
        Some(vec![new_peer_1.to_string(), new_peer_2.to_string()]), // 2 members, valid for t=2
        None,                                                       // absent → fallback = 2
    )
    .await;

    let result = validate_reshare_session_init(
        ring_pk,
        sender_hex,
        &[new_peer_1.to_string(), new_peer_2.to_string()],
        1, // differs from fallback = 2
        "",
        BULLETIN_RING_NAMESPACE,
        &app_state.local_storage,
        &app_state.bulletin,
    )
    .await;
    assert!(
        matches!(result, Err(crate::dkg::error::DkgError::Unauthorized(_))),
        "Expected Unauthorized when proposed threshold differs from fallback: {:?}",
        result
    );
    cleanup_db(&db_path);
}

// =============================================================================
// Reshare end-to-end tests
//
// Each scenario runs a complete DKG first (Alice initiates, t=2, n=3), then a
// reshare ceremony, and verifies that P(0) of every new-committee node's public
// polynomial equals the original aggregate public key — confirming the secret is
// preserved across the reshare.
// =============================================================================

/// Create an additional test node that shares an existing `DummyBulletin`.
/// Starts a DKG router on the node immediately.
async fn create_extra_test_node(db_suffix: &str, bulletin: Arc<DummyBulletin>) -> TestNode {
    use bulletin::r#trait::Bulletin as BulletinTrait;
    let shared: Arc<dyn BulletinTrait + Send + Sync> = bulletin.clone();
    let state = create_test_app_state_with_bulletin(
        Some("127.0.0.1:0".to_string()),
        true,
        shared,
        db_suffix,
    )
    .await;

    let peer_id = state.network.local_peer_id();
    let address = state.network.local_address().expect("extra node address");
    let socket_addr = state
        .network
        .bound_addresses()
        .first()
        .copied()
        .map(|a| format!("{}", a))
        .unwrap_or_else(|| "127.0.0.1:0".to_string());
    let address_with_port = format!("{}@{}", address, socket_addr);

    let router = {
        let arc_state = Arc::new(state.clone());
        Some(
            create_router_with_all_handlers::<DkgImpl, PreImpl, SignImpl>(
                &state.network,
                arc_state,
            )
            .expect("extra node router"),
        )
    };

    TestNode {
        app_state: state,
        peer_id,
        address: address_with_port,
        router,
    }
}

/// Poll the `DummyBulletin` until the DKG posts a ring entry.
///
/// Returns `(key_string, ring_pk_hex, ring_pk_bytes)`:
/// - `key_string`   — `aggregate_pk.to_string()` — the local-storage ring key
/// - `ring_pk_hex`  — hex-encoded compressed bytes of the aggregate PK (bulletin field)
/// - `ring_pk_bytes`— raw bytes used for comparison in `verify_reshare_pk_preserved`
async fn wait_for_dkg_complete_on_bulletin(bulletin: &DummyBulletin) -> (String, String, Vec<u8>) {
    let start = Instant::now();
    let max_wait = Duration::from_secs(60);
    loop {
        let post = get_test_ring_post(bulletin);
        if !post.payload.is_empty() {
            let ring_payload: RingPayload = post.try_into().expect("parse RingPayload");
            let ring_pk_hex = ring_payload.ring_pk.clone();
            let ring_pk_bytes = hex::decode(&ring_pk_hex).expect("decode ring_pk_hex");
            let agg_key = <DkgImpl as Dkg>::PublicKey::from_bytes(&ring_pk_bytes)
                .expect("deserialize aggregate PK");
            return (agg_key.to_string(), ring_pk_hex, ring_pk_bytes);
        }
        assert!(
            start.elapsed() < max_wait,
            "DKG did not post to bulletin within 60 s"
        );
        sleep(Duration::from_millis(500)).await;
    }
}

/// Post a reshare-announcement `RingPayload` to the bulletin and update every
/// old-committee node's `RingIndex` entry to point to the new post.
///
/// Returns the bulletin `post_id` of the announcement entry.
async fn post_reshare_announcement(
    old_nodes: &[&crate::app_state::AppState<DkgImpl>],
    old_peer_ids: &[String],
    old_threshold: u32,
    key_string: &str,
    sorted_new_peer_ids: &[String],
    new_threshold: u32,
    bulletin: &DummyBulletin,
) -> String {
    use bulletin::r#trait::Bulletin as BulletinTrait;

    let payload = RingPayload {
        ring_pk: key_string.to_string(),
        peer_ids: old_peer_ids.to_vec(),
        threshold: old_threshold,
        new_peer_ids: Some(sorted_new_peer_ids.to_vec()),
        new_threshold: Some(new_threshold),
        pss_interval: None,
        block_number_nonce: 0,
        policy_id: None,
    };
    let bytes = serde_json::to_vec(&payload).unwrap();

    bulletin
        .post(
            BULLETIN_RING_NAMESPACE.to_string(),
            BulletinKind::Ring,
            bytes.clone(),
            None,
        )
        .await
        .expect("post reshare announcement to bulletin");

    let new_post_id = bulletin
        .get_post_id(BULLETIN_RING_NAMESPACE, &bytes)
        .expect("get reshare announcement post_id");

    // Point every old-committee node's RingIndex entry at the new post.
    for state in old_nodes {
        let mut ring_index: Vec<RingIndexEntry> = state
            .local_storage
            .get(LocalStorageKeys::RingIndex)
            .ok()
            .flatten()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        for entry in &mut ring_index {
            if entry.ring_pk_str == key_string {
                entry.bulletin_post_id = new_post_id.clone();
            }
        }
        state
            .local_storage
            .set(
                LocalStorageKeys::RingIndex,
                serde_json::to_vec(&ring_index).unwrap(),
            )
            .unwrap();
    }

    new_post_id
}

/// Drive a full reshare ceremony from the initiator's perspective:
///
/// 1. Build `DkgMessage::SessionInit { kind: Reshare }`.
/// 2. Process it locally on the initiator via `handle_message` (sets session state).
/// 3. Broadcast it to every other union-committee peer.
/// 4. Call `initiate_phase1_commitments` on the initiator.
/// 5. Poll `new_committee_states` until all show an updated `RingShareBundle`.
async fn run_reshare_ceremony(
    initiator_state: &crate::app_state::AppState<DkgImpl>,
    initiator_peer_id: &PeerId,
    old_peer_ids: &[String],
    old_threshold: u32,
    union_peer_ids: &[String],
    key_string: &str,
    sorted_new_peer_ids: &[String],
    new_threshold: u32,
    bulletin_post_id: &str,
    new_committee_states: &[&crate::app_state::AppState<DkgImpl>],
) {
    let session_id = derive_reshare_session_id(
        key_string,
        bulletin_post_id,
        old_peer_ids,
        sorted_new_peer_ids,
        new_threshold,
    );

    // Snapshot share bytes before reshare so we can detect when they change.
    let pre_snapshots: Vec<Option<zeroize::Zeroizing<Vec<u8>>>> = new_committee_states
        .iter()
        .map(|s| {
            RingShareBundle::load_by_ring_key(&s.local_storage, key_string)
                .ok()
                .map(|b| b.share_bytes.clone())
        })
        .collect();

    // Build deterministic old-committee node_id assignments.
    let mut sorted_old = old_peer_ids.to_vec();
    sorted_old.sort();
    let mut node_id_assignments = std::collections::HashMap::new();
    for (idx, pid) in sorted_old.iter().enumerate() {
        node_id_assignments.insert(extract_node_part(pid), (idx + 1) as u32);
    }

    let init_msg = DkgMessage::SessionInit {
        session_id,
        threshold: old_threshold,
        total_participants: old_peer_ids.len() as u32,
        peer_ids: old_peer_ids.to_vec(),
        node_id_assignments,
        token_string: String::new(),
        kind: SessionKind::Reshare {
            ring_pk_hex: key_string.to_string(),
            new_peer_ids: sorted_new_peer_ids.to_vec(),
            new_threshold,
            bulletin_post_id: bulletin_post_id.to_string(),
        },
        pss_interval: None,
        policy_id: None,
        namespace: BULLETIN_RING_NAMESPACE.to_string(),
        ring_id: String::new(),
    };

    // Process own SessionInit — sets up session state and reshare_params.
    let coordinator = DkgCoordinator::new(Arc::new(initiator_state.clone()));
    coordinator
        .handle_message(init_msg.clone(), initiator_peer_id)
        .await
        .expect("initiator handle own SessionInit");

    // Broadcast SessionInit to all other union-committee peers.
    let initiator_part = extract_node_part(&hex::encode(initiator_peer_id.as_bytes()));
    for peer_addr in union_peer_ids {
        if extract_node_part(peer_addr) == initiator_part {
            continue;
        }
        if let Err(e) = coordinator
            .send_message_to_peer(peer_addr, init_msg.clone(), Some(session_id))
            .await
        {
            tracing::warn!(
                peer = %peer_addr,
                error = %e,
                "test reshare: failed to send SessionInit to target peer; continuing"
            );
        }
    }

    // Start Phase 1 on the initiator (generates polynomial + broadcasts commitment).
    coordinator
        .initiate_phase1_commitments(session_id, sorted_new_peer_ids)
        .await
        .expect("initiate phase 1 commitments");

    // Wait until every new-committee node has a fresh share bundle.
    let start = Instant::now();
    let max_wait = Duration::from_secs(60);
    loop {
        let all_done = new_committee_states
            .iter()
            .zip(pre_snapshots.iter())
            .all(|(state, pre)| {
                match RingShareBundle::load_by_ring_key(&state.local_storage, key_string) {
                    Ok(bundle) => match pre {
                        None => true,                            // pure Receiver: any bundle
                        Some(old) => bundle.share_bytes != *old, // DealerReceiver: changed
                    },
                    Err(_) => false,
                }
            });
        if all_done {
            break;
        }
        assert!(
            start.elapsed() < max_wait,
            "Reshare ceremony did not complete within 60 s"
        );
        sleep(Duration::from_millis(500)).await;
    }

    // The reshare is not complete until the designated new-committee node 1
    // posts the final bulletin update and clears the pending reshare fields.
    let start = Instant::now();
    loop {
        let post = initiator_state
            .bulletin
            .read(
                BULLETIN_RING_NAMESPACE.to_string(),
                bulletin_post_id.to_string(),
                BulletinKind::Ring,
            )
            .await
            .expect("read reshare bulletin post");
        let payload: RingPayload =
            serde_json::from_slice(&post.payload).expect("parse reshare RingPayload");

        let mut actual_peer_ids = payload.peer_ids.clone();
        actual_peer_ids.sort();
        let mut expected_peer_ids = sorted_new_peer_ids.to_vec();
        expected_peer_ids.sort();

        if payload.new_peer_ids.is_none()
            && payload.new_threshold.is_none()
            && actual_peer_ids == expected_peer_ids
            && payload.threshold == new_threshold
        {
            break;
        }

        assert!(
            start.elapsed() < max_wait,
            "Reshare ceremony did not update bulletin RingPayload within 60 s; payload={:?}",
            payload
        );
        sleep(Duration::from_millis(500)).await;
    }
}

/// Verify that P(0) of each new-committee node's stored public polynomial
/// equals the original aggregate public key bytes.
fn verify_reshare_pk_preserved(
    new_committee_nodes: &[(&str, &crate::app_state::AppState<DkgImpl>)],
    key_string: &str,
    original_pk_bytes: &[u8],
) {
    for (label, state) in new_committee_nodes {
        let bundle = RingShareBundle::load_by_ring_key(&state.local_storage, key_string)
            .unwrap_or_else(|e| panic!("{label}: load reshare bundle: {e}"));
        let poly_bytes = hex::decode(&bundle.public_polynomial)
            .unwrap_or_else(|e| panic!("{label}: decode public_polynomial hex: {e}"));
        let pub_poly = <DkgImpl as Dkg>::PubPoly::from_bytes(&poly_bytes)
            .unwrap_or_else(|e| panic!("{label}: deserialize PubPoly: {e}"));
        let recovered = CryptoSerialize::to_bytes(&pub_poly.eval(0))
            .unwrap_or_else(|e| panic!("{label}: serialize P(0): {e}"));
        assert_eq!(
            recovered, original_pk_bytes,
            "{label}: P(0) after reshare must equal the original aggregate public key"
        );
    }
}

/// Reshare scenario: same committee, threshold lowered (t=2→1).
///
/// All three nodes are DealerReceivers — they deal from their old share and
/// receive a new share under the reduced threshold scheme.
#[tokio::test]
#[serial_test::serial]
async fn test_reshare_lower_threshold() {
    let db_name = "test_reshare_lower_threshold";
    let db_paths = [
        test_db_path(&format!("{}_1", db_name)),
        test_db_path(&format!("{}_2", db_name)),
        test_db_path(&format!("{}_3", db_name)),
    ];
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_test_writer()
        .try_init();

    let mut network = setup_three_node_network(true, db_name).await;
    let peer_ids = network.get_all_peer_ids();
    let dummy_bulletin = network.dummy_bulletin.as_ref().unwrap().clone();

    // Phase A: initial DKG (t=2, n=3).
    let alice_service = DkgServiceImpl::<DkgImpl>::new(network.alice.app_state.clone());
    let test_keys = TestKeyPair::new();
    let token = test_keys
        .create_dkg_jwt(
            2,
            &peer_ids,
            None,
            None,
            BULLETIN_RING_NAMESPACE,
            TEST_FRESH_DKG_RING_ID,
        )
        .expect("JWT");
    alice_service
        .start_dkg(
            create_authenticated_request(
                StartDkgRequest {
                    threshold: 2,
                    peer_ids: peer_ids.clone(),
                    pss_interval: None,
                    policy_id: None,
                    namespace: BULLETIN_RING_NAMESPACE.to_string(),
                    ring_id: TEST_FRESH_DKG_RING_ID.to_string(),
                },
                &token,
            )
            .unwrap(),
        )
        .await
        .expect("DKG should start");
    let (key_string, _ring_pk_hex, original_pk_bytes) =
        wait_for_dkg_complete_on_bulletin(&dummy_bulletin).await;
    println!("DKG complete. key_string={}", key_string);

    // Phase B: reshare announcement — same committee, t=2→1.
    let mut sorted_new = peer_ids.clone();
    sorted_new.sort();
    let old_node_states: Vec<&crate::app_state::AppState<DkgImpl>> = vec![
        &network.alice.app_state,
        &network.bob.app_state,
        &network.charlie.app_state,
    ];
    let announcement_post_id = post_reshare_announcement(
        &old_node_states,
        &peer_ids,
        2,
        &key_string,
        &sorted_new,
        1,
        &dummy_bulletin,
    )
    .await;

    // Phase C: reshare ceremony (all DealerReceivers).
    let new_committee_states: Vec<&crate::app_state::AppState<DkgImpl>> = vec![
        &network.alice.app_state,
        &network.bob.app_state,
        &network.charlie.app_state,
    ];
    run_reshare_ceremony(
        &network.alice.app_state,
        &network.alice.peer_id,
        &peer_ids,
        2,
        &peer_ids,
        &key_string,
        &sorted_new,
        1,
        &announcement_post_id,
        &new_committee_states,
    )
    .await;

    // Phase D: verify the ring public key is unchanged.
    verify_reshare_pk_preserved(
        &[
            ("alice", &network.alice.app_state),
            ("bob", &network.bob.app_state),
            ("charlie", &network.charlie.app_state),
        ],
        &key_string,
        &original_pk_bytes,
    );

    network.shutdown_routers().await.expect("shutdown routers");
    for path in &db_paths {
        cleanup_db(path);
    }
}

/// Reshare scenario: one member rotated out ({A,B,C}→{A,B,D}, t=2→2).
///
/// A and B are DealerReceivers; C is a pure Dealer (leaves);
/// D is a pure Receiver (joins).
#[tokio::test]
#[serial_test::serial]
async fn test_reshare_one_member_rotated() {
    let db_name = "test_reshare_one_member_rotated";
    let db_paths = [
        test_db_path(&format!("{}_1", db_name)),
        test_db_path(&format!("{}_2", db_name)),
        test_db_path(&format!("{}_3", db_name)),
        test_db_path(&format!("{}_4", db_name)),
    ];
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_test_writer()
        .try_init();

    let mut network = setup_three_node_network(true, db_name).await;
    let dummy_bulletin = network.dummy_bulletin.as_ref().unwrap().clone();
    let peer_ids = network.get_all_peer_ids();

    // Extra node D joins the new committee.
    let mut dave = create_extra_test_node(&format!("{}_4", db_name), dummy_bulletin.clone()).await;

    // Phase A: DKG with A, B, C (t=2).
    let alice_service = DkgServiceImpl::<DkgImpl>::new(network.alice.app_state.clone());
    let test_keys = TestKeyPair::new();
    let token = test_keys
        .create_dkg_jwt(
            2,
            &peer_ids,
            None,
            None,
            BULLETIN_RING_NAMESPACE,
            TEST_FRESH_DKG_RING_ID,
        )
        .expect("JWT");
    alice_service
        .start_dkg(
            create_authenticated_request(
                StartDkgRequest {
                    threshold: 2,
                    peer_ids: peer_ids.clone(),
                    pss_interval: None,
                    policy_id: None,
                    namespace: BULLETIN_RING_NAMESPACE.to_string(),
                    ring_id: TEST_FRESH_DKG_RING_ID.to_string(),
                },
                &token,
            )
            .unwrap(),
        )
        .await
        .expect("DKG should start");
    let (key_string, _ring_pk_hex, original_pk_bytes) =
        wait_for_dkg_complete_on_bulletin(&dummy_bulletin).await;
    println!("DKG complete. key_string={}", key_string);

    // Phase B: reshare to {A,B,D}, t=2.
    let mut sorted_new = vec![
        network.alice.address.clone(),
        network.bob.address.clone(),
        dave.address.clone(),
    ];
    sorted_new.sort();

    let old_node_states: Vec<&crate::app_state::AppState<DkgImpl>> = vec![
        &network.alice.app_state,
        &network.bob.app_state,
        &network.charlie.app_state,
    ];
    let announcement_post_id = post_reshare_announcement(
        &old_node_states,
        &peer_ids,
        2,
        &key_string,
        &sorted_new,
        2,
        &dummy_bulletin,
    )
    .await;

    let new_committee_states: Vec<&crate::app_state::AppState<DkgImpl>> = vec![
        &network.alice.app_state,
        &network.bob.app_state,
        &dave.app_state,
    ];
    run_reshare_ceremony(
        &network.alice.app_state,
        &network.alice.peer_id,
        &peer_ids,
        2,
        &sorted_new,
        &key_string,
        &sorted_new,
        2,
        &announcement_post_id,
        &new_committee_states,
    )
    .await;

    // Phase D: verify PK preserved on the new committee.
    verify_reshare_pk_preserved(
        &[
            ("alice", &network.alice.app_state),
            ("bob", &network.bob.app_state),
            ("dave", &dave.app_state),
        ],
        &key_string,
        &original_pk_bytes,
    );

    network.shutdown_routers().await.expect("shutdown routers");
    if let Some(r) = dave.router.take() {
        r.shutdown().await.expect("shutdown dave router");
    }
    for path in &db_paths {
        cleanup_db(path);
    }
}

/// Reshare should complete when one old dealer is offline, as long as the old
/// threshold of valid dealers contributes shares to every new receiver.
#[tokio::test]
#[serial_test::serial]
async fn test_reshare_one_old_dealer_offline_completes() {
    let db_name = "test_reshare_one_old_dealer_offline_completes";
    let db_paths = [
        test_db_path(&format!("{}_1", db_name)),
        test_db_path(&format!("{}_2", db_name)),
        test_db_path(&format!("{}_3", db_name)),
        test_db_path(&format!("{}_4", db_name)),
    ];
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_test_writer()
        .try_init();

    let mut network = setup_three_node_network(true, db_name).await;
    let dummy_bulletin = network.dummy_bulletin.as_ref().unwrap().clone();
    let peer_ids = network.get_all_peer_ids();
    let mut dave = create_extra_test_node(&format!("{}_4", db_name), dummy_bulletin.clone()).await;

    // Phase A: DKG with A, B, C (t=2).
    let alice_service = DkgServiceImpl::<DkgImpl>::new(network.alice.app_state.clone());
    let test_keys = TestKeyPair::new();
    let token = test_keys
        .create_dkg_jwt(
            2,
            &peer_ids,
            None,
            None,
            BULLETIN_RING_NAMESPACE,
            TEST_FRESH_DKG_RING_ID,
        )
        .expect("JWT");
    alice_service
        .start_dkg(
            create_authenticated_request(
                StartDkgRequest {
                    threshold: 2,
                    peer_ids: peer_ids.clone(),
                    pss_interval: None,
                    policy_id: None,
                    namespace: BULLETIN_RING_NAMESPACE.to_string(),
                    ring_id: TEST_FRESH_DKG_RING_ID.to_string(),
                },
                &token,
            )
            .unwrap(),
        )
        .await
        .expect("DKG should start");
    let (key_string, _ring_pk_hex, original_pk_bytes) =
        wait_for_dkg_complete_on_bulletin(&dummy_bulletin).await;

    // Phase B: reshare to {A,B,D}, t=2. C is leaving and will be offline.
    let mut sorted_new = vec![
        network.alice.address.clone(),
        network.bob.address.clone(),
        dave.address.clone(),
    ];
    sorted_new.sort();

    let old_node_states: Vec<&crate::app_state::AppState<DkgImpl>> = vec![
        &network.alice.app_state,
        &network.bob.app_state,
        &network.charlie.app_state,
    ];
    let announcement_post_id = post_reshare_announcement(
        &old_node_states,
        &peer_ids,
        2,
        &key_string,
        &sorted_new,
        2,
        &dummy_bulletin,
    )
    .await;

    if let Some(router) = network.charlie.router.take() {
        router
            .shutdown()
            .await
            .expect("shutdown offline old dealer");
    }

    let new_committee_states: Vec<&crate::app_state::AppState<DkgImpl>> = vec![
        &network.alice.app_state,
        &network.bob.app_state,
        &dave.app_state,
    ];
    run_reshare_ceremony(
        &network.alice.app_state,
        &network.alice.peer_id,
        &peer_ids,
        2,
        &sorted_new,
        &key_string,
        &sorted_new,
        2,
        &announcement_post_id,
        &new_committee_states,
    )
    .await;

    verify_reshare_pk_preserved(
        &[
            ("alice", &network.alice.app_state),
            ("bob", &network.bob.app_state),
            ("dave", &dave.app_state),
        ],
        &key_string,
        &original_pk_bytes,
    );

    network.shutdown_routers().await.expect("shutdown routers");
    if let Some(r) = dave.router.take() {
        r.shutdown().await.expect("shutdown dave router");
    }
    for path in &db_paths {
        cleanup_db(path);
    }
}

/// Reshare scenario: committee expanded ({A,B,C}→{A,B,C,D}, t=2→3).
///
/// A, B, C are DealerReceivers; D is a pure Receiver (joins).
#[tokio::test]
#[serial_test::serial]
async fn test_reshare_expand_committee() {
    let db_name = "test_reshare_expand_committee";
    let db_paths = [
        test_db_path(&format!("{}_1", db_name)),
        test_db_path(&format!("{}_2", db_name)),
        test_db_path(&format!("{}_3", db_name)),
        test_db_path(&format!("{}_4", db_name)),
    ];
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_test_writer()
        .try_init();

    let mut network = setup_three_node_network(true, db_name).await;
    let dummy_bulletin = network.dummy_bulletin.as_ref().unwrap().clone();
    let peer_ids = network.get_all_peer_ids();

    let mut dave = create_extra_test_node(&format!("{}_4", db_name), dummy_bulletin.clone()).await;

    // Phase A: DKG with A, B, C (t=2).
    let alice_service = DkgServiceImpl::<DkgImpl>::new(network.alice.app_state.clone());
    let test_keys = TestKeyPair::new();
    let token = test_keys
        .create_dkg_jwt(
            2,
            &peer_ids,
            None,
            None,
            BULLETIN_RING_NAMESPACE,
            TEST_FRESH_DKG_RING_ID,
        )
        .expect("JWT");
    alice_service
        .start_dkg(
            create_authenticated_request(
                StartDkgRequest {
                    threshold: 2,
                    peer_ids: peer_ids.clone(),
                    pss_interval: None,
                    policy_id: None,
                    namespace: BULLETIN_RING_NAMESPACE.to_string(),
                    ring_id: TEST_FRESH_DKG_RING_ID.to_string(),
                },
                &token,
            )
            .unwrap(),
        )
        .await
        .expect("DKG should start");
    let (key_string, _ring_pk_hex, original_pk_bytes) =
        wait_for_dkg_complete_on_bulletin(&dummy_bulletin).await;

    // Phase B: reshare to {A,B,C,D}, t=3.
    let mut sorted_new = vec![
        network.alice.address.clone(),
        network.bob.address.clone(),
        network.charlie.address.clone(),
        dave.address.clone(),
    ];
    sorted_new.sort();

    let mut union_peers = peer_ids.clone();
    for p in &sorted_new {
        if !union_peers.contains(p) {
            union_peers.push(p.clone());
        }
    }

    let old_node_states: Vec<&crate::app_state::AppState<DkgImpl>> = vec![
        &network.alice.app_state,
        &network.bob.app_state,
        &network.charlie.app_state,
    ];
    let announcement_post_id = post_reshare_announcement(
        &old_node_states,
        &peer_ids,
        2,
        &key_string,
        &sorted_new,
        3,
        &dummy_bulletin,
    )
    .await;

    let new_committee_states: Vec<&crate::app_state::AppState<DkgImpl>> = vec![
        &network.alice.app_state,
        &network.bob.app_state,
        &network.charlie.app_state,
        &dave.app_state,
    ];
    run_reshare_ceremony(
        &network.alice.app_state,
        &network.alice.peer_id,
        &peer_ids,
        2,
        &union_peers,
        &key_string,
        &sorted_new,
        3,
        &announcement_post_id,
        &new_committee_states,
    )
    .await;

    verify_reshare_pk_preserved(
        &[
            ("alice", &network.alice.app_state),
            ("bob", &network.bob.app_state),
            ("charlie", &network.charlie.app_state),
            ("dave", &dave.app_state),
        ],
        &key_string,
        &original_pk_bytes,
    );

    network.shutdown_routers().await.expect("shutdown routers");
    if let Some(r) = dave.router.take() {
        r.shutdown().await.expect("shutdown dave router");
    }
    for path in &db_paths {
        cleanup_db(path);
    }
}

/// Reshare scenario: committee shrunk ({A,B,C}→{A,B}, t=2→1).
///
/// A and B are DealerReceivers; C is a pure Dealer (leaves).
#[tokio::test]
#[serial_test::serial]
async fn test_reshare_shrink_committee() {
    let db_name = "test_reshare_shrink_committee";
    let db_paths = [
        test_db_path(&format!("{}_1", db_name)),
        test_db_path(&format!("{}_2", db_name)),
        test_db_path(&format!("{}_3", db_name)),
    ];
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_test_writer()
        .try_init();

    let mut network = setup_three_node_network(true, db_name).await;
    let dummy_bulletin = network.dummy_bulletin.as_ref().unwrap().clone();
    let peer_ids = network.get_all_peer_ids();

    // Phase A: DKG with A, B, C (t=2).
    let alice_service = DkgServiceImpl::<DkgImpl>::new(network.alice.app_state.clone());
    let test_keys = TestKeyPair::new();
    let token = test_keys
        .create_dkg_jwt(
            2,
            &peer_ids,
            None,
            None,
            BULLETIN_RING_NAMESPACE,
            TEST_FRESH_DKG_RING_ID,
        )
        .expect("JWT");
    alice_service
        .start_dkg(
            create_authenticated_request(
                StartDkgRequest {
                    threshold: 2,
                    peer_ids: peer_ids.clone(),
                    pss_interval: None,
                    policy_id: None,
                    namespace: BULLETIN_RING_NAMESPACE.to_string(),
                    ring_id: TEST_FRESH_DKG_RING_ID.to_string(),
                },
                &token,
            )
            .unwrap(),
        )
        .await
        .expect("DKG should start");
    let (key_string, _ring_pk_hex, original_pk_bytes) =
        wait_for_dkg_complete_on_bulletin(&dummy_bulletin).await;

    // Phase B: reshare to {A,B}, t=1.
    let mut sorted_new = vec![network.alice.address.clone(), network.bob.address.clone()];
    sorted_new.sort();

    // New committee ⊆ old: union == old.
    let old_node_states: Vec<&crate::app_state::AppState<DkgImpl>> = vec![
        &network.alice.app_state,
        &network.bob.app_state,
        &network.charlie.app_state,
    ];
    let announcement_post_id = post_reshare_announcement(
        &old_node_states,
        &peer_ids,
        2,
        &key_string,
        &sorted_new,
        1,
        &dummy_bulletin,
    )
    .await;

    let new_committee_states: Vec<&crate::app_state::AppState<DkgImpl>> =
        vec![&network.alice.app_state, &network.bob.app_state];
    run_reshare_ceremony(
        &network.alice.app_state,
        &network.alice.peer_id,
        &peer_ids,
        2,
        &peer_ids, // union == old (new ⊆ old)
        &key_string,
        &sorted_new,
        1,
        &announcement_post_id,
        &new_committee_states,
    )
    .await;

    verify_reshare_pk_preserved(
        &[
            ("alice", &network.alice.app_state),
            ("bob", &network.bob.app_state),
        ],
        &key_string,
        &original_pk_bytes,
    );

    network.shutdown_routers().await.expect("shutdown routers");
    for path in &db_paths {
        cleanup_db(path);
    }
}

/// Reshare scenario: full committee rotation ({A,B,C}→{D,E,F}, t=2→2).
///
/// A, B, C are pure Dealers (leave the ring);
/// D, E, F are pure Receivers (join the ring).
#[tokio::test]
#[serial_test::serial]
async fn test_reshare_full_rotation() {
    let db_name = "test_reshare_full_rotation";
    let db_paths = [
        test_db_path(&format!("{}_1", db_name)),
        test_db_path(&format!("{}_2", db_name)),
        test_db_path(&format!("{}_3", db_name)),
        test_db_path(&format!("{}_4", db_name)),
        test_db_path(&format!("{}_5", db_name)),
        test_db_path(&format!("{}_6", db_name)),
    ];
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_test_writer()
        .try_init();

    let mut network = setup_three_node_network(true, db_name).await;
    let dummy_bulletin = network.dummy_bulletin.as_ref().unwrap().clone();
    let peer_ids = network.get_all_peer_ids();

    // Three extra Receiver nodes that will form the new committee.
    let mut dave = create_extra_test_node(&format!("{}_4", db_name), dummy_bulletin.clone()).await;
    let mut eve = create_extra_test_node(&format!("{}_5", db_name), dummy_bulletin.clone()).await;
    let mut frank = create_extra_test_node(&format!("{}_6", db_name), dummy_bulletin.clone()).await;

    // Phase A: DKG with A, B, C (t=2).
    let alice_service = DkgServiceImpl::<DkgImpl>::new(network.alice.app_state.clone());
    let test_keys = TestKeyPair::new();
    let token = test_keys
        .create_dkg_jwt(
            2,
            &peer_ids,
            None,
            None,
            BULLETIN_RING_NAMESPACE,
            TEST_FRESH_DKG_RING_ID,
        )
        .expect("JWT");
    alice_service
        .start_dkg(
            create_authenticated_request(
                StartDkgRequest {
                    threshold: 2,
                    peer_ids: peer_ids.clone(),
                    pss_interval: None,
                    policy_id: None,
                    namespace: BULLETIN_RING_NAMESPACE.to_string(),
                    ring_id: TEST_FRESH_DKG_RING_ID.to_string(),
                },
                &token,
            )
            .unwrap(),
        )
        .await
        .expect("DKG should start");
    let (key_string, _ring_pk_hex, original_pk_bytes) =
        wait_for_dkg_complete_on_bulletin(&dummy_bulletin).await;
    println!("DKG complete. key_string={}", key_string);

    // Phase B: reshare to {D,E,F}, t=2.
    let mut sorted_new = vec![
        dave.address.clone(),
        eve.address.clone(),
        frank.address.clone(),
    ];
    sorted_new.sort();

    let mut union_peers = peer_ids.clone();
    for p in &sorted_new {
        if !union_peers.contains(p) {
            union_peers.push(p.clone());
        }
    }

    let old_node_states: Vec<&crate::app_state::AppState<DkgImpl>> = vec![
        &network.alice.app_state,
        &network.bob.app_state,
        &network.charlie.app_state,
    ];
    let announcement_post_id = post_reshare_announcement(
        &old_node_states,
        &peer_ids,
        2,
        &key_string,
        &sorted_new,
        2,
        &dummy_bulletin,
    )
    .await;

    let new_committee_states: Vec<&crate::app_state::AppState<DkgImpl>> =
        vec![&dave.app_state, &eve.app_state, &frank.app_state];
    run_reshare_ceremony(
        &network.alice.app_state,
        &network.alice.peer_id,
        &peer_ids,
        2,
        &union_peers,
        &key_string,
        &sorted_new,
        2,
        &announcement_post_id,
        &new_committee_states,
    )
    .await;

    // Phase D: verify PK on all three new-committee nodes.
    verify_reshare_pk_preserved(
        &[
            ("dave", &dave.app_state),
            ("eve", &eve.app_state),
            ("frank", &frank.app_state),
        ],
        &key_string,
        &original_pk_bytes,
    );

    network.shutdown_routers().await.expect("shutdown routers");
    if let Some(r) = dave.router.take() {
        r.shutdown().await.expect("shutdown dave");
    }
    if let Some(r) = eve.router.take() {
        r.shutdown().await.expect("shutdown eve");
    }
    if let Some(r) = frank.router.take() {
        r.shutdown().await.expect("shutdown frank");
    }
    for path in &db_paths {
        cleanup_db(path);
    }
}
