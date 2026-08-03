use super::support::{invoke_session_init, TestSessionInit};
use crate::dkg::v0::service::DkgServiceImpl;
use crate::dkg::v0::{
    coordinator::DkgCoordinator,
    error::DkgError,
    helpers::derive_reshare_session_id,
    messages::SessionKind,
    network::{start_reshare, ReshareStartOutcome},
    session_state::{RingPssClaimOutcome, SessionStateManager},
    transport::{canonical_leader, AttemptKey},
};
use crate::helpers::create_routers::create_router_with_all_handlers;
use crate::helpers::test_helpers::TEST_FRESH_DKG_RING_ID;
use crate::helpers::test_helpers::{
    cleanup_db, create_authenticated_request, create_test_app_state_with_bulletin,
    get_test_ring_post, setup_three_node_network, test_db_path, write_ring_to_bulletin,
    TestKeyPair, TestNode,
};
use crate::ring_state::{RingIndexEntry, RingShareBundle};
use bulletin::dummy::DummyBulletin;
use bulletin::r#trait::{BulletinKind, NodeInfo, RingPayload};
use crypto::r#trait::{CryptoDeserialize, Dkg, DkgRole, PubPoly as PubPolyTrait};
use crypto::CryptoSerialize;
use local_storage::r#trait::{LocalStorage, LocalStorageKeys};
use network::PeerId;
use proto::v0::dkg::{dkg_service_server::DkgService, StartDkgRequest};
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
// path: unknown ring, noncanonical next leader, concurrent ceremony blocked.
// Additionally, includes unit tests for the Dealer Phase 4 cleanup path
// (share deletion, ring index removal, PSS flag cleared) and the session-state
// PSS blocking behaviour (ring/session claim idempotency).
// =============================================================================

/// Build a minimal reshare `SessionInit` that the coordinator can inspect.
///
/// Minimal validation tests reuse the same strings for route peer IDs and
/// peer_node_keys because no real network routing occurs.
fn reshare_session_init(
    ring_pk: &str,
    peer_node_keys: Vec<String>,
    new_peer_node_keys: Vec<String>,
    new_threshold: u32,
) -> TestSessionInit {
    let mut node_id_assignments = std::collections::HashMap::new();
    for (i, p) in peer_node_keys.iter().enumerate() {
        node_id_assignments.insert(p.clone(), (i + 1) as u32);
    }
    let peer_ids = peer_node_keys.clone();
    TestSessionInit {
        // Arbitrary non-colliding session ID for reshare validation tests.
        session_id: 99_999_100,
        threshold: 1,
        total_participants: peer_ids.len() as u32,
        peer_ids: peer_ids.clone(),
        peer_node_keys,
        node_id_assignments,
        token_string: String::new(),
        kind: SessionKind::Reshare {
            ring_pk_hex: ring_pk.to_string(),
            new_peer_node_keys,
            new_threshold,
            bulletin_post_id: String::new(),
        },
        pss_interval: 86400,
        policy_id: None,
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
/// rejected by the fail-closed protocol-state guard.
#[tokio::test]
async fn test_reshare_session_init_rejects_unknown_ring() {
    let db_name = "test_reshare_rejects_unknown_ring";
    let db_path = test_db_path(db_name);
    let dummy_bulletin = Arc::new(
        DummyBulletin::new()
            .await
            .expect("Failed to initialize dummy bulletin"),
    );
    let app_state =
        Arc::new(create_test_app_state_with_bulletin(true, dummy_bulletin.clone(), db_name).await);
    let coordinator = DkgCoordinator::with_routes(app_state, &::network::V0);

    let sender_bytes = hex::decode("aabbccdd").unwrap();
    let sender_peer_id = PeerId::from_bytes(&sender_bytes);

    // "unknown_ring_pk" is not present in RingIndex or the bulletin.
    let msg = reshare_session_init(
        "unknown_ring_pk",
        vec!["aabbccdd".to_string()],
        vec!["00112233".to_string()],
        1,
    );
    let result = invoke_session_init(&coordinator, msg, &sender_peer_id).await;
    assert!(
        matches!(result, Err(DkgError::ProtocolError(_))),
        "Expected ProtocolError for unknown ring, got: {:?}",
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
    let dummy_bulletin = Arc::new(
        DummyBulletin::new()
            .await
            .expect("Failed to initialize dummy bulletin"),
    );
    let app_state =
        Arc::new(create_test_app_state_with_bulletin(true, dummy_bulletin.clone(), db_name).await);

    use local_storage::r#trait::LocalStorageKeys;

    let sender_hex = "aabbccdd";
    let session_ring_pk = "session_ring_hex";
    let payload = RingPayload {
        upgrade_info: Default::default(),
        ring_pk: "payload_ring_pk_other".to_string(),
        peer_node_keys: vec![sender_hex.to_string()],
        new_peer_node_keys: Some(vec!["00112233".to_string()]),
        new_threshold: Some(1),
        threshold: 2,
        pss_interval: 86400,
        block_number_nonce: 0,
        policy_id: None,
        reporting: Default::default(),
    };
    let post_id = "test-mismatched-ring-pk".to_string();
    dummy_bulletin
        .set_ring(post_id.clone(), payload)
        .expect("seed ring fixture");

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
        indexed_at_secs: 0,
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
    let coordinator = DkgCoordinator::with_routes(app_state, &::network::V0);

    let msg = reshare_session_init(
        session_ring_pk,
        vec![sender_hex.to_string()],
        vec!["00112233".to_string()],
        1,
    );
    let result = invoke_session_init(&coordinator, msg, &sender_peer_id).await;
    assert!(
        matches!(result, Err(DkgError::Unauthorized(_))),
        "Expected Unauthorized when bulletin ring_pk != session ring, got: {:?}",
        result
    );
    cleanup_db(&db_path);
}

/// Reshare `SessionInit` must come from the canonical next-committee leader.
///
/// This fixture deliberately sends a fully SourceHub-anchored initialization
/// from another authenticated next-committee receiver so the test reaches the
/// leader check rather than failing an earlier committee or route check.
#[tokio::test]
async fn test_reshare_session_init_rejects_noncanonical_next_leader() {
    let db_name = "test_reshare_rejects_noncanonical_next_leader";
    let db_path = test_db_path(db_name);
    let dummy_bulletin = Arc::new(
        DummyBulletin::new()
            .await
            .expect("Failed to initialize dummy bulletin"),
    );
    let app_state =
        Arc::new(create_test_app_state_with_bulletin(true, dummy_bulletin.clone(), db_name).await);

    let ring_pk = "reshare_ring";
    let post_id = "test-reshare-noncanonical-next-leader".to_string();
    let old_node_key = "old-node".to_string();
    let old_peer_hex = "11".repeat(32);
    let canonical_next_key = "000-next-leader".to_string();
    let canonical_next_peer_hex = "aa".repeat(32);
    let sender_node_key = "zzz-next-member".to_string();
    let sender_peer_hex = "dd".repeat(32);
    let receiver_node_key = app_state.node_key.clone();
    let receiver_peer_hex = hex::encode(app_state.network.local_peer_id().as_bytes());
    let mut next_node_keys = vec![
        canonical_next_key.clone(),
        sender_node_key.clone(),
        receiver_node_key.clone(),
    ];
    next_node_keys.sort();
    assert_eq!(
        canonical_leader(&next_node_keys),
        Some(canonical_next_key.as_str())
    );

    for (node_key, peer_id) in [
        (&old_node_key, &old_peer_hex),
        (&canonical_next_key, &canonical_next_peer_hex),
        (&sender_node_key, &sender_peer_hex),
        (&receiver_node_key, &receiver_peer_hex),
    ] {
        dummy_bulletin
            .set_node_info(
                node_key.clone(),
                NodeInfo {
                    peer_id: peer_id.clone(),
                    controller_key: "test-controller-key".to_string(),
                    whitelisted_policy_ids: vec![],
                    whitelisted_ring_ids: vec![post_id.clone()],
                },
            )
            .expect("seed routed NodeInfo");
    }
    dummy_bulletin
        .set_ring(
            post_id.clone(),
            RingPayload {
                upgrade_info: Default::default(),
                ring_pk: ring_pk.to_string(),
                peer_node_keys: vec![old_node_key.clone()],
                new_peer_node_keys: Some(next_node_keys.clone()),
                new_threshold: Some(2),
                threshold: 1,
                pss_interval: 86400,
                block_number_nonce: 0,
                policy_id: None,
                reporting: Default::default(),
            },
        )
        .expect("seed reshare announcement");
    app_state
        .local_storage
        .set(
            LocalStorageKeys::RingIndex,
            serde_json::to_vec(&vec![RingIndexEntry {
                ring_pk_str: ring_pk.to_string(),
                bulletin_post_id: post_id.clone(),
                indexed_at_secs: 0,
            }])
            .unwrap(),
        )
        .unwrap();

    let session_id = derive_reshare_session_id(
        ring_pk,
        &post_id,
        std::slice::from_ref(&old_node_key),
        &next_node_keys,
        2,
    )
    .unwrap();
    let msg = TestSessionInit {
        session_id,
        threshold: 1,
        total_participants: 1,
        peer_ids: vec![old_peer_hex],
        peer_node_keys: vec![old_node_key.clone()],
        node_id_assignments: std::collections::HashMap::from([(old_node_key, 1)]),
        token_string: String::new(),
        kind: SessionKind::Reshare {
            ring_pk_hex: ring_pk.to_string(),
            new_peer_node_keys: next_node_keys,
            new_threshold: 2,
            bulletin_post_id: post_id,
        },
        pss_interval: 86400,
        policy_id: None,
        ring_id: String::new(),
    };

    let sender_bytes = hex::decode(sender_peer_hex).unwrap();
    let sender_peer_id = PeerId::from_bytes(&sender_bytes);
    let coordinator = DkgCoordinator::with_routes(app_state, &::network::V0);
    let result = invoke_session_init(&coordinator, msg, &sender_peer_id).await;
    match result {
        Err(DkgError::Unauthorized(message)) => assert!(
            message.contains("not the canonical next-committee leader"),
            "expected canonical next-leader rejection, got: {message}"
        ),
        other => panic!("Expected Unauthorized for noncanonical next leader, got: {other:?}"),
    }
    cleanup_db(&db_path);
}

/// A pure new-committee receiver must explicitly opt in via its NodeInfo policy/ring
/// allowlist before accepting a reshare `SessionInit`.
#[tokio::test]
async fn test_reshare_session_init_rejects_new_receiver_without_node_allowlist() {
    let db_name = "test_reshare_rejects_new_receiver_without_allowlist";
    let db_path = test_db_path(db_name);
    let dummy_bulletin = Arc::new(
        DummyBulletin::new()
            .await
            .expect("Failed to initialize dummy bulletin"),
    );
    let app_state =
        Arc::new(create_test_app_state_with_bulletin(true, dummy_bulletin.clone(), db_name).await);

    let ring_pk = "reshare_ring";
    let post_id = "test-reshare-unauthorized-receiver".to_string();
    let sender_node_key = "old-node-key".to_string();
    let sender_peer_hex = "aabbccdd".to_string();
    let receiver_node_key = app_state.node_key.clone();
    let receiver_peer_hex = hex::encode(app_state.network.local_peer_id().as_bytes());

    dummy_bulletin
        .set_node_info(
            sender_node_key.clone(),
            NodeInfo {
                peer_id: sender_peer_hex.clone(),
                controller_key: "test-controller-key".to_string(),
                whitelisted_policy_ids: vec!["test-policy".to_string()],
                whitelisted_ring_ids: vec![post_id.clone()],
            },
        )
        .expect("seed sender NodeInfo");
    dummy_bulletin
        .set_node_info(
            receiver_node_key.clone(),
            NodeInfo {
                peer_id: receiver_peer_hex,
                controller_key: "test-controller-key".to_string(),
                whitelisted_policy_ids: vec![],
                whitelisted_ring_ids: vec![],
            },
        )
        .expect("override receiver NodeInfo without allowlist");

    dummy_bulletin
        .set_ring(
            post_id.clone(),
            RingPayload {
                upgrade_info: Default::default(),
                ring_pk: ring_pk.to_string(),
                peer_node_keys: vec![sender_node_key.clone()],
                new_peer_node_keys: Some(vec![receiver_node_key.clone()]),
                new_threshold: Some(1),
                threshold: 1,
                pss_interval: 86400,
                block_number_nonce: 0,
                policy_id: Some("test-policy".to_string()),
                reporting: Default::default(),
            },
        )
        .expect("seed reshare announcement");

    let mut node_id_assignments = std::collections::HashMap::new();
    node_id_assignments.insert(sender_node_key.clone(), 1);
    let session_id = 99_999_500;
    let msg = TestSessionInit {
        session_id,
        threshold: 1,
        total_participants: 1,
        peer_ids: vec![sender_peer_hex.clone()],
        peer_node_keys: vec![sender_node_key],
        node_id_assignments,
        token_string: String::new(),
        kind: SessionKind::Reshare {
            ring_pk_hex: ring_pk.to_string(),
            new_peer_node_keys: vec![receiver_node_key],
            new_threshold: 1,
            bulletin_post_id: post_id,
        },
        pss_interval: 86400,
        policy_id: None,
        ring_id: String::new(),
    };

    let sender_bytes = hex::decode(sender_peer_hex).unwrap();
    let sender_peer_id = PeerId::from_bytes(&sender_bytes);
    let coordinator = DkgCoordinator::with_routes(app_state.clone(), &::network::V0);
    let result = invoke_session_init(&coordinator, msg, &sender_peer_id).await;
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
    assert!(
        !app_state
            .dkg_session_state
            .session_exists(&session_id)
            .await,
        "unauthorized reshare must not create local session state"
    );
    cleanup_db(&db_path);
}

/// If `try_mark_ring_pss` is already held for a ring, an incoming reshare
/// `SessionInit` for that ring must be rejected with `Unauthorized`.
#[tokio::test]
async fn test_reshare_session_init_blocks_concurrent_ceremony() {
    let db_name = "test_reshare_blocks_concurrent";
    let db_path = test_db_path(db_name);
    let dummy_bulletin = Arc::new(
        DummyBulletin::new()
            .await
            .expect("Failed to initialize dummy bulletin"),
    );
    let app_state =
        Arc::new(create_test_app_state_with_bulletin(true, dummy_bulletin.clone(), db_name).await);

    let ring_pk = "reshare_ring";
    let sender_hex = "aabbccdd";
    // Include this node's own peer ID in the new committee so it is a Receiver
    // and reaches the try_mark_ring_pss check (the (false,false) guard fires before
    // the mark check, so the test node must be in at least one committee).
    let our_hex = hex::encode(app_state.network.local_peer_id().as_bytes());
    // Bulletin must pre-announce new_peer_node_keys and new_threshold (matching what the
    // message will propose) so checks 3 & 4 pass and the test reaches the PSS flag check.
    write_ring_with_announced_reshare(
        &app_state,
        &dummy_bulletin,
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
        RingPssClaimOutcome::Claimed,
        "initial conflicting claim should succeed"
    );

    let sender_bytes = hex::decode(sender_hex).unwrap();
    let sender_peer_id = PeerId::from_bytes(&sender_bytes);
    let coordinator = DkgCoordinator::with_routes(app_state, &::network::V0);
    let msg = reshare_session_init(ring_pk, vec![sender_hex.to_string()], vec![our_hex], 1);
    let result = invoke_session_init(&coordinator, msg, &sender_peer_id).await;
    assert!(
        matches!(result, Err(DkgError::Unauthorized(_))),
        "Expected Unauthorized for already-in-progress reshare, got: {:?}",
        result
    );
    cleanup_db(&db_path);
}

/// A pure Dealer must retain its old share until SourceHub finalizes a
/// committee that excludes it, then delete both the bundle and index entry.
#[tokio::test]
async fn test_dealer_phase4_retains_share_until_finalized_exclusion() {
    let db_name = "test_dealer_phase4_finalized_cleanup";
    let db_path = test_db_path(db_name);
    let dummy_bulletin = Arc::new(
        DummyBulletin::new()
            .await
            .expect("Failed to initialize dummy bulletin"),
    );
    let app_state =
        Arc::new(create_test_app_state_with_bulletin(true, dummy_bulletin.clone(), db_name).await);

    let ring_pk = "dealer_phase4_ring";
    // Arbitrary non-colliding session ID for Dealer Phase 4 tests.
    let session_id = 88_000_001u128;

    // Pre-populate local storage: share bundle + ring index entry.
    write_last_refresh(&app_state.local_storage, ring_pk, 0);
    write_ring_to_bulletin(
        &app_state.local_storage,
        &dummy_bulletin,
        ring_pk,
        vec![app_state.node_key.clone()],
        86400,
    )
    .await;
    let bulletin_post_id = format!("test-ring-{ring_pk}");
    let pending_payload = RingPayload {
        upgrade_info: Default::default(),
        ring_pk: ring_pk.to_string(),
        peer_node_keys: vec![app_state.node_key.clone()],
        new_peer_node_keys: Some(vec!["00112233".to_string()]),
        new_threshold: Some(1),
        threshold: 1,
        pss_interval: 86400,
        block_number_nonce: 0,
        policy_id: None,
        reporting: Default::default(),
    };
    dummy_bulletin
        .set_ring(bulletin_post_id.clone(), pending_payload.clone())
        .expect("seed pending committee transition");

    // Create a session where this node acts as a pure Dealer.
    let coordinator = DkgCoordinator::with_routes(app_state.clone(), &::network::V0);
    coordinator
        .create_session(
            AttemptKey::test(session_id),
            1,
            1,
            3,
            DkgRole::Dealer,
            |_| {},
        )
        .await
        .expect("create_session should succeed");

    app_state
        .dkg_session_state
        .set_session_kind(
            &session_id,
            SessionKind::Reshare {
                ring_pk_hex: ring_pk.to_string(),
                new_peer_node_keys: vec!["00112233".to_string()],
                new_threshold: 1,
                bulletin_post_id: bulletin_post_id.clone(),
            },
        )
        .await;

    // Trigger Phase 4 directly — the Dealer path cleans up without any crypto.
    coordinator
        .initiate_phase4_completion(AttemptKey::test(session_id))
        .await
        .expect("phase4 should succeed for Dealer");

    // Phase 4 only marks the dealer complete locally. Until SourceHub finalizes
    // the exclusion, both the secret bundle and its index entry remain usable.
    assert!(
        RingShareBundle::load_by_ring_key(&app_state.local_storage, ring_pk).is_ok(),
        "share bundle must be retained before committee finalization"
    );
    let retained_index: Vec<RingIndexEntry> = app_state
        .local_storage
        .get(local_storage::r#trait::LocalStorageKeys::RingIndex)
        .ok()
        .flatten()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();
    assert!(
        retained_index.iter().any(|e| e.ring_pk_str == ring_pk),
        "RingIndex must retain the dealer's ring before finalization"
    );

    let mut finalized_payload = pending_payload;
    finalized_payload.peer_node_keys = vec!["00112233".to_string()];
    finalized_payload.new_peer_node_keys = None;
    finalized_payload.new_threshold = None;
    dummy_bulletin
        .set_ring(bulletin_post_id, finalized_payload)
        .expect("finalize committee transition");

    // Poll the actual condition under test (bundle deletion), not session
    // removal as a proxy for it — the two are separate cleanup steps with no
    // guaranteed ordering, so a proxy wait could exit before deletion
    // actually completes.
    let deadline = Instant::now() + Duration::from_secs(5);
    while RingShareBundle::load_by_ring_key(&app_state.local_storage, ring_pk).is_ok()
        && Instant::now() < deadline
    {
        sleep(Duration::from_millis(20)).await;
    }

    assert!(
        RingShareBundle::load_by_ring_key(&app_state.local_storage, ring_pk).is_err(),
        "share bundle should be deleted after finalized committee exclusion"
    );
    let finalized_index: Vec<RingIndexEntry> = app_state
        .local_storage
        .get(local_storage::r#trait::LocalStorageKeys::RingIndex)
        .ok()
        .flatten()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();
    assert!(
        !finalized_index.iter().any(|e| e.ring_pk_str == ring_pk),
        "RingIndex should remove the dealer's ring after finalized exclusion"
    );

    cleanup_db(&db_path);
}

/// The PSS claim remains held after a pure Dealer finishes sending shares and
/// is released only once SourceHub finalizes the committee transition.
#[tokio::test]
async fn test_dealer_phase4_holds_pss_until_finalized_exclusion() {
    let db_name = "test_dealer_phase4_finalized_pss";
    let db_path = test_db_path(db_name);
    let dummy_bulletin = Arc::new(
        DummyBulletin::new()
            .await
            .expect("Failed to initialize dummy bulletin"),
    );
    let app_state =
        Arc::new(create_test_app_state_with_bulletin(true, dummy_bulletin.clone(), db_name).await);

    let ring_pk = "dealer_phase4_pss_ring";
    // Arbitrary non-colliding session ID for Dealer Phase 4 PSS flag test.
    let session_id = 88_000_002u128;

    write_last_refresh(&app_state.local_storage, ring_pk, 0);
    write_ring_to_bulletin(
        &app_state.local_storage,
        &dummy_bulletin,
        ring_pk,
        vec![app_state.node_key.clone()],
        86400,
    )
    .await;
    let bulletin_post_id = format!("test-ring-{ring_pk}");
    let pending_payload = RingPayload {
        upgrade_info: Default::default(),
        ring_pk: ring_pk.to_string(),
        peer_node_keys: vec![app_state.node_key.clone()],
        new_peer_node_keys: Some(vec!["00112233".to_string()]),
        new_threshold: Some(1),
        threshold: 1,
        pss_interval: 86400,
        block_number_nonce: 0,
        policy_id: None,
        reporting: Default::default(),
    };
    dummy_bulletin
        .set_ring(bulletin_post_id.clone(), pending_payload.clone())
        .expect("seed pending committee transition");

    let coordinator = DkgCoordinator::with_routes(app_state.clone(), &::network::V0);
    coordinator
        .create_session(
            AttemptKey::test(session_id),
            1,
            1,
            3,
            DkgRole::Dealer,
            |_| {},
        )
        .await
        .expect("create_session should succeed");

    app_state
        .dkg_session_state
        .set_session_kind(
            &session_id,
            SessionKind::Reshare {
                ring_pk_hex: ring_pk.to_string(),
                new_peer_node_keys: vec!["00112233".to_string()],
                new_threshold: 1,
                bulletin_post_id: bulletin_post_id.clone(),
            },
        )
        .await;

    // Mark the ring as having an active PSS ceremony.
    let attempt = AttemptKey::test(session_id);
    assert_eq!(
        app_state
            .dkg_session_state
            .claim_ring_pss_attempt(ring_pk, attempt)
            .await,
        RingPssClaimOutcome::Claimed,
        "PSS claim should be markable before Phase 4"
    );

    coordinator
        .initiate_phase4_completion(attempt)
        .await
        .expect("phase4 should succeed for Dealer");

    assert!(
        app_state
            .dkg_session_state
            .is_ring_pss_active(ring_pk)
            .await,
        "PSS claim must remain held before committee finalization"
    );

    let mut finalized_payload = pending_payload;
    finalized_payload.peer_node_keys = vec!["00112233".to_string()];
    finalized_payload.new_peer_node_keys = None;
    finalized_payload.new_threshold = None;
    dummy_bulletin
        .set_ring(bulletin_post_id, finalized_payload)
        .expect("finalize committee transition");

    let deadline = Instant::now() + Duration::from_secs(5);
    while app_state
        .dkg_session_state
        .is_ring_pss_active(ring_pk)
        .await
        && Instant::now() < deadline
    {
        sleep(Duration::from_millis(20)).await;
    }
    assert!(
        !app_state
            .dkg_session_state
            .is_ring_pss_active(ring_pk)
            .await,
        "PSS claim should be released after finalized committee exclusion"
    );

    cleanup_db(&db_path);
}

// =============================================================================
// validate_reshare_session_init — bulletin-anchor checks
//
// These tests exercise the two new bulletin-anchor checks added to
// `validate_reshare_session_init`:
//   • proposed `new_peer_node_keys` must match `RingPayload::new_peer_node_keys` when set
//   • proposed `new_threshold` must match `RingPayload::new_threshold` when set
// =============================================================================

/// Post a `RingPayload` with caller-supplied `new_peer_node_keys` / `new_threshold`
/// and seed `RingIndex` so the coordinator can find the ring.
async fn write_ring_with_announced_reshare(
    app_state: &crate::app_state::AppState<crypto::DkgImpl>,
    bulletin: &DummyBulletin,
    ring_pk: &str,
    peer_node_keys: Vec<String>,
    announced_new_peer_node_keys: Option<Vec<String>>,
    announced_new_threshold: Option<u32>,
) {
    use local_storage::r#trait::LocalStorageKeys;

    let payload = RingPayload {
        upgrade_info: Default::default(),
        ring_pk: ring_pk.to_string(),
        peer_node_keys,
        new_peer_node_keys: announced_new_peer_node_keys,
        new_threshold: announced_new_threshold,
        threshold: 2,
        pss_interval: 86400,
        block_number_nonce: 0,
        policy_id: None,
        reporting: Default::default(),
    };
    let post_id = format!("test-reshare-{ring_pk}");
    bulletin
        .set_ring(post_id.clone(), payload)
        .expect("seed ring fixture");
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
        indexed_at_secs: 0,
    });
    app_state
        .local_storage
        .set(
            LocalStorageKeys::RingIndex,
            serde_json::to_vec(&ring_index).unwrap(),
        )
        .unwrap();
}

/// Reshare `SessionInit` whose `new_peer_node_keys` differs from the bulletin-announced
/// committee must be rejected with `Unauthorized`.
#[tokio::test]
async fn test_reshare_session_init_rejects_mismatched_new_peer_node_keys() {
    let db_name = "test_reshare_rejects_mismatch_peers";
    let db_path = test_db_path(db_name);
    let dummy_bulletin = Arc::new(
        DummyBulletin::new()
            .await
            .expect("Failed to initialize dummy bulletin"),
    );
    let app_state =
        Arc::new(create_test_app_state_with_bulletin(true, dummy_bulletin.clone(), db_name).await);

    let ring_pk = "reshare_ring";
    let sender_hex = "aabbccdd";

    // Bulletin pre-announces "11223344" as the only new-committee member, with threshold 1.
    // new_threshold must also be set so check 4 passes and the test reaches check 3.
    write_ring_with_announced_reshare(
        &app_state,
        &dummy_bulletin,
        ring_pk,
        vec![sender_hex.to_string()],
        Some(vec!["11223344".to_string()]),
        Some(1),
    )
    .await;

    let sender_bytes = hex::decode(sender_hex).unwrap();
    let sender_peer_id = PeerId::from_bytes(&sender_bytes);
    let coordinator = DkgCoordinator::with_routes(app_state, &::network::V0);

    // Propose a *different* new committee — should be rejected.
    let msg = reshare_session_init(
        ring_pk,
        vec![sender_hex.to_string()],
        vec!["deadbeef".to_string()], // does not match "11223344"
        1,
    );
    let result = invoke_session_init(&coordinator, msg, &sender_peer_id).await;
    assert!(
        matches!(result, Err(DkgError::Unauthorized(_))),
        "Expected Unauthorized for mismatched new_peer_node_keys, got: {:?}",
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
    let dummy_bulletin = Arc::new(
        DummyBulletin::new()
            .await
            .expect("Failed to initialize dummy bulletin"),
    );
    let app_state =
        Arc::new(create_test_app_state_with_bulletin(true, dummy_bulletin.clone(), db_name).await);

    let ring_pk = "reshare_ring";
    let sender_hex = "aabbccdd";

    // Bulletin pre-announces new_threshold = 2, with matching new_peer_node_keys.
    // new_peer_node_keys must also be set (matching the proposal) so check 3 passes
    // and the test actually reaches check 4 (the threshold mismatch).
    write_ring_with_announced_reshare(
        &app_state,
        &dummy_bulletin,
        ring_pk,
        vec![sender_hex.to_string()],
        Some(vec!["00112233".to_string()]),
        Some(2),
    )
    .await;

    let sender_bytes = hex::decode(sender_hex).unwrap();
    let sender_peer_id = PeerId::from_bytes(&sender_bytes);
    let coordinator = DkgCoordinator::with_routes(app_state, &::network::V0);

    // Propose new_threshold = 1 — does not match announced 2.
    let msg = reshare_session_init(
        ring_pk,
        vec![sender_hex.to_string()],
        vec!["00112233".to_string()],
        1, // does not match announced 2
    );
    let result = invoke_session_init(&coordinator, msg, &sender_peer_id).await;
    assert!(
        matches!(result, Err(DkgError::Unauthorized(_))),
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
//   • new_peer_node_keys must be non-empty
//   • new_threshold must be in [1, len(new_peer_node_keys)]
// No bulletin entry is needed because the checks fire before the bulletin lookup.
// =============================================================================

/// When neither bulletin field is set, the fallback authoritative values are the
/// current `peer_ids` and `threshold`.  Proposing a different committee is still
/// rejected — absent fields mean "keep current", not "accept anything".
#[tokio::test]
async fn test_reshare_session_init_rejects_no_bulletin_announcement() {
    let db_name = "test_reshare_rejects_no_announcement";
    let db_path = test_db_path(db_name);
    let dummy_bulletin = Arc::new(
        DummyBulletin::new()
            .await
            .expect("Failed to initialize dummy bulletin"),
    );
    let app_state =
        Arc::new(create_test_app_state_with_bulletin(true, dummy_bulletin.clone(), db_name).await);

    let ring_pk = "reshare_ring";
    let sender_hex = "aabbccdd";
    // Bulletin has neither field; fallback committee = peer_ids = ["aabbccdd"].
    write_ring_with_announced_reshare(
        &app_state,
        &dummy_bulletin,
        ring_pk,
        vec![sender_hex.to_string()],
        None,
        None,
    )
    .await;

    let sender_bytes = hex::decode(sender_hex).unwrap();
    let sender_peer_id = PeerId::from_bytes(&sender_bytes);
    let coordinator = DkgCoordinator::with_routes(app_state, &::network::V0);
    // Propose a *different* committee — must be rejected even though no field is announced.
    let msg = reshare_session_init(
        ring_pk,
        vec![sender_hex.to_string()],
        vec!["00112233".to_string()], // differs from fallback = ["aabbccdd"]
        1,
    );
    let result = invoke_session_init(&coordinator, msg, &sender_peer_id).await;
    assert!(
        matches!(result, Err(DkgError::Unauthorized(_))),
        "Expected Unauthorized when proposed peers differ from fallback committee, got: {:?}",
        result
    );
    cleanup_db(&db_path);
}

/// Reshare `SessionInit` with an empty `new_peer_node_keys` must be rejected with
/// `InvalidInput` before any bulletin lookup occurs.
#[tokio::test]
async fn test_reshare_session_init_rejects_empty_new_committee() {
    let db_name = "test_reshare_rejects_empty_committee";
    let db_path = test_db_path(db_name);
    let dummy_bulletin = Arc::new(
        DummyBulletin::new()
            .await
            .expect("Failed to initialize dummy bulletin"),
    );
    let app_state =
        Arc::new(create_test_app_state_with_bulletin(true, dummy_bulletin.clone(), db_name).await);
    let coordinator = DkgCoordinator::with_routes(app_state, &::network::V0);

    let sender_bytes = hex::decode("aabbccdd").unwrap();
    let sender_peer_id = PeerId::from_bytes(&sender_bytes);

    let msg = reshare_session_init(
        "some_ring",
        vec!["aabbccdd".to_string()],
        vec![], // empty new committee
        0,      // threshold irrelevant — empty check fires first
    );
    let result = invoke_session_init(&coordinator, msg, &sender_peer_id).await;
    assert!(
        matches!(result, Err(DkgError::InvalidInput(_))),
        "Expected InvalidInput for empty new_peer_node_keys, got: {:?}",
        result
    );
    cleanup_db(&db_path);
}

/// Reshare `SessionInit` with `new_threshold > len(new_peer_node_keys)` must be
/// rejected with `InvalidInput` before any bulletin lookup occurs.
#[tokio::test]
async fn test_reshare_session_init_rejects_threshold_exceeds_committee_size() {
    let db_name = "test_reshare_rejects_threshold_too_high";
    let db_path = test_db_path(db_name);
    let dummy_bulletin = Arc::new(
        DummyBulletin::new()
            .await
            .expect("Failed to initialize dummy bulletin"),
    );
    let app_state =
        Arc::new(create_test_app_state_with_bulletin(true, dummy_bulletin.clone(), db_name).await);
    let coordinator = DkgCoordinator::with_routes(app_state, &::network::V0);

    let sender_bytes = hex::decode("aabbccdd").unwrap();
    let sender_peer_id = PeerId::from_bytes(&sender_bytes);

    // new_threshold = 3 with only 1 new-committee member — structurally impossible.
    let msg = reshare_session_init(
        "some_ring",
        vec!["aabbccdd".to_string()],
        vec!["00112233".to_string()],
        3, // exceeds committee size of 1
    );
    let result = invoke_session_init(&coordinator, msg, &sender_peer_id).await;
    assert!(
        matches!(result, Err(DkgError::InvalidInput(_))),
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
    let dummy_bulletin = Arc::new(
        DummyBulletin::new()
            .await
            .expect("Failed to initialize dummy bulletin"),
    );
    let app_state =
        Arc::new(create_test_app_state_with_bulletin(true, dummy_bulletin.clone(), db_name).await);
    let coordinator = DkgCoordinator::with_routes(app_state, &::network::V0);

    let sender_bytes = hex::decode("aabbccdd").unwrap();
    let sender_peer_id = PeerId::from_bytes(&sender_bytes);

    let msg = reshare_session_init(
        "some_ring",
        vec!["aabbccdd".to_string()],
        vec!["00112233".to_string()],
        0, // threshold of zero is never valid
    );
    let result = invoke_session_init(&coordinator, msg, &sender_peer_id).await;
    assert!(
        matches!(result, Err(DkgError::InvalidInput(_))),
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
//   • new_peer_node_keys absent → authoritative = ring_payload.peer_node_keys
//   • new_threshold absent → authoritative = ring_payload.threshold
// The tests below call validate_reshare_session_init directly so that committee
// membership of the receiving node is not a factor.
// =============================================================================

/// Build and post a RingPayload with configurable threshold and reshare fields,
/// seeding RingIndex so validate_reshare_session_init can locate the ring.
async fn post_ring_for_validation(
    app_state: &crate::app_state::AppState<crypto::DkgImpl>,
    bulletin: &DummyBulletin,
    ring_pk: &str,
    peer_node_keys: Vec<String>,
    threshold: u32,
    new_peer_node_keys: Option<Vec<String>>,
    new_threshold: Option<u32>,
) {
    use local_storage::r#trait::LocalStorageKeys;

    let payload = RingPayload {
        upgrade_info: Default::default(),
        ring_pk: ring_pk.to_string(),
        peer_node_keys,
        new_peer_node_keys,
        new_threshold,
        threshold,
        pss_interval: 86400,
        block_number_nonce: 0,
        policy_id: None,
        reporting: Default::default(),
    };
    let post_id = format!("test-validation-{ring_pk}");
    bulletin
        .set_ring(post_id.clone(), payload)
        .expect("seed ring fixture");
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
        indexed_at_secs: 0,
    });
    app_state
        .local_storage
        .set(
            LocalStorageKeys::RingIndex,
            serde_json::to_vec(&ring_index).unwrap(),
        )
        .unwrap();
}

/// When `new_peer_node_keys` is absent and proposed committee equals current `peer_ids`,
/// validation must succeed (fallback = keep current committee).
#[tokio::test]
async fn test_validate_reshare_accepts_new_peer_node_keys_fallback_to_current() {
    use crate::dkg::v0::helpers::validate_reshare_session_init_for_version;

    let db_name = "validate_reshare_fallback_accepts_peers";
    let db_path = test_db_path(db_name);
    let dummy_bulletin = Arc::new(
        DummyBulletin::new()
            .await
            .expect("Failed to initialize dummy bulletin"),
    );
    let app_state =
        create_test_app_state_with_bulletin(true, dummy_bulletin.clone(), db_name).await;

    let ring_pk = "fallback_peers_ring";
    let sender_hex = "aabbccdd";

    // Only new_threshold is announced; new_peer_node_keys absent → fallback = peer_ids.
    post_ring_for_validation(
        &app_state,
        &dummy_bulletin,
        ring_pk,
        vec![sender_hex.to_string()],
        1,
        None, // absent → fallback = peer_ids = [sender_hex]
        Some(1),
    )
    .await;

    let result = validate_reshare_session_init_for_version(
        ring_pk,
        &[sender_hex.to_string()], // matches fallback = peer_ids
        1,
        "",
        &app_state.local_storage,
        &app_state.bulletin,
        network::V0.version,
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
    use crate::dkg::v0::helpers::validate_reshare_session_init_for_version;

    let db_name = "validate_reshare_fallback_accepts_threshold";
    let db_path = test_db_path(db_name);
    let dummy_bulletin = Arc::new(
        DummyBulletin::new()
            .await
            .expect("Failed to initialize dummy bulletin"),
    );
    let app_state =
        create_test_app_state_with_bulletin(true, dummy_bulletin.clone(), db_name).await;

    let ring_pk = "fallback_threshold_ring";
    let sender_hex = "aabbccdd";
    let new_peer = "00112233";

    // Only new_peer_node_keys is announced; new_threshold absent → fallback = threshold = 1.
    post_ring_for_validation(
        &app_state,
        &dummy_bulletin,
        ring_pk,
        vec![sender_hex.to_string()],
        1, // current threshold
        Some(vec![new_peer.to_string()]),
        None, // absent → fallback = 1
    )
    .await;

    let result = validate_reshare_session_init_for_version(
        ring_pk,
        &[new_peer.to_string()],
        1, // matches fallback = current threshold
        "",
        &app_state.local_storage,
        &app_state.bulletin,
        network::V0.version,
    )
    .await;
    assert!(
        result.is_ok(),
        "Expected Ok when proposed threshold matches current threshold (fallback): {:?}",
        result
    );
    cleanup_db(&db_path);
}

/// When `new_peer_node_keys` is absent and proposed committee differs from current `peer_ids`,
/// validation must reject — absent does not mean "accept any committee".
#[tokio::test]
async fn test_validate_reshare_rejects_when_peers_differ_from_fallback() {
    use crate::dkg::v0::helpers::validate_reshare_session_init_for_version;

    let db_name = "validate_reshare_fallback_rejects_peers";
    let db_path = test_db_path(db_name);
    let dummy_bulletin = Arc::new(
        DummyBulletin::new()
            .await
            .expect("Failed to initialize dummy bulletin"),
    );
    let app_state =
        create_test_app_state_with_bulletin(true, dummy_bulletin.clone(), db_name).await;

    let ring_pk = "fallback_reject_peers_ring";
    let sender_hex = "aabbccdd";

    // new_peer_node_keys absent → fallback = peer_ids = ["aabbccdd"].
    post_ring_for_validation(
        &app_state,
        &dummy_bulletin,
        ring_pk,
        vec![sender_hex.to_string()],
        1,
        None,
        Some(1),
    )
    .await;

    let result = validate_reshare_session_init_for_version(
        ring_pk,
        &["00112233".to_string()], // differs from fallback = ["aabbccdd"]
        1,
        "",
        &app_state.local_storage,
        &app_state.bulletin,
        network::V0.version,
    )
    .await;
    assert!(
        matches!(result, Err(DkgError::Unauthorized(_))),
        "Expected Unauthorized when proposed peers differ from fallback: {:?}",
        result
    );
    cleanup_db(&db_path);
}

/// When `new_threshold` is absent and proposed threshold differs from current `threshold`,
/// validation must reject — absent does not mean "accept any threshold".
#[tokio::test]
async fn test_validate_reshare_rejects_when_threshold_differs_from_fallback() {
    use crate::dkg::v0::helpers::validate_reshare_session_init_for_version;

    let db_name = "validate_reshare_fallback_rejects_threshold";
    let db_path = test_db_path(db_name);
    let dummy_bulletin = Arc::new(
        DummyBulletin::new()
            .await
            .expect("Failed to initialize dummy bulletin"),
    );
    let app_state =
        create_test_app_state_with_bulletin(true, dummy_bulletin.clone(), db_name).await;

    let ring_pk = "fallback_reject_threshold_ring";
    let sender_hex = "aabbccdd";
    let new_peer_1 = "00112233";
    let new_peer_2 = "11223344";

    // new_threshold absent → fallback = threshold = 2.
    post_ring_for_validation(
        &app_state,
        &dummy_bulletin,
        ring_pk,
        vec![sender_hex.to_string()],
        2,                                                          // current threshold
        Some(vec![new_peer_1.to_string(), new_peer_2.to_string()]), // 2 members, valid for t=2
        None,                                                       // absent → fallback = 2
    )
    .await;

    let result = validate_reshare_session_init_for_version(
        ring_pk,
        &[new_peer_1.to_string(), new_peer_2.to_string()],
        1, // differs from fallback = 2
        "",
        &app_state.local_storage,
        &app_state.bulletin,
        network::V0.version,
    )
    .await;
    assert!(
        matches!(result, Err(DkgError::Unauthorized(_))),
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
    let bulletin_for_seed = bulletin.clone();
    let state = create_test_app_state_with_bulletin(true, bulletin, db_suffix).await;

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
    bulletin_for_seed
        .set_node_info(
            state.node_key.clone(),
            NodeInfo {
                peer_id: address_with_port.clone(),
                controller_key: "test-controller-key".to_string(),
                whitelisted_policy_ids: vec!["test-policy".to_string()],
                whitelisted_ring_ids: vec![TEST_FRESH_DKG_RING_ID.to_string()],
            },
        )
        .expect("seed extra node routed NodeInfo");

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
    old_peer_node_keys: &[String],
    old_threshold: u32,
    key_string: &str,
    sorted_new_peer_node_keys: &[String],
    new_threshold: u32,
    bulletin: &DummyBulletin,
) -> String {
    let payload = RingPayload {
        upgrade_info: Default::default(),
        ring_pk: key_string.to_string(),
        peer_node_keys: old_peer_node_keys.to_vec(),
        threshold: old_threshold,
        new_peer_node_keys: Some(sorted_new_peer_node_keys.to_vec()),
        new_threshold: Some(new_threshold),
        pss_interval: 86400,
        block_number_nonce: 0,
        policy_id: Some("test-policy".to_string()),
        reporting: Default::default(),
    };
    bulletin
        .set_ring(format!("test-reshare-announcement-{key_string}"), payload)
        .expect("seed reshare announcement");
    let new_post_id = format!("test-reshare-announcement-{key_string}");

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

/// Drive a full reshare ceremony through the production three-plane transport,
/// then poll until every new-committee node has installed its new bundle.
async fn run_reshare_ceremony(
    old_committee_states: &[&crate::app_state::AppState<DkgImpl>],
    old_peer_node_keys: &[String],
    key_string: &str,
    sorted_new_peer_node_keys: &[String],
    new_threshold: u32,
    bulletin_post_id: &str,
    new_committee_states: &[&crate::app_state::AppState<DkgImpl>],
) {
    let leader_key = canonical_leader(sorted_new_peer_node_keys)
        .expect("new committee has a canonical transport leader");
    assert!(
        new_committee_states
            .iter()
            .any(|state| state.node_key == leader_key),
        "canonical next-committee transport leader is present in the test network"
    );
    let initiator_state = old_committee_states
        .iter()
        .copied()
        .find(|old| {
            new_committee_states
                .iter()
                .any(|new| new.node_key == old.node_key)
        })
        .or_else(|| old_committee_states.first().copied())
        .expect("reshare test has at least one current member to forward start");

    let session_id = derive_reshare_session_id(
        key_string,
        bulletin_post_id,
        old_peer_node_keys,
        sorted_new_peer_node_keys,
        new_threshold,
    )
    .unwrap();

    // Snapshot share bytes before reshare so we can detect when they change.
    let pre_snapshots: Vec<Option<zeroize::Zeroizing<Vec<u8>>>> = new_committee_states
        .iter()
        .map(|s| {
            RingShareBundle::load_by_ring_key(&s.local_storage, key_string)
                .ok()
                .map(|b| b.share_bytes.clone())
        })
        .collect();

    let secondary_state = old_committee_states
        .iter()
        .copied()
        .find(|state| state.node_key != initiator_state.node_key)
        .expect("reshare convergence test has two live current members");
    let first_start = start_reshare(
        Arc::new(initiator_state.clone()),
        &::network::V0,
        bulletin_post_id.to_string(),
        key_string.to_string(),
    );
    let second_start = start_reshare(
        Arc::new(secondary_state.clone()),
        &::network::V0,
        bulletin_post_id.to_string(),
        key_string.to_string(),
    );
    let (first_outcome, second_outcome) = tokio::join!(first_start, second_start);
    let first_outcome = first_outcome.expect("first current member starts reshare");
    let second_outcome = second_outcome.expect("second current member starts reshare");
    let outcome_ids = |outcome| match outcome {
        ReshareStartOutcome::Started(ceremony, attempt)
        | ReshareStartOutcome::Forwarded(ceremony, attempt)
        | ReshareStartOutcome::AlreadyActive(ceremony, attempt) => (ceremony, attempt),
    };
    let (first_ceremony, first_attempt) = outcome_ids(first_outcome);
    let (second_ceremony, second_attempt) = outcome_ids(second_outcome);
    assert_eq!(first_ceremony.0, session_id);
    assert_eq!(second_ceremony, first_ceremony);
    assert_eq!(
        second_attempt, first_attempt,
        "concurrent current-member forwards must converge on the one attempt created by the next leader"
    );

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
        if start.elapsed() >= max_wait {
            let mut statuses = Vec::new();
            for state in new_committee_states {
                let status = state
                    .dkg_session_state
                    .with_state(&session_id, |session| {
                        format!(
                            "node={} role={:?} phase={:?} commitments_received={} pending_shares={:?} valid_dealers={:?} share_acks={:?} selected={:?} shares_received={}",
                            state.node_key.chars().take(12).collect::<String>(),
                            session.node.role(),
                            session.phase,
                            session.commitments_received,
                            session
                                .pending
                                .pending_shares_waiting_for_commitment
                                .keys()
                                .copied()
                                .collect::<Vec<_>>(),
                            session.reshare.valid_share_dealers,
                            session.reshare.share_acks,
                            session.reshare.selected_dealers,
                            session.shares_received,
                        )
                    })
                    .await
                    .unwrap_or_else(|| {
                        format!(
                            "node={} session=missing",
                            state.node_key.chars().take(12).collect::<String>()
                        )
                    });
                statuses.push(status);
            }
            for state in old_committee_states {
                let status = state
                    .dkg_session_state
                    .with_state(&session_id, |session| {
                        format!(
                            "dealer={} role={:?} phase={:?} cached_private={} acked_private={}",
                            state.node_key.chars().take(12).collect::<String>(),
                            session.node.role(),
                            session.phase,
                            session.transport.outbound_private_messages.len(),
                            session.transport.acknowledged_private_messages.len(),
                        )
                    })
                    .await
                    .unwrap_or_else(|| {
                        format!(
                            "dealer={} session=missing",
                            state.node_key.chars().take(12).collect::<String>()
                        )
                    });
                statuses.push(status);
            }
            panic!(
                "Reshare ceremony did not complete within 60 s: {}",
                statuses.join("; ")
            );
        }
        sleep(Duration::from_millis(500)).await;
    }

    // The reshare is not complete until the designated new-committee node 1
    // posts the final bulletin update and clears the pending reshare fields.
    let start = Instant::now();
    loop {
        let post = initiator_state
            .bulletin
            .read(bulletin_post_id.to_string(), BulletinKind::Ring)
            .await
            .expect("read reshare bulletin post");
        let payload: RingPayload =
            serde_json::from_slice(&post.payload).expect("parse reshare RingPayload");

        let mut actual_peer_ids = payload.peer_node_keys.clone();
        actual_peer_ids.sort();
        let mut expected_peer_ids = sorted_new_peer_node_keys.to_vec();
        expected_peer_ids.sort();

        if payload.new_peer_node_keys.is_none()
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
    let old_peer_node_keys = vec![
        network.alice.app_state.node_key.clone(),
        network.bob.app_state.node_key.clone(),
        network.charlie.app_state.node_key.clone(),
    ];
    let dummy_bulletin = network.dummy_bulletin.as_ref().unwrap().clone();

    // Phase A: initial DKG (t=2, n=3).
    let alice_service =
        DkgServiceImpl::<DkgImpl>::with_routes(network.alice.app_state.clone(), &network::V0);
    let test_keys = TestKeyPair::new();
    let token = test_keys
        .create_dkg_jwt(TEST_FRESH_DKG_RING_ID)
        .expect("JWT");
    alice_service
        .start_dkg(
            create_authenticated_request(
                StartDkgRequest {
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
    let mut sorted_new = old_peer_node_keys.clone();
    sorted_new.sort();
    let old_node_states: Vec<&crate::app_state::AppState<DkgImpl>> = vec![
        &network.alice.app_state,
        &network.bob.app_state,
        &network.charlie.app_state,
    ];
    let announcement_post_id = post_reshare_announcement(
        &old_node_states,
        &old_peer_node_keys,
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
        &old_node_states,
        &old_peer_node_keys,
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
    let old_peer_node_keys = vec![
        network.alice.app_state.node_key.clone(),
        network.bob.app_state.node_key.clone(),
        network.charlie.app_state.node_key.clone(),
    ];

    // Extra node D joins the new committee.
    let mut dave = create_extra_test_node(&format!("{}_4", db_name), dummy_bulletin.clone()).await;

    // Phase A: DKG with A, B, C (t=2).
    let alice_service =
        DkgServiceImpl::<DkgImpl>::with_routes(network.alice.app_state.clone(), &network::V0);
    let test_keys = TestKeyPair::new();
    let token = test_keys
        .create_dkg_jwt(TEST_FRESH_DKG_RING_ID)
        .expect("JWT");
    alice_service
        .start_dkg(
            create_authenticated_request(
                StartDkgRequest {
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
        network.alice.app_state.node_key.clone(),
        network.bob.app_state.node_key.clone(),
        dave.app_state.node_key.clone(),
    ];
    sorted_new.sort();

    let old_node_states: Vec<&crate::app_state::AppState<DkgImpl>> = vec![
        &network.alice.app_state,
        &network.bob.app_state,
        &network.charlie.app_state,
    ];
    let announcement_post_id = post_reshare_announcement(
        &old_node_states,
        &old_peer_node_keys,
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
    let mut union_peer_ids = peer_ids.clone();
    if !union_peer_ids.contains(&dave.address) {
        union_peer_ids.push(dave.address.clone());
    }

    run_reshare_ceremony(
        &old_node_states,
        &old_peer_node_keys,
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
    let old_peer_node_keys = vec![
        network.alice.app_state.node_key.clone(),
        network.bob.app_state.node_key.clone(),
        network.charlie.app_state.node_key.clone(),
    ];
    let mut dave = create_extra_test_node(&format!("{}_4", db_name), dummy_bulletin.clone()).await;

    // Phase A: DKG with A, B, C (t=2).
    let alice_service =
        DkgServiceImpl::<DkgImpl>::with_routes(network.alice.app_state.clone(), &network::V0);
    let test_keys = TestKeyPair::new();
    let token = test_keys
        .create_dkg_jwt(TEST_FRESH_DKG_RING_ID)
        .expect("JWT");
    alice_service
        .start_dkg(
            create_authenticated_request(
                StartDkgRequest {
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

    // Phase B: retain two old members and add D while taking the canonical old
    // dealer offline. Reshare leadership belongs to the next committee, so no
    // particular old dealer is required while the old threshold remains.
    let leader_key =
        canonical_leader(&old_peer_node_keys).expect("old committee has a canonical dealer");
    let offline_index = old_peer_node_keys
        .iter()
        .position(|node_key| node_key == leader_key)
        .expect("canonical old dealer is present");
    let mut sorted_new = old_peer_node_keys
        .iter()
        .enumerate()
        .filter(|(index, _)| *index != offline_index)
        .map(|(_, node_key)| node_key.clone())
        .chain(std::iter::once(dave.app_state.node_key.clone()))
        .collect::<Vec<_>>();
    sorted_new.sort();

    let old_node_states: Vec<&crate::app_state::AppState<DkgImpl>> = vec![
        &network.alice.app_state,
        &network.bob.app_state,
        &network.charlie.app_state,
    ];
    let announcement_post_id = post_reshare_announcement(
        &old_node_states,
        &old_peer_node_keys,
        2,
        &key_string,
        &sorted_new,
        2,
        &dummy_bulletin,
    )
    .await;

    let offline_router = match offline_index {
        0 => network.alice.router.take(),
        1 => network.bob.router.take(),
        2 => network.charlie.router.take(),
        _ => unreachable!("old committee has exactly three members"),
    };
    if let Some(router) = offline_router {
        router
            .shutdown()
            .await
            .expect("shutdown offline old dealer");
    }

    let new_committee_states: Vec<&crate::app_state::AppState<DkgImpl>> = old_node_states
        .iter()
        .enumerate()
        .filter(|(index, _)| *index != offline_index)
        .map(|(_, state)| *state)
        .chain(std::iter::once(&dave.app_state))
        .collect();
    let live_old_node_states: Vec<&crate::app_state::AppState<DkgImpl>> = old_node_states
        .iter()
        .enumerate()
        .filter(|(index, _)| *index != offline_index)
        .map(|(_, state)| *state)
        .collect();

    run_reshare_ceremony(
        &live_old_node_states,
        &old_peer_node_keys,
        &key_string,
        &sorted_new,
        2,
        &announcement_post_id,
        &new_committee_states,
    )
    .await;

    let verification_states = new_committee_states
        .iter()
        .enumerate()
        .map(|(index, state)| (if index == 2 { "dave" } else { "retained" }, *state))
        .collect::<Vec<_>>();
    verify_reshare_pk_preserved(&verification_states, &key_string, &original_pk_bytes);

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
    let old_peer_node_keys = vec![
        network.alice.app_state.node_key.clone(),
        network.bob.app_state.node_key.clone(),
        network.charlie.app_state.node_key.clone(),
    ];

    let mut dave = create_extra_test_node(&format!("{}_4", db_name), dummy_bulletin.clone()).await;

    // Phase A: DKG with A, B, C (t=2).
    let alice_service =
        DkgServiceImpl::<DkgImpl>::with_routes(network.alice.app_state.clone(), &network::V0);
    let test_keys = TestKeyPair::new();
    let token = test_keys
        .create_dkg_jwt(TEST_FRESH_DKG_RING_ID)
        .expect("JWT");
    alice_service
        .start_dkg(
            create_authenticated_request(
                StartDkgRequest {
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
        network.alice.app_state.node_key.clone(),
        network.bob.app_state.node_key.clone(),
        network.charlie.app_state.node_key.clone(),
        dave.app_state.node_key.clone(),
    ];
    sorted_new.sort();

    let mut union_peers = peer_ids.clone();
    for p in [&dave.address] {
        if !union_peers.contains(p) {
            union_peers.push((*p).clone());
        }
    }

    let old_node_states: Vec<&crate::app_state::AppState<DkgImpl>> = vec![
        &network.alice.app_state,
        &network.bob.app_state,
        &network.charlie.app_state,
    ];
    let announcement_post_id = post_reshare_announcement(
        &old_node_states,
        &old_peer_node_keys,
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
        &old_node_states,
        &old_peer_node_keys,
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
    let old_peer_node_keys = vec![
        network.alice.app_state.node_key.clone(),
        network.bob.app_state.node_key.clone(),
        network.charlie.app_state.node_key.clone(),
    ];

    // Phase A: DKG with A, B, C (t=2).
    let alice_service =
        DkgServiceImpl::<DkgImpl>::with_routes(network.alice.app_state.clone(), &network::V0);
    let test_keys = TestKeyPair::new();
    let token = test_keys
        .create_dkg_jwt(TEST_FRESH_DKG_RING_ID)
        .expect("JWT");
    alice_service
        .start_dkg(
            create_authenticated_request(
                StartDkgRequest {
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
    let mut sorted_new = vec![
        network.alice.app_state.node_key.clone(),
        network.bob.app_state.node_key.clone(),
    ];
    sorted_new.sort();

    // New committee ⊆ old: union == old.
    let old_node_states: Vec<&crate::app_state::AppState<DkgImpl>> = vec![
        &network.alice.app_state,
        &network.bob.app_state,
        &network.charlie.app_state,
    ];
    let announcement_post_id = post_reshare_announcement(
        &old_node_states,
        &old_peer_node_keys,
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
        &old_node_states,
        &old_peer_node_keys,
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
    let old_peer_node_keys = vec![
        network.alice.app_state.node_key.clone(),
        network.bob.app_state.node_key.clone(),
        network.charlie.app_state.node_key.clone(),
    ];

    // Three extra Receiver nodes that will form the new committee.
    let mut dave = create_extra_test_node(&format!("{}_4", db_name), dummy_bulletin.clone()).await;
    let mut eve = create_extra_test_node(&format!("{}_5", db_name), dummy_bulletin.clone()).await;
    let mut frank = create_extra_test_node(&format!("{}_6", db_name), dummy_bulletin.clone()).await;

    // Phase A: DKG with A, B, C (t=2).
    let alice_service =
        DkgServiceImpl::<DkgImpl>::with_routes(network.alice.app_state.clone(), &network::V0);
    let test_keys = TestKeyPair::new();
    let token = test_keys
        .create_dkg_jwt(TEST_FRESH_DKG_RING_ID)
        .expect("JWT");
    alice_service
        .start_dkg(
            create_authenticated_request(
                StartDkgRequest {
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
        dave.app_state.node_key.clone(),
        eve.app_state.node_key.clone(),
        frank.app_state.node_key.clone(),
    ];
    sorted_new.sort();

    let mut union_peers = peer_ids.clone();
    for p in [&dave.address, &eve.address, &frank.address] {
        if !union_peers.contains(p) {
            union_peers.push((*p).clone());
        }
    }

    let old_node_states: Vec<&crate::app_state::AppState<DkgImpl>> = vec![
        &network.alice.app_state,
        &network.bob.app_state,
        &network.charlie.app_state,
    ];
    let announcement_post_id = post_reshare_announcement(
        &old_node_states,
        &old_peer_node_keys,
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
        &old_node_states,
        &old_peer_node_keys,
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
