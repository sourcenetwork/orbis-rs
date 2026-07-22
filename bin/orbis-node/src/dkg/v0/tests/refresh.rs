use crate::dkg::v0::service::DkgServiceImpl;
use crate::dkg::v0::{
    coordinator::DkgCoordinator,
    helpers::{derive_refresh_session_id, serialize_commitment_coefficients},
    messages::{DkgMessage, SessionKind},
};
use crate::helpers::test_helpers::TEST_FRESH_DKG_RING_ID;
use crate::helpers::test_helpers::{
    cleanup_db, create_authenticated_request, create_test_app_state_default,
    create_test_app_state_with_bulletin, get_test_ring_post, setup_three_node_network,
    test_db_path, write_ring_to_bulletin, TestKeyPair,
};
use crate::ring_state::RingPolyState;
use bulletin::dummy::DummyBulletin;
use bulletin::r#trait::{NodeInfo, RingPayload};
use crypto::r#trait::{CryptoDeserialize, Dkg, DkgMode, DkgRole, PubPoly as PubPolyTrait};
use crypto::CryptoSerialize;
use local_storage::r#trait::{LocalStorage, LocalStorageKeys};
use network::PeerId;
use proto::v0::dkg::{dkg_service_server::DkgService, StartDkgRequest};
use std::sync::Arc;
use std::time::Instant;
use tokio::time::{sleep, Duration};
use tracing_subscriber;

// Concrete crypto implementation for tests (selected via crypto crate features)
use crypto::DkgImpl;

// ============================================================================
// PSS Refresh Integration Test
// ============================================================================

/// Test: Full DKG followed by a PSS refresh ceremony.
///
/// This test verifies the complete share-rotation lifecycle:
/// 1. Three nodes run a DKG to establish a shared secret.
/// 2. The initiator (smallest sorted peer ID) triggers a PSS refresh.
/// 3. All nodes complete the refresh protocol using `DkgMode::Refresh`
///    (zero constant term — same secret, new share values).
/// 4. Each node's stored share is different after the refresh, confirming
///    that share rotation happened while preserving the distributed secret.
///
/// Detection of completion: the DummyBulletin will have a second ring entry
/// (posted by the refresh's Phase 4), one per ceremony.
#[tokio::test]
#[serial_test::serial]
async fn test_dkg_followed_by_pss_refresh() {
    run_dkg_followed_by_pss_refresh("test_dkg_followed_by_pss_refresh", false).await;
}

/// The complete refresh ceremony converges when its public batches are lost
/// and the first private pair streams are reset. Faults are injected below the
/// protocol through `FaultNetwork`, so this exercises production repair logic.
#[cfg(feature = "fault-injection")]
#[tokio::test]
#[serial_test::serial]
async fn test_pss_refresh_repairs_gossip_loss_and_private_disconnects() {
    run_dkg_followed_by_pss_refresh("test_pss_refresh_hybrid_repair", true).await;
}

async fn run_dkg_followed_by_pss_refresh(db_name: &str, inject_hybrid_faults: bool) {
    let db_paths = [
        test_db_path(&format!("{}_1", db_name)),
        test_db_path(&format!("{}_2", db_name)),
        test_db_path(&format!("{}_3", db_name)),
    ];

    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_test_writer()
        .try_init();

    let mut network = setup_three_node_network(!inject_hybrid_faults, db_name).await;

    #[cfg(feature = "fault-injection")]
    let fault_controllers = if inject_hybrid_faults {
        let mut controllers = Vec::with_capacity(3);
        for node in [&mut network.alice, &mut network.bob, &mut network.charlie] {
            let (fault_network, controller) =
                network::FaultNetwork::new(node.app_state.network.clone());
            node.app_state.network = Arc::new(fault_network);
            controllers.push(controller);
        }
        for node in [&mut network.alice, &mut network.bob, &mut network.charlie] {
            node.router = Some(
                crate::helpers::create_routers::create_router_with_all_handlers::<
                    DkgImpl,
                    crypto::PreImpl,
                    crypto::SignImpl,
                >(&node.app_state.network, Arc::new(node.app_state.clone()))
                .expect("start faultable refresh test router"),
            );
        }
        controllers
    } else {
        Vec::new()
    };

    #[cfg(not(feature = "fault-injection"))]
    assert!(
        !inject_hybrid_faults,
        "hybrid fault injection requires the fault-injection feature"
    );

    let peer_node_keys = vec![
        network.alice.app_state.node_key.clone(),
        network.bob.app_state.node_key.clone(),
        network.charlie.app_state.node_key.clone(),
    ];

    // ── Phase A: Run the initial DKG ──────────────────────────────────────────
    let alice_service =
        DkgServiceImpl::<DkgImpl>::with_routes(network.alice.app_state.clone(), &network::V0);
    let test_keys = TestKeyPair::new();
    let token = test_keys
        .create_dkg_jwt(TEST_FRESH_DKG_RING_ID)
        .expect("create JWT");
    let tonic_req = create_authenticated_request(
        StartDkgRequest {
            ring_id: TEST_FRESH_DKG_RING_ID.to_string(),
        },
        &token,
    )
    .unwrap();
    alice_service
        .start_dkg(tonic_req)
        .await
        .expect("DKG should start");

    // Wait for DKG Phase 4 to complete (bulletin has a ring entry).
    let (key_string, ring_pk_hex) = {
        let start = Instant::now();
        let max_wait = Duration::from_secs(60);
        loop {
            let dummy_bulletin = network.dummy_bulletin.as_ref().unwrap();
            let post = get_test_ring_post(dummy_bulletin);
            if !post.payload.is_empty() {
                let ring_payload: RingPayload = post.try_into().expect("parse RingPayload");
                println!("DKG complete. ring_pk={}", ring_payload.ring_pk);
                let ring_pk_bytes = hex::decode(&ring_payload.ring_pk).expect("decode ring_pk hex");
                let agg_key = <DkgImpl as Dkg>::PublicKey::from_bytes(&ring_pk_bytes)
                    .expect("deserialize aggregate PK");
                break (agg_key.to_string(), ring_payload.ring_pk);
            }
            assert!(start.elapsed() < max_wait, "DKG did not complete in time");
            sleep(Duration::from_millis(500)).await;
        }
    };

    // Snapshot each node's share immediately after DKG.
    let share_before_alice = network
        .alice
        .app_state
        .local_storage
        .get_encrypted(LocalStorageKeys::RingKey(key_string.clone()))
        .expect("read alice share")
        .expect("alice share must exist after DKG");
    let share_before_bob = network
        .bob
        .app_state
        .local_storage
        .get_encrypted(LocalStorageKeys::RingKey(key_string.clone()))
        .expect("read bob share")
        .expect("bob share must exist after DKG");
    let share_before_charlie = network
        .charlie
        .app_state
        .local_storage
        .get_encrypted(LocalStorageKeys::RingKey(key_string.clone()))
        .expect("read charlie share")
        .expect("charlie share must exist after DKG");

    // Backdate last_pss in each node's RingShareBundle so the time-elapsed
    // check passes immediately.  We load the real bundle (written by DKG Phase 4),
    // reset last_pss to epoch, and write it back.
    for state in [
        &network.alice.app_state,
        &network.bob.app_state,
        &network.charlie.app_state,
    ] {
        let mut bundle =
            crate::ring_state::RingShareBundle::load_by_ring_key(&state.local_storage, &key_string)
                .expect("load RingShareBundle for backdate");
        bundle.last_pss = 0;
        bundle
            .save_by_ring_key(&state.local_storage, &key_string)
            .expect("save backdated RingShareBundle");
    }

    // ── Phase B: Set up and run a PSS refresh ─────────────────────────────────

    let mut sorted_node_keys = peer_node_keys.clone();
    sorted_node_keys.sort();
    let initiator_node_key = sorted_node_keys[0].clone();
    let initiator_state = if network.alice.app_state.node_key == initiator_node_key {
        network.alice.app_state.clone()
    } else if network.bob.app_state.node_key == initiator_node_key {
        network.bob.app_state.clone()
    } else {
        network.charlie.app_state.clone()
    };

    #[cfg(feature = "fault-injection")]
    for controller in &fault_controllers {
        controller.drop_gossip_broadcasts_after(0, 1).await;
        controller.drop_gossip_deliveries_after(1, 4).await;
        controller.inject_gossip_neighbor_flaps(2).await;
        controller
            .fail_protocol_responses_after(network::V0.dkg_control_alpn, 0, 1)
            .await;
        controller
            .fail_protocol_streams_after(network::V0.dkg_private_alpn, 0, 1)
            .await;
    }

    let (refresh_ceremony, refresh_attempt) = crate::dkg::v0::hybrid::start_refresh(
        Arc::new(initiator_state),
        &::network::V0,
        TEST_FRESH_DKG_RING_ID.to_string(),
        key_string.clone(),
    )
    .await
    .expect("canonical leader should start hybrid refresh");

    println!(
        "Hybrid PSS refresh initiated (session_id={}, attempt_id={})",
        refresh_ceremony.0,
        hex::encode(refresh_attempt.0)
    );

    // ── Phase C: Wait for refresh to complete ─────────────────────────────────
    // Poll RingPolyState on all three nodes until each has last_pss > 0,
    // which is set atomically with the updated private share in Phase 4.
    {
        let start = Instant::now();
        let max_wait = Duration::from_secs(60);
        loop {
            let all_done = [
                &network.alice.app_state.local_storage,
                &network.bob.app_state.local_storage,
                &network.charlie.app_state.local_storage,
            ]
            .iter()
            .all(|storage| {
                RingPolyState::load_from_ring_pk_hex(*storage, &ring_pk_hex)
                    .map(|s| s.last_pss > 0)
                    .unwrap_or(false)
            });
            if all_done {
                println!("Refresh complete (all 3 nodes updated RingPolyState)");
                break;
            }
            assert!(
                start.elapsed() < max_wait,
                "PSS refresh did not complete within {} seconds",
                max_wait.as_secs()
            );
            sleep(Duration::from_millis(500)).await;
        }
    }

    // ── Phase D: Verify shares were rotated ───────────────────────────────────
    let share_after_alice = network
        .alice
        .app_state
        .local_storage
        .get_encrypted(LocalStorageKeys::RingKey(key_string.clone()))
        .expect("read alice share after refresh")
        .expect("alice share must exist after refresh");
    let share_after_bob = network
        .bob
        .app_state
        .local_storage
        .get_encrypted(LocalStorageKeys::RingKey(key_string.clone()))
        .expect("read bob share after refresh")
        .expect("bob share must exist after refresh");
    let share_after_charlie = network
        .charlie
        .app_state
        .local_storage
        .get_encrypted(LocalStorageKeys::RingKey(key_string.clone()))
        .expect("read charlie share after refresh")
        .expect("charlie share must exist after refresh");

    assert_ne!(
        share_before_alice, share_after_alice,
        "Alice's share should have been rotated by the refresh"
    );
    assert_ne!(
        share_before_bob, share_after_bob,
        "Bob's share should have been rotated by the refresh"
    );
    assert_ne!(
        share_before_charlie, share_after_charlie,
        "Charlie's share should have been rotated by the refresh"
    );

    // ── Phase E: Verify the underlying secret was preserved ───────────────────
    // PSS refresh uses DkgMode::Refresh (zero constant term on each delta poly),
    // so the combined polynomial's constant term P(0) must equal the original
    // aggregate public key. We deserialize each node's stored public polynomial,
    // evaluate at 0, and compare with ring_pk_hex captured from the bulletin
    // immediately after the initial DKG.
    {
        let original_pk_bytes = hex::decode(&ring_pk_hex).expect("decode original ring_pk_hex");

        for (label, storage) in [
            ("alice", &network.alice.app_state.local_storage),
            ("bob", &network.bob.app_state.local_storage),
            ("charlie", &network.charlie.app_state.local_storage),
        ] {
            let bundle = crate::ring_state::RingShareBundle::load_by_ring_key(storage, &key_string)
                .unwrap_or_else(|e| panic!("{label}: load post-refresh bundle: {e}"));
            let poly_bytes = hex::decode(&bundle.public_polynomial)
                .unwrap_or_else(|e| panic!("{label}: decode public_polynomial hex: {e}"));
            let pub_poly = <DkgImpl as Dkg>::PubPoly::from_bytes(&poly_bytes)
                .unwrap_or_else(|e| panic!("{label}: deserialize PubPoly: {e}"));

            let recovered_pk_bytes = CryptoSerialize::to_bytes(&pub_poly.eval(0))
                .unwrap_or_else(|e| panic!("{label}: serialize P(0): {e}"));

            assert_eq!(
                recovered_pk_bytes, original_pk_bytes,
                "{label}: P(0) of post-refresh polynomial must equal the original aggregate public key"
            );
        }
    }

    network.shutdown_routers().await.expect("shutdown routers");
    for path in &db_paths {
        cleanup_db(path);
    }
}

/// Verify that a Share arriving just before the sender's Phase 1 commitment is
/// retried once the commitment lands.  This covers scheduler-driven PSS refreshes
/// where independent peer streams can briefly reorder commitment/share delivery.
#[tokio::test]
async fn test_share_before_commitment_waits_for_commitment() {
    let db_name = "test_share_before_commitment_waits";
    let db_path = test_db_path(db_name);
    let app_state = Arc::new(create_test_app_state_default(db_name).await);
    let coordinator = DkgCoordinator::with_routes(app_state.clone(), &::network::V0);

    let session_id: u128 = 77_777;
    coordinator
        .create_session(session_id, 1, 2, 3, DkgRole::Standard, |_| {})
        .await
        .expect("create session");

    let sender_hex = "deadbeef";
    let third_hex = "feedface";
    let all_peer_ids = vec![
        "aabbccdd".to_string(),
        sender_hex.to_string(),
        third_hex.to_string(),
    ];
    coordinator.set_peer_ids(&session_id, all_peer_ids).await;
    let mut node_peer_map = std::collections::HashMap::new();
    node_peer_map.insert(1u32, "aabbccdd".to_string());
    node_peer_map.insert(2u32, sender_hex.to_string());
    node_peer_map.insert(3u32, third_hex.to_string());
    app_state
        .dkg_session_state
        .set_node_peer_mappings(&session_id, node_peer_map)
        .await;

    coordinator
        .initiate_phase0_commitment_hashes(session_id, &[])
        .await
        .expect("phase 0 with no peers");

    let mut sender_node =
        *DkgImpl::new(2, 2, 3, session_id, DkgRole::Standard).expect("create sender node");
    sender_node
        .generate_polynomial(DkgMode::Fresh)
        .expect("sender polynomial");
    let commitment = serialize_commitment_coefficients(&sender_node.commitment().coefficients)
        .expect("serialize sender commitment");
    let commitment_hash =
        crate::dkg::v0::helpers::fresh_commitment_hash(session_id, 2, &commitment);
    let share = sender_node
        .generate_shares()
        .expect("sender shares")
        .into_iter()
        .find(|share| share.to_id == 1)
        .expect("share for node 1");
    let share_value = CryptoSerialize::to_bytes(&share.value).expect("serialize share");

    let share_msg = DkgMessage::Share {
        session_id,
        from_node_id: 2,
        to_node_id: 1,
        share_value,
        nonce: share.nonce,
        report_evidence: None,
    };
    let hash_msg = DkgMessage::CommitmentHash {
        session_id,
        from_node_id: 2,
        commitment_hash,
    };
    let commitment_msg = DkgMessage::Commitment {
        session_id,
        from_node_id: 2,
        commitment,
        report_evidence: None,
    };
    let sender_bytes = hex::decode(sender_hex).unwrap();
    let sender_peer_id = PeerId::from_bytes(&sender_bytes);

    coordinator
        .handle_message(hash_msg, &sender_peer_id)
        .await
        .expect("commitment hash should be accepted");

    let share_coordinator = DkgCoordinator::with_routes(app_state.clone(), &::network::V0);
    let share_sender = sender_peer_id.clone();
    let share_task = tokio::spawn(async move {
        share_coordinator
            .handle_message(share_msg, &share_sender)
            .await
    });

    sleep(Duration::from_millis(50)).await;
    coordinator
        .handle_message(commitment_msg, &sender_peer_id)
        .await
        .expect("commitment should be accepted");

    let result = share_task.await.expect("share task join");
    assert!(
        result.is_ok(),
        "Expected share to verify after commitment arrives, got: {:?}",
        result
    );

    cleanup_db(&db_path);
}

/// `rings_refreshing` only guards the PSS refresh path; a concurrent fresh DKG
/// on the same ring is not blocked.  This test verifies that:
///
/// 1. Marking a ring as refreshing does NOT prevent a fresh DKG session from
///    being created (different code paths, no shared mutex).
/// 2. Both sessions coexist in state simultaneously.
/// 3. At the storage layer the two paths race with last-writer-wins semantics:
///    a refresh bundle written after a fresh-DKG bundle silently overwrites it.
#[tokio::test]
async fn test_concurrent_fresh_dkg_and_refresh_same_ring() {
    let db_name = "test_concurrent_fresh_dkg_and_refresh";
    let db_path = test_db_path(db_name);
    let app_state = Arc::new(create_test_app_state_default(db_name).await);

    // ── Step 1: Simulate a ring that is already undergoing a PSS refresh. ──────
    let ring_key = "deadbeef1234ring";
    let refresh_session_id: u128 = 100;

    // Mark the ring as refreshing — this is what PSS mod.rs does before
    // creating a refresh session.
    assert_eq!(
        app_state
            .dkg_session_state
            .claim_ring_pss_session(ring_key, refresh_session_id)
            .await,
        crate::dkg::v0::session_state::RingPssClaimOutcome::Claimed,
        "should be able to claim a fresh ring as refreshing"
    );

    // Create the refresh session.
    let coordinator = DkgCoordinator::with_routes(app_state.clone(), &::network::V0);
    coordinator
        .create_session(refresh_session_id, 1, 2, 3, DkgRole::Standard, |_| {})
        .await
        .expect("refresh session creation should succeed");
    app_state
        .dkg_session_state
        .set_session_kind(
            &refresh_session_id,
            SessionKind::Refresh {
                ring_pk_hex: ring_key.to_string(),
            },
        )
        .await;

    // ── Step 2: A fresh DKG on the same ring is NOT blocked. ─────────────────
    // rings_refreshing has no effect on create_session for a new DKG.
    let fresh_dkg_session_id: u128 = 200;
    coordinator
        .create_session(fresh_dkg_session_id, 1, 2, 3, DkgRole::Standard, |_| {})
        .await
        .expect("fresh DKG session creation must not be blocked by rings_refreshing");

    // ── Step 3: Both sessions coexist in state. ───────────────────────────────
    assert!(
        app_state
            .dkg_session_state
            .session_exists(&refresh_session_id)
            .await,
        "refresh session should still exist in state"
    );
    assert!(
        app_state
            .dkg_session_state
            .session_exists(&fresh_dkg_session_id)
            .await,
        "fresh DKG session should exist in state alongside the refresh session"
    );

    // ── Step 4: Storage last-writer-wins race. ────────────────────────────────
    // Simulate Phase 4 of the fresh DKG writing its bundle first.
    let fresh_dkg_bundle = crate::ring_state::RingShareBundle {
        share_bytes: vec![0xAA; 32].into(),
        public_polynomial: "fresh_poly".to_string(),
        last_pss: 1_000,
    };
    fresh_dkg_bundle
        .save_by_ring_key(&app_state.local_storage, ring_key)
        .expect("fresh DKG bundle write should succeed");

    // Simulate Phase 4 of the refresh writing its bundle second (wins).
    let refresh_bundle = crate::ring_state::RingShareBundle {
        share_bytes: vec![0xBB; 32].into(),
        public_polynomial: "refresh_poly".to_string(),
        last_pss: 2_000,
    };
    refresh_bundle
        .save_by_ring_key(&app_state.local_storage, ring_key)
        .expect("refresh bundle write should succeed");

    // The refresh silently overwrote the fresh DKG result — no error, but the
    // fresh DKG's polynomial is gone.  This demonstrates the unguarded race.
    let stored =
        crate::ring_state::RingShareBundle::load_by_ring_key(&app_state.local_storage, ring_key)
            .expect("bundle should be readable");
    assert_eq!(
        stored.public_polynomial, "refresh_poly",
        "refresh bundle (written last) should have overwritten the fresh DKG bundle"
    );
    assert_eq!(
        stored.share_bytes.as_slice(),
        vec![0xBB; 32],
        "refresh share bytes should be present (last writer wins)"
    );

    cleanup_db(&db_path);
}

// =============================================================================
// coordinator rejects invalid PSS refresh SessionInit messages
//
// These tests confirm that the coordinator enforces the three validation
// checks (local-node membership, minimum elapsed time, no concurrent refresh)
// before creating any session state.  They use a single-node app_state with
// pre-populated local storage — no three-node network is required because the
// checks happen before any network I/O.
// =============================================================================

/// Write a minimal `RingShareBundle` with the given `last_pss` timestamp.
fn write_last_refresh(
    storage: &impl local_storage::r#trait::LocalStorage,
    ring_pk: &str,
    secs: u64,
) {
    let bundle = crate::ring_state::RingShareBundle {
        share_bytes: vec![].into(),
        public_polynomial: String::new(),
        last_pss: secs,
    };
    bundle.save_by_ring_key(storage, ring_pk).unwrap();
}

/// Build a minimal refresh `SessionInit` targeted at `ring_pk`.
fn refresh_session_init(ring_pk: &str, peer_node_key: &str, peer_id: &str) -> DkgMessage {
    let peer_node_keys = vec![peer_node_key.to_string()];
    let peer_ids = vec![peer_id.to_string()];
    let mut node_id_assignments = std::collections::HashMap::new();
    node_id_assignments.insert(peer_node_key.to_string(), 1u32);
    DkgMessage::SessionInit {
        session_id: derive_refresh_session_id(ring_pk, &peer_node_keys, 1, "").unwrap(),
        threshold: 1,
        total_participants: 1,
        peer_ids: peer_ids.clone(),
        peer_node_keys,
        node_id_assignments,
        token_string: String::new(),
        kind: SessionKind::Refresh {
            ring_pk_hex: ring_pk.to_string(),
        },
        pss_interval: 86400,
        policy_id: None,
        ring_id: format!("test-ring-{ring_pk}"),
    }
}

#[tokio::test]
async fn test_refresh_accepts_external_sender_when_local_node_in_ring() {
    let db_name = "test_refresh_accepts_external_sender_when_local_node_in_ring";
    let db_path = test_db_path(db_name);
    let dummy_bulletin = Arc::new(
        DummyBulletin::new()
            .await
            .expect("Failed to initialize dummy bulletin"),
    );
    let app_state =
        Arc::new(create_test_app_state_with_bulletin(true, dummy_bulletin.clone(), db_name).await);

    let ring_pk = "ring_pk";
    let local_node_key = app_state.node_key.clone();
    let local_peer_hex = hex::encode(app_state.network.local_peer_id().as_bytes());
    write_ring_to_bulletin(
        &app_state.local_storage,
        &dummy_bulletin,
        ring_pk,
        vec![local_node_key.clone()],
        86400,
    )
    .await;
    write_last_refresh(&app_state.local_storage, ring_pk, 0); // epoch → enough time has passed

    let sender_bytes = hex::decode("deadbeef").unwrap();
    let sender_peer_id = PeerId::from_bytes(&sender_bytes);
    let coordinator = DkgCoordinator::with_routes(app_state, &::network::V0);
    let msg = refresh_session_init(ring_pk, &local_node_key, &local_peer_hex);

    let result = coordinator.handle_message(msg, &sender_peer_id).await;
    assert!(
        matches!(result, Ok(None)),
        "Expected external sender to be accepted when local node is in ring, got: {:?}",
        result
    );
    cleanup_db(&db_path);
}

#[tokio::test]
async fn test_refresh_rejected_local_node_not_in_ring() {
    let db_name = "test_refresh_rejected_local_node_not_in_ring";
    let db_path = test_db_path(db_name);
    let dummy_bulletin = Arc::new(
        DummyBulletin::new()
            .await
            .expect("Failed to initialize dummy bulletin"),
    );
    let app_state =
        Arc::new(create_test_app_state_with_bulletin(true, dummy_bulletin.clone(), db_name).await);

    let ring_pk = "ring_pk";
    let other_node_key = "other-node-key".to_string();
    let other_peer_hex = "a".repeat(64);
    dummy_bulletin
        .set_node_info(
            other_node_key.clone(),
            NodeInfo {
                peer_id: other_peer_hex.clone(),
                controller_key: "test-controller-key".to_string(),
                whitelisted_policy_ids: vec![],
                whitelisted_ring_ids: vec![],
            },
        )
        .expect("seed other node info");
    write_ring_to_bulletin(
        &app_state.local_storage,
        &dummy_bulletin,
        ring_pk,
        vec![other_node_key.clone()],
        86400,
    )
    .await;
    write_last_refresh(&app_state.local_storage, ring_pk, 0); // epoch → enough time has passed

    let sender_bytes = hex::decode("deadbeef").unwrap();
    let sender_peer_id = PeerId::from_bytes(&sender_bytes);
    let coordinator = DkgCoordinator::with_routes(app_state, &::network::V0);
    let msg = refresh_session_init(ring_pk, &other_node_key, &other_peer_hex);

    let result = coordinator.handle_message(msg, &sender_peer_id).await;
    assert!(
        matches!(result, Err(crate::dkg::v0::error::DkgError::Unauthorized(ref msg)) if msg.contains("Local node")),
        "Expected Unauthorized for local node not in ring, got: {:?}",
        result
    );
    cleanup_db(&db_path);
}

#[tokio::test]
async fn test_refresh_rejected_too_soon() {
    let db_name = "test_refresh_rejected_too_soon";
    let db_path = test_db_path(db_name);
    let dummy_bulletin = Arc::new(
        DummyBulletin::new()
            .await
            .expect("Failed to initialize dummy bulletin"),
    );
    let app_state =
        Arc::new(create_test_app_state_with_bulletin(true, dummy_bulletin.clone(), db_name).await);

    let ring_pk = "ring_pk";
    let local_node_key = app_state.node_key.clone();
    let local_peer_hex = hex::encode(app_state.network.local_peer_id().as_bytes());
    write_ring_to_bulletin(
        &app_state.local_storage,
        &dummy_bulletin,
        ring_pk,
        vec![local_node_key.clone()],
        86400, // 24h interval required
    )
    .await;

    // Set last refresh to "now" — 0 seconds have elapsed, below any minimum interval.
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    write_last_refresh(&app_state.local_storage, ring_pk, now_secs);

    let sender_bytes = hex::decode(&local_peer_hex).unwrap();
    let sender_peer_id = PeerId::from_bytes(&sender_bytes);
    let coordinator = DkgCoordinator::with_routes(app_state, &::network::V0);
    let msg = refresh_session_init(ring_pk, &local_node_key, &local_peer_hex);

    let result = coordinator.handle_message(msg, &sender_peer_id).await;
    assert!(
        matches!(
            result,
            Err(crate::dkg::v0::error::DkgError::Unauthorized(_))
        ),
        "Expected Unauthorized for refresh too soon, got: {:?}",
        result
    );
    cleanup_db(&db_path);
}

#[tokio::test]
async fn test_refresh_rejected_already_in_progress() {
    let db_name = "test_refresh_rejected_already_in_progress";
    let db_path = test_db_path(db_name);
    let dummy_bulletin = Arc::new(
        DummyBulletin::new()
            .await
            .expect("Failed to initialize dummy bulletin"),
    );
    let app_state =
        Arc::new(create_test_app_state_with_bulletin(true, dummy_bulletin.clone(), db_name).await);

    let ring_pk = "ring_pk";
    let local_node_key = app_state.node_key.clone();
    let local_peer_hex = hex::encode(app_state.network.local_peer_id().as_bytes());
    write_ring_to_bulletin(
        &app_state.local_storage,
        &dummy_bulletin,
        ring_pk,
        vec![local_node_key.clone()],
        86400,
    )
    .await;
    write_last_refresh(&app_state.local_storage, ring_pk, 0); // epoch → enough time has passed

    // Pre-mark the ring as already refreshing so the coordinator rejects the second attempt.
    let expected_session_id =
        derive_refresh_session_id(ring_pk, std::slice::from_ref(&local_node_key), 1, "").unwrap();
    assert_eq!(
        app_state
            .dkg_session_state
            .claim_ring_pss_session(ring_pk, expected_session_id + 1)
            .await,
        crate::dkg::v0::session_state::RingPssClaimOutcome::Claimed,
        "initial conflicting claim should succeed"
    );

    let sender_bytes = hex::decode(&local_peer_hex).unwrap();
    let sender_peer_id = PeerId::from_bytes(&sender_bytes);
    let coordinator = DkgCoordinator::with_routes(app_state, &::network::V0);
    let msg = refresh_session_init(ring_pk, &local_node_key, &local_peer_hex);

    let result = coordinator.handle_message(msg, &sender_peer_id).await;
    assert!(
        matches!(
            result,
            Err(crate::dkg::v0::error::DkgError::Unauthorized(_))
        ),
        "Expected Unauthorized for refresh already in progress, got: {:?}",
        result
    );
    cleanup_db(&db_path);
}
