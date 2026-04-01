use crate::constants::MAX_DKG_SESSIONS;
use crate::dkg::{
    coordinator::DkgCoordinator,
    messages::{DkgMessage, SessionKind},
    session_state::{DkgMessageType, DkgPhase, SessionStateManager},
};
use crate::helpers::create_routers::create_router_with_dkg_handler;
use crate::helpers::helpers::extract_node_part;
use crate::helpers::test_helpers::{
    cleanup_db, create_authenticated_request, create_test_app_state, create_test_app_state_default,
    create_test_app_state_with_bulletin, get_test_ring_post, setup_three_node_network,
    test_db_path, write_ring_to_bulletin, TestKeyPair, TestNode,
};
use crate::ring_state::{RingIndexEntry, RingPolyState, RingShareBundle};
use crate::DkgServiceImpl;
use bulletin::dummy::DummyBulletin;
use bulletin::r#trait::RingPayload;
use crypto::r#trait::{CryptoDeserialize, Dkg, DkgRole, PubPoly as PubPolyTrait};
use crypto::CryptoSerialize;
use local_storage::r#trait::{LocalStorage, LocalStorageKeys};
use network::PeerId;
use network::Router;
use proto::dkg_service::{dkg_service_server::DkgService, StartDkgRequest};
use std::sync::Arc;
use std::time::Instant;
use tokio::time::{sleep, Duration};
use tonic::{Request, Response};
use tracing_subscriber;

// Concrete crypto implementation for tests (selected via crypto crate features)
use crypto::DkgImpl;

/// Unit test: Test start_dkg with empty participant list returns error
#[tokio::test]
async fn test_start_dkg_empty_participants() {
    let db_path = test_db_path("test_start_dkg_empty_participants");
    let app_state = create_test_app_state_default("test_start_dkg_empty_participants").await;
    let service = DkgServiceImpl::<DkgImpl>::new(app_state);

    let peer_ids: Vec<String> = vec![]; // Empty - should result in error
    let request = StartDkgRequest {
        threshold: 0,
        peer_ids: peer_ids.clone(),
        pss_interval: None,
    };

    // Create authenticated request
    let test_keys = TestKeyPair::new();
    let token = test_keys
        .create_dkg_jwt(0, &peer_ids, None)
        .expect("Failed to create JWT");
    let tonic_request = create_authenticated_request(request, &token).unwrap();

    let result = service.start_dkg(tonic_request).await;

    // Should fail with 0 participants (validation error)
    assert!(result.is_err(), "start_dkg should fail with 0 participants");
    cleanup_db(&db_path);
}

/// Integration test: Three nodes connect to each other
///
/// This test spins up three nodes (Alice, Bob, Charlie), starts routers for all,
/// and has Alice send a StartDkgRequest including all peer IDs so they can all
/// participate in the DKG.
#[tokio::test]
#[serial_test::serial]
async fn test_three_nodes_connect() {
    let db_name = "test_three_nodes_connect";
    let db_paths = [
        test_db_path(&format!("{}_1", db_name)),
        test_db_path(&format!("{}_2", db_name)),
        test_db_path(&format!("{}_3", db_name)),
    ];

    // Set up three-node network with routers started for all nodes
    let mut network = setup_three_node_network(true, db_name).await;

    // Get all peer IDs (including Alice) for participation
    let peer_ids = network.get_all_peer_ids();
    println!("Peer IDs for connection: {:?}", peer_ids);

    // Create Alice's service (clone app_state to avoid move)
    let alice_service = DkgServiceImpl::<DkgImpl>::new(network.alice.app_state.clone());

    // Alice sends StartDkgRequest with Bob and Charlie's peer IDs
    let request = StartDkgRequest {
        threshold: 2,
        peer_ids: peer_ids.clone(),
        pss_interval: None,
    };

    // Create authenticated request
    let test_keys = TestKeyPair::new();
    let token = test_keys
        .create_dkg_jwt(2, &peer_ids, None)
        .expect("Failed to create JWT");

    println!("Alice sending StartDkgRequest with peer IDs...");
    let tonic_request = create_authenticated_request(request, &token).unwrap();
    let result = alice_service.start_dkg(tonic_request).await;

    assert!(result.is_ok(), "start_dkg should succeed");

    let response: Response<_> = result.unwrap();
    let inner = response.into_inner();

    // Verify response
    assert_eq!(inner.status, "started");
    assert!(inner.message.contains("DKG session started"));

    // Note: In a real test, you might want to verify that connections were actually established
    // by checking connection state or sending test messages. For now, we verify the request
    // was processed successfully.

    // Clean up routers
    println!("Cleaning up routers...");
    network
        .shutdown_routers()
        .await
        .expect("Failed to shutdown routers");
    for path in &db_paths {
        cleanup_db(path);
    }

    println!("Test completed successfully!");
}

/// Test: Verify that StartDkg fails when unable to connect to all requested peers
///
/// This test verifies that if a node receives invalid peer IDs,
/// the gRPC service validates them and returns an error before attempting connections.
#[tokio::test]
async fn test_start_dkg_fails_on_connection_failure() {
    let db_name = "test_start_dkg_fails_on_connection_failure";
    let db_path = test_db_path(db_name);

    // Create only Alice node
    let alice_state =
        create_test_app_state(Some("127.0.0.1:0".to_string()), true, true, db_name).await;

    // Create Alice's service
    let alice_service = DkgServiceImpl::<DkgImpl>::new(alice_state);

    // Create a request with invalid peer IDs that fail validation
    // Using obviously invalid peer IDs (not valid hex-encoded Ed25519 public keys)
    let peer_ids = vec![
        "invalid-peer-id-1".to_string(),
        "invalid-peer-id-2".to_string(),
    ];
    let request = StartDkgRequest {
        threshold: 2,
        peer_ids: peer_ids.clone(),
        pss_interval: None,
    };

    // Create authenticated request (even with invalid peer_ids, JWT should match request)
    let test_keys = TestKeyPair::new();
    let token = test_keys
        .create_dkg_jwt(2, &peer_ids, None)
        .expect("Failed to create JWT");

    println!("Alice sending StartDkgRequest with invalid peer IDs...");
    let tonic_request = create_authenticated_request(request, &token).unwrap();
    let result = alice_service.start_dkg(tonic_request).await;

    // Verify that the request fails with a gRPC error due to invalid peer ID format
    assert!(
        result.is_err(),
        "start_dkg should fail when peer IDs are invalid"
    );

    let status = result.unwrap_err();
    assert_eq!(
        status.code(),
        tonic::Code::InvalidArgument,
        "Error code should be InvalidArgument for invalid peer IDs"
    );
    assert!(
        status.message().contains("Invalid peer ID"),
        "Error message should indicate invalid peer ID: {}",
        status.message()
    );

    println!("Test passed: Service correctly returned error for failed connections");
    cleanup_db(&db_path);
}

/// Test: Verify that StartDkg succeeds when connecting to valid peers
///
/// This test verifies that if a node can connect to all requested peer IDs,
/// the gRPC service succeeds.
#[tokio::test]
#[serial_test::serial]
async fn test_start_dkg_succeeds_on_all_connections() {
    let db_name = "test_start_dkg_succeeds_on_all_connections";
    let db_paths = [
        test_db_path(&format!("{}_1", db_name)),
        test_db_path(&format!("{}_2", db_name)),
        test_db_path(&format!("{}_3", db_name)),
    ];

    // Initialize tracing for debugging
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_test_writer()
        .try_init();

    // Set up three-node network with routers started for all nodes
    let mut network = setup_three_node_network(true, db_name).await;

    // Get all peer IDs (including Alice) for participation
    let peer_ids = network.get_all_peer_ids();
    println!("Peer IDs for connection: {:?}", peer_ids);

    // Create Alice's service
    let alice_service = DkgServiceImpl::<DkgImpl>::new(network.alice.app_state.clone());

    // Alice sends StartDkgRequest with all peer IDs (including herself)
    let request = StartDkgRequest {
        threshold: 2,
        peer_ids: peer_ids.clone(),
        pss_interval: None,
    };

    // Create authenticated request
    let test_keys = TestKeyPair::new();
    let token = test_keys
        .create_dkg_jwt(2, &peer_ids, None)
        .expect("Failed to create JWT");

    println!("Alice sending StartDkgRequest with valid peer IDs...");
    let tonic_request = create_authenticated_request(request, &token).unwrap();
    let result = alice_service.start_dkg(tonic_request).await;

    // Verify that the request succeeds when all connections are successful
    assert!(
        result.is_ok(),
        "start_dkg should succeed when all peer connections are successful"
    );

    let response: Response<_> = result.unwrap();
    let inner = response.into_inner();

    // Verify response
    assert_eq!(inner.status, "started");
    assert!(inner.message.contains("DKG session started"));

    // Wait up to 10 seconds for DKG to complete
    let check_interval = Duration::from_millis(1000);
    let max_wait = Duration::from_secs(50);

    let start = std::time::Instant::now();
    loop {
        // Debug: check session count
        let session_count = network
            .alice
            .app_state
            .dkg_session_state
            .session_count()
            .await;
        if start.elapsed().as_secs() % 5 == 0 {
            println!(
                "Session count: {}, elapsed: {:?}",
                session_count,
                start.elapsed()
            );
        }

        // Try to get the ring payload from bulletin (indicates Phase 4 complete)
        let dummy_bulletin = network
            .dummy_bulletin
            .as_ref()
            .expect("DKG tests require DummyBulletin");
        let post = get_test_ring_post(dummy_bulletin);

        // Check if payload is non-empty (DKG complete, ring info posted to bulletin)
        if !post.payload.is_empty() {
            println!("Found ring payload in bulletin!");

            // Parse RingPayload from bulletin post
            let ring_payload: RingPayload = post.try_into().expect("parse RingPayload");
            println!("Ring public key from bulletin: {}", &ring_payload.ring_pk);

            // Deserialize the public key to get the key string for local storage lookup
            let ring_pk_bytes = hex::decode(&ring_payload.ring_pk).expect("decode hex");
            let aggregate_key = <DkgImpl as Dkg>::PublicKey::from_bytes(&ring_pk_bytes)
                .expect("deserialize public key");
            let key_string = aggregate_key.to_string();

            // Since all nodes read from the same bulletin, they all see the same ring_pk
            // No need to verify across nodes - it's the same shared bulletin
            println!(
                "Success! DKG complete with aggregate key: {:?}",
                aggregate_key
            );

            // Verify that each node stored its secret share in local storage
            let share_alice = network
                .alice
                .app_state
                .local_storage
                .get_encrypted(LocalStorageKeys::RingKey(key_string.clone()));
            let share_bob = network
                .bob
                .app_state
                .local_storage
                .get_encrypted(LocalStorageKeys::RingKey(key_string.clone()));
            let share_charlie = network
                .charlie
                .app_state
                .local_storage
                .get_encrypted(LocalStorageKeys::RingKey(key_string));

            // Verify all shares exist (they should be different, so we don't compare them)
            assert!(
                share_alice.is_ok() && share_alice.as_ref().unwrap().is_some(),
                "Alice should have stored her secret share"
            );
            assert!(
                share_bob.is_ok() && share_bob.as_ref().unwrap().is_some(),
                "Bob should have stored his secret share"
            );
            assert!(
                share_charlie.is_ok() && share_charlie.as_ref().unwrap().is_some(),
                "Charlie should have stored his secret share"
            );

            println!("Success! All nodes stored their secret shares in local storage");
            break;
        }

        if start.elapsed() > max_wait {
            panic!("DKG did not complete within {} seconds", max_wait.as_secs());
        }

        sleep(check_interval).await;
    }

    // Clean up routers
    network
        .shutdown_routers()
        .await
        .expect("Failed to shutdown routers");
    for path in &db_paths {
        cleanup_db(path);
    }

    println!(
        "Test passed: Service correctly succeeded when all connections worked and DKG completed"
    );
}

#[tokio::test]
async fn test_start_dkg_fails_missing_auth_header() {
    let db_name = "test_start_dkg_fails_missing_auth_header";
    let db_path = test_db_path(db_name);
    let app_state = create_test_app_state_default(db_name).await;
    let service = DkgServiceImpl::<DkgImpl>::new(app_state);

    let peer_ids = vec!["peer1".to_string(), "peer2".to_string()];
    let request = StartDkgRequest {
        threshold: 2,
        peer_ids,
        pss_interval: None,
    };

    // Create request WITHOUT authentication header
    let tonic_request = Request::new(request);

    let result = service.start_dkg(tonic_request).await;

    assert!(
        result.is_err(),
        "start_dkg should fail when Authorization header is missing"
    );

    let status = result.unwrap_err();
    assert_eq!(
        status.code(),
        tonic::Code::Unauthenticated,
        "Error code should be Unauthenticated for missing auth header"
    );

    assert!(
        status.message().contains("Unauthorized"),
        "Error message should indicate missing authorization: {}",
        status.message()
    );
    cleanup_db(&db_path);
}

#[tokio::test]
async fn test_start_dkg_fails_malformed_jwt() {
    let db_name = "test_start_dkg_fails_malformed_jwt";
    let db_path = test_db_path(db_name);
    let app_state = create_test_app_state_default(db_name).await;
    let service = DkgServiceImpl::<DkgImpl>::new(app_state);

    let peer_ids = vec!["peer1".to_string(), "peer2".to_string()];
    let request = StartDkgRequest {
        threshold: 2,
        peer_ids,
        pss_interval: None,
    };

    // Create request with malformed JWT (not a valid JWT structure)
    let tonic_request = create_authenticated_request(request, "not-a-valid-jwt-token").unwrap();

    let result = service.start_dkg(tonic_request).await;

    assert!(
        result.is_err(),
        "start_dkg should fail with malformed JWT token"
    );

    let status = result.unwrap_err();
    assert_eq!(
        status.code(),
        tonic::Code::Unauthenticated,
        "Error code should be Unauthenticated for malformed JWT"
    );
    cleanup_db(&db_path);
}

#[tokio::test]
async fn test_start_dkg_fails_wrong_signature() {
    let db_name = "test_start_dkg_fails_wrong_signature";
    let db_path = test_db_path(db_name);
    let app_state = create_test_app_state_default(db_name).await;
    let service = DkgServiceImpl::<DkgImpl>::new(app_state);

    let peer_ids = vec!["peer1".to_string(), "peer2".to_string()];

    // Create a valid JWT with key_pair_1
    let key_pair_1 = TestKeyPair::new();
    let valid_token = key_pair_1
        .create_dkg_jwt(2, &peer_ids, None)
        .expect("Failed to create JWT");

    // Tamper with the signature by changing a character
    // JWT format: header.payload.signature
    let parts: Vec<&str> = valid_token.split('.').collect();
    assert_eq!(parts.len(), 3, "JWT should have 3 parts");

    // Modify the signature portion to invalidate it
    let mut tampered_sig = parts[2].to_string();
    if let Some(c) = tampered_sig.pop() {
        // Change the last character to invalidate the signature
        let new_char = if c == 'A' { 'B' } else { 'A' };
        tampered_sig.push(new_char);
    }
    let tampered_token = format!("{}.{}.{}", parts[0], parts[1], tampered_sig);

    let request = StartDkgRequest {
        threshold: 2,
        peer_ids,
        pss_interval: None,
    };

    let tonic_request = create_authenticated_request(request, &tampered_token).unwrap();

    let result = service.start_dkg(tonic_request).await;

    assert!(
        result.is_err(),
        "start_dkg should fail with tampered JWT signature"
    );

    let status = result.unwrap_err();
    assert_eq!(
        status.code(),
        tonic::Code::Unauthenticated,
        "Error code should be Unauthenticated for invalid signature"
    );
    cleanup_db(&db_path);
}

/// Test: Verify that SessionInit with invalid JWT token is rejected by peer nodes
///
/// This test verifies that when a peer node receives a SessionInit message
/// with an invalid JWT token, it rejects the session initialization.
#[tokio::test]
async fn test_dkg_session_init_fails_with_invalid_jwt() {
    let db_name = "test_dkg_session_init_fails_with_invalid_jwt";
    let db_path = test_db_path(db_name);

    // Create a node to receive the SessionInit
    let app_state = create_test_app_state_default(db_name).await;
    let coordinator = DkgCoordinator::new(Arc::new(app_state));

    // Create a SessionInit message with an invalid JWT token
    let session_init = DkgMessage::SessionInit {
        session_id: 12345,
        threshold: 2,
        total_participants: 3,
        peer_ids: vec![
            "peer1".to_string(),
            "peer2".to_string(),
            "peer3".to_string(),
        ],
        node_id_assignments: std::collections::HashMap::from([
            ("peer1".to_string(), 1),
            ("peer2".to_string(), 2),
            ("peer3".to_string(), 3),
        ]),
        token_string: "not-a-valid-jwt-token".to_string(), // Invalid JWT
        kind: SessionKind::Fresh,
        pss_interval: None,
    };

    // Try to handle the message - should fail due to invalid JWT
    let dummy_peer_id = network::PeerId::new(b"dummy-peer".to_vec());
    let result = coordinator
        .handle_message(session_init, &dummy_peer_id)
        .await;

    assert!(
        result.is_err(),
        "SessionInit with invalid JWT should be rejected"
    );

    let error = result.unwrap_err();
    println!("SessionInit correctly rejected with error: {}", error);
    assert!(
        error.to_string().contains("Unauthorized")
            || error.to_string().contains("JWT")
            || error.to_string().contains("validation"),
        "Error should indicate authentication failure: {}",
        error
    );

    println!("SUCCESS! SessionInit with invalid JWT was correctly rejected");
    cleanup_db(&db_path);
}

/// Test: Verify that SessionInit with mismatched JWT claims is rejected
///
/// This test verifies that when a peer node receives a SessionInit message
/// with a JWT token that has claims that don't match the SessionInit fields,
/// it rejects the session initialization.
#[tokio::test]
async fn test_dkg_session_init_fails_with_mismatched_claims() {
    let db_name = "test_dkg_session_init_fails_with_mismatched_claims";
    let db_path = test_db_path(db_name);

    // Create a node to receive the SessionInit
    let app_state = create_test_app_state_default(db_name).await;
    let coordinator = DkgCoordinator::new(Arc::new(app_state));

    // Create a valid JWT but with WRONG claims (threshold mismatch)
    let test_keys = TestKeyPair::new();
    let peer_ids = vec![
        "peer1".to_string(),
        "peer2".to_string(),
        "peer3".to_string(),
    ];

    // Create JWT with threshold=3, but SessionInit will have threshold=2
    let mismatched_token = test_keys
        .create_dkg_jwt(3, &peer_ids, None) // Wrong threshold!
        .expect("Failed to create JWT");

    // Create a SessionInit message with threshold=2 (doesn't match JWT's threshold=3)
    let session_init = DkgMessage::SessionInit {
        session_id: 12345,
        threshold: 2, // Doesn't match JWT claim of 3
        total_participants: 3,
        peer_ids: peer_ids.clone(),
        node_id_assignments: std::collections::HashMap::from([
            ("peer1".to_string(), 1),
            ("peer2".to_string(), 2),
            ("peer3".to_string(), 3),
        ]),
        token_string: mismatched_token,
        kind: SessionKind::Fresh,
        pss_interval: None,
    };

    // Try to handle the message - should fail due to claim mismatch
    let dummy_peer_id = network::PeerId::new(b"dummy-peer".to_vec());
    let result = coordinator
        .handle_message(session_init, &dummy_peer_id)
        .await;

    assert!(
        result.is_err(),
        "SessionInit with mismatched JWT claims should be rejected"
    );

    let error = result.unwrap_err();
    println!("SessionInit correctly rejected with error: {}", error);
    assert!(
        error.to_string().contains("match"),
        "Error should indicate claim mismatch: {}",
        error
    );
    cleanup_db(&db_path);
}

/// Test: Verify that SessionInit with mismatched peer_ids in JWT is rejected
#[tokio::test]
async fn test_dkg_session_init_fails_with_wrong_peer_ids() {
    let db_name = "test_dkg_session_init_fails_with_wrong_peer_ids";
    let db_path = test_db_path(db_name);

    // Create a node to receive the SessionInit
    let app_state = create_test_app_state_default(db_name).await;
    let coordinator = DkgCoordinator::new(Arc::new(app_state));

    // Create a valid JWT with different peer_ids than what's in SessionInit
    let test_keys = TestKeyPair::new();
    let jwt_peer_ids = vec![
        "different_peer1".to_string(),
        "different_peer2".to_string(),
        "different_peer3".to_string(),
    ];

    let mismatched_token = test_keys
        .create_dkg_jwt(2, &jwt_peer_ids, None)
        .expect("Failed to create JWT");

    // SessionInit has different peer_ids than the JWT
    let session_peer_ids = vec![
        "peer1".to_string(),
        "peer2".to_string(),
        "peer3".to_string(),
    ];

    let session_init = DkgMessage::SessionInit {
        session_id: 12345,
        threshold: 2,
        total_participants: 3,
        peer_ids: session_peer_ids,
        node_id_assignments: std::collections::HashMap::from([
            ("peer1".to_string(), 1),
            ("peer2".to_string(), 2),
            ("peer3".to_string(), 3),
        ]),
        token_string: mismatched_token,
        kind: SessionKind::Fresh,
        pss_interval: None,
    };

    // Try to handle the message - should fail due to peer_ids mismatch
    let dummy_peer_id = network::PeerId::new(b"dummy-peer".to_vec());
    let result = coordinator
        .handle_message(session_init, &dummy_peer_id)
        .await;

    assert!(
        result.is_err(),
        "SessionInit with mismatched peer_ids should be rejected"
    );

    let error = result.unwrap_err();
    println!("SessionInit correctly rejected with error: {}", error);
    assert!(
        error.to_string().contains("Unauthorized")
            || error.to_string().contains("peer_ids")
            || error.to_string().contains("match"),
        "Error should indicate peer_ids mismatch: {}",
        error
    );

    println!("SUCCESS! SessionInit with mismatched peer_ids was correctly rejected");
    cleanup_db(&db_path);
}

// ============================================================================
// Session Cleanup Guard Tests
// ============================================================================

/// Test: Verify that SessionCleanupGuard cleans up on drop (error path)
///
/// When a guard is dropped without calling defuse(), the session should be
/// automatically cleaned up via the background worker.
#[tokio::test]
async fn test_session_cleanup_guard_cleans_up_on_drop() {
    let manager: SessionStateManager<DkgImpl> = SessionStateManager::new();

    // Create a mock DKG node and session
    let session_id = 12345u64;
    let dkg_node = *DkgImpl::new(1, 2, 3, session_id, DkgRole::Standard).expect("create DKG node");
    manager.create_session(session_id, dkg_node, 3).await;

    // Verify session exists
    assert!(
        manager.session_exists(&session_id).await,
        "Session should exist after creation"
    );
    assert_eq!(manager.session_count().await, 1, "Should have 1 session");

    // Create guard and drop it without defusing (simulates error path)
    {
        let _guard = manager.cleanup_guard(session_id);
        // guard is dropped here without defuse()
    }

    // Give the background worker time to process the cleanup
    sleep(Duration::from_millis(50)).await;

    // Verify session was cleaned up
    assert!(
        !manager.session_exists(&session_id).await,
        "Session should be cleaned up after guard drop"
    );
    assert_eq!(
        manager.session_count().await,
        0,
        "Should have 0 sessions after cleanup"
    );

    println!("SUCCESS! SessionCleanupGuard correctly cleaned up session on drop");
}

/// Test: Verify that defuse() prevents cleanup
///
/// When defuse() is called on the guard, the session should NOT be cleaned up.
#[tokio::test]
async fn test_session_cleanup_guard_defuse_prevents_cleanup() {
    let manager: SessionStateManager<DkgImpl> = SessionStateManager::new();

    // Create a mock DKG node and session
    let session_id = 67890u64;
    let dkg_node = *DkgImpl::new(1, 2, 3, session_id, DkgRole::Standard).expect("create DKG node");
    manager.create_session(session_id, dkg_node, 3).await;

    // Verify session exists
    assert!(
        manager.session_exists(&session_id).await,
        "Session should exist after creation"
    );

    // Create guard, defuse it, then drop (simulates success path)
    {
        let guard = manager.cleanup_guard(session_id);
        guard.defuse(); // Prevent cleanup
                        // guard is dropped here, but cleanup should NOT happen
    }

    // Give time for any (incorrectly triggered) cleanup to process
    sleep(Duration::from_millis(50)).await;

    // Verify session still exists
    assert!(
        manager.session_exists(&session_id).await,
        "Session should still exist after defused guard drop"
    );
    assert_eq!(
        manager.session_count().await,
        1,
        "Should still have 1 session"
    );

    // Manual cleanup for test
    manager.remove_session(&session_id).await;

    println!("SUCCESS! defuse() correctly prevented cleanup");
}

/// Test: Verify that expired sessions are automatically removed
///
/// Sessions older than SESSION_TTL that haven't completed Phase 4 should be
/// removed by the expiration worker.
#[tokio::test]
async fn test_session_expiration_removes_old_sessions() {
    let manager: SessionStateManager<DkgImpl> = SessionStateManager::new();

    // Create a session
    let session_id = 11111u64;
    let dkg_node = *DkgImpl::new(1, 2, 3, session_id, DkgRole::Standard).expect("create DKG node");
    manager.create_session(session_id, dkg_node, 3).await;

    // Verify session exists
    assert!(
        manager.session_exists(&session_id).await,
        "Session should exist after creation"
    );

    // Manually backdate the session's created_at to simulate an old session
    // We need to access the internal state to do this
    {
        let mut states = manager.states.write().await;
        if let Some(state) = states.get_mut(&session_id) {
            // Set created_at to 31 minutes ago (beyond 30 min TTL)
            state.created_at = Instant::now() - std::time::Duration::from_secs(31 * 60);
            // Ensure it's not in Phase4Complete (which is exempt from expiration)
            assert_ne!(
                state.phase,
                DkgPhase::Phase4Complete,
                "Session should not be complete"
            );
        }
    }

    // The expiration worker runs every 60 seconds by default, but we can
    // trigger cleanup by waiting. For faster testing, let's just verify
    // the session was backdated and manually call the check logic.
    //
    // In a real scenario, the expiration_worker would handle this automatically.
    // For this test, we'll simulate what the worker does.

    // Wait for the expiration worker to run (interval is 60s, but we backdated
    // the session so it should be cleaned up on first check)
    // Note: In production, SESSION_EXPIRATION_CHECK_INTERVAL is 60s.
    // For this test, we wait a bit and check manually.

    // Give expiration worker time to run at least once
    // (it runs immediately on start, then every 60s)
    sleep(Duration::from_millis(100)).await;

    // The expiration worker should have removed the session
    // Note: If this fails, the expiration worker might not have run yet.
    // In that case, increase the sleep duration or manually trigger expiration.

    let session_exists = manager.session_exists(&session_id).await;
    if session_exists {
        // Worker might not have run yet - let's check the age manually
        let states = manager.states.read().await;
        if let Some(state) = states.get(&session_id) {
            let age = Instant::now().duration_since(state.created_at);
            println!("Session age: {:?}, phase: {:?}", age.as_secs(), state.phase);
        }
        drop(states);

        // Wait longer for expiration worker
        println!("Waiting for expiration worker to run...");
        sleep(Duration::from_secs(2)).await;
    }

    // Check again
    assert!(
        !manager.session_exists(&session_id).await,
        "Expired session should have been removed by expiration worker"
    );

    println!("SUCCESS! Expired session was automatically removed");
}

// ============================================================================
// Message Deduplication Tests
// ============================================================================

/// Test: Verify that duplicate messages are correctly detected
#[tokio::test]
async fn test_message_dedup_detects_duplicates() {
    let manager: SessionStateManager<DkgImpl> = SessionStateManager::new();

    let session_id = 100u64;
    let dkg_node = *DkgImpl::new(1, 2, 3, session_id, DkgRole::Standard).expect("create DKG node");
    manager.create_session(session_id, dkg_node, 3).await;

    // First message should not be seen as processed
    assert!(
        !manager
            .is_message_processed(&session_id, 2, DkgMessageType::Commitment)
            .await,
        "First message should not be processed"
    );

    // Mark it as processed
    manager
        .mark_message_processed(&session_id, 2, DkgMessageType::Commitment)
        .await;

    // Now it should be detected as a duplicate
    assert!(
        manager
            .is_message_processed(&session_id, 2, DkgMessageType::Commitment)
            .await,
        "Same message should now be detected as duplicate"
    );

    manager.remove_session(&session_id).await;
}

/// Test: Different message types from the same node are not duplicates
#[tokio::test]
async fn test_message_dedup_different_types_not_duplicate() {
    let manager: SessionStateManager<DkgImpl> = SessionStateManager::new();

    let session_id = 101u64;
    let dkg_node = *DkgImpl::new(1, 2, 3, session_id, DkgRole::Standard).expect("create DKG node");
    manager.create_session(session_id, dkg_node, 3).await;

    // Mark commitment from node 2 as processed
    manager
        .mark_message_processed(&session_id, 2, DkgMessageType::Commitment)
        .await;

    // Share from same node should NOT be a duplicate (different message type)
    assert!(
        !manager
            .is_message_processed(&session_id, 2, DkgMessageType::Share)
            .await,
        "Different message type from same node should not be duplicate"
    );

    manager.remove_session(&session_id).await;
}

/// Test: Same message type from different nodes are not duplicates
#[tokio::test]
async fn test_message_dedup_different_nodes_not_duplicate() {
    let manager: SessionStateManager<DkgImpl> = SessionStateManager::new();

    let session_id = 102u64;
    let dkg_node = *DkgImpl::new(1, 2, 3, session_id, DkgRole::Standard).expect("create DKG node");
    manager.create_session(session_id, dkg_node, 3).await;

    // Mark commitment from node 2 as processed
    manager
        .mark_message_processed(&session_id, 2, DkgMessageType::Commitment)
        .await;

    // Commitment from node 3 should NOT be a duplicate (different sender)
    assert!(
        !manager
            .is_message_processed(&session_id, 3, DkgMessageType::Commitment)
            .await,
        "Same message type from different node should not be duplicate"
    );

    manager.remove_session(&session_id).await;
}

/// Test: Messages for different sessions are not duplicates
#[tokio::test]
async fn test_message_dedup_different_sessions_isolated() {
    let manager: SessionStateManager<DkgImpl> = SessionStateManager::new();

    let session_1 = 103u64;
    let session_2 = 104u64;
    let dkg_node_1 = *DkgImpl::new(1, 2, 3, session_1, DkgRole::Standard).expect("create DKG node");
    let dkg_node_2 = *DkgImpl::new(1, 2, 3, session_2, DkgRole::Standard).expect("create DKG node");
    manager.create_session(session_1, dkg_node_1, 3).await;
    manager.create_session(session_2, dkg_node_2, 3).await;

    // Mark message in session 1
    manager
        .mark_message_processed(&session_1, 2, DkgMessageType::Commitment)
        .await;

    // Same (node_id, type) in session 2 should NOT be a duplicate
    assert!(
        !manager
            .is_message_processed(&session_2, 2, DkgMessageType::Commitment)
            .await,
        "Messages in different sessions should be isolated"
    );

    manager.remove_session(&session_1).await;
    manager.remove_session(&session_2).await;
}

/// Test: Dedup state is cleaned up when session is removed
#[tokio::test]
async fn test_message_dedup_cleaned_up_with_session() {
    let manager: SessionStateManager<DkgImpl> = SessionStateManager::new();

    let session_id = 105u64;
    let dkg_node = *DkgImpl::new(1, 2, 3, session_id, DkgRole::Standard).expect("create DKG node");
    manager.create_session(session_id, dkg_node, 3).await;

    manager
        .mark_message_processed(&session_id, 2, DkgMessageType::Commitment)
        .await;
    assert!(
        manager
            .is_message_processed(&session_id, 2, DkgMessageType::Commitment)
            .await
    );

    // Remove session
    manager.remove_session(&session_id).await;

    // Dedup check on removed session returns false (no session = no duplicate)
    assert!(
        !manager
            .is_message_processed(&session_id, 2, DkgMessageType::Commitment)
            .await,
        "Dedup state should be gone after session removal"
    );
}

// ============================================================================
// Peer Identity Mapping Tests
// ============================================================================

/// Test: Peer-to-node and node-to-peer mappings are consistent
#[tokio::test]
async fn test_peer_node_mappings_consistent() {
    let manager: SessionStateManager<DkgImpl> = SessionStateManager::new();

    let session_id = 200u64;
    let dkg_node = *DkgImpl::new(1, 2, 3, session_id, DkgRole::Standard).expect("create DKG node");
    manager.create_session(session_id, dkg_node, 3).await;

    let mut mappings = std::collections::HashMap::new();
    mappings.insert(1, "aaa@192.168.1.1:4000".to_string());
    mappings.insert(2, "bbb@192.168.1.2:4000".to_string());
    mappings.insert(3, "ccc@192.168.1.3:4000".to_string());

    manager.set_node_peer_mappings(&session_id, mappings).await;

    // Forward lookup: node_id -> peer_id
    assert_eq!(
        manager.get_peer_id_for_node(&session_id, 1).await,
        Some("aaa@192.168.1.1:4000".to_string())
    );
    assert_eq!(
        manager.get_peer_id_for_node(&session_id, 2).await,
        Some("bbb@192.168.1.2:4000".to_string())
    );

    // Reverse lookup: peer_id -> node_id (via with_state)
    let node_id = manager
        .with_state(&session_id, |state| {
            state
                .peer_id_to_node_id
                .get("bbb@192.168.1.2:4000")
                .copied()
        })
        .await
        .flatten();
    assert_eq!(node_id, Some(2));

    // Unknown node_id returns None
    assert_eq!(manager.get_peer_id_for_node(&session_id, 99).await, None);

    manager.remove_session(&session_id).await;
}

/// Test: Peer identity validation rejects unknown peers
#[tokio::test]
async fn test_peer_identity_unknown_peer_not_in_mapping() {
    let manager: SessionStateManager<DkgImpl> = SessionStateManager::new();

    let session_id = 201u64;
    let dkg_node = *DkgImpl::new(1, 2, 3, session_id, DkgRole::Standard).expect("create DKG node");
    manager.create_session(session_id, dkg_node, 3).await;

    let mut mappings = std::collections::HashMap::new();
    mappings.insert(1, "aaa@192.168.1.1:4000".to_string());
    mappings.insert(2, "bbb@192.168.1.2:4000".to_string());
    manager.set_node_peer_mappings(&session_id, mappings).await;

    // Simulate what the coordinator does: look up peer in mapping
    let unknown_peer_hex = "zzz";
    let found = manager
        .with_state(&session_id, |state| {
            state
                .peer_id_to_node_id
                .iter()
                .find(|(peer_id, _)| extract_node_part(peer_id) == unknown_peer_hex)
                .map(|(_, node_id)| *node_id)
        })
        .await
        .flatten();

    assert_eq!(found, None, "Unknown peer should not be found in mappings");

    manager.remove_session(&session_id).await;
}

// ============================================================================
// Session Limit Tests
// ============================================================================

/// Test: Session creation is rejected when limit is reached
#[tokio::test]
async fn test_session_limit_enforced() {
    let manager: SessionStateManager<DkgImpl> = SessionStateManager::new();

    // Fill up to the limit
    for i in 0..MAX_DKG_SESSIONS {
        let dkg_node =
            *DkgImpl::new(1, 2, 3, i as u64, DkgRole::Standard).expect("create DKG node");
        assert!(
            manager.create_session(i as u64, dkg_node, 3).await,
            "Session {} should be created within limit",
            i
        );
    }

    assert_eq!(manager.session_count().await, MAX_DKG_SESSIONS);

    // One more should be rejected
    let dkg_node = *DkgImpl::new(1, 2, 3, MAX_DKG_SESSIONS as u64, DkgRole::Standard)
        .expect("create DKG node");
    assert!(
        !manager
            .create_session(MAX_DKG_SESSIONS as u64, dkg_node, 3)
            .await,
        "Session beyond limit should be rejected"
    );

    // Clean up
    for i in 0..MAX_DKG_SESSIONS {
        manager.remove_session(&(i as u64)).await;
    }
}

/// Test: Duplicate session_id is rejected
#[tokio::test]
async fn test_duplicate_session_id_rejected() {
    let manager: SessionStateManager<DkgImpl> = SessionStateManager::new();

    let session_id = 300u64;
    let dkg_node_1 =
        *DkgImpl::new(1, 2, 3, session_id, DkgRole::Standard).expect("create DKG node");
    let dkg_node_2 =
        *DkgImpl::new(1, 2, 3, session_id, DkgRole::Standard).expect("create DKG node");

    assert!(manager.create_session(session_id, dkg_node_1, 3).await);
    assert!(
        !manager.create_session(session_id, dkg_node_2, 3).await,
        "Duplicate session_id should be rejected"
    );

    manager.remove_session(&session_id).await;
}

/// Test: Commitment and share counters track correctly
#[tokio::test]
async fn test_commitment_and_share_counters() {
    let manager: SessionStateManager<DkgImpl> = SessionStateManager::new();

    let session_id = 400u64;
    let dkg_node = *DkgImpl::new(1, 2, 3, session_id, DkgRole::Standard).expect("create DKG node");
    manager.create_session(session_id, dkg_node, 3).await;

    // Initially zero
    let (commitments, shares) = manager
        .with_state(&session_id, |state| {
            (state.commitments_received, state.shares_received)
        })
        .await
        .unwrap();
    assert_eq!(commitments, 0);
    assert_eq!(shares, 0);

    // Increment commitments
    manager.increment_commitments(&session_id).await;
    manager.increment_commitments(&session_id).await;

    // Increment shares
    manager.increment_shares(&session_id).await;

    let (commitments, shares) = manager
        .with_state(&session_id, |state| {
            (state.commitments_received, state.shares_received)
        })
        .await
        .unwrap();
    assert_eq!(commitments, 2);
    assert_eq!(shares, 1);

    // Check completion helpers (3 participants, need 2 from others)
    let all_commitments = manager
        .with_state(&session_id, |state| state.all_commitments_received())
        .await
        .unwrap();
    assert!(
        all_commitments,
        "2 commitments should satisfy 3-participant session (need 2)"
    );

    let all_shares = manager
        .with_state(&session_id, |state| state.all_shares_received())
        .await
        .unwrap();
    assert!(
        !all_shares,
        "1 share should not satisfy 3-participant session (need 2)"
    );

    manager.remove_session(&session_id).await;
}

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
    let db_name = "test_dkg_followed_by_pss_refresh";
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

    // ── Phase A: Run the initial DKG ──────────────────────────────────────────
    let alice_service = DkgServiceImpl::<DkgImpl>::new(network.alice.app_state.clone());
    let test_keys = TestKeyPair::new();
    let token = test_keys
        .create_dkg_jwt(2, &peer_ids, None)
        .expect("create JWT");
    let tonic_req = create_authenticated_request(
        StartDkgRequest {
            threshold: 2,
            peer_ids: peer_ids.clone(),
            pss_interval: None,
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

    // Backdate refreshed_at in each node's RingShareBundle so the time-elapsed
    // check passes immediately.  We load the real bundle (written by DKG Phase 4),
    // reset refreshed_at to epoch, and write it back.
    for state in [
        &network.alice.app_state,
        &network.bob.app_state,
        &network.charlie.app_state,
    ] {
        let mut bundle =
            crate::ring_state::RingShareBundle::load_by_ring_key(&state.local_storage, &key_string)
                .expect("load RingShareBundle for backdate");
        bundle.refreshed_at = 0;
        bundle
            .save_by_ring_key(&state.local_storage, &key_string)
            .expect("save backdated RingShareBundle");
    }

    // ── Phase B: Set up and run a PSS refresh ─────────────────────────────────

    // Determine node_id assignments (same deterministic rule as DKG service).
    let mut sorted_peers = peer_ids.clone();
    sorted_peers.sort();
    let mut node_id_assignments = std::collections::HashMap::new();
    for (idx, peer) in sorted_peers.iter().enumerate() {
        node_id_assignments.insert(extract_node_part(peer), (idx + 1) as u32);
    }

    // The initiator is the node whose peer_id is first in sorted order.
    let initiator_node_part = extract_node_part(&sorted_peers[0]);

    let alice_hex = hex::encode(network.alice.app_state.network.local_peer_id().as_bytes());
    let bob_hex = hex::encode(network.bob.app_state.network.local_peer_id().as_bytes());

    let (initiator_state, initiator_node_id) =
        if extract_node_part(&alice_hex) == initiator_node_part {
            let nid = *node_id_assignments.get(&initiator_node_part).unwrap();
            (network.alice.app_state.clone(), nid)
        } else if extract_node_part(&bob_hex) == initiator_node_part {
            let nid = *node_id_assignments.get(&initiator_node_part).unwrap();
            (network.bob.app_state.clone(), nid)
        } else {
            let nid = *node_id_assignments.get(&initiator_node_part).unwrap();
            (network.charlie.app_state.clone(), nid)
        };

    println!("Refresh initiator: node_id={}", initiator_node_id);

    let refresh_session_id: u64 = rand::random();
    let coordinator = DkgCoordinator::new(Arc::new(initiator_state.clone()));

    coordinator
        .create_session(
            refresh_session_id,
            initiator_node_id,
            2,
            3,
            DkgRole::Standard,
        )
        .await
        .expect("create refresh session");

    // Refresh session: Phase 1 uses DkgMode::Refresh (zero constant term).
    // Ring key is stored on the initiator; non-initiators receive it via SessionInit.
    initiator_state
        .dkg_session_state
        .set_session_kind(
            &refresh_session_id,
            SessionKind::Refresh {
                ring_pk_hex: key_string.clone(),
            },
        )
        .await;

    coordinator
        .set_peer_ids(&refresh_session_id, peer_ids.clone())
        .await;

    // Set node_id ↔ peer_id mappings on the initiator.
    let mut node_id_to_peer_id = std::collections::HashMap::new();
    for (peer_key, &node_id) in &node_id_assignments {
        let full_peer = peer_ids
            .iter()
            .find(|p| extract_node_part(p) == *peer_key)
            .cloned()
            .unwrap();
        node_id_to_peer_id.insert(node_id, full_peer);
    }
    initiator_state
        .dkg_session_state
        .set_node_peer_mappings(&refresh_session_id, node_id_to_peer_id)
        .await;

    // Broadcast SessionInit{is_refresh:true} to all peers so they create their
    // own sessions and enter Phase 1.
    let init_msg = DkgMessage::SessionInit {
        session_id: refresh_session_id,
        threshold: 2,
        total_participants: 3,
        peer_ids: peer_ids.clone(),
        node_id_assignments: node_id_assignments.clone(),
        token_string: String::new(), // refresh bypasses JWT
        kind: SessionKind::Refresh {
            ring_pk_hex: key_string.clone(),
        },
        pss_interval: None,
    };
    for peer_id_str in &peer_ids {
        if let Err(e) = coordinator
            .send_message_to_peer(peer_id_str, init_msg.clone(), Some(refresh_session_id))
            .await
        {
            println!(
                "SessionInit send error (non-fatal): {} — {}",
                peer_id_str, e
            );
        }
    }

    // Kick off Phase 1 on the initiator.
    coordinator
        .initiate_phase1_commitments(refresh_session_id, &peer_ids)
        .await
        .expect("initiate phase 1 for refresh");

    println!("PSS refresh initiated (session_id={})", refresh_session_id);

    // ── Phase C: Wait for refresh to complete ─────────────────────────────────
    // Poll RingPolyState on all three nodes until each has refreshed_at > 0,
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
                    .map(|s| s.refreshed_at > 0)
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

/// Verify that receiving a Share before the sender's Phase 1 commitment has
/// arrived returns `ShareVerificationFailed` — the persistent-stream design
/// guarantees that in production this ordering cannot occur, but the error path
/// is still correct and explicit.
#[tokio::test]
async fn test_share_before_commitment_fails() {
    let db_name = "test_share_before_commitment";
    let db_path = test_db_path(db_name);
    let app_state = Arc::new(create_test_app_state_default(db_name).await);
    let coordinator = DkgCoordinator::new(app_state.clone());

    let session_id: u64 = 77_777;
    coordinator
        .create_session(session_id, 1, 2, 2, DkgRole::Standard)
        .await
        .expect("create session");

    let sender_hex = "deadbeef";
    let all_peer_ids = vec!["aabbccdd".to_string(), sender_hex.to_string()];
    coordinator.set_peer_ids(&session_id, all_peer_ids).await;
    let mut node_peer_map = std::collections::HashMap::new();
    node_peer_map.insert(1u32, "aabbccdd".to_string());
    node_peer_map.insert(2u32, sender_hex.to_string());
    app_state
        .dkg_session_state
        .set_node_peer_mappings(&session_id, node_peer_map)
        .await;

    coordinator
        .initiate_phase1_commitments(session_id, &[])
        .await
        .expect("phase 1 with no peers");

    // Deliver a share without the sender's commitment — should fail immediately.
    let share_msg = DkgMessage::Share {
        session_id,
        from_node_id: 2,
        to_node_id: 1,
        share_value: vec![0u8; 32],
        nonce: [0u8; 16],
    };
    let sender_bytes = hex::decode(sender_hex).unwrap();
    let sender_peer_id = PeerId::from_bytes(&sender_bytes);

    let result = coordinator.handle_message(share_msg, &sender_peer_id).await;
    assert!(
        matches!(
            result,
            Err(crate::dkg::error::DkgError::ShareVerificationFailed(_))
        ),
        "Expected ShareVerificationFailed when commitment is absent, got: {:?}",
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
    let refresh_session_id: u64 = 100;

    // Mark the ring as refreshing — this is what PSS mod.rs does before
    // creating a refresh session.
    let marked = app_state
        .dkg_session_state
        .try_mark_ring_pss(ring_key)
        .await;
    assert!(marked, "should be able to mark a fresh ring as refreshing");

    // Create the refresh session.
    let coordinator = DkgCoordinator::new(app_state.clone());
    coordinator
        .create_session(refresh_session_id, 1, 2, 3, DkgRole::Standard)
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
    let fresh_dkg_session_id: u64 = 200;
    coordinator
        .create_session(fresh_dkg_session_id, 1, 2, 3, DkgRole::Standard)
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
        share_bytes: vec![0xAA; 32],
        public_polynomial: "fresh_poly".to_string(),
        refreshed_at: 1_000,
    };
    fresh_dkg_bundle
        .save_by_ring_key(&app_state.local_storage, ring_key)
        .expect("fresh DKG bundle write should succeed");

    // Simulate Phase 4 of the refresh writing its bundle second (wins).
    let refresh_bundle = crate::ring_state::RingShareBundle {
        share_bytes: vec![0xBB; 32],
        public_polynomial: "refresh_poly".to_string(),
        refreshed_at: 2_000,
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
        stored.share_bytes,
        vec![0xBB; 32],
        "refresh share bytes should be present (last writer wins)"
    );

    cleanup_db(&db_path);
}

// =============================================================================
// coordinator rejects invalid PSS refresh SessionInit messages
//
// These tests confirm that the coordinator enforces the three validation
// checks (sender membership, minimum elapsed time, no concurrent refresh)
// before creating any session state.  They use a single-node app_state with
// pre-populated local storage — no three-node network is required because the
// checks happen before any network I/O.
// =============================================================================

/// Write a minimal `RingShareBundle` with the given `refreshed_at` timestamp.
fn write_last_refresh(
    storage: &impl local_storage::r#trait::LocalStorage,
    ring_pk: &str,
    secs: u64,
) {
    let bundle = crate::ring_state::RingShareBundle {
        share_bytes: vec![],
        public_polynomial: String::new(),
        refreshed_at: secs,
    };
    bundle.save_by_ring_key(storage, ring_pk).unwrap();
}

/// Build a minimal refresh `SessionInit` targeted at `ring_pk`.
fn refresh_session_init(ring_pk: &str, sender_hex: &str) -> DkgMessage {
    let mut node_id_assignments = std::collections::HashMap::new();
    node_id_assignments.insert(sender_hex.to_string(), 1u32);
    DkgMessage::SessionInit {
        session_id: 99_999_001,
        threshold: 1,
        total_participants: 1,
        peer_ids: vec![sender_hex.to_string()],
        node_id_assignments,
        token_string: String::new(),
        kind: SessionKind::Refresh {
            ring_pk_hex: ring_pk.to_string(),
        },
        pss_interval: None,
    }
}

#[tokio::test]
async fn test_refresh_rejected_sender_not_in_ring() {
    let db_name = "test_refresh_rejected_sender_not_in_ring";
    let db_path = test_db_path(db_name);
    let app_state = Arc::new(create_test_app_state_default(db_name).await);

    let ring_pk = "ring_pk";
    // Ring contains only "aabbccdd"; the sender will be "deadbeef".
    write_ring_to_bulletin(
        &app_state.local_storage,
        &app_state.bulletin,
        ring_pk,
        vec!["aabbccdd".to_string()],
        None, // membership check fires before time check
    )
    .await;
    write_last_refresh(&app_state.local_storage, ring_pk, 0); // epoch → enough time has passed

    let sender_bytes = hex::decode("deadbeef").unwrap();
    let sender_peer_id = PeerId::from_bytes(&sender_bytes);
    let coordinator = DkgCoordinator::new(app_state);
    let msg = refresh_session_init(ring_pk, "deadbeef");

    let result = coordinator.handle_message(msg, &sender_peer_id).await;
    assert!(
        matches!(result, Err(crate::dkg::error::DkgError::Unauthorized(_))),
        "Expected Unauthorized for sender not in ring, got: {:?}",
        result
    );
    cleanup_db(&db_path);
}

#[tokio::test]
async fn test_refresh_rejected_too_soon() {
    let db_name = "test_refresh_rejected_too_soon";
    let db_path = test_db_path(db_name);
    let app_state = Arc::new(create_test_app_state_default(db_name).await);

    let ring_pk = "ring_pk";
    let sender_hex = "aabbccdd";
    write_ring_to_bulletin(
        &app_state.local_storage,
        &app_state.bulletin,
        ring_pk,
        vec![sender_hex.to_string()],
        Some(86400), // 24h interval required
    )
    .await;

    // Set last refresh to "now" — 0 seconds have elapsed, below any minimum interval.
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    write_last_refresh(&app_state.local_storage, ring_pk, now_secs);

    let sender_bytes = hex::decode(sender_hex).unwrap();
    let sender_peer_id = PeerId::from_bytes(&sender_bytes);
    let coordinator = DkgCoordinator::new(app_state);
    let msg = refresh_session_init(ring_pk, sender_hex);

    let result = coordinator.handle_message(msg, &sender_peer_id).await;
    assert!(
        matches!(result, Err(crate::dkg::error::DkgError::Unauthorized(_))),
        "Expected Unauthorized for refresh too soon, got: {:?}",
        result
    );
    cleanup_db(&db_path);
}

#[tokio::test]
async fn test_refresh_rejected_already_in_progress() {
    let db_name = "test_refresh_rejected_already_in_progress";
    let db_path = test_db_path(db_name);
    let app_state = Arc::new(create_test_app_state_default(db_name).await);

    let ring_pk = "ring_pk";
    let sender_hex = "aabbccdd";
    write_ring_to_bulletin(
        &app_state.local_storage,
        &app_state.bulletin,
        ring_pk,
        vec![sender_hex.to_string()],
        None, // time check irrelevant; rejected by in-progress flag
    )
    .await;
    write_last_refresh(&app_state.local_storage, ring_pk, 0); // epoch → enough time has passed

    // Pre-mark the ring as already refreshing so the coordinator rejects the second attempt.
    let first_mark = app_state.dkg_session_state.try_mark_ring_pss(ring_pk).await;
    assert!(first_mark, "initial mark should succeed");

    let sender_bytes = hex::decode(sender_hex).unwrap();
    let sender_peer_id = PeerId::from_bytes(&sender_bytes);
    let coordinator = DkgCoordinator::new(app_state);
    let msg = refresh_session_init(ring_pk, sender_hex);

    let result = coordinator.handle_message(msg, &sender_peer_id).await;
    assert!(
        matches!(result, Err(crate::dkg::error::DkgError::Unauthorized(_))),
        "Expected Unauthorized for refresh already in progress, got: {:?}",
        result
    );
    cleanup_db(&db_path);
}

// =============================================================================
// Reshare validation tests
//
// Exercise the reshare code
// path: unknown ring, sender not in old committee, concurrent ceremony blocked.
// Additionally, includes unit tests for the Dealer Phase 4 cleanup path
// (share deletion, ring index removal, PSS flag cleared) and the session-state
// PSS blocking behaviour (try_mark_ring_pss idempotency).
// =============================================================================

/// Build a minimal reshare `SessionInit` that the coordinator can inspect.
///
/// `peer_ids` = old committee, `next_peer_ids` = new committee.
fn reshare_session_init(
    ring_pk: &str,
    peer_ids: Vec<String>,
    next_peer_ids: Vec<String>,
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
            next_peer_ids,
            new_threshold,
            bulletin_post_id: String::new(),
        },
        pss_interval: None,
    }
}

/// `try_mark_ring_pss` is idempotent: marking the same ring twice returns false,
/// and after unmark it can be marked again.
#[tokio::test]
async fn test_rings_pss_blocks_refresh_and_reshare_equally() {
    use crate::dkg::session_state::SessionStateManager;
    let manager: SessionStateManager<DkgImpl> = SessionStateManager::new();
    let ring_pk = "ring_pss_idempotent_test";

    let first = manager.try_mark_ring_pss(ring_pk).await;
    assert!(first, "first mark should succeed");

    let second = manager.try_mark_ring_pss(ring_pk).await;
    assert!(!second, "second mark on same ring must return false");

    manager.unmark_ring_pss(ring_pk).await;
    let third = manager.try_mark_ring_pss(ring_pk).await;
    assert!(third, "mark after unmark should succeed");
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

/// Reshare `SessionInit` where the ring is known but the sender is not listed in
/// the ring's old committee (`RingPayload::peer_ids`) must be rejected.
#[tokio::test]
async fn test_reshare_session_init_rejects_sender_not_in_old_committee() {
    let db_name = "test_reshare_rejects_sender_not_in_committee";
    let db_path = test_db_path(db_name);
    let app_state = Arc::new(create_test_app_state_default(db_name).await);

    let ring_pk = "reshare_ring";
    // Ring contains "aabbccdd"; sender will be "deadbeef" (not a member).
    // Bulletin must pre-announce next_peer_ids and new_threshold so checks 3 & 4
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
    // Bulletin must pre-announce next_peer_ids and new_threshold (matching what the
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
    let marked = app_state.dkg_session_state.try_mark_ring_pss(ring_pk).await;
    assert!(marked, "initial mark should succeed");

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
        .create_session(session_id, 1, 1, 3, DkgRole::Dealer)
        .await
        .expect("create_session should succeed");

    app_state
        .dkg_session_state
        .set_session_kind(
            &session_id,
            SessionKind::Reshare {
                ring_pk_hex: ring_pk.to_string(),
                next_peer_ids: vec!["00112233".to_string()],
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
        .create_session(session_id, 1, 1, 3, DkgRole::Dealer)
        .await
        .expect("create_session should succeed");

    app_state
        .dkg_session_state
        .set_session_kind(
            &session_id,
            SessionKind::Reshare {
                ring_pk_hex: ring_pk.to_string(),
                next_peer_ids: vec!["00112233".to_string()],
                new_threshold: 1,
                bulletin_post_id: String::new(),
            },
        )
        .await;

    // Mark the ring as having an active PSS ceremony.
    let marked = app_state.dkg_session_state.try_mark_ring_pss(ring_pk).await;
    assert!(marked, "PSS flag should be markable before Phase 4");

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
//   • proposed `next_peer_ids` must match `RingPayload::next_peer_ids` when set
//   • proposed `new_threshold` must match `RingPayload::new_threshold` when set
// =============================================================================

/// Post a `RingPayload` with caller-supplied `next_peer_ids` / `new_threshold`
/// and seed `RingIndex` so the coordinator can find the ring.
async fn write_ring_with_announced_reshare(
    app_state: &crate::app_state::AppState<crypto::DkgImpl>,
    ring_pk: &str,
    peer_ids: Vec<String>,
    announced_next_peer_ids: Option<Vec<String>>,
    announced_new_threshold: Option<u32>,
) {
    use crate::constants::BULLETIN_RING_NAMESPACE;
    use crate::ring_state::RingIndexEntry;
    use local_storage::r#trait::LocalStorageKeys;

    let payload = RingPayload {
        ring_pk: ring_pk.to_string(),
        peer_ids,
        next_peer_ids: announced_next_peer_ids,
        new_threshold: announced_new_threshold,
        threshold: 2,
        pss_interval: None,
    };
    let bytes = serde_json::to_vec(&payload).unwrap();
    app_state
        .bulletin
        .post(
            BULLETIN_RING_NAMESPACE.to_string(),
            bytes.clone(),
            vec![],
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
    });
    app_state
        .local_storage
        .set(
            LocalStorageKeys::RingIndex,
            serde_json::to_vec(&ring_index).unwrap(),
        )
        .unwrap();
}

/// Reshare `SessionInit` whose `next_peer_ids` differs from the bulletin-announced
/// committee must be rejected with `Unauthorized`.
#[tokio::test]
async fn test_reshare_session_init_rejects_mismatched_next_peer_ids() {
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
        "Expected Unauthorized for mismatched next_peer_ids, got: {:?}",
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

    // Bulletin pre-announces new_threshold = 2, with a matching next_peer_ids.
    // next_peer_ids must also be set (matching the proposal) so check 3 passes
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
//   • next_peer_ids must be non-empty
//   • new_threshold must be in [1, len(next_peer_ids)]
// No bulletin entry is needed because the checks fire before the bulletin lookup.
// =============================================================================

/// Reshare `SessionInit` for a ring whose bulletin entry has no `next_peer_ids`
/// pre-announced must be rejected — the ring has not been authorised for reshare on-chain.
#[tokio::test]
async fn test_reshare_session_init_rejects_no_bulletin_announcement() {
    let db_name = "test_reshare_rejects_no_announcement";
    let db_path = test_db_path(db_name);
    let app_state = Arc::new(create_test_app_state_default(db_name).await);

    let ring_pk = "reshare_ring";
    let sender_hex = "aabbccdd";
    // Write a ring payload with no reshare announcement (next_peer_ids and new_threshold absent).
    write_ring_with_announced_reshare(
        &app_state,
        ring_pk,
        vec![sender_hex.to_string()],
        None, // no pre-announced committee
        None, // no pre-announced threshold
    )
    .await;

    let sender_bytes = hex::decode(sender_hex).unwrap();
    let sender_peer_id = PeerId::from_bytes(&sender_bytes);
    let coordinator = DkgCoordinator::new(app_state);
    let msg = reshare_session_init(
        ring_pk,
        vec![sender_hex.to_string()],
        vec!["00112233".to_string()],
        1,
    );
    let result = coordinator.handle_message(msg, &sender_peer_id).await;
    assert!(
        matches!(result, Err(crate::dkg::error::DkgError::Unauthorized(_))),
        "Expected Unauthorized when bulletin has no reshare announcement, got: {:?}",
        result
    );
    cleanup_db(&db_path);
}

/// Reshare `SessionInit` with an empty `next_peer_ids` must be rejected with
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
        "Expected InvalidInput for empty next_peer_ids, got: {:?}",
        result
    );
    cleanup_db(&db_path);
}

/// Reshare `SessionInit` with `new_threshold > len(next_peer_ids)` must be
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
            create_router_with_dkg_handler::<DkgImpl>(&state.network, arc_state)
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
    sorted_next_peer_ids: &[String],
    new_threshold: u32,
    bulletin: &DummyBulletin,
) -> String {
    use bulletin::r#trait::Bulletin as BulletinTrait;

    let payload = RingPayload {
        ring_pk: key_string.to_string(),
        peer_ids: old_peer_ids.to_vec(),
        threshold: old_threshold,
        next_peer_ids: Some(sorted_next_peer_ids.to_vec()),
        new_threshold: Some(new_threshold),
        pss_interval: None,
    };
    let bytes = serde_json::to_vec(&payload).unwrap();

    bulletin
        .post(
            crate::constants::BULLETIN_RING_NAMESPACE.to_string(),
            bytes.clone(),
            vec![],
            None,
        )
        .await
        .expect("post reshare announcement to bulletin");

    let new_post_id = bulletin
        .get_post_id(crate::constants::BULLETIN_RING_NAMESPACE, &bytes)
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
    sorted_next_peer_ids: &[String],
    new_threshold: u32,
    bulletin_post_id: &str,
    new_committee_states: &[&crate::app_state::AppState<DkgImpl>],
) {
    let session_id: u64 = rand::random();

    // Snapshot share bytes before reshare so we can detect when they change.
    let pre_snapshots: Vec<Option<Vec<u8>>> = new_committee_states
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
            next_peer_ids: sorted_next_peer_ids.to_vec(),
            new_threshold,
            bulletin_post_id: bulletin_post_id.to_string(),
        },
        pss_interval: None,
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
        coordinator
            .send_message_to_peer(peer_addr, init_msg.clone(), Some(session_id))
            .await
            .expect("send SessionInit to union peer");
    }

    // Start Phase 1 on the initiator (generates polynomial + broadcasts commitment).
    coordinator
        .initiate_phase1_commitments(session_id, union_peer_ids)
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
    let token = test_keys.create_dkg_jwt(2, &peer_ids, None).expect("JWT");
    alice_service
        .start_dkg(
            create_authenticated_request(
                StartDkgRequest {
                    threshold: 2,
                    peer_ids: peer_ids.clone(),
                    pss_interval: None,
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
    let mut sorted_next = peer_ids.clone();
    sorted_next.sort();
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
        &sorted_next,
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
        &sorted_next,
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
    let token = test_keys.create_dkg_jwt(2, &peer_ids, None).expect("JWT");
    alice_service
        .start_dkg(
            create_authenticated_request(
                StartDkgRequest {
                    threshold: 2,
                    peer_ids: peer_ids.clone(),
                    pss_interval: None,
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
    let mut sorted_next = vec![
        network.alice.address.clone(),
        network.bob.address.clone(),
        dave.address.clone(),
    ];
    sorted_next.sort();

    let mut union_peers = peer_ids.clone();
    for p in &sorted_next {
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
        &sorted_next,
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
        &union_peers,
        &key_string,
        &sorted_next,
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
    let token = test_keys.create_dkg_jwt(2, &peer_ids, None).expect("JWT");
    alice_service
        .start_dkg(
            create_authenticated_request(
                StartDkgRequest {
                    threshold: 2,
                    peer_ids: peer_ids.clone(),
                    pss_interval: None,
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
    let mut sorted_next = vec![
        network.alice.address.clone(),
        network.bob.address.clone(),
        network.charlie.address.clone(),
        dave.address.clone(),
    ];
    sorted_next.sort();

    let mut union_peers = peer_ids.clone();
    for p in &sorted_next {
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
        &sorted_next,
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
        &sorted_next,
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
    let token = test_keys.create_dkg_jwt(2, &peer_ids, None).expect("JWT");
    alice_service
        .start_dkg(
            create_authenticated_request(
                StartDkgRequest {
                    threshold: 2,
                    peer_ids: peer_ids.clone(),
                    pss_interval: None,
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
    let mut sorted_next = vec![network.alice.address.clone(), network.bob.address.clone()];
    sorted_next.sort();

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
        &sorted_next,
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
        &sorted_next,
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
    let token = test_keys.create_dkg_jwt(2, &peer_ids, None).expect("JWT");
    alice_service
        .start_dkg(
            create_authenticated_request(
                StartDkgRequest {
                    threshold: 2,
                    peer_ids: peer_ids.clone(),
                    pss_interval: None,
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
    let mut sorted_next = vec![
        dave.address.clone(),
        eve.address.clone(),
        frank.address.clone(),
    ];
    sorted_next.sort();

    let mut union_peers = peer_ids.clone();
    for p in &sorted_next {
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
        &sorted_next,
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
        &sorted_next,
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
