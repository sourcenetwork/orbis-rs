use crate::dkg::coordinator::DkgCoordinator;
use crate::helpers::test_helpers::{
    create_test_app_state, create_test_app_state_default, setup_three_node_network,
};
use crate::{
    crypto_service::{crypto_service_server::CryptoService, StartDkgRequest},
    CryptoServiceImpl,
};
use crypto::r#trait::Dkg;
use local_storage::r#trait::{LocalStorage, LocalStorageKeys};
use std::{
    collections::{hash_map::DefaultHasher, HashMap},
    hash::{Hash, Hasher},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::time::{sleep, Duration};
use tonic::{Request, Response};

/// Unit test: Test start_dkg directly
#[tokio::test]
async fn test_start_dkg_unit() {
    let app_state = create_test_app_state_default().await;
    let service = CryptoServiceImpl::new(app_state);

    let request = StartDkgRequest {
        session_id: "test-session-123".to_string(),
        threshold: 2,
        total_participants: 3,
        participant_ids: vec![
            "participant-1".to_string(),
            "participant-2".to_string(),
            "participant-3".to_string(),
        ],
        parameters: {
            let mut map = HashMap::new();
            map.insert("key_type".to_string(), "BLS12_381".to_string());
            map.insert("curve".to_string(), "bls12_381".to_string());
            map
        },
        peer_ids: vec![], // Empty for unit tests - no actual connections needed
    };

    let tonic_request = Request::new(request.clone());
    let result = service.start_dkg(tonic_request).await;

    assert!(result.is_ok(), "start_dkg should succeed");

    let response: Response<_> = result.unwrap();
    let inner = response.into_inner();

    // Verify response fields
    assert_eq!(inner.session_id, request.session_id);
    assert_eq!(inner.status, "started");
    assert!(inner.message.contains("DKG session started"));
    assert!(inner.message.contains("threshold 2"));
    assert!(inner.message.contains("3 participants"));

    // Verify timestamp is reasonable (within last minute)
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    assert!(
        inner.created_at <= now && inner.created_at >= now - 60,
        "created_at should be recent, got: {}, now: {}",
        inner.created_at,
        now
    );
}

/// Unit test: Test start_dkg with minimal request
#[tokio::test]
async fn test_start_dkg_minimal() {
    let app_state = create_test_app_state_default().await;
    let service = CryptoServiceImpl::new(app_state);

    let request = StartDkgRequest {
        session_id: "minimal-session".to_string(),
        threshold: 1,
        total_participants: 1,
        participant_ids: vec!["single-participant".to_string()],
        parameters: HashMap::new(),
        peer_ids: vec![], // Empty for unit tests - no actual connections needed
    };

    let tonic_request = Request::new(request.clone());
    let result = service.start_dkg(tonic_request).await;

    assert!(
        result.is_ok(),
        "start_dkg should succeed with minimal request"
    );

    let response: Response<_> = result.unwrap();
    let inner = response.into_inner();

    assert_eq!(inner.session_id, request.session_id);
    assert_eq!(inner.status, "started");
    assert!(inner.message.contains("threshold 1"));
    assert!(inner.message.contains("1 participants"));
}

/// Unit test: Test start_dkg with empty participant list
#[tokio::test]
async fn test_start_dkg_empty_participants() {
    let app_state = create_test_app_state_default().await;
    let service = CryptoServiceImpl::new(app_state);

    let request = StartDkgRequest {
        session_id: "empty-session".to_string(),
        threshold: 0,
        total_participants: 0,
        participant_ids: vec![],
        parameters: HashMap::new(),
        peer_ids: vec![], // Empty for unit tests - no actual connections needed
    };

    let tonic_request = Request::new(request.clone());
    let result = service.start_dkg(tonic_request).await;

    // Should still succeed even with empty participants
    assert!(result.is_ok(), "start_dkg should handle empty participants");

    let response: Response<_> = result.unwrap();
    let inner = response.into_inner();

    assert_eq!(inner.session_id, request.session_id);
    assert_eq!(inner.status, "started");
    assert!(inner.message.contains("threshold 0"));
    assert!(inner.message.contains("0 participants"));
}

/// Unit test: Test start_dkg with custom parameters
#[tokio::test]
async fn test_start_dkg_with_parameters() {
    let app_state = create_test_app_state_default().await;
    let service = CryptoServiceImpl::new(app_state);

    let mut parameters = HashMap::new();
    parameters.insert("algorithm".to_string(), "ECDSA".to_string());
    parameters.insert("key_size".to_string(), "256".to_string());
    parameters.insert("curve".to_string(), "secp256k1".to_string());

    let request = StartDkgRequest {
        session_id: "parameterized-session".to_string(),
        threshold: 3,
        total_participants: 5,
        participant_ids: vec![
            "p1".to_string(),
            "p2".to_string(),
            "p3".to_string(),
            "p4".to_string(),
            "p5".to_string(),
        ],
        parameters: parameters.clone(),
        peer_ids: vec![], // Empty for unit tests - no actual connections needed
    };

    let tonic_request = Request::new(request.clone());
    let result = service.start_dkg(tonic_request).await;

    assert!(result.is_ok(), "start_dkg should succeed with parameters");

    let response: Response<_> = result.unwrap();
    let inner = response.into_inner();

    assert_eq!(inner.session_id, request.session_id);
    assert_eq!(inner.status, "started");
    assert!(inner.message.contains("threshold 3"));
    assert!(inner.message.contains("5 participants"));
}

/// Integration test: Three nodes connect to each other
///
/// This test spins up three nodes (Alice, Bob, Charlie), starts routers for Bob and Charlie,
/// and has Alice send a StartDkgRequest with Bob and Charlie's peer IDs so they can all
/// establish connections to each other.
#[tokio::test]
async fn test_three_nodes_connect() {
    // Set up three-node network with routers started for Bob and Charlie
    let mut network = setup_three_node_network(true).await;

    // Get peer IDs for connection (Bob and Charlie)
    let peer_ids = network.get_peer_ids_for_connection();
    println!("Peer IDs for connection: {:?}", peer_ids);

    // Create Alice's service (clone app_state to avoid move)
    let alice_service = CryptoServiceImpl::new(network.alice.app_state.clone());

    // Alice sends StartDkgRequest with Bob and Charlie's peer IDs
    let request = StartDkgRequest {
        session_id: "three-node-session".to_string(),
        threshold: 2,
        total_participants: 3,
        participant_ids: vec![
            "alice".to_string(),
            "bob".to_string(),
            "charlie".to_string(),
        ],
        peer_ids,
        parameters: {
            let mut map = HashMap::new();
            map.insert("key_type".to_string(), "BLS12_381".to_string());
            map.insert("curve".to_string(), "bls12_381".to_string());
            map
        },
    };

    println!("Alice sending StartDkgRequest with peer IDs...");
    let tonic_request = Request::new(request.clone());
    let result = alice_service.start_dkg(tonic_request).await;

    assert!(result.is_ok(), "start_dkg should succeed");

    let response: Response<_> = result.unwrap();
    let inner = response.into_inner();

    // Verify response
    assert_eq!(inner.session_id, request.session_id);
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

    println!("Test completed successfully!");
}

/// Test: Verify that StartDkg fails when unable to connect to all requested peers
///
/// This test verifies that if a node cannot connect to all requested peer IDs,
/// the gRPC service returns an error and stops execution.
#[tokio::test]
async fn test_start_dkg_fails_on_connection_failure() {
    // Create only Alice node
    let alice_state = create_test_app_state(Some(1), Some("127.0.0.1:0".to_string())).await;

    // Create Alice's service
    let alice_service = CryptoServiceImpl::new(alice_state);

    // Create a request with invalid peer IDs that won't connect
    // Using obviously invalid peer IDs that won't resolve
    let request = StartDkgRequest {
        session_id: "failure-test-session".to_string(),
        threshold: 2,
        total_participants: 3,
        participant_ids: vec![
            "alice".to_string(),
            "bob".to_string(),
            "charlie".to_string(),
        ],
        peer_ids: vec![
            "invalid-peer-id-1".to_string(),
            "invalid-peer-id-2".to_string(),
        ],
        parameters: {
            let mut map = HashMap::new();
            map.insert("key_type".to_string(), "BLS12_381".to_string());
            map.insert("curve".to_string(), "bls12_381".to_string());
            map
        },
    };

    println!("Alice sending StartDkgRequest with invalid peer IDs...");
    let tonic_request = Request::new(request);
    let result = alice_service.start_dkg(tonic_request).await;

    // Verify that the request fails with a gRPC error
    assert!(
        result.is_err(),
        "start_dkg should fail when unable to connect to all peers"
    );

    let status = result.unwrap_err();
    assert_eq!(
        status.code(),
        tonic::Code::FailedPrecondition,
        "Error code should be FailedPrecondition"
    );
    assert!(
        status
            .message()
            .contains("Failed to connect to all required peers"),
        "Error message should indicate connection failure"
    );
    assert!(
        status.message().contains("Connected to 0/2 peers"),
        "Error message should show connection statistics"
    );

    println!("Test passed: Service correctly returned error for failed connections");
}

/// Test: Verify that StartDkg succeeds when connecting to valid peers
///
/// This test verifies that if a node can connect to all requested peer IDs,
/// the gRPC service succeeds.
#[tokio::test]
async fn test_start_dkg_succeeds_on_all_connections() {
    // Set up three-node network with routers started for Bob and Charlie
    let mut network = setup_three_node_network(true).await;

    // Get peer IDs for connection (Bob and Charlie)
    let peer_ids = network.get_peer_ids_for_connection();
    println!("Peer IDs for connection: {:?}", peer_ids);

    // Create Alice's service
    let alice_service = CryptoServiceImpl::new(network.alice.app_state.clone());

    // Alice sends StartDkgRequest with Bob and Charlie's peer IDs
    let request = StartDkgRequest {
        session_id: "success-test-session".to_string(),
        threshold: 2,
        total_participants: 3,
        participant_ids: vec![
            "alice".to_string(),
            "bob".to_string(),
            "charlie".to_string(),
        ],
        peer_ids,
        parameters: {
            let mut map = HashMap::new();
            map.insert("key_type".to_string(), "BLS12_381".to_string());
            map.insert("curve".to_string(), "bls12_381".to_string());
            map
        },
    };

    println!("Alice sending StartDkgRequest with valid peer IDs...");
    let tonic_request = Request::new(request.clone());
    let result = alice_service.start_dkg(tonic_request).await;

    // Verify that the request succeeds when all connections are successful
    assert!(
        result.is_ok(),
        "start_dkg should succeed when all peer connections are successful"
    );

    let response: Response<_> = result.unwrap();
    let inner = response.into_inner();

    // Verify response
    assert_eq!(inner.session_id, request.session_id);
    assert_eq!(inner.status, "started");
    assert!(inner.message.contains("DKG session started"));

    // Wait for DKG to complete (all nodes should reach Phase 4)
    // Convert session_id string to u64 (same as in service.rs)
    let mut hasher = DefaultHasher::new();
    request.session_id.hash(&mut hasher);
    let session_id = hasher.finish();

    // Wait up to 10 seconds for DKG to complete
    let check_interval = Duration::from_millis(1000);
    let max_wait = Duration::from_secs(50);

    let start = std::time::Instant::now();
    loop {
        // Check if Alice's session has completed Phase 4
        // We can check by trying to get the session and see if we can compute the aggregate key
        let alice_coordinator = DkgCoordinator::new(Arc::new(network.alice.app_state.clone()));

        // Try to get the session and check if we can compute aggregate key (indicates Phase 4 complete)
        if let Some(session) = alice_coordinator.get_session(&session_id).await {
            let session_guard = session.read().await;
            let key = session_guard.compute_aggregate_public_key();
            // If we can compute aggregate key, Phase 4 is complete
            if let Ok(aggregate_key_alice) = key {
                println!("Alice computed aggregate key: {:?}", aggregate_key_alice);

                // Get Bob and Charlie's aggregate public keys
                let bob_coordinator = DkgCoordinator::new(Arc::new(network.bob.app_state.clone()));
                let charlie_coordinator =
                    DkgCoordinator::new(Arc::new(network.charlie.app_state.clone()));

                let bob_session = bob_coordinator.get_session(&session_id).await;
                let charlie_session = charlie_coordinator.get_session(&session_id).await;

                if let (Some(bob_sess), Some(charlie_sess)) = (bob_session, charlie_session) {
                    let bob_guard = bob_sess.read().await;
                    let charlie_guard = charlie_sess.read().await;

                    let aggregate_key_bob = bob_guard.compute_aggregate_public_key();
                    let aggregate_key_charlie = charlie_guard.compute_aggregate_public_key();

                    if let (Ok(agg_bob), Ok(agg_charlie)) =
                        (aggregate_key_bob, aggregate_key_charlie)
                    {
                        println!("Bob computed aggregate key: {:?}", agg_bob);
                        println!("Charlie computed aggregate key: {:?}", agg_charlie);

                        // Test that all nodes computed the same aggregate public key
                        assert_eq!(
                            aggregate_key_alice, agg_bob,
                            "Alice and Bob should have the same aggregate public key"
                        );
                        assert_eq!(
                            aggregate_key_alice, agg_charlie,
                            "Alice and Charlie should have the same aggregate public key"
                        );

                        println!("Success! All nodes computed the same aggregate public key");

                        // Verify that each node stored its secret share in local storage
                        let key_string = aggregate_key_alice.to_string();
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
                }
            }
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

    println!(
        "Test passed: Service correctly succeeded when all connections worked and DKG completed"
    );
}
