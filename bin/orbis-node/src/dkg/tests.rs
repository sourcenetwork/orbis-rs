use crate::dkg::coordinator::DkgCoordinator;
use crate::helpers::helpers::session_id_string_to_u64;
use crate::helpers::test_helpers::{
    create_test_app_state, create_test_app_state_default, setup_three_node_network,
};
use crate::{
    dkg_service::{dkg_service_server::DkgService, StartDkgRequest},
    DkgServiceImpl,
};
use crypto::r#trait::Dkg;
use local_storage::r#trait::{LocalStorage, LocalStorageKeys};
use std::sync::Arc;
use tokio::time::{sleep, Duration};
use tonic::{Request, Response};
use tracing_subscriber;

// Concrete crypto implementations for tests
use crypto::bls12_381::dkg::DKGNode;
type DkgImpl = DKGNode;

/// Unit test: Test start_dkg with empty participant list returns error
#[tokio::test]
async fn test_start_dkg_empty_participants() {
    let app_state = create_test_app_state_default().await;
    let service = DkgServiceImpl::<DkgImpl>::new(app_state);

    let request = StartDkgRequest {
        session_id: "empty-session".to_string(),
        threshold: 0,
        peer_ids: vec![], // Empty - should result in error
    };

    let tonic_request = Request::new(request.clone());
    let result = service.start_dkg(tonic_request).await;

    // Should fail with 0 participants (validation error)
    assert!(result.is_err(), "start_dkg should fail with 0 participants");
}

/// Integration test: Three nodes connect to each other
///
/// This test spins up three nodes (Alice, Bob, Charlie), starts routers for all,
/// and has Alice send a StartDkgRequest including all peer IDs so they can all
/// participate in the DKG.
#[tokio::test]
async fn test_three_nodes_connect() {
    // Set up three-node network with routers started for all nodes
    let mut network = setup_three_node_network(true).await;

    // Get all peer IDs (including Alice) for participation
    let peer_ids = network.get_all_peer_ids();
    println!("Peer IDs for connection: {:?}", peer_ids);

    // Create Alice's service (clone app_state to avoid move)
    let alice_service = DkgServiceImpl::<DkgImpl>::new(network.alice.app_state.clone());

    // Alice sends StartDkgRequest with Bob and Charlie's peer IDs
    let request = StartDkgRequest {
        session_id: "three-node-session".to_string(),
        threshold: 2,
        peer_ids,
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
/// This test verifies that if a node receives invalid peer IDs,
/// the gRPC service validates them and returns an error before attempting connections.
#[tokio::test]
async fn test_start_dkg_fails_on_connection_failure() {
    // Create only Alice node
    let alice_state = create_test_app_state(Some("127.0.0.1:0".to_string())).await;

    // Create Alice's service
    let alice_service = DkgServiceImpl::<DkgImpl>::new(alice_state);

    // Create a request with invalid peer IDs that fail validation
    // Using obviously invalid peer IDs (not valid hex-encoded Ed25519 public keys)
    let request = StartDkgRequest {
        session_id: "failure-test-session".to_string(),
        threshold: 2,
        peer_ids: vec![
            "invalid-peer-id-1".to_string(),
            "invalid-peer-id-2".to_string(),
        ],
    };

    println!("Alice sending StartDkgRequest with invalid peer IDs...");
    let tonic_request = Request::new(request);
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
}

/// Test: Verify that StartDkg succeeds when connecting to valid peers
///
/// This test verifies that if a node can connect to all requested peer IDs,
/// the gRPC service succeeds.
#[tokio::test]
async fn test_start_dkg_succeeds_on_all_connections() {
    // Initialize tracing for debugging
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_test_writer()
        .try_init();

    // Set up three-node network with routers started for all nodes
    let mut network = setup_three_node_network(true).await;

    // Get all peer IDs (including Alice) for participation
    let peer_ids = network.get_all_peer_ids();
    println!("Peer IDs for connection: {:?}", peer_ids);

    // Create Alice's service
    let alice_service = DkgServiceImpl::<DkgImpl>::new(network.alice.app_state.clone());

    // Alice sends StartDkgRequest with all peer IDs (including herself)
    let request = StartDkgRequest {
        session_id: "success-test-session".to_string(),
        threshold: 2,
        peer_ids,
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
    let session_id =
        session_id_string_to_u64(&request.session_id).expect("Failed to convert session_id to u64");

    // Wait up to 10 seconds for DKG to complete
    let check_interval = Duration::from_millis(1000);
    let max_wait = Duration::from_secs(50);

    let start = std::time::Instant::now();
    println!("Looking for session_id: {}", session_id);
    loop {
        // Check if Alice's session has completed Phase 4
        // We can check by trying to get the session and see if we can compute the aggregate key
        let alice_coordinator = DkgCoordinator::new(Arc::new(network.alice.app_state.clone()));

        // Debug: check session count
        let session_count = network.alice.app_state.session_count().await;
        if start.elapsed().as_secs() % 5 == 0 {
            println!(
                "Session count: {}, elapsed: {:?}",
                session_count,
                start.elapsed()
            );
        }

        // Try to get the session and check if we can compute aggregate key (indicates Phase 4 complete)
        if let Some(session) = alice_coordinator.get_session(&session_id).await {
            println!("Found session!");
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
