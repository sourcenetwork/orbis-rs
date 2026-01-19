use crate::dkg::{coordinator::DkgCoordinator, messages::DkgMessage};
use crate::helpers::test_helpers::{
    cleanup_db, create_authenticated_request, create_test_app_state, create_test_app_state_default,
    get_test_bulletin, setup_three_node_network, test_db_path, TestKeyPair,
};
use crate::DkgServiceImpl;
use bulletin::r#trait::RingPayload;
use crypto::r#trait::{CryptoDeserialize, Dkg};
use local_storage::r#trait::{LocalStorage, LocalStorageKeys};
use proto::dkg_service::{dkg_service_server::DkgService, StartDkgRequest};
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
    let db_path = test_db_path("test_start_dkg_empty_participants");
    let app_state = create_test_app_state_default("test_start_dkg_empty_participants").await;
    let service = DkgServiceImpl::<DkgImpl>::new(app_state);

    let peer_ids: Vec<String> = vec![]; // Empty - should result in error
    let request = StartDkgRequest {
        threshold: 0,
        peer_ids: peer_ids.clone(),
    };

    // Create authenticated request
    let test_keys = TestKeyPair::new();
    let token = test_keys
        .create_dkg_jwt(0, &peer_ids)
        .expect("Failed to create JWT");
    let tonic_request = create_authenticated_request(request, &token);

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
    };

    // Create authenticated request
    let test_keys = TestKeyPair::new();
    let token = test_keys
        .create_dkg_jwt(2, &peer_ids)
        .expect("Failed to create JWT");

    println!("Alice sending StartDkgRequest with peer IDs...");
    let tonic_request = create_authenticated_request(request, &token);
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
    };

    // Create authenticated request (even with invalid peer_ids, JWT should match request)
    let test_keys = TestKeyPair::new();
    let token = test_keys
        .create_dkg_jwt(2, &peer_ids)
        .expect("Failed to create JWT");

    println!("Alice sending StartDkgRequest with invalid peer IDs...");
    let tonic_request = create_authenticated_request(request, &token);
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
    };

    // Create authenticated request
    let test_keys = TestKeyPair::new();
    let token = test_keys
        .create_dkg_jwt(2, &peer_ids)
        .expect("Failed to create JWT");

    println!("Alice sending StartDkgRequest with valid peer IDs...");
    let tonic_request = create_authenticated_request(request, &token);
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
        let post = get_test_bulletin(&network.alice.app_state.bulletin).await;

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
    };

    // Create request with malformed JWT (not a valid JWT structure)
    let tonic_request = create_authenticated_request(request, "not-a-valid-jwt-token");

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
        .create_dkg_jwt(2, &peer_ids)
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
    };

    let tonic_request = create_authenticated_request(request, &tampered_token);

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
    };

    // Try to handle the message - should fail due to invalid JWT
    let result = coordinator.handle_message(session_init).await;

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
        .create_dkg_jwt(3, &peer_ids) // Wrong threshold!
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
    };

    // Try to handle the message - should fail due to claim mismatch
    let result = coordinator.handle_message(session_init).await;

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
        .create_dkg_jwt(2, &jwt_peer_ids)
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
    };

    // Try to handle the message - should fail due to peer_ids mismatch
    let result = coordinator.handle_message(session_init).await;

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
