use crate::constants::MAX_DKG_SESSIONS;
use crate::dkg::v0::service::DkgServiceImpl;
use crate::dkg::v0::{
    coordinator::DkgCoordinator,
    error::DkgError,
    messages::{DkgMessage, SessionKind},
    session_state::{CreateSessionOutcome, DkgMessageType, DkgPhase, SessionStateManager},
};
use crate::helpers::helpers::extract_node_part;
use crate::helpers::test_helpers::TEST_FRESH_DKG_RING_ID;
use crate::helpers::test_helpers::{
    cleanup_db, create_authenticated_request, create_test_app_state, create_test_app_state_default,
    create_test_app_state_with_bulletin, get_test_ring_post, setup_three_node_network,
    test_db_path, TestKeyPair,
};
use crate::ring_state::RingIndexEntry;
use bulletin::dummy::DummyBulletin;
use bulletin::r#trait::{NodeInfo, RingPayload};
use crypto::r#trait::{CryptoDeserialize, Dkg, DkgRole};
use local_storage::r#trait::{LocalStorage, LocalStorageKeys};
use proto::v0::dkg::{dkg_service_server::DkgService, StartDkgRequest};
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

    let request = StartDkgRequest {
        ring_id: TEST_FRESH_DKG_RING_ID.to_string(),
    };

    // Create authenticated request
    let test_keys = TestKeyPair::new();
    let token = test_keys
        .create_dkg_jwt(TEST_FRESH_DKG_RING_ID)
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
        ring_id: TEST_FRESH_DKG_RING_ID.to_string(),
    };

    // Create authenticated request
    let test_keys = TestKeyPair::new();
    let token = test_keys
        .create_dkg_jwt(TEST_FRESH_DKG_RING_ID)
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

/// Test: start_dkg fails closed when the ring does not exist on the bulletin.
///
/// In the new flow the bulletin is read before any participant resolution happens,
/// so a missing ring is the first meaningful rejection after JWT validation.
#[tokio::test]
async fn test_start_dkg_ring_not_found() {
    let db_name = "test_start_dkg_ring_not_found";
    let db_path = test_db_path(db_name);

    // DummyBulletin has NodeInfo for this node but no ring seeded.
    let app_state =
        create_test_app_state(Some("127.0.0.1:0".to_string()), true, true, db_name).await;
    let service = DkgServiceImpl::<DkgImpl>::new(app_state);

    let test_keys = TestKeyPair::new();
    let token = test_keys
        .create_dkg_jwt(TEST_FRESH_DKG_RING_ID)
        .expect("Failed to create JWT");

    let tonic_request = create_authenticated_request(
        StartDkgRequest {
            ring_id: TEST_FRESH_DKG_RING_ID.to_string(),
        },
        &token,
    )
    .unwrap();

    let result = service.start_dkg(tonic_request).await;

    assert!(
        result.is_err(),
        "start_dkg should fail when ring does not exist"
    );
    let status = result.unwrap_err();
    assert_eq!(
        status.code(),
        tonic::Code::FailedPrecondition,
        "ring not found should return FailedPrecondition: {}",
        status.message()
    );
    assert!(
        status.message().contains("not found"),
        "error message should indicate ring not found: {}",
        status.message()
    );

    cleanup_db(&db_path);
}

/// Test: start_dkg returns Unavailable when it cannot reach a ring participant.
///
/// Seeds a ring whose sole participant has a peer_id that passes format validation
/// but fails at iroh's Ed25519 key parse (or immediately refuses at port 1).
/// Either path produces DkgError::NetworkConnection → Unavailable.
#[tokio::test]
async fn test_start_dkg_fails_on_connection_failure() {
    let db_name = "test_start_dkg_fails_on_connection_failure";
    let db_path = test_db_path(db_name);

    let bulletin = Arc::new(DummyBulletin::new().await.expect("DummyBulletin::new"));
    let other_node_key = "unreachable-node-key".to_string();
    // 64 hex chars (passes validate_peer_id) + port 1 (immediately refused).
    let unreachable_peer_id = format!("{}@127.0.0.1:1", "aa".repeat(32));

    bulletin
        .set_ring(
            TEST_FRESH_DKG_RING_ID.to_string(),
            RingPayload {
                upgrade_info: Default::default(),
                ring_pk: String::new(),
                peer_node_keys: vec![other_node_key.clone()],
                new_peer_node_keys: None,
                new_threshold: None,
                threshold: 1,
                pss_interval: 86400,
                block_number_nonce: 0,
                policy_id: Some("test-policy".to_string()),
            },
        )
        .expect("seed ring");
    bulletin
        .set_node_info(
            other_node_key,
            NodeInfo {
                peer_id: unreachable_peer_id,
                controller_key: "controller".to_string(),
                whitelisted_policy_ids: vec![],
                whitelisted_ring_ids: vec![],
            },
        )
        .expect("seed NodeInfo for unreachable peer");

    let app_state = create_test_app_state_with_bulletin(None, true, bulletin, db_name).await;
    let service = DkgServiceImpl::<DkgImpl>::new(app_state);

    let test_keys = TestKeyPair::new();
    let token = test_keys
        .create_dkg_jwt(TEST_FRESH_DKG_RING_ID)
        .expect("Failed to create JWT");

    let tonic_request = create_authenticated_request(
        StartDkgRequest {
            ring_id: TEST_FRESH_DKG_RING_ID.to_string(),
        },
        &token,
    )
    .unwrap();

    let result = service.start_dkg(tonic_request).await;

    assert!(
        result.is_err(),
        "start_dkg should fail when peers are unreachable"
    );
    let status = result.unwrap_err();
    assert_eq!(
        status.code(),
        tonic::Code::Unavailable,
        "connection failure should return Unavailable: {}",
        status.message()
    );

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
    let policy_id = Some("test-policy".to_string());
    println!("Peer IDs for connection: {:?}", peer_ids);

    // Create Alice's service
    let alice_service = DkgServiceImpl::<DkgImpl>::new(network.alice.app_state.clone());

    // Alice sends StartDkgRequest with all peer IDs (including herself)
    let request = StartDkgRequest {
        ring_id: TEST_FRESH_DKG_RING_ID.to_string(),
    };

    // Create authenticated request
    let test_keys = TestKeyPair::new();
    let token = test_keys
        .create_dkg_jwt(TEST_FRESH_DKG_RING_ID)
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
        if start.elapsed().as_secs().is_multiple_of(5) {
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
            assert_eq!(ring_payload.policy_id, policy_id);
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
                .get_encrypted(LocalStorageKeys::RingKey(key_string.clone()));

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

            let nodes = [
                ("Alice", &network.alice.app_state),
                ("Bob", &network.bob.app_state),
                ("Charlie", &network.charlie.app_state),
            ];
            for (name, state) in nodes {
                let ring_index_bytes = state
                    .local_storage
                    .get(LocalStorageKeys::RingIndex)
                    .expect("read RingIndex")
                    .expect("RingIndex should exist");
                let ring_index: Vec<RingIndexEntry> =
                    serde_json::from_slice(&ring_index_bytes).expect("parse RingIndex");
                assert!(
                    ring_index.iter().any(|entry| {
                        entry.ring_pk_str == key_string
                            && entry.bulletin_post_id == TEST_FRESH_DKG_RING_ID
                    }),
                    "{name} should index the finalized ring by the original ring_id"
                );
            }

            assert_eq!(
                dummy_bulletin.finalization_count(TEST_FRESH_DKG_RING_ID),
                3,
                "each participant should submit a fresh FinalizeRing confirmation"
            );
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

    let request = StartDkgRequest {
        ring_id: TEST_FRESH_DKG_RING_ID.to_string(),
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

    let request = StartDkgRequest {
        ring_id: TEST_FRESH_DKG_RING_ID.to_string(),
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

    // Create a valid JWT with key_pair_1
    let key_pair_1 = TestKeyPair::new();
    let valid_token = key_pair_1
        .create_dkg_jwt(TEST_FRESH_DKG_RING_ID)
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
        ring_id: TEST_FRESH_DKG_RING_ID.to_string(),
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
    let app_state = Arc::new(app_state);
    let coordinator = DkgCoordinator::new(app_state.clone());

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
        peer_node_keys: vec![
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
        pss_interval: 86400,
        policy_id: None,
        ring_id: TEST_FRESH_DKG_RING_ID.to_string(),
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

/// Test: Verify that SessionInit with params not matching the bulletin ring is rejected.
///
/// In the new DKG flow the bulletin is the authoritative source. The coordinator
/// reads the ring from the bulletin and runs validate_fresh_session_init_params to
/// cross-check every field. This test seeds a ring with threshold=3, sends a
/// SessionInit with threshold=2, and asserts the mismatch error fires.
#[tokio::test]
async fn test_dkg_session_init_fails_with_mismatched_claims() {
    let db_name = "test_dkg_session_init_fails_with_mismatched_claims";
    let db_path = test_db_path(db_name);

    let peer_ids = vec![
        "peer1".to_string(),
        "peer2".to_string(),
        "peer3".to_string(),
    ];

    // Seed the bulletin with a ring that advertises threshold=3.
    let bulletin = Arc::new(DummyBulletin::new().await.expect("DummyBulletin::new"));
    bulletin
        .set_ring(
            TEST_FRESH_DKG_RING_ID.to_string(),
            RingPayload {
                upgrade_info: Default::default(),
                ring_pk: String::new(),
                peer_node_keys: peer_ids.clone(),
                new_peer_node_keys: None,
                new_threshold: None,
                threshold: 3,
                pss_interval: 86400,
                block_number_nonce: 0,
                policy_id: Some("test-policy".to_string()),
            },
        )
        .expect("seed ring");

    let app_state = create_test_app_state_with_bulletin(None, true, bulletin, db_name).await;
    let coordinator = DkgCoordinator::new(Arc::new(app_state));

    let test_keys = TestKeyPair::new();
    let token = test_keys
        .create_dkg_jwt(TEST_FRESH_DKG_RING_ID)
        .expect("Failed to create JWT");

    // SessionInit claims threshold=2, bulletin says 3 → validate_fresh_session_init_params rejects.
    let session_init = DkgMessage::SessionInit {
        session_id: 12345,
        threshold: 2,
        total_participants: 3,
        peer_ids: peer_ids.clone(),
        peer_node_keys: peer_ids,
        node_id_assignments: std::collections::HashMap::from([
            ("peer1".to_string(), 1),
            ("peer2".to_string(), 2),
            ("peer3".to_string(), 3),
        ]),
        token_string: token,
        kind: SessionKind::Fresh,
        pss_interval: 86400,
        policy_id: None,
        ring_id: TEST_FRESH_DKG_RING_ID.to_string(),
    };

    let dummy_peer_id = network::PeerId::new(b"dummy-peer".to_vec());
    let result = coordinator
        .handle_message(session_init, &dummy_peer_id)
        .await;

    assert!(
        result.is_err(),
        "SessionInit with params not matching bulletin should be rejected"
    );

    let error = result.unwrap_err();
    println!("SessionInit correctly rejected with error: {}", error);
    assert!(
        error.to_string().contains("match"),
        "Error should indicate params mismatch: {}",
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
    let mismatched_token = test_keys
        .create_dkg_jwt(TEST_FRESH_DKG_RING_ID)
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
        peer_ids: session_peer_ids.clone(),
        peer_node_keys: session_peer_ids,
        node_id_assignments: std::collections::HashMap::from([
            ("peer1".to_string(), 1),
            ("peer2".to_string(), 2),
            ("peer3".to_string(), 3),
        ]),
        token_string: mismatched_token,
        kind: SessionKind::Fresh,
        pss_interval: 86400,
        policy_id: None,
        ring_id: TEST_FRESH_DKG_RING_ID.to_string(),
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
            || error.to_string().contains("match")
            || error.to_string().contains("protocol state"),
        "Error should indicate peer_ids mismatch: {}",
        error
    );

    println!("SUCCESS! SessionInit with mismatched peer_ids was correctly rejected");
    cleanup_db(&db_path);
}

#[tokio::test]
async fn test_dkg_session_init_rejects_nodeinfo_deny_before_session_creation() {
    let db_name = "test_dkg_session_init_rejects_nodeinfo_deny";
    let db_path = test_db_path(db_name);

    let bulletin = Arc::new(DummyBulletin::new().await.expect("DummyBulletin::new"));
    let app_state =
        create_test_app_state_with_bulletin(None, true, bulletin.clone(), db_name).await;
    let node_key = app_state.node_key.clone();
    let local_peer_id_hex = hex::encode(app_state.network.local_peer_id().as_bytes());
    let denied_node_info = NodeInfo {
        peer_id: local_peer_id_hex.clone(),
        controller_key: "controller".to_string(),
        whitelisted_policy_ids: vec!["other-policy".to_string()],
        whitelisted_ring_ids: vec![],
    };
    bulletin
        .set_node_info(node_key.clone(), denied_node_info)
        .expect("override NodeInfo");
    bulletin
        .set_ring(
            TEST_FRESH_DKG_RING_ID.to_string(),
            RingPayload {
                upgrade_info: Default::default(),
                ring_pk: String::new(),
                peer_node_keys: vec![node_key.clone()],
                new_peer_node_keys: None,
                new_threshold: None,
                threshold: 1,
                pss_interval: 86400,
                block_number_nonce: 0,
                policy_id: Some("test-policy".to_string()),
            },
        )
        .expect("seed ring");

    let app_state = Arc::new(app_state);
    let coordinator = DkgCoordinator::new(app_state.clone());
    let peer_ids = vec![local_peer_id_hex.clone()];
    let peer_node_keys = vec![node_key.clone()];
    let token = TestKeyPair::new()
        .create_dkg_jwt(TEST_FRESH_DKG_RING_ID)
        .expect("create JWT");
    let session_init = DkgMessage::SessionInit {
        session_id: 98765,
        threshold: 1,
        total_participants: 1,
        peer_ids,
        peer_node_keys,
        node_id_assignments: std::collections::HashMap::from([(node_key, 1)]),
        token_string: token,
        kind: SessionKind::Fresh,
        pss_interval: 86400,
        policy_id: None,
        ring_id: TEST_FRESH_DKG_RING_ID.to_string(),
    };

    let sender_peer_id = network::PeerId::new(b"sender-peer".to_vec());
    let result = coordinator
        .handle_message(session_init, &sender_peer_id)
        .await;
    assert!(matches!(result, Err(DkgError::Unauthorized(_))));
    assert!(
        !app_state.dkg_session_state.session_exists(&98765).await,
        "unauthorized SessionInit must not create session state"
    );
    cleanup_db(&db_path);
}

#[tokio::test]
async fn test_fresh_session_init_publishes_complete_state() {
    let db_name = "test_fresh_session_init_publishes_complete_state";
    let db_path = test_db_path(db_name);

    let bulletin = Arc::new(DummyBulletin::new().await.expect("DummyBulletin::new"));
    let app_state =
        create_test_app_state_with_bulletin(None, true, bulletin.clone(), db_name).await;
    let node_key = app_state.node_key.clone();
    let local_peer_id_hex = hex::encode(app_state.network.local_peer_id().as_bytes());
    let session_id = 222_333u128;
    let pss_interval = 60u64;

    bulletin
        .set_ring(
            TEST_FRESH_DKG_RING_ID.to_string(),
            RingPayload {
                upgrade_info: Default::default(),
                ring_pk: String::new(),
                peer_node_keys: vec![node_key.clone()],
                new_peer_node_keys: None,
                new_threshold: None,
                threshold: 1,
                pss_interval,
                block_number_nonce: 0,
                policy_id: Some("test-policy".to_string()),
            },
        )
        .expect("seed fresh ring");

    let app_state = Arc::new(app_state);
    let coordinator = DkgCoordinator::new(app_state.clone());
    let token = TestKeyPair::new()
        .create_dkg_jwt(TEST_FRESH_DKG_RING_ID)
        .expect("create JWT");
    let session_init = DkgMessage::SessionInit {
        session_id,
        threshold: 1,
        total_participants: 1,
        peer_ids: vec![local_peer_id_hex.clone()],
        peer_node_keys: vec![node_key.clone()],
        node_id_assignments: std::collections::HashMap::from([(node_key.clone(), 1)]),
        token_string: token,
        kind: SessionKind::Fresh,
        pss_interval,
        policy_id: Some("test-policy".to_string()),
        ring_id: TEST_FRESH_DKG_RING_ID.to_string(),
    };

    let sender_peer_id = app_state.network.local_peer_id().clone();
    coordinator
        .handle_message(session_init, &sender_peer_id)
        .await
        .expect("valid SessionInit should create session");

    let snapshot = app_state
        .dkg_session_state
        .with_state(&session_id, |state| {
            (
                state.peer_ids.clone(),
                state.peer_node_keys.clone(),
                state.ring_id.clone(),
                state.pss_interval,
                state.policy_id.clone(),
                state.node_id_to_peer_id.clone(),
                state.peer_id_to_node_id.clone(),
            )
        })
        .await
        .expect("session should exist");

    assert_eq!(snapshot.0, vec![local_peer_id_hex.clone()]);
    assert_eq!(snapshot.1, vec![node_key]);
    assert_eq!(snapshot.2, TEST_FRESH_DKG_RING_ID);
    assert_eq!(snapshot.3, pss_interval);
    assert_eq!(snapshot.4, Some("test-policy".to_string()));
    assert_eq!(snapshot.5.get(&1), Some(&local_peer_id_hex));
    assert_eq!(snapshot.6.get(&local_peer_id_hex), Some(&1));

    cleanup_db(&db_path);
}

#[tokio::test]
async fn test_start_dkg_rejects_self_participant_nodeinfo_deny() {
    let db_name = "test_start_dkg_rejects_self_participant_nodeinfo_deny";
    let db_path = test_db_path(db_name);

    let bulletin = Arc::new(DummyBulletin::new().await.expect("DummyBulletin::new"));
    let app_state =
        create_test_app_state_with_bulletin(None, true, bulletin.clone(), db_name).await;
    let node_key = app_state.node_key.clone();
    let local_peer_id_hex = hex::encode(app_state.network.local_peer_id().as_bytes());
    let denied_node_info = NodeInfo {
        peer_id: local_peer_id_hex.clone(),
        controller_key: "controller".to_string(),
        whitelisted_policy_ids: vec!["other-policy".to_string()],
        whitelisted_ring_ids: vec![],
    };
    bulletin
        .set_node_info(node_key, denied_node_info)
        .expect("override NodeInfo");

    let token = TestKeyPair::new()
        .create_dkg_jwt(TEST_FRESH_DKG_RING_ID)
        .expect("create JWT");
    let service = DkgServiceImpl::<DkgImpl>::new(app_state);
    let request = StartDkgRequest {
        ring_id: TEST_FRESH_DKG_RING_ID.to_string(),
    };
    let result = service
        .start_dkg(create_authenticated_request(request, &token).unwrap())
        .await;

    assert!(result.is_err(), "start_dkg should reject unauthorized node");
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
    let session_id = 12345u128;
    let dkg_node = *DkgImpl::new(1, 2, 3, session_id, DkgRole::Standard).expect("create DKG node");
    manager
        .create_session(session_id, dkg_node, 3, |_| {})
        .await;

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
    let session_id = 67890u128;
    let dkg_node = *DkgImpl::new(1, 2, 3, session_id, DkgRole::Standard).expect("create DKG node");
    manager
        .create_session(session_id, dkg_node, 3, |_| {})
        .await;

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
    let session_id = 11111u128;
    let dkg_node = *DkgImpl::new(1, 2, 3, session_id, DkgRole::Standard).expect("create DKG node");
    manager
        .create_session(session_id, dkg_node, 3, |_| {})
        .await;

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
            // Ensure the active-session TTL path is exercised, not the separate
            // completed-session retention policy.
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

    let session_id = 100u128;
    let dkg_node = *DkgImpl::new(1, 2, 3, session_id, DkgRole::Standard).expect("create DKG node");
    manager
        .create_session(session_id, dkg_node, 3, |_| {})
        .await;

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

    let session_id = 101u128;
    let dkg_node = *DkgImpl::new(1, 2, 3, session_id, DkgRole::Standard).expect("create DKG node");
    manager
        .create_session(session_id, dkg_node, 3, |_| {})
        .await;

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

    let session_id = 102u128;
    let dkg_node = *DkgImpl::new(1, 2, 3, session_id, DkgRole::Standard).expect("create DKG node");
    manager
        .create_session(session_id, dkg_node, 3, |_| {})
        .await;

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

    let session_1 = 103u128;
    let session_2 = 104u128;
    let dkg_node_1 = *DkgImpl::new(1, 2, 3, session_1, DkgRole::Standard).expect("create DKG node");
    let dkg_node_2 = *DkgImpl::new(1, 2, 3, session_2, DkgRole::Standard).expect("create DKG node");
    manager
        .create_session(session_1, dkg_node_1, 3, |_| {})
        .await;
    manager
        .create_session(session_2, dkg_node_2, 3, |_| {})
        .await;

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

    let session_id = 105u128;
    let dkg_node = *DkgImpl::new(1, 2, 3, session_id, DkgRole::Standard).expect("create DKG node");
    manager
        .create_session(session_id, dkg_node, 3, |_| {})
        .await;

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

    let session_id = 200u128;
    let dkg_node = *DkgImpl::new(1, 2, 3, session_id, DkgRole::Standard).expect("create DKG node");
    manager
        .create_session(session_id, dkg_node, 3, |_| {})
        .await;

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

    let session_id = 201u128;
    let dkg_node = *DkgImpl::new(1, 2, 3, session_id, DkgRole::Standard).expect("create DKG node");
    manager
        .create_session(session_id, dkg_node, 3, |_| {})
        .await;

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
            *DkgImpl::new(1, 2, 3, i as u128, DkgRole::Standard).expect("create DKG node");
        assert_eq!(
            manager.create_session(i as u128, dkg_node, 3, |_| {}).await,
            CreateSessionOutcome::Created,
            "Session {} should be created within limit",
            i
        );
    }

    assert_eq!(manager.session_count().await, MAX_DKG_SESSIONS);

    // One more should be rejected
    let dkg_node = *DkgImpl::new(1, 2, 3, MAX_DKG_SESSIONS as u128, DkgRole::Standard)
        .expect("create DKG node");
    assert_eq!(
        manager
            .create_session(MAX_DKG_SESSIONS as u128, dkg_node, 3, |_| {})
            .await,
        CreateSessionOutcome::LimitReached,
        "Session beyond limit should be rejected"
    );

    // Clean up
    for i in 0..MAX_DKG_SESSIONS {
        manager.remove_session(&(i as u128)).await;
    }
}

/// Test: Duplicate session_id is rejected
#[tokio::test]
async fn test_duplicate_session_id_rejected() {
    let manager: SessionStateManager<DkgImpl> = SessionStateManager::new();

    let session_id = 300u128;
    let dkg_node_1 =
        *DkgImpl::new(1, 2, 3, session_id, DkgRole::Standard).expect("create DKG node");
    let dkg_node_2 =
        *DkgImpl::new(1, 2, 3, session_id, DkgRole::Standard).expect("create DKG node");

    assert_eq!(
        manager
            .create_session(session_id, dkg_node_1, 3, |_| {})
            .await,
        CreateSessionOutcome::Created
    );
    assert_eq!(
        manager
            .create_session(session_id, dkg_node_2, 3, |_| {})
            .await,
        CreateSessionOutcome::AlreadyExists,
        "Duplicate session_id should be rejected"
    );

    manager.remove_session(&session_id).await;
}

/// Test: Commitment and share counters track correctly
#[tokio::test]
async fn test_commitment_and_share_counters() {
    let manager: SessionStateManager<DkgImpl> = SessionStateManager::new();

    let session_id = 400u128;
    let dkg_node = *DkgImpl::new(1, 2, 3, session_id, DkgRole::Standard).expect("create DKG node");
    manager
        .create_session(session_id, dkg_node, 3, |_| {})
        .await;

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
