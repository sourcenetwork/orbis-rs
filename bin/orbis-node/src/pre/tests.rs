//! PRE End-to-End Tests
//!
//! This module contains end-to-end tests for the PRE (Proxy Re-Encryption) protocol.
//! These tests verify the complete flow: DKG → Alice encrypts → PRE to Bob → Bob decrypts.

use crate::dkg::coordinator::DkgCoordinator;
use crate::helpers::test_helpers::{
    cleanup_db, create_authenticated_request, create_test_app_state_default,
    setup_three_node_network_with_pre, test_db_path, TestKeyPair,
};
use crate::pre::coordinator::{PreCoordinator, PreResponse};
use crate::pre::service::PreServiceImpl;
use crate::DkgServiceImpl;
use crypto::bls12_381::dkg::DKGNode;
use crypto::bls12_381::pre::ThresholdDealerNode;
use crypto::r#trait::{CryptoDeserialize, CryptoSerialize, Dkg, ThresholdDealer};
use proto::dkg_service::{dkg_service_server::DkgService, StartDkgRequest};
use proto::pre_service::{pre_service_server::PreService, StartPreRequest};
use std::sync::Arc;
use tokio::time::{sleep, Duration};
use tonic::Request;

// Type aliases for tests
type DkgImpl = DKGNode;
type PreImpl = ThresholdDealerNode;

/// End-to-end test: DKG → Alice encrypts → PRE to Bob → Bob decrypts
///
/// This test demonstrates the complete proxy re-encryption flow:
/// 1. Three nodes (node1, node2, node3) run DKG to generate a shared public key
/// 2. Alice encrypts a secret message using the DKG public key
/// 3. Bob generates his own keypair
/// 4. The nodes perform PRE to re-encrypt the secret to Bob's public key
/// 5. Bob decrypts the secret using his private key
#[tokio::test]
async fn test_dkg_then_pre_end_to_end() {
    let db_name = "test_dkg_then_pre_end_to_end";
    let db_paths = [
        test_db_path(&format!("{}_1", db_name)),
        test_db_path(&format!("{}_2", db_name)),
        test_db_path(&format!("{}_3", db_name)),
    ];

    println!("=== Starting End-to-End PRE Test ===\n");

    // =========================================================================
    // Step 1: Setup the three-node network with both DKG and PRE handlers
    // =========================================================================
    println!("Step 1: Setting up three-node network...");
    let mut network = setup_three_node_network_with_pre(true, true, true, db_name).await;

    // Get all peer IDs (including initiator) for participation
    let peer_ids = network.get_all_peer_ids();
    println!("Peer IDs for connection: {:?}", peer_ids);

    // =========================================================================
    // Step 2: Run DKG to completion
    // =========================================================================
    println!("\nStep 2: Running DKG protocol...");

    // Create node1's service (initiator)
    let node1_service = DkgServiceImpl::<DkgImpl>::new(network.alice.app_state.clone());

    // node1 sends StartDkgRequest to initiate the protocol
    let request = StartDkgRequest {
        threshold: 2,
        peer_ids: peer_ids.clone(),
    };

    // Create authenticated request
    let test_keys = TestKeyPair::new();
    let token = test_keys
        .create_dkg_jwt(2, &peer_ids)
        .expect("Failed to create JWT");

    println!("Node1 sending StartDkgRequest...");
    let tonic_request = create_authenticated_request(request, &token);
    let result = node1_service.start_dkg(tonic_request).await;
    assert!(
        result.is_ok(),
        "start_dkg should succeed: {:?}",
        result.err()
    );

    // Wait for DKG to complete and get the aggregate public key
    println!("Waiting for DKG to complete...");
    let aggregate_pk = wait_for_dkg_completion(
        &network,
        result.unwrap().into_inner().session_id.parse().unwrap(),
    )
    .await;
    println!("DKG completed! Aggregate public key: {:?}", aggregate_pk);

    // =========================================================================
    // Step 3: Alice encrypts a secret message
    // =========================================================================
    println!("\nStep 3: Alice encrypts a secret message...");

    let secret_message = b"Hello Bob! This is a secret message from Alice via PRE.";
    println!(
        "Original message: {:?}",
        String::from_utf8_lossy(secret_message)
    );

    // Alice encrypts the message using the DKG aggregate public key
    let (enc_cmt, encrypted_secret) =
        ThresholdDealerNode::encrypt_secret(&aggregate_pk, secret_message)
            .expect("Encryption should succeed");

    println!("Message encrypted successfully!");
    println!("  - enc_cmt (commitment): {:?}", enc_cmt);
    println!(
        "  - encrypted_data length: {} bytes",
        encrypted_secret.encrypted_data.len()
    );

    // Serialize the secret for transmission
    let secret_bytes = serde_json::to_vec(&encrypted_secret).expect("Failed to serialize secret");

    // =========================================================================
    // Step 4: Bob generates his keypair
    // =========================================================================
    println!("\nStep 4: Bob generates his keypair...");

    let (bob_sk, bob_pk) = ThresholdDealerNode::generate_keypair();

    println!("Bob's keypair generated!");
    println!("  - Bob's public key: {:?}", bob_pk);

    // Serialize Bob's public key using trait method
    let bob_pk_bytes = bob_pk
        .to_bytes()
        .expect("Failed to serialize Bob's public key");

    // Serialize the ring (DKG) public key using trait method
    let ring_pk_bytes = aggregate_pk
        .to_bytes()
        .expect("Failed to serialize ring public key");

    // =========================================================================
    // Step 5: Initiate PRE to re-encrypt to Bob's public key
    // =========================================================================
    println!("\nStep 5: Initiating PRE (proxy re-encryption) to Bob's public key...");

    // Create a PRE coordinator using node1's app state
    let pre_coordinator =
        PreCoordinator::<DkgImpl, PreImpl>::new(Arc::new(network.alice.app_state.clone()));

    // Generate a unique request ID
    let request_id = format!(
        "pre-request-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    );

    // Get peer IDs for PRE (node2 and node3)
    let pre_peer_ids = vec![network.bob.address.clone(), network.charlie.address.clone()];

    println!("Sending PRE requests to peers: {:?}", pre_peer_ids);

    // Create PRE JWT token
    let pre_token = test_keys
        .create_pre_jwt(&hex::encode(&bob_pk_bytes), &hex::encode(&ring_pk_bytes))
        .expect("Failed to create PRE JWT");

    // Initiate re-encryption
    let pre_response_bytes = pre_coordinator
        .initiate_reencryption(
            request_id.clone(),
            ring_pk_bytes.clone(),
            secret_bytes.clone(),
            bob_pk_bytes.clone(),
            &pre_peer_ids,
            "".to_string(),
            "".to_string(),
            "".to_string(),
            "".to_string(),
            pre_token,
        )
        .await
        .expect("PRE should succeed");

    println!("PRE completed successfully!");

    // Deserialize the PRE response
    let pre_response: PreResponse =
        serde_json::from_slice(&pre_response_bytes).expect("Failed to deserialize PRE response");

    println!(
        "  - xnc_cmt (re-encrypted commitment): {}",
        pre_response.xnc_cmt
    );

    // =========================================================================
    // Step 6: Bob decrypts the secret using his private key
    // =========================================================================
    println!("\nStep 6: Bob decrypts the secret...");

    // Deserialize the xnc_cmt from hex using trait method
    let xnc_cmt_bytes = hex::decode(&pre_response.xnc_cmt).expect("Failed to decode xnc_cmt hex");
    let xnc_cmt = <PreImpl as ThresholdDealer>::PublicKey::from_bytes(&xnc_cmt_bytes)
        .expect("Failed to deserialize xnc_cmt");

    // Bob decrypts using his private key
    let decrypted_message =
        PreImpl::decrypt_secret(&aggregate_pk, &xnc_cmt, &bob_sk, &pre_response.secret)
            .expect("Decryption should succeed");

    println!(
        "Decrypted message: {:?}",
        String::from_utf8_lossy(&decrypted_message)
    );

    // =========================================================================
    // Step 7: Verify the decrypted message matches the original
    // =========================================================================
    println!("\nStep 7: Verifying decrypted message...");

    assert_eq!(
        decrypted_message, secret_message,
        "Decrypted message should match the original"
    );

    println!("SUCCESS! The decrypted message matches the original!");
    println!("\n=== End-to-End PRE Test Completed Successfully ===");

    // =========================================================================
    // Cleanup
    // =========================================================================
    println!("\nCleaning up routers...");
    network
        .shutdown_routers()
        .await
        .expect("Failed to shutdown routers");
    for path in &db_paths {
        cleanup_db(path);
    }
}

/// Helper function to wait for DKG completion and return the aggregate public key
async fn wait_for_dkg_completion(
    network: &crate::helpers::test_helpers::ThreeNodeNetwork,
    session_id: u64,
) -> <DkgImpl as Dkg>::PublicKey {
    let check_interval = Duration::from_millis(500);
    let max_wait = Duration::from_secs(60);
    let start = std::time::Instant::now();

    loop {
        // Check if node1's session has completed Phase 4
        let node1_coordinator =
            DkgCoordinator::<DkgImpl>::new(Arc::new(network.alice.app_state.clone()));

        if let Some(session) = node1_coordinator.get_session(&session_id).await {
            let session_guard = session.read().await;
            if let Ok(aggregate_key) = session_guard.compute_aggregate_public_key() {
                // Verify all nodes have the same aggregate key
                let node2_coordinator =
                    DkgCoordinator::<DkgImpl>::new(Arc::new(network.bob.app_state.clone()));
                let node3_coordinator =
                    DkgCoordinator::<DkgImpl>::new(Arc::new(network.charlie.app_state.clone()));

                let node2_session = node2_coordinator.get_session(&session_id).await;
                let node3_session = node3_coordinator.get_session(&session_id).await;

                if let (Some(node2_sess), Some(node3_sess)) = (node2_session, node3_session) {
                    let node2_guard = node2_sess.read().await;
                    let node3_guard = node3_sess.read().await;

                    if let (Ok(key2), Ok(key3)) = (
                        node2_guard.compute_aggregate_public_key(),
                        node3_guard.compute_aggregate_public_key(),
                    ) {
                        if aggregate_key == key2 && aggregate_key == key3 {
                            println!("All nodes have computed the same aggregate public key!");
                            return aggregate_key;
                        }
                    }
                }
            }
        }

        if start.elapsed() > max_wait {
            panic!("DKG did not complete within {} seconds", max_wait.as_secs());
        }

        sleep(check_interval).await;
    }
}

/// Test PRE with a larger secret
#[tokio::test]
async fn test_pre_with_large_secret() {
    let db_name = "test_pre_with_large_secret";
    let db_paths = [
        test_db_path(&format!("{}_1", db_name)),
        test_db_path(&format!("{}_2", db_name)),
        test_db_path(&format!("{}_3", db_name)),
    ];

    println!("=== Starting PRE Test with Large Secret ===\n");

    // Setup network
    let mut network = setup_three_node_network_with_pre(true, true, true, db_name).await;
    let peer_ids = network.get_all_peer_ids();

    // Run DKG
    let node1_service = DkgServiceImpl::<DkgImpl>::new(network.alice.app_state.clone());

    let request = StartDkgRequest {
        threshold: 2,
        peer_ids: peer_ids.clone(),
    };

    // Create authenticated request
    let test_keys = TestKeyPair::new();
    let token = test_keys
        .create_dkg_jwt(2, &peer_ids)
        .expect("Failed to create JWT");

    let result = node1_service
        .start_dkg(create_authenticated_request(request, &token))
        .await;
    assert!(result.is_ok());

    let aggregate_pk = wait_for_dkg_completion(
        &network,
        result.unwrap().into_inner().session_id.parse().unwrap(),
    )
    .await;

    // Create a large secret (1KB)
    let large_secret: Vec<u8> = (0..1024).map(|i| (i % 256) as u8).collect();
    println!("Large secret size: {} bytes", large_secret.len());

    // Alice encrypts
    let (_, encrypted_secret) =
        PreImpl::encrypt_secret(&aggregate_pk, &large_secret).expect("Encryption should succeed");
    let secret_bytes = serde_json::to_vec(&encrypted_secret).unwrap();

    // Bob's keys using trait method
    let (bob_sk, bob_pk) = ThresholdDealerNode::generate_keypair();
    let bob_pk_bytes = bob_pk.to_bytes().unwrap();
    let ring_pk_bytes = aggregate_pk.to_bytes().unwrap();

    // PRE
    let pre_coordinator =
        PreCoordinator::<DkgImpl, PreImpl>::new(Arc::new(network.alice.app_state.clone()));
    let pre_peer_ids = vec![network.bob.address.clone(), network.charlie.address.clone()];

    // Create PRE JWT token
    let pre_token = test_keys
        .create_pre_jwt(&hex::encode(&bob_pk_bytes), &hex::encode(&ring_pk_bytes))
        .expect("Failed to create PRE JWT");

    let pre_response_bytes = pre_coordinator
        .initiate_reencryption(
            "large-pre-request".to_string(),
            ring_pk_bytes,
            secret_bytes,
            bob_pk_bytes,
            &pre_peer_ids,
            "".to_string(),
            "".to_string(),
            "".to_string(),
            "".to_string(),
            pre_token,
        )
        .await
        .expect("PRE should succeed");

    let pre_response: PreResponse = serde_json::from_slice(&pre_response_bytes).unwrap();

    // Bob decrypts using trait methods
    let xnc_cmt_bytes = hex::decode(&pre_response.xnc_cmt).unwrap();
    let xnc_cmt = <PreImpl as ThresholdDealer>::PublicKey::from_bytes(&xnc_cmt_bytes).unwrap();

    let decrypted = PreImpl::decrypt_secret(&aggregate_pk, &xnc_cmt, &bob_sk, &pre_response.secret)
        .expect("Decryption should succeed");

    assert_eq!(
        decrypted, large_secret,
        "Large secret should match after PRE"
    );
    println!(
        "SUCCESS! Large secret ({} bytes) correctly encrypted, re-encrypted, and decrypted!",
        large_secret.len()
    );

    network
        .shutdown_routers()
        .await
        .expect("Failed to shutdown");
    for path in &db_paths {
        cleanup_db(path);
    }
}

/// Test that PRE fails with wrong Bob private key
#[tokio::test]
#[serial_test::serial]
async fn test_pre_fails_with_wrong_key() {
    let db_name = "test_pre_fails_with_wrong_key";
    let db_paths = [
        test_db_path(&format!("{}_1", db_name)),
        test_db_path(&format!("{}_2", db_name)),
        test_db_path(&format!("{}_3", db_name)),
    ];

    println!("=== Starting PRE Failure Test (Wrong Key) ===\n");

    // Setup network
    let mut network = setup_three_node_network_with_pre(true, true, true, db_name).await;
    let peer_ids = network.get_all_peer_ids();

    // Run DKG
    let node1_service = DkgServiceImpl::<DkgImpl>::new(network.alice.app_state.clone());

    let request = StartDkgRequest {
        threshold: 2,
        peer_ids: peer_ids.clone(),
    };

    // Create authenticated request
    let test_keys = TestKeyPair::new();
    let token = test_keys
        .create_dkg_jwt(2, &peer_ids)
        .expect("Failed to create JWT");

    let result = node1_service
        .start_dkg(create_authenticated_request(request, &token))
        .await;
    assert!(result.is_ok());

    let aggregate_pk = wait_for_dkg_completion(
        &network,
        result.unwrap().into_inner().session_id.parse().unwrap(),
    )
    .await;

    // Alice encrypts
    let secret_message = b"Secret that should not be decrypted with wrong key";
    let (_, encrypted_secret) =
        PreImpl::encrypt_secret(&aggregate_pk, secret_message).expect("Encryption should succeed");
    let secret_bytes = serde_json::to_vec(&encrypted_secret).unwrap();

    // Bob's real keys
    let (_bob_sk, bob_pk) = ThresholdDealerNode::generate_keypair();
    let bob_pk_bytes = bob_pk.to_bytes().unwrap();
    let ring_pk_bytes = aggregate_pk.to_bytes().unwrap();

    // Wrong private key (Eve trying to decrypt)
    let (eve_sk, _eve_pk) = ThresholdDealerNode::generate_keypair();

    // PRE to Bob's public key
    let pre_coordinator =
        PreCoordinator::<DkgImpl, PreImpl>::new(Arc::new(network.alice.app_state.clone()));
    let pre_peer_ids = vec![network.bob.address.clone(), network.charlie.address.clone()];

    // Create PRE JWT token
    let pre_token = test_keys
        .create_pre_jwt(&hex::encode(&bob_pk_bytes), &hex::encode(&ring_pk_bytes))
        .expect("Failed to create PRE JWT");

    let pre_response_bytes = pre_coordinator
        .initiate_reencryption(
            "wrong-key-pre-request".to_string(),
            ring_pk_bytes,
            secret_bytes,
            bob_pk_bytes,
            &pre_peer_ids,
            "".to_string(),
            "".to_string(),
            "".to_string(),
            "".to_string(),
            pre_token,
        )
        .await
        .expect("PRE should succeed");

    let pre_response: PreResponse = serde_json::from_slice(&pre_response_bytes).unwrap();

    // Eve tries to decrypt with her key using trait methods
    let xnc_cmt_bytes = hex::decode(&pre_response.xnc_cmt).unwrap();
    let xnc_cmt = <PreImpl as ThresholdDealer>::PublicKey::from_bytes(&xnc_cmt_bytes).unwrap();

    let decrypt_result = PreImpl::decrypt_secret(
        &aggregate_pk,
        &xnc_cmt,
        &eve_sk, // Wrong key!
        &pre_response.secret,
    );

    assert!(
        decrypt_result.is_err(),
        "Decryption with wrong key should fail"
    );
    println!("SUCCESS! Decryption correctly failed with wrong private key");

    network
        .shutdown_routers()
        .await
        .expect("Failed to shutdown");
    for path in &db_paths {
        cleanup_db(path);
    }
}

/// Test that PRE fails when an invalid JWT token is sent to peer nodes
#[tokio::test]
#[serial_test::serial]
async fn test_pre_fails_with_invalid_jwt_token() {
    let db_name = "test_pre_fails_with_invalid_jwt_token";
    let db_paths = [
        test_db_path(&format!("{}_1", db_name)),
        test_db_path(&format!("{}_2", db_name)),
        test_db_path(&format!("{}_3", db_name)),
    ];

    println!("=== Starting PRE Failure Test (Invalid JWT Token) ===\n");

    // Setup network
    let mut network = setup_three_node_network_with_pre(true, true, true, db_name).await;
    let peer_ids = network.get_all_peer_ids();

    // Run DKG
    let node1_service = DkgServiceImpl::<DkgImpl>::new(network.alice.app_state.clone());

    let request = StartDkgRequest {
        threshold: 2,
        peer_ids: peer_ids.clone(),
    };

    // Create authenticated request
    let test_keys = TestKeyPair::new();
    let token = test_keys
        .create_dkg_jwt(2, &peer_ids)
        .expect("Failed to create JWT");

    let result = node1_service
        .start_dkg(create_authenticated_request(request, &token))
        .await;
    assert!(result.is_ok());

    let aggregate_pk = wait_for_dkg_completion(
        &network,
        result.unwrap().into_inner().session_id.parse().unwrap(),
    )
    .await;

    // Alice encrypts
    let secret_message = b"Secret that should not be re-encrypted with bad token";
    let (_, encrypted_secret) =
        PreImpl::encrypt_secret(&aggregate_pk, secret_message).expect("Encryption should succeed");
    let secret_bytes = serde_json::to_vec(&encrypted_secret).unwrap();

    // Bob's keys
    let (_bob_sk, bob_pk) = ThresholdDealerNode::generate_keypair();
    let bob_pk_bytes = bob_pk.to_bytes().unwrap();
    let ring_pk_bytes = aggregate_pk.to_bytes().unwrap();

    // PRE with invalid token
    let pre_coordinator =
        PreCoordinator::<DkgImpl, PreImpl>::new(Arc::new(network.alice.app_state.clone()));
    let pre_peer_ids = vec![network.bob.address.clone(), network.charlie.address.clone()];

    // Use a completely invalid JWT token
    let invalid_token = "not-a-valid-jwt-token".to_string();

    let pre_result = pre_coordinator
        .initiate_reencryption(
            "invalid-token-pre-request".to_string(),
            ring_pk_bytes,
            secret_bytes,
            bob_pk_bytes,
            &pre_peer_ids,
            "".to_string(),
            "".to_string(),
            "".to_string(),
            "".to_string(),
            invalid_token,
        )
        .await;

    assert!(
        pre_result.is_err(),
        "PRE should fail with invalid JWT token"
    );

    let error = pre_result.unwrap_err();
    println!("PRE correctly failed with error: {}", error);
    // When peers reject due to invalid JWT, the coordinator may get a timeout
    // (no valid responses) or an explicit auth error depending on error propagation
    assert!(
        error.to_string().contains("Unauthorized")
            || error.to_string().contains("JWT")
            || error.to_string().contains("validation")
            || error.to_string().contains("Insufficient responses"),
        "Error should indicate authentication failure or timeout due to peer rejection: {}",
        error
    );

    println!("SUCCESS! PRE correctly rejected invalid JWT token");

    network
        .shutdown_routers()
        .await
        .expect("Failed to shutdown");
    for path in &db_paths {
        cleanup_db(path);
    }
}

/// Test that PRE fails when JWT claims don't match the request parameters
#[tokio::test]
#[serial_test::serial]
async fn test_pre_fails_with_mismatched_jwt_claims() {
    let db_name = "test_pre_fails_with_mismatched_jwt_claims";
    let db_paths = [
        test_db_path(&format!("{}_1", db_name)),
        test_db_path(&format!("{}_2", db_name)),
        test_db_path(&format!("{}_3", db_name)),
    ];

    println!("=== Starting PRE Failure Test (Mismatched JWT Claims) ===\n");

    // Setup network
    let mut network = setup_three_node_network_with_pre(true, true, true, db_name).await;
    let peer_ids = network.get_all_peer_ids();

    // Run DKG
    let node1_service = DkgServiceImpl::<DkgImpl>::new(network.alice.app_state.clone());

    let request = StartDkgRequest {
        threshold: 2,
        peer_ids: peer_ids.clone(),
    };

    let test_keys = TestKeyPair::new();
    let token = test_keys
        .create_dkg_jwt(2, &peer_ids)
        .expect("Failed to create JWT");

    let result = node1_service
        .start_dkg(create_authenticated_request(request, &token))
        .await;
    assert!(result.is_ok());

    let aggregate_pk = wait_for_dkg_completion(
        &network,
        result.unwrap().into_inner().session_id.parse().unwrap(),
    )
    .await;

    // Alice encrypts
    let secret_message = b"Secret with mismatched claims";
    let (_, encrypted_secret) =
        PreImpl::encrypt_secret(&aggregate_pk, secret_message).expect("Encryption should succeed");
    let secret_bytes = serde_json::to_vec(&encrypted_secret).unwrap();

    // Bob's keys
    let (_bob_sk, bob_pk) = ThresholdDealerNode::generate_keypair();
    let bob_pk_bytes = bob_pk.to_bytes().unwrap();
    let ring_pk_bytes = aggregate_pk.to_bytes().unwrap();

    // PRE with token that has WRONG claims (different rdr_pk)
    let pre_coordinator =
        PreCoordinator::<DkgImpl, PreImpl>::new(Arc::new(network.alice.app_state.clone()));
    let pre_peer_ids = vec![network.bob.address.clone(), network.charlie.address.clone()];

    // Create a valid JWT but with wrong rdr_pk claim
    let wrong_rdr_pk = "0000000000000000000000000000000000000000000000000000000000000000";
    let mismatched_token = test_keys
        .create_pre_jwt(
            wrong_rdr_pk, // Wrong rdr_pk - doesn't match bob_pk_bytes
            &hex::encode(&ring_pk_bytes),
        )
        .expect("Failed to create JWT");

    let pre_result = pre_coordinator
        .initiate_reencryption(
            "mismatched-claims-pre-request".to_string(),
            ring_pk_bytes,
            secret_bytes,
            bob_pk_bytes, // Actual rdr_pk doesn't match JWT claim
            &pre_peer_ids,
            "".to_string(),
            "".to_string(),
            "".to_string(),
            "".to_string(),
            mismatched_token,
        )
        .await;

    assert!(
        pre_result.is_err(),
        "PRE should fail when JWT claims don't match request"
    );

    let error = pre_result.unwrap_err();
    println!("PRE correctly failed with error: {}", error);
    // When peers reject due to claim mismatch, the coordinator may get a timeout
    // (no valid responses) or an explicit auth error depending on error propagation
    assert!(
        error.to_string().contains("Unauthorized")
            || error.to_string().contains("rdr_pk")
            || error.to_string().contains("match")
            || error.to_string().contains("Insufficient responses"),
        "Error should indicate claim mismatch or timeout due to peer rejection: {}",
        error
    );

    println!("SUCCESS! PRE correctly rejected mismatched JWT claims");

    network
        .shutdown_routers()
        .await
        .expect("Failed to shutdown");
    for path in &db_paths {
        cleanup_db(path);
    }
}

#[tokio::test]
async fn test_start_pre_fails_missing_auth_header() {
    let db_name = "test_start_pre_fails_missing_auth_header";
    let db_path = test_db_path(db_name);
    let app_state = create_test_app_state_default(db_name).await;
    let service = PreServiceImpl::<DkgImpl, PreImpl>::new(app_state);

    let peer_ids = vec!["peer1".to_string(), "peer2".to_string()];
    let request = StartPreRequest {
        ring_pk: "abc123".to_string(),
        secret: "secret_data".to_string(),
        rdr_pk: "def456".to_string(),
        peer_ids,
        policy_id: "".to_string(),
        resource: "".to_string(),
        object_id: "".to_string(),
        permission: "".to_string(),
    };

    // Create request WITHOUT authentication header
    let tonic_request = Request::new(request);

    let result = service.start_pre(tonic_request).await;

    assert!(
        result.is_err(),
        "start_pre should fail when Authorization header is missing"
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
async fn test_start_pre_fails_malformed_jwt() {
    let db_name = "test_start_pre_fails_malformed_jwt";
    let db_path = test_db_path(db_name);
    let app_state = create_test_app_state_default(db_name).await;
    let service = PreServiceImpl::<DkgImpl, PreImpl>::new(app_state);

    let peer_ids = vec!["peer1".to_string(), "peer2".to_string()];
    let request = StartPreRequest {
        ring_pk: "abc123".to_string(),
        secret: "secret_data".to_string(),
        rdr_pk: "def456".to_string(),
        peer_ids,
        policy_id: "".to_string(),
        resource: "".to_string(),
        object_id: "".to_string(),
        permission: "".to_string(),
    };

    // Create request with malformed JWT (not a valid JWT structure)
    let tonic_request = create_authenticated_request(request, "not-a-valid-jwt-token");

    let result = service.start_pre(tonic_request).await;

    assert!(
        result.is_err(),
        "start_pre should fail with malformed JWT token"
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
async fn test_start_pre_fails_wrong_signature() {
    let db_name = "test_start_pre_fails_wrong_signature";
    let db_path = test_db_path(db_name);
    let app_state = create_test_app_state_default(db_name).await;
    let service = PreServiceImpl::<DkgImpl, PreImpl>::new(app_state);

    let peer_ids = vec!["peer1".to_string(), "peer2".to_string()];

    // Create a valid JWT with key_pair_1
    let key_pair_1 = TestKeyPair::new();
    let valid_token = key_pair_1
        .create_pre_jwt("def456", "abc123")
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

    let request = StartPreRequest {
        ring_pk: "abc123".to_string(),
        secret: "secret_data".to_string(),
        rdr_pk: "def456".to_string(),
        peer_ids,
        policy_id: "".to_string(),
        resource: "".to_string(),
        object_id: "".to_string(),
        permission: "".to_string(),
    };

    let tonic_request = create_authenticated_request(request, &tampered_token);

    let result = service.start_pre(tonic_request).await;

    assert!(
        result.is_err(),
        "start_pre should fail with tampered JWT signature"
    );

    let status = result.unwrap_err();
    assert_eq!(
        status.code(),
        tonic::Code::Unauthenticated,
        "Error code should be Unauthenticated for invalid signature"
    );
    cleanup_db(&db_path);
}
