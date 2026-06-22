//! PRE End-to-End Tests
//!
//! This module contains end-to-end tests for the PRE (Proxy Re-Encryption) protocol.
//! These tests verify the complete flow: DKG → Alice encrypts → PRE to Bob → Bob decrypts.

use crate::dkg::v0::service::DkgServiceImpl;
use crate::helpers::test_helpers::{
    cleanup_db, create_authenticated_request, create_test_app_state_default, get_test_ring_post,
    setup_three_node_network_with_pre, test_db_path, TestKeyPair, TEST_FRESH_DKG_RING_ID,
};
use crate::pre::v0::coordinator::{PreCoordinator, PreResponse};
use crate::pre::v0::service::PreServiceImpl;
use bulletin::r#trait::{Bulletin, BulletinWriteKind, DocumentPayload, RingPayload};
use crypto::r#trait::{
    CryptoDeserialize, CryptoSerialize, Dkg, DkgMode, DkgRole, EncryptionProof, ThresholdDealer,
};
use crypto::{DkgImpl, PreImpl};
use proto::v0::dkg::{dkg_service_server::DkgService, StartDkgRequest};
use proto::v0::pre::{pre_service_server::PreService, StartPreRequest};
use std::sync::Arc;
use tokio::time::{sleep, Duration};
use tonic::Request;
use zeroize::Zeroizing;

use crate::helpers::ring::RingConfig;
use crate::pre::v0::error::PreError;
use crate::pre::v0::helpers::check_policy_access;
use crate::pre::v0::messages::PreRequestContext;
use crate::ring_state::{RingPolyState, RingShareBundle};
use bulletin::dummy::DummyBulletin;

/// Generate policy metadata matching the test DocumentPayload fields.
fn generate_test_policy_metadata() -> Vec<u8> {
    PreImpl::encode_metadata(
        "test-policy",
        "test-resource",
        "test-permission",
        None,
        None,
        None,
    )
}

/// Helper to store a DocumentPayload in the bulletin for PRE tests.
///
/// This creates the document payload with the encrypted secret and stores it in the bulletin,
/// returning the computed object_id that can be used in PRE requests.
async fn setup_document_in_bulletin(
    dummy_bulletin: &DummyBulletin,
    secret_bytes: &[u8],
    proof: EncryptionProof,
) -> String {
    // Get the ring_id from the bulletin post
    let ring_post = get_test_ring_post(dummy_bulletin);
    let ring_id = ring_post.id.clone();

    // Create DocumentPayload with the secret and test policy values
    let document_payload = DocumentPayload {
        ring_id,
        document: String::from_utf8(secret_bytes.to_vec())
            .unwrap_or_else(|_| hex::encode(secret_bytes)),
        proof: String::try_from(proof).expect("serialize EncryptionProof"),
        policy_id: "test-policy".to_string(),
        resource: "test-resource".to_string(),
        permission: "test-permission".to_string(),
        tier: None,
        timestamp: None,
    };
    let document_payload_bytes: Vec<u8> = document_payload
        .try_into()
        .expect("serialize DocumentPayload");

    dummy_bulletin
        .post(BulletinWriteKind::Document, document_payload_bytes)
        .await
        .expect("store document")
}

/// End-to-end test: DKG → Alice encrypts → PRE to Bob → Bob decrypts
///
/// This test demonstrates the complete proxy re-encryption flow:
/// 1. Three nodes (node1, node2, node3) run DKG to generate a shared public key
/// 2. Alice encrypts a secret message using the DKG public key
/// 3. Bob generates his own keypair
/// 4. The nodes perform PRE to re-encrypt the secret to Bob's public key
/// 5. Bob decrypts the secret using his private key
#[tokio::test]
#[serial_test::serial]
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
    let node1_service =
        DkgServiceImpl::<DkgImpl>::with_routes(network.alice.app_state.clone(), &network::V0);

    // node1 sends StartDkgRequest to initiate the protocol
    let request = StartDkgRequest {
        ring_id: TEST_FRESH_DKG_RING_ID.to_string(),
    };

    // Create authenticated request
    let test_keys = TestKeyPair::new();
    let token = test_keys
        .create_dkg_jwt(TEST_FRESH_DKG_RING_ID)
        .expect("Failed to create JWT");

    println!("Node1 sending StartDkgRequest...");
    let tonic_request = create_authenticated_request(request, &token).unwrap();
    let result = node1_service.start_dkg(tonic_request).await;
    assert!(
        result.is_ok(),
        "start_dkg should succeed: {:?}",
        result.err()
    );

    // Wait for DKG to complete and get the ring payload from bulletin
    println!("Waiting for DKG to complete...");
    let ring_payload = wait_for_dkg_completion(&network).await;

    // Deserialize the aggregate public key from the ring payload
    let ring_pk_bytes = hex::decode(&ring_payload.ring_pk).expect("decode ring_pk hex");
    let aggregate_pk =
        <DkgImpl as Dkg>::PublicKey::from_bytes(&ring_pk_bytes).expect("deserialize public key");
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
    let metadata = generate_test_policy_metadata();
    let (enc_cmt, encrypted_secret, proof) =
        PreImpl::encrypt_secret(&aggregate_pk, secret_message, None, Some(&metadata))
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

    let (bob_sk, bob_pk) = PreImpl::generate_keypair();

    println!("Bob's keypair generated!");
    println!("  - Bob's public key: {:?}", bob_pk);

    // Serialize Bob's public key using trait method
    let bob_pk_bytes =
        CryptoSerialize::to_bytes(&bob_pk).expect("Failed to serialize Bob's public key");

    // Serialize the ring (DKG) public key using trait method
    let ring_pk_bytes =
        CryptoSerialize::to_bytes(&aggregate_pk).expect("Failed to serialize ring public key");

    // =========================================================================
    // Step 5: Initiate PRE to re-encrypt to Bob's public key
    // =========================================================================
    println!("\nStep 5: Initiating PRE (proxy re-encryption) to Bob's public key...");

    // Create a PRE coordinator using node1's app state
    let pre_coordinator = PreCoordinator::<DkgImpl, PreImpl>::with_routes(
        Arc::new(network.alice.app_state.clone()),
        &::network::V0,
    );

    // Generate a unique request ID
    let request_id = format!(
        "pre-request-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    );

    // Use the full ring route list; the coordinator skips itself and keeps
    // route order aligned with the ring's peer_node_keys.
    let pre_peer_ids = peer_ids.clone();

    println!("Sending PRE requests to peers: {:?}", pre_peer_ids);

    // Store the document in the bulletin so receiving nodes can fetch secret info
    let dummy_bulletin = network
        .dummy_bulletin
        .as_ref()
        .expect("PRE tests require DummyBulletin");
    let object_id = setup_document_in_bulletin(dummy_bulletin, &secret_bytes, proof).await;

    // Create PRE JWT token
    let pre_token = test_keys
        .create_pre_jwt(bob_pk_bytes.clone(), &object_id, None, None)
        .expect("Failed to create PRE JWT");

    // Initiate re-encryption using threshold, total_nodes, and public_polynomial from bulletin
    let pre_response_bytes = pre_coordinator
        .initiate_reencryption(
            request_id.clone(),
            RingConfig {
                ring_pk_bytes: ring_pk_bytes.clone(),
                peer_ids: pre_peer_ids.clone(),
                peer_node_keys: ring_payload.peer_node_keys.clone(),
                threshold: ring_payload.threshold as usize,
                total_participants: ring_payload.peer_node_keys.len(),
                public_polynomial_hex: RingPolyState::load_from_ring_pk_hex(
                    &network.alice.app_state.local_storage,
                    &ring_payload.ring_pk,
                )
                .expect("load RingPolyState")
                .public_polynomial,
            },
            secret_bytes.clone(),
            PreRequestContext {
                rdr_pk_bytes: bob_pk_bytes.clone(),
                object_id,
                token_string: pre_token,
                derivation: None,
                salt: None,
                valid_window: None,
            },
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

/// Helper function to wait for DKG completion and return the RingPayload
async fn wait_for_dkg_completion(
    network: &crate::helpers::test_helpers::ThreeNodeNetwork,
) -> RingPayload {
    let check_interval = Duration::from_millis(500);
    let max_wait = Duration::from_secs(60);
    let start = std::time::Instant::now();

    let dummy_bulletin = network
        .dummy_bulletin
        .as_ref()
        .expect("PRE tests require DummyBulletin");

    loop {
        // Check if ring payload has been posted to bulletin (indicates Phase 4 complete)
        let post = get_test_ring_post(dummy_bulletin);

        // Check if payload is non-empty (DKG complete, ring info posted to bulletin)
        if !post.payload.is_empty() {
            // Parse RingPayload from bulletin post
            let ring_payload: RingPayload = post.try_into().expect("parse RingPayload");

            println!("All nodes have computed the same aggregate public key!");
            return ring_payload;
        }

        if start.elapsed() > max_wait {
            panic!("DKG did not complete within {} seconds", max_wait.as_secs());
        }

        sleep(check_interval).await;
    }
}

/// Test PRE with a larger secret
#[tokio::test]
#[serial_test::serial]
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
    let node1_service =
        DkgServiceImpl::<DkgImpl>::with_routes(network.alice.app_state.clone(), &network::V0);

    let request = StartDkgRequest {
        ring_id: TEST_FRESH_DKG_RING_ID.to_string(),
    };

    // Create authenticated request
    let test_keys = TestKeyPair::new();
    let token = test_keys
        .create_dkg_jwt(TEST_FRESH_DKG_RING_ID)
        .expect("Failed to create JWT");

    let result = node1_service
        .start_dkg(create_authenticated_request(request, &token).unwrap())
        .await;
    assert!(result.is_ok());

    let ring_payload = wait_for_dkg_completion(&network).await;

    // Deserialize the aggregate public key from the ring payload
    let ring_pk_bytes = hex::decode(&ring_payload.ring_pk).expect("decode ring_pk hex");
    let aggregate_pk =
        <DkgImpl as Dkg>::PublicKey::from_bytes(&ring_pk_bytes).expect("deserialize public key");

    // Create a large secret (1KB)
    let large_secret: Vec<u8> = (0..1024).map(|i| (i % 256) as u8).collect();
    println!("Large secret size: {} bytes", large_secret.len());

    // Alice encrypts
    let metadata = generate_test_policy_metadata();
    let (_, encrypted_secret, proof) =
        PreImpl::encrypt_secret(&aggregate_pk, &large_secret, None, Some(&metadata))
            .expect("Encryption should succeed");
    let secret_bytes = serde_json::to_vec(&encrypted_secret).unwrap();

    // Bob's keys using trait method
    let (bob_sk, bob_pk) = PreImpl::generate_keypair();
    let bob_pk_bytes = CryptoSerialize::to_bytes(&bob_pk).unwrap();

    // PRE
    let pre_coordinator = PreCoordinator::<DkgImpl, PreImpl>::with_routes(
        Arc::new(network.alice.app_state.clone()),
        &::network::V0,
    );
    let pre_peer_ids = peer_ids.clone();

    // Store the document in the bulletin
    let dummy_bulletin = network
        .dummy_bulletin
        .as_ref()
        .expect("PRE tests require DummyBulletin");
    let object_id = setup_document_in_bulletin(dummy_bulletin, &secret_bytes, proof).await;

    // Create PRE JWT token
    let pre_token = test_keys
        .create_pre_jwt(bob_pk_bytes.clone(), &object_id, None, None)
        .expect("Failed to create PRE JWT");

    // Initiate re-encryption using threshold, total_nodes, and public_polynomial from bulletin
    let pre_response_bytes = pre_coordinator
        .initiate_reencryption(
            "large-pre-request".to_string(),
            RingConfig {
                ring_pk_bytes,
                peer_ids: pre_peer_ids.clone(),
                peer_node_keys: ring_payload.peer_node_keys.clone(),
                threshold: ring_payload.threshold as usize,
                total_participants: ring_payload.peer_node_keys.len(),
                public_polynomial_hex: RingPolyState::load_from_ring_pk_hex(
                    &network.alice.app_state.local_storage,
                    &ring_payload.ring_pk,
                )
                .expect("load RingPolyState")
                .public_polynomial,
            },
            secret_bytes,
            PreRequestContext {
                rdr_pk_bytes: bob_pk_bytes,
                object_id,
                token_string: pre_token,
                derivation: None,
                salt: None,
                valid_window: None,
            },
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
    let node1_service =
        DkgServiceImpl::<DkgImpl>::with_routes(network.alice.app_state.clone(), &network::V0);

    let request = StartDkgRequest {
        ring_id: TEST_FRESH_DKG_RING_ID.to_string(),
    };

    // Create authenticated request
    let test_keys = TestKeyPair::new();
    let token = test_keys
        .create_dkg_jwt(TEST_FRESH_DKG_RING_ID)
        .expect("Failed to create JWT");

    let result = node1_service
        .start_dkg(create_authenticated_request(request, &token).unwrap())
        .await;
    assert!(result.is_ok());

    let ring_payload = wait_for_dkg_completion(&network).await;

    // Deserialize the aggregate public key from the ring payload
    let ring_pk_bytes = hex::decode(&ring_payload.ring_pk).expect("decode ring_pk hex");
    let aggregate_pk =
        <DkgImpl as Dkg>::PublicKey::from_bytes(&ring_pk_bytes).expect("deserialize public key");

    // Alice encrypts
    let secret_message = b"Secret that should not be decrypted with wrong key";
    let metadata = generate_test_policy_metadata();
    let (_, encrypted_secret, proof) =
        PreImpl::encrypt_secret(&aggregate_pk, secret_message, None, Some(&metadata))
            .expect("Encryption should succeed");
    let secret_bytes = serde_json::to_vec(&encrypted_secret).unwrap();

    // Bob's real keys
    let (_bob_sk, bob_pk) = PreImpl::generate_keypair();
    let bob_pk_bytes = CryptoSerialize::to_bytes(&bob_pk).unwrap();

    // Wrong private key (Eve trying to decrypt)
    let (eve_sk, _eve_pk) = PreImpl::generate_keypair();

    // PRE to Bob's public key
    let pre_coordinator = PreCoordinator::<DkgImpl, PreImpl>::with_routes(
        Arc::new(network.alice.app_state.clone()),
        &::network::V0,
    );
    let pre_peer_ids = peer_ids.clone();

    // Store the document in the bulletin
    let dummy_bulletin = network
        .dummy_bulletin
        .as_ref()
        .expect("PRE tests require DummyBulletin");
    let object_id = setup_document_in_bulletin(dummy_bulletin, &secret_bytes, proof).await;

    // Create PRE JWT token
    let pre_token = test_keys
        .create_pre_jwt(bob_pk_bytes.clone(), &object_id, None, None)
        .expect("Failed to create PRE JWT");

    // Initiate re-encryption using threshold, total_nodes, and public_polynomial from bulletin
    let pre_response_bytes = pre_coordinator
        .initiate_reencryption(
            "wrong-key-pre-request".to_string(),
            RingConfig {
                ring_pk_bytes,
                peer_ids: pre_peer_ids.clone(),
                peer_node_keys: ring_payload.peer_node_keys.clone(),
                threshold: ring_payload.threshold as usize,
                total_participants: ring_payload.peer_node_keys.len(),
                public_polynomial_hex: RingPolyState::load_from_ring_pk_hex(
                    &network.alice.app_state.local_storage,
                    &ring_payload.ring_pk,
                )
                .expect("load RingPolyState")
                .public_polynomial,
            },
            secret_bytes,
            PreRequestContext {
                rdr_pk_bytes: bob_pk_bytes,
                object_id,
                token_string: pre_token,
                derivation: None,
                salt: None,
                valid_window: None,
            },
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
    let node1_service =
        DkgServiceImpl::<DkgImpl>::with_routes(network.alice.app_state.clone(), &network::V0);

    let request = StartDkgRequest {
        ring_id: TEST_FRESH_DKG_RING_ID.to_string(),
    };

    // Create authenticated request
    let test_keys = TestKeyPair::new();
    let token = test_keys
        .create_dkg_jwt(TEST_FRESH_DKG_RING_ID)
        .expect("Failed to create JWT");

    let result = node1_service
        .start_dkg(create_authenticated_request(request, &token).unwrap())
        .await;
    assert!(result.is_ok());

    let ring_payload = wait_for_dkg_completion(&network).await;

    // Deserialize the aggregate public key from the ring payload
    let ring_pk_bytes = hex::decode(&ring_payload.ring_pk).expect("decode ring_pk hex");
    let aggregate_pk =
        <DkgImpl as Dkg>::PublicKey::from_bytes(&ring_pk_bytes).expect("deserialize public key");

    // Alice encrypts
    let secret_message = b"Secret that should not be re-encrypted with bad token";
    let metadata = generate_test_policy_metadata();
    let (_, encrypted_secret, proof) =
        PreImpl::encrypt_secret(&aggregate_pk, secret_message, None, Some(&metadata))
            .expect("Encryption should succeed");
    let secret_bytes = serde_json::to_vec(&encrypted_secret).unwrap();

    // Bob's keys
    let (_bob_sk, bob_pk) = PreImpl::generate_keypair();
    let bob_pk_bytes = CryptoSerialize::to_bytes(&bob_pk).unwrap();

    // PRE with invalid token
    let pre_coordinator = PreCoordinator::<DkgImpl, PreImpl>::with_routes(
        Arc::new(network.alice.app_state.clone()),
        &::network::V0,
    );
    let pre_peer_ids = peer_ids.clone();

    // Store the document in the bulletin
    let dummy_bulletin = network
        .dummy_bulletin
        .as_ref()
        .expect("PRE tests require DummyBulletin");
    let object_id = setup_document_in_bulletin(dummy_bulletin, &secret_bytes, proof).await;

    // Use a completely invalid JWT token
    let invalid_token = "not-a-valid-jwt-token".to_string();

    // Initiate re-encryption using threshold, total_nodes, and public_polynomial from bulletin
    let pre_result = pre_coordinator
        .initiate_reencryption(
            "invalid-token-pre-request".to_string(),
            RingConfig {
                ring_pk_bytes,
                peer_ids: pre_peer_ids.clone(),
                peer_node_keys: ring_payload.peer_node_keys.clone(),
                threshold: ring_payload.threshold as usize,
                total_participants: ring_payload.peer_node_keys.len(),
                public_polynomial_hex: RingPolyState::load_from_ring_pk_hex(
                    &network.alice.app_state.local_storage,
                    &ring_payload.ring_pk,
                )
                .expect("load RingPolyState")
                .public_polynomial,
            },
            secret_bytes,
            PreRequestContext {
                rdr_pk_bytes: bob_pk_bytes,
                object_id,
                token_string: invalid_token,
                derivation: None,
                salt: None,
                valid_window: None,
            },
        )
        .await;

    assert!(
        pre_result.is_err(),
        "PRE should fail with invalid JWT token"
    );

    let error = pre_result.unwrap_err();
    println!("PRE correctly failed with error: {}", error);
    // When peers reject due to invalid JWT, the initiator may surface either the
    // underlying auth failure or, after early verification/filtering, insufficient
    // verified shares.
    assert!(
        error.to_string().contains("Unauthorized")
            || error.to_string().contains("JWT")
            || error.to_string().contains("validation")
            || error.to_string().contains("Insufficient responses")
            || error.to_string().contains("Insufficient shares"),
        "Error should indicate authentication failure or insufficient verified shares due to peer rejection: {}",
        error
    );

    // Verify pre_response was cleaned up even though PRE failed
    // This tests the cleanup-on-error behavior added to initiate_reencryption
    let remaining_responses = network
        .alice
        .app_state
        .pre_response_state
        .get_responses("invalid-token-pre-request")
        .await;
    assert!(
        remaining_responses.is_none(),
        "pre_response should be cleaned up after PRE failure"
    );

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
    let node1_service =
        DkgServiceImpl::<DkgImpl>::with_routes(network.alice.app_state.clone(), &network::V0);

    let request = StartDkgRequest {
        ring_id: TEST_FRESH_DKG_RING_ID.to_string(),
    };

    let test_keys = TestKeyPair::new();
    let token = test_keys
        .create_dkg_jwt(TEST_FRESH_DKG_RING_ID)
        .expect("Failed to create JWT");

    let result = node1_service
        .start_dkg(create_authenticated_request(request, &token).unwrap())
        .await;
    assert!(result.is_ok());

    let ring_payload = wait_for_dkg_completion(&network).await;

    // Deserialize the aggregate public key from the ring payload
    let ring_pk_bytes = hex::decode(&ring_payload.ring_pk).expect("decode ring_pk hex");
    let aggregate_pk =
        <DkgImpl as Dkg>::PublicKey::from_bytes(&ring_pk_bytes).expect("deserialize public key");

    // Alice encrypts
    let secret_message = b"Secret with mismatched claims";
    let metadata = generate_test_policy_metadata();
    let (_, encrypted_secret, proof) =
        PreImpl::encrypt_secret(&aggregate_pk, secret_message, None, Some(&metadata))
            .expect("Encryption should succeed");
    let secret_bytes = serde_json::to_vec(&encrypted_secret).unwrap();

    // Bob's keys
    let (_bob_sk, bob_pk) = PreImpl::generate_keypair();
    let bob_pk_bytes = CryptoSerialize::to_bytes(&bob_pk).unwrap();

    // PRE with token that has WRONG claims (different rdr_pk)
    let pre_coordinator = PreCoordinator::<DkgImpl, PreImpl>::with_routes(
        Arc::new(network.alice.app_state.clone()),
        &::network::V0,
    );
    let pre_peer_ids = peer_ids.clone();

    // Store the document in the bulletin
    let dummy_bulletin = network
        .dummy_bulletin
        .as_ref()
        .expect("PRE tests require DummyBulletin");
    let object_id = setup_document_in_bulletin(dummy_bulletin, &secret_bytes, proof).await;

    // Create a valid JWT but with wrong rdr_pk claim
    let wrong_rdr_pk = vec![0u8; 32]; // Zero bytes - doesn't match bob_pk_bytes

    let mismatched_token = test_keys
        .create_pre_jwt(
            wrong_rdr_pk, // Wrong rdr_pk - doesn't match bob_pk_bytes
            &object_id,
            None,
            None,
        )
        .expect("Failed to create JWT");

    // Initiate re-encryption using threshold, total_nodes, and public_polynomial from bulletin
    let pre_result = pre_coordinator
        .initiate_reencryption(
            "mismatched-claims-pre-request".to_string(),
            RingConfig {
                ring_pk_bytes,
                peer_ids: pre_peer_ids.clone(),
                peer_node_keys: ring_payload.peer_node_keys.clone(),
                threshold: ring_payload.threshold as usize,
                total_participants: ring_payload.peer_node_keys.len(),
                public_polynomial_hex: RingPolyState::load_from_ring_pk_hex(
                    &network.alice.app_state.local_storage,
                    &ring_payload.ring_pk,
                )
                .expect("load RingPolyState")
                .public_polynomial,
            },
            secret_bytes,
            PreRequestContext {
                rdr_pk_bytes: bob_pk_bytes, // Actual rdr_pk doesn't match JWT claim
                object_id,
                token_string: mismatched_token,
                derivation: None,
                salt: None,
                valid_window: None,
            },
        )
        .await;

    assert!(
        pre_result.is_err(),
        "PRE should fail when JWT claims don't match request"
    );

    let error = pre_result.unwrap_err();
    println!("PRE correctly failed with error: {}", error);
    // When peers reject due to claim mismatch, the initiator may surface either the
    // underlying auth failure or, after early verification/filtering, insufficient
    // verified shares.
    assert!(
        error.to_string().contains("Unauthorized")
            || error.to_string().contains("rdr_pk")
            || error.to_string().contains("match")
            || error.to_string().contains("Insufficient responses")
            || error.to_string().contains("Insufficient shares"),
        "Error should indicate claim mismatch or insufficient verified shares due to peer rejection: {}",
        error
    );

    // Verify pre_response was cleaned up even though PRE failed
    let remaining_responses = network
        .alice
        .app_state
        .pre_response_state
        .get_responses("mismatched-claims-pre-request")
        .await;
    assert!(
        remaining_responses.is_none(),
        "pre_response should be cleaned up after PRE failure"
    );

    network
        .shutdown_routers()
        .await
        .expect("Failed to shutdown");
    for path in &db_paths {
        cleanup_db(path);
    }
}

#[tokio::test]
#[serial_test::serial]
async fn test_start_pre_fails_missing_auth_header() {
    let db_name = "test_start_pre_fails_missing_auth_header";
    let db_path = test_db_path(db_name);
    let app_state = create_test_app_state_default(db_name).await;
    let service = PreServiceImpl::<DkgImpl, PreImpl>::with_routes(app_state, &network::V0);

    let request = StartPreRequest {
        rdr_pk: b"def456".to_vec(),
        object_id: "".to_string(),
        derivation: None,
        salt: None,
        valid_window: None,
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
#[serial_test::serial]
async fn test_start_pre_fails_malformed_jwt() {
    let db_name = "test_start_pre_fails_malformed_jwt";
    let db_path = test_db_path(db_name);
    let app_state = create_test_app_state_default(db_name).await;
    let service = PreServiceImpl::<DkgImpl, PreImpl>::with_routes(app_state, &network::V0);

    let request = StartPreRequest {
        rdr_pk: b"def456".to_vec(),
        object_id: "".to_string(),
        derivation: None,
        salt: None,
        valid_window: None,
    };

    // Create request with malformed JWT (not a valid JWT structure)
    let tonic_request = create_authenticated_request(request, "not-a-valid-jwt-token").unwrap();

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
#[serial_test::serial]
async fn test_start_pre_fails_wrong_signature() {
    let db_name = "test_start_pre_fails_wrong_signature";
    let db_path = test_db_path(db_name);
    let app_state = create_test_app_state_default(db_name).await;
    let service = PreServiceImpl::<DkgImpl, PreImpl>::with_routes(app_state, &network::V0);

    let object_id = "object_id_test".to_string();

    // Create a valid JWT with key_pair_1
    let key_pair_1 = TestKeyPair::new();
    let valid_token = key_pair_1
        .create_pre_jwt(b"def456".to_vec(), &object_id, None, None)
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
        rdr_pk: b"def456".to_vec(),
        object_id: "".to_string(),
        derivation: None,
        salt: None,
        valid_window: None,
    };

    let tonic_request = create_authenticated_request(request, &tampered_token).unwrap();

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

/// Test that PRE fails when wrong derivation is used for decryption
///
/// This test verifies that if Alice encrypts with derivation D1, and Bob tries
/// to decrypt using derivation D2, the decryption fails (AES-GCM auth failure).
#[tokio::test]
#[serial_test::serial]
async fn test_pre_fails_with_wrong_derivation() {
    let db_name = "test_pre_fails_with_wrong_derivation";
    let db_paths = [
        test_db_path(&format!("{}_1", db_name)),
        test_db_path(&format!("{}_2", db_name)),
        test_db_path(&format!("{}_3", db_name)),
    ];

    println!("=== Starting PRE Failure Test (Wrong Derivation) ===\n");

    // Setup network
    let mut network = setup_three_node_network_with_pre(true, true, true, db_name).await;
    let peer_ids = network.get_all_peer_ids();

    // Run DKG
    let node1_service =
        DkgServiceImpl::<DkgImpl>::with_routes(network.alice.app_state.clone(), &network::V0);

    let request = StartDkgRequest {
        ring_id: TEST_FRESH_DKG_RING_ID.to_string(),
    };

    let test_keys = TestKeyPair::new();
    let token = test_keys
        .create_dkg_jwt(TEST_FRESH_DKG_RING_ID)
        .expect("Failed to create JWT");

    let result = node1_service
        .start_dkg(create_authenticated_request(request, &token).unwrap())
        .await;
    assert!(result.is_ok());

    let ring_payload = wait_for_dkg_completion(&network).await;

    // Deserialize the aggregate public key from the ring payload
    let ring_pk_bytes = hex::decode(&ring_payload.ring_pk).expect("decode ring_pk hex");
    let aggregate_pk =
        <DkgImpl as Dkg>::PublicKey::from_bytes(&ring_pk_bytes).expect("deserialize public key");

    // Alice encrypts WITH derivation
    let secret_message = b"Secret encrypted with specific derivation";
    let correct_derivation = b"correct_derivation_path".to_vec();
    let wrong_derivation = b"wrong_derivation_path".to_vec();

    let metadata = generate_test_policy_metadata();
    let (_, encrypted_secret, proof) = PreImpl::encrypt_secret(
        &aggregate_pk,
        secret_message,
        Some(&correct_derivation),
        Some(&metadata),
    )
    .expect("Encryption with derivation should succeed");
    let secret_bytes = serde_json::to_vec(&encrypted_secret).unwrap();

    // Bob's keys
    let (bob_sk, bob_pk) = PreImpl::generate_keypair();
    let bob_pk_bytes = CryptoSerialize::to_bytes(&bob_pk).unwrap();

    // PRE with CORRECT derivation (re-encryption should work)
    let pre_coordinator = PreCoordinator::<DkgImpl, PreImpl>::with_routes(
        Arc::new(network.alice.app_state.clone()),
        &::network::V0,
    );
    let pre_peer_ids = peer_ids.clone();

    // Store the document in the bulletin
    let dummy_bulletin = network
        .dummy_bulletin
        .as_ref()
        .expect("PRE tests require DummyBulletin");
    let object_id = setup_document_in_bulletin(dummy_bulletin, &secret_bytes, proof).await;

    // Create PRE JWT token with CORRECT derivation
    let pre_token = test_keys
        .create_pre_jwt(
            bob_pk_bytes.clone(),
            &object_id,
            Some(correct_derivation.clone()),
            None,
        )
        .expect("Failed to create PRE JWT");

    // Initiate re-encryption with CORRECT derivation
    let pre_response_bytes = pre_coordinator
        .initiate_reencryption(
            "correct-derivation-pre-request".to_string(),
            RingConfig {
                ring_pk_bytes: ring_pk_bytes.clone(),
                peer_ids: pre_peer_ids.clone(),
                peer_node_keys: ring_payload.peer_node_keys.clone(),
                threshold: ring_payload.threshold as usize,
                total_participants: ring_payload.peer_node_keys.len(),
                public_polynomial_hex: RingPolyState::load_from_ring_pk_hex(
                    &network.alice.app_state.local_storage,
                    &ring_payload.ring_pk,
                )
                .expect("load RingPolyState")
                .public_polynomial,
            },
            secret_bytes.clone(),
            PreRequestContext {
                rdr_pk_bytes: bob_pk_bytes.clone(),
                object_id: object_id.clone(),
                token_string: pre_token,
                derivation: Some(correct_derivation.clone()),
                salt: None,
                valid_window: None,
            },
        )
        .await
        .expect("PRE with correct derivation should succeed");

    let pre_response: PreResponse = serde_json::from_slice(&pre_response_bytes).unwrap();

    // Bob decrypts with CORRECT derivation - should succeed
    let xnc_cmt_bytes = hex::decode(&pre_response.xnc_cmt).unwrap();
    let xnc_cmt = <PreImpl as ThresholdDealer>::PublicKey::from_bytes(&xnc_cmt_bytes).unwrap();

    // Compute correct derived_pk for decryption
    let correct_effective_pk =
        PreImpl::derive_public_key(&aggregate_pk, &correct_derivation).unwrap();

    let decrypt_result_correct = PreImpl::decrypt_secret(
        &correct_effective_pk,
        &xnc_cmt,
        &bob_sk,
        &pre_response.secret,
    );

    assert!(
        decrypt_result_correct.is_ok(),
        "Decryption with correct derivation should succeed"
    );
    assert_eq!(
        decrypt_result_correct.unwrap(),
        secret_message,
        "Decrypted message should match original"
    );
    println!("Decryption with correct derivation succeeded!");

    // Now try to decrypt with WRONG derivation - should fail
    let wrong_effective_pk = PreImpl::derive_public_key(&aggregate_pk, &wrong_derivation).unwrap();

    let decrypt_result_wrong =
        PreImpl::decrypt_secret(&wrong_effective_pk, &xnc_cmt, &bob_sk, &pre_response.secret);

    assert!(
        decrypt_result_wrong.is_err(),
        "Decryption with wrong derivation should fail"
    );

    // Also verify that using no derivation (ring_pk directly) fails
    let decrypt_result_no_derivation =
        PreImpl::decrypt_secret(&aggregate_pk, &xnc_cmt, &bob_sk, &pre_response.secret);

    assert!(
        decrypt_result_no_derivation.is_err(),
        "Decryption without derivation should fail when secret was encrypted with derivation"
    );

    network
        .shutdown_routers()
        .await
        .expect("Failed to shutdown");
    for path in &db_paths {
        cleanup_db(path);
    }
}

/// Test that PRE fails when the document has a tampered encryption proof
///
/// This test verifies that if a document is stored in the bulletin with a
/// bad proof (e.g. tampered challenge bytes), the PRE nodes reject the
/// re-encryption request because policy binding verification fails.
#[tokio::test]
#[serial_test::serial]
async fn test_pre_fails_with_bad_proof() {
    let db_name = "test_pre_fails_with_bad_proof";
    let db_paths = [
        test_db_path(&format!("{}_1", db_name)),
        test_db_path(&format!("{}_2", db_name)),
        test_db_path(&format!("{}_3", db_name)),
    ];

    println!("=== Starting PRE Failure Test (Bad Proof) ===\n");

    // Setup network
    let mut network = setup_three_node_network_with_pre(true, true, true, db_name).await;
    let peer_ids = network.get_all_peer_ids();

    // Run DKG
    let node1_service =
        DkgServiceImpl::<DkgImpl>::with_routes(network.alice.app_state.clone(), &network::V0);

    let request = StartDkgRequest {
        ring_id: TEST_FRESH_DKG_RING_ID.to_string(),
    };

    let test_keys = TestKeyPair::new();
    let token = test_keys
        .create_dkg_jwt(TEST_FRESH_DKG_RING_ID)
        .expect("Failed to create JWT");

    let result = node1_service
        .start_dkg(create_authenticated_request(request, &token).unwrap())
        .await;
    assert!(result.is_ok());

    let ring_payload = wait_for_dkg_completion(&network).await;

    // Deserialize the aggregate public key from the ring payload
    let ring_pk_bytes = hex::decode(&ring_payload.ring_pk).expect("decode ring_pk hex");
    let aggregate_pk =
        <DkgImpl as Dkg>::PublicKey::from_bytes(&ring_pk_bytes).expect("deserialize public key");

    // Alice encrypts
    let secret_message = b"Secret with tampered proof";
    let metadata = generate_test_policy_metadata();
    let (_, encrypted_secret, mut proof) =
        PreImpl::encrypt_secret(&aggregate_pk, secret_message, None, Some(&metadata))
            .expect("Encryption should succeed");
    let secret_bytes = serde_json::to_vec(&encrypted_secret).unwrap();

    // Tamper with the proof by flipping a byte in the challenge
    if let Some(byte) = proof.challenge.first_mut() {
        *byte ^= 0xFF;
    }

    // Bob's keys
    let (_bob_sk, bob_pk) = PreImpl::generate_keypair();
    let bob_pk_bytes = CryptoSerialize::to_bytes(&bob_pk).unwrap();

    // PRE
    let pre_coordinator = PreCoordinator::<DkgImpl, PreImpl>::with_routes(
        Arc::new(network.alice.app_state.clone()),
        &::network::V0,
    );
    let pre_peer_ids = peer_ids.clone();

    // Store the document in the bulletin with the TAMPERED proof
    let dummy_bulletin = network
        .dummy_bulletin
        .as_ref()
        .expect("PRE tests require DummyBulletin");
    let object_id = setup_document_in_bulletin(dummy_bulletin, &secret_bytes, proof).await;

    // Create PRE JWT token
    let pre_token = test_keys
        .create_pre_jwt(bob_pk_bytes.clone(), &object_id, None, None)
        .expect("Failed to create PRE JWT");

    // Attempt re-encryption — should fail because proof verification fails on peer nodes
    let pre_result = pre_coordinator
        .initiate_reencryption(
            "bad-proof-pre-request".to_string(),
            RingConfig {
                ring_pk_bytes,
                peer_ids: pre_peer_ids.clone(),
                peer_node_keys: ring_payload.peer_node_keys.clone(),
                threshold: ring_payload.threshold as usize,
                total_participants: ring_payload.peer_node_keys.len(),
                public_polynomial_hex: RingPolyState::load_from_ring_pk_hex(
                    &network.alice.app_state.local_storage,
                    &ring_payload.ring_pk,
                )
                .expect("load RingPolyState")
                .public_polynomial,
            },
            secret_bytes,
            PreRequestContext {
                rdr_pk_bytes: bob_pk_bytes,
                object_id,
                token_string: pre_token,
                derivation: None,
                salt: None,
                valid_window: None,
            },
        )
        .await;

    assert!(
        pre_result.is_err(),
        "PRE should fail when document has a tampered proof"
    );

    let error = pre_result.unwrap_err();
    println!("PRE correctly failed with error: {}", error);
    // With early verification, peers that answer with a bad proof no longer count toward
    // the threshold, so the coordinator fails on insufficient verified shares.
    assert!(
        error.to_string().contains("Insufficient shares"),
        "Error should indicate insufficient verified shares: {}",
        error
    );

    network
        .shutdown_routers()
        .await
        .expect("Failed to shutdown");
    for path in &db_paths {
        cleanup_db(path);
    }
}

#[tokio::test]
#[serial_test::serial]
async fn test_local_pre_share_verification_failure_is_not_counted() {
    let db_name = "test_local_pre_share_verification_failure_is_not_counted";
    let db_path = test_db_path(db_name);
    let app_state = create_test_app_state_default(db_name).await;

    let mut dkg_node = DkgImpl::new(1, 1, 1, 42, DkgRole::Standard).expect("create DKG node");
    dkg_node
        .generate_polynomial(DkgMode::Fresh)
        .expect("generate polynomial");
    let pri_share = dkg_node
        .compute_secret_share()
        .expect("compute local secret share");
    let aggregate_pk = dkg_node
        .compute_aggregate_public_key()
        .expect("compute aggregate public key");

    let mut mismatched_dkg_node =
        DkgImpl::new(1, 1, 1, 43, DkgRole::Standard).expect("create mismatched DKG node");
    mismatched_dkg_node
        .generate_polynomial(DkgMode::Refresh)
        .expect("generate mismatched polynomial");
    let mismatched_pub_poly = mismatched_dkg_node
        .compute_public_polynomial()
        .expect("compute mismatched public polynomial");

    let share_bytes = CryptoSerialize::to_bytes(&pri_share).expect("serialize private share");
    let mismatched_pub_poly_bytes =
        CryptoSerialize::to_bytes(&mismatched_pub_poly).expect("serialize mismatched polynomial");
    let ring_pk_bytes =
        CryptoSerialize::to_bytes(&aggregate_pk).expect("serialize aggregate public key");
    let mismatched_public_polynomial_hex = hex::encode(&mismatched_pub_poly_bytes);

    RingShareBundle {
        share_bytes: Zeroizing::new(share_bytes),
        public_polynomial: mismatched_public_polynomial_hex.clone(),
        last_pss: 0,
    }
    .save(&app_state.local_storage, &aggregate_pk)
    .expect("save local ring share bundle");

    let (_bob_sk, bob_pk) = PreImpl::generate_keypair();
    let bob_pk_bytes = CryptoSerialize::to_bytes(&bob_pk).expect("serialize reader public key");
    let (_, encrypted_secret, _) =
        PreImpl::encrypt_secret(&aggregate_pk, b"local verification failure", None, None)
            .expect("encrypt secret");
    let secret_bytes = serde_json::to_vec(&encrypted_secret).expect("serialize secret");

    let request_id = "local-share-verify-failure".to_string();
    assert_eq!(
        app_state
            .pre_response_state
            .init_response_for_version(0, request_id.clone(), &[])
            .await,
        crate::helpers::response_manager::ResponseInitOutcome::Created,
        "response collection should initialize"
    );

    let peer_id = hex::encode(app_state.network.local_peer_id().as_bytes());
    let coordinator = PreCoordinator::<DkgImpl, PreImpl>::with_routes(
        Arc::new(app_state.clone()),
        &::network::V0,
    );
    let result = coordinator
        .initiate_reencryption_inner(
            request_id.clone(),
            RingConfig {
                ring_pk_bytes,
                peer_ids: vec![peer_id],
                peer_node_keys: vec![app_state.node_key.clone()],
                threshold: 1,
                total_participants: 1,
                public_polynomial_hex: mismatched_public_polynomial_hex,
            },
            secret_bytes,
            1,
            true,
            0,
            PreRequestContext {
                rdr_pk_bytes: bob_pk_bytes,
                object_id: "local-verify-failure-object".to_string(),
                token_string: "unused".to_string(),
                derivation: None,
                salt: None,
                valid_window: None,
            },
        )
        .await;

    app_state
        .pre_response_state
        .remove_response_for_version(0, &request_id)
        .await;

    match result {
        Err(PreError::InsufficientShares { got, need }) => {
            assert_eq!(got, 0, "unverified local share must not be counted");
            assert_eq!(need, 1);
        }
        other => panic!("expected InsufficientShares got=0 need=1, got {other:?}"),
    }

    cleanup_db(&db_path);
}

/// Regression test: check_policy_access must propagate authz denial as an error.
///
/// Before the fix, check_policy_access discarded the boolean returned by authz.check()
/// and always returned Ok(()), silently passing all policy checks.
#[tokio::test]
async fn test_check_policy_access_enforces_authz_denial() {
    struct DenyAuthZ;

    #[async_trait::async_trait]
    impl authz::r#trait::Authz for DenyAuthZ {
        async fn check(&self, _: Vec<u8>, _: &str) -> authz::error::Result<bool> {
            Ok(false)
        }
    }

    let document_payload = DocumentPayload {
        ring_id: "ring-1".to_string(),
        document: "{}".to_string(),
        proof: "".to_string(),
        policy_id: "policy-1".to_string(),
        resource: "document".to_string(),
        permission: "read".to_string(),
        tier: None,
        timestamp: None,
    };

    let result =
        check_policy_access(&DenyAuthZ, &document_payload, "obj-1", "did:key:test", None).await;

    assert!(result.is_err(), "denied authz should return Err");
    assert!(
        matches!(result.unwrap_err(), PreError::Unauthorized(_)),
        "denial should be PreError::Unauthorized"
    );
}
