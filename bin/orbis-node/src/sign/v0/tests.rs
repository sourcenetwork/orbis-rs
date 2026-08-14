//! Sign End-to-End Tests
//!
//! This module contains end-to-end tests for the threshold BLS signing protocol.
//! These tests verify the complete flow: DKG → Sign message → Verify signature.

use crate::constants::MAX_SIGN_MESSAGE_BYTES;
use crate::dkg::v0::service::DkgServiceImpl;
use crate::helpers::ring::RingConfig;
use crate::helpers::test_helpers::{
    cleanup_db, create_authenticated_request, create_test_app_state, get_test_ring_post,
    setup_three_node_network_with_sign, setup_three_node_network_with_sign_and_trusted_relays,
    test_db_path, TestKeyPair, TEST_FRESH_DKG_RING_ID,
};
use crate::ring_state::RingPolyState;
use crate::sign::v0::coordinator::{SignCoordinator, SignResponse, SigningOptions};
use crate::sign::v0::error::SignError;
use crate::sign::v0::helpers::{check_policy_access, check_policy_access_at};
use crate::sign::v0::messages::{PolicyContext, SignContext};
#[cfg(feature = "decaf377")]
use crate::sign::v0::messages::{SignMessage, SignRequest};
use crate::sign::v0::service::SignServiceImpl;
use authn::{DkgClaims, SignClaims};
use authz::sourcehub::{AccessCheckRequest, ValidWindow};
use bulletin::dummy::DummyBulletin;
use bulletin::r#trait::{
    Bulletin, BulletinPost, BulletinWriteKind, DocumentPayload, KeyDerivation, RingPayload,
};
use crypto::r#trait::{CryptoDeserialize, Dkg, ThresholdSigner};
use crypto::{DkgImpl, SignImpl};
use proto::v0::dkg::{dkg_service_server::DkgService, StartDkgRequest};
use proto::v0::sign::{sign_service_server::SignService, StartSignRequest};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio::time::{sleep, Duration};
/// End-to-end test: DKG → Sign message → Verify signature
///
/// This test demonstrates the complete threshold BLS signing flow:
/// 1. Three nodes (node1, node2, node3) run DKG to generate a shared public key
/// 2. A message hash is created to sign
/// 3. The nodes perform threshold signing to produce signature shares
/// 4. The signature shares are combined into a full signature
/// 5. The signature is verified against the aggregate public key
#[tokio::test]
#[serial_test::serial]
async fn test_dkg_then_sign_end_to_end() {
    let db_name = "test_dkg_then_sign_end_to_end";
    let db_paths = [
        test_db_path(&format!("{}_1", db_name)),
        test_db_path(&format!("{}_2", db_name)),
        test_db_path(&format!("{}_3", db_name)),
    ];

    println!("=== Starting End-to-End Sign Test ===\n");

    // =========================================================================
    // Step 1: Setup the three-node network with DKG, PRE, and Sign handlers
    // =========================================================================
    println!("Step 1: Setting up three-node network...");
    let mut network = setup_three_node_network_with_sign(true, true, true, db_name).await;

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
    let (ring_payload, ring_id) = wait_for_dkg_completion(&network).await;

    // Deserialize the aggregate public key from the ring payload
    let ring_pk_bytes = hex::decode(&ring_payload.ring_pk).expect("decode ring_pk hex");
    let aggregate_pk =
        <DkgImpl as Dkg>::PublicKey::from_bytes(&ring_pk_bytes).expect("deserialize public key");
    println!("DKG completed! Aggregate public key obtained.");

    // =========================================================================
    // Step 3: Create a document, post it to bulletin, and get the message to sign
    // =========================================================================
    println!("\nStep 3: Creating document and posting to bulletin...");

    let message = create_test_document_and_post(&network.alice.app_state.bulletin, &ring_id).await;

    println!(
        "Document posted to bulletin, message length: {} bytes",
        message.len()
    );

    // =========================================================================
    // Step 4: Initiate threshold signing
    // =========================================================================
    println!("\nStep 4: Initiating threshold signing...");

    // Create a Sign coordinator using node1's app state
    let sign_coordinator = SignCoordinator::<DkgImpl, SignImpl>::with_routes(
        Arc::new(network.alice.app_state.clone()),
        &::network::V0,
    );

    // Generate a unique request ID
    let request_id = format!(
        "sign-request-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    );

    // Get peer IDs for signing (all nodes including initiator)
    let sign_peer_ids = network.get_all_peer_ids();

    println!("Sending sign requests to peers: {:?}", sign_peer_ids);

    // Initiate signing using threshold, total_nodes, and public_polynomial from bulletin
    let sign_response_bytes = sign_coordinator
        .initiate_signing(
            request_id.clone(),
            RingConfig {
                ring_id: String::new(),
                ring_pk_bytes: ring_pk_bytes.clone(),
                peer_ids: sign_peer_ids.clone(),
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
            message.clone(),
            SignContext::Bulletin {
                object_id: bulletin_object_id(&message),
            },
            SigningOptions::default(),
        )
        .await
        .expect("Signing should succeed");

    println!("Signing completed successfully!");

    // Deserialize the sign response
    let sign_response: SignResponse =
        serde_json::from_slice(&sign_response_bytes).expect("Failed to deserialize sign response");

    println!(
        "  - signature (hex): {}",
        &sign_response.signature[..64.min(sign_response.signature.len())]
    );

    // =========================================================================
    // Step 5: Verify the signature
    // =========================================================================
    println!("\nStep 5: Verifying the signature...");

    // Deserialize the signature from hex
    let signature_bytes =
        hex::decode(&sign_response.signature).expect("Failed to decode signature hex");
    let signature = <SignImpl as ThresholdSigner>::Signature::from_bytes(&signature_bytes)
        .expect("Failed to deserialize signature");

    // Verify the signature using the ThresholdSigner trait
    let signer = SignImpl::new();
    let verify_result = signer.verify(&aggregate_pk, &message, &signature);

    assert!(
        verify_result.is_ok(),
        "Signature verification should succeed: {:?}",
        verify_result.err()
    );

    println!("SUCCESS! Signature verified successfully!");
    println!("\n=== End-to-End Sign Test Completed Successfully ===");

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

/// Helper function to wait for DKG completion and return the RingPayload and ring_id
async fn wait_for_dkg_completion(
    network: &crate::helpers::test_helpers::ThreeNodeNetwork,
) -> (RingPayload, String) {
    let check_interval = Duration::from_millis(500);
    let max_wait = Duration::from_secs(60);
    let start = std::time::Instant::now();

    let dummy_bulletin = network
        .dummy_bulletin
        .as_ref()
        .expect("sign tests require DummyBulletin");

    loop {
        // Check if ring payload has been posted to bulletin (indicates Phase 4 complete)
        let post = get_test_ring_post(dummy_bulletin);

        // Check if payload is non-empty (DKG complete, ring info posted to bulletin)
        if !post.payload.is_empty() {
            // Parse RingPayload from bulletin post
            let ring_payload: RingPayload = post.clone().try_into().expect("parse RingPayload");
            let ring_id = post.id.clone();

            println!("All nodes have computed the same aggregate public key!");
            return (ring_payload, ring_id);
        }

        if start.elapsed() > max_wait {
            panic!("DKG did not complete within {} seconds", max_wait.as_secs());
        }

        sleep(check_interval).await;
    }
}

/// Helper function to create a DocumentPayload, post it to bulletin, and return the serialized BulletinPost
async fn create_test_document_and_post(
    bulletin: &Arc<dyn Bulletin + Send + Sync>,
    ring_id: &str,
) -> Vec<u8> {
    // Create a test DocumentPayload
    let doc_payload = DocumentPayload {
        ring_id: ring_id.to_string(),
        document: "test_encrypted_document".to_string(),
        proof: "test_proof".to_string(),
        policy_id: "test_policy".to_string(),
        resource: "test_resource".to_string(),
        permission: "read".to_string(),
        tier: None,
        timestamp: None,
    };

    // Serialize DocumentPayload to bytes
    let payload_bytes: Vec<u8> = doc_payload
        .clone()
        .try_into()
        .expect("serialize DocumentPayload");

    // Post to bulletin
    let post_id = bulletin
        .post(BulletinWriteKind::Document, payload_bytes.clone())
        .await
        .expect("post to bulletin");

    // Create the BulletinPost that was stored (this is what gets signed)
    let bulletin_post = BulletinPost {
        id: post_id,
        payload: payload_bytes,
    };

    // Serialize BulletinPost to bytes
    bulletin_post.try_into().expect("serialize BulletinPost")
}

fn bulletin_object_id(message: &[u8]) -> String {
    BulletinPost::try_from(message.to_vec())
        .expect("deserialize test BulletinPost")
        .id
}

/// Test signing with different message hashes
#[tokio::test]
#[serial_test::serial]
async fn test_sign_different_messages() {
    let db_name = "test_sign_different_messages";
    let db_paths = [
        test_db_path(&format!("{}_1", db_name)),
        test_db_path(&format!("{}_2", db_name)),
        test_db_path(&format!("{}_3", db_name)),
    ];

    println!("=== Starting Sign Different Messages Test ===\n");

    // Setup network
    let mut network = setup_three_node_network_with_sign(true, true, true, db_name).await;
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

    let (ring_payload, ring_id) = wait_for_dkg_completion(&network).await;

    let ring_pk_bytes = hex::decode(&ring_payload.ring_pk).expect("decode ring_pk hex");
    let aggregate_pk =
        <DkgImpl as Dkg>::PublicKey::from_bytes(&ring_pk_bytes).expect("deserialize public key");

    // Sign two different documents
    for i in 0..2 {
        // Create and post a document for each message
        let message =
            create_test_document_and_post(&network.alice.app_state.bulletin, &ring_id).await;

        let sign_coordinator = SignCoordinator::<DkgImpl, SignImpl>::with_routes(
            Arc::new(network.alice.app_state.clone()),
            &::network::V0,
        );

        let request_id = format!(
            "sign-msg-{}-{}",
            i,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis()
        );

        let sign_response_bytes = sign_coordinator
            .initiate_signing(
                request_id,
                RingConfig {
                    ring_id: String::new(),
                    ring_pk_bytes: ring_pk_bytes.clone(),
                    peer_ids: peer_ids.clone(),
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
                message.clone(),
                SignContext::Bulletin {
                    object_id: bulletin_object_id(&message),
                },
                SigningOptions::default(),
            )
            .await
            .expect("Signing should succeed");

        let sign_response: SignResponse = serde_json::from_slice(&sign_response_bytes).unwrap();

        let signature_bytes = hex::decode(&sign_response.signature).unwrap();
        let signature =
            <SignImpl as ThresholdSigner>::Signature::from_bytes(&signature_bytes).unwrap();

        let signer = SignImpl::new();
        assert!(
            signer.verify(&aggregate_pk, &message, &signature).is_ok(),
            "Signature {} should verify",
            i
        );

        println!("Message {} signed and verified successfully", i + 1);
    }

    println!("SUCCESS! Both messages signed and verified!");

    network
        .shutdown_routers()
        .await
        .expect("Failed to shutdown");
    for path in &db_paths {
        cleanup_db(path);
    }
}

/// Test that signature verification fails with wrong message
#[tokio::test]
#[serial_test::serial]
async fn test_sign_fails_wrong_message() {
    let db_name = "test_sign_fails_wrong_message";
    let db_paths = [
        test_db_path(&format!("{}_1", db_name)),
        test_db_path(&format!("{}_2", db_name)),
        test_db_path(&format!("{}_3", db_name)),
    ];

    println!("=== Starting Sign Fails Wrong Message Test ===\n");

    // Setup network
    let mut network = setup_three_node_network_with_sign(true, true, true, db_name).await;
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

    let (ring_payload, ring_id) = wait_for_dkg_completion(&network).await;

    let ring_pk_bytes = hex::decode(&ring_payload.ring_pk).expect("decode ring_pk hex");
    let aggregate_pk =
        <DkgImpl as Dkg>::PublicKey::from_bytes(&ring_pk_bytes).expect("deserialize public key");

    // Create and post a document, then sign it
    let original_message =
        create_test_document_and_post(&network.alice.app_state.bulletin, &ring_id).await;

    let sign_coordinator = SignCoordinator::<DkgImpl, SignImpl>::with_routes(
        Arc::new(network.alice.app_state.clone()),
        &::network::V0,
    );

    let request_id = format!(
        "sign-wrong-msg-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    );

    let sign_response_bytes = sign_coordinator
        .initiate_signing(
            request_id,
            RingConfig {
                ring_id: String::new(),
                ring_pk_bytes: ring_pk_bytes.clone(),
                peer_ids: peer_ids.clone(),
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
            original_message.clone(),
            SignContext::Bulletin {
                object_id: bulletin_object_id(&original_message),
            },
            SigningOptions::default(),
        )
        .await
        .expect("Signing should succeed");

    let sign_response: SignResponse = serde_json::from_slice(&sign_response_bytes).unwrap();

    let signature_bytes = hex::decode(&sign_response.signature).unwrap();
    let signature = <SignImpl as ThresholdSigner>::Signature::from_bytes(&signature_bytes).unwrap();

    // Verify with the correct message should succeed
    let signer = SignImpl::new();
    assert!(
        signer
            .verify(&aggregate_pk, &original_message, &signature)
            .is_ok(),
        "Signature should verify with correct message"
    );

    // Verify with a different message should fail
    let wrong_message = b"Wrong message that was not signed";

    let verify_result = signer.verify(&aggregate_pk, wrong_message, &signature);
    assert!(
        verify_result.is_err(),
        "Signature verification should fail with wrong message"
    );

    println!("SUCCESS! Signature correctly fails verification with wrong message");

    network
        .shutdown_routers()
        .await
        .expect("Failed to shutdown");
    for path in &db_paths {
        cleanup_db(path);
    }
}

/// Test that sign response is cleaned up after completion
#[tokio::test]
#[serial_test::serial]
async fn test_sign_response_cleanup() {
    let db_name = "test_sign_response_cleanup";
    let db_paths = [
        test_db_path(&format!("{}_1", db_name)),
        test_db_path(&format!("{}_2", db_name)),
        test_db_path(&format!("{}_3", db_name)),
    ];

    println!("=== Starting Sign Response Cleanup Test ===\n");

    // Setup network
    let mut network = setup_three_node_network_with_sign(true, true, true, db_name).await;
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

    let (ring_payload, ring_id) = wait_for_dkg_completion(&network).await;

    let ring_pk_bytes = hex::decode(&ring_payload.ring_pk).expect("decode ring_pk hex");

    // Create and post a document, then sign it
    let message = create_test_document_and_post(&network.alice.app_state.bulletin, &ring_id).await;

    let sign_coordinator = SignCoordinator::<DkgImpl, SignImpl>::with_routes(
        Arc::new(network.alice.app_state.clone()),
        &::network::V0,
    );

    let request_id = format!(
        "sign-cleanup-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    );
    let object_id = bulletin_object_id(&message);

    let _sign_response_bytes = sign_coordinator
        .initiate_signing(
            request_id.clone(),
            RingConfig {
                ring_id: String::new(),
                ring_pk_bytes: ring_pk_bytes.clone(),
                peer_ids: peer_ids.clone(),
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
            message,
            SignContext::Bulletin { object_id },
            SigningOptions::default(),
        )
        .await
        .expect("Signing should succeed");

    // Verify sign response was cleaned up
    let remaining_responses = network
        .alice
        .app_state
        .sign_response_state
        .get_responses(&request_id)
        .await;
    assert!(
        remaining_responses.is_none(),
        "sign_response should be cleaned up after signing"
    );

    println!("SUCCESS! Sign response correctly cleaned up after completion");

    network
        .shutdown_routers()
        .await
        .expect("Failed to shutdown");
    for path in &db_paths {
        cleanup_db(path);
    }
}

// ============================================================================
// verify_message tests
// ============================================================================

/// Test that signing fails when the message is not a valid BulletinPost (malformed bytes)
#[tokio::test]
#[serial_test::serial]
async fn test_sign_fails_invalid_bulletin_post() {
    let db_name = "test_sign_fails_invalid_bulletin_post";
    let db_paths = [
        test_db_path(&format!("{}_1", db_name)),
        test_db_path(&format!("{}_2", db_name)),
        test_db_path(&format!("{}_3", db_name)),
    ];

    println!("=== Starting Sign Fails Invalid BulletinPost Test ===\n");

    let mut network = setup_three_node_network_with_sign(true, true, true, db_name).await;
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

    let (ring_payload, _ring_id) = wait_for_dkg_completion(&network).await;

    let ring_pk_bytes = hex::decode(&ring_payload.ring_pk).expect("decode ring_pk hex");

    // Try to sign with invalid message (not a valid BulletinPost)
    let invalid_message = b"this is not a valid BulletinPost JSON";

    let sign_coordinator = SignCoordinator::<DkgImpl, SignImpl>::with_routes(
        Arc::new(network.alice.app_state.clone()),
        &::network::V0,
    );

    let request_id = format!(
        "sign-invalid-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    );

    let sign_result = sign_coordinator
        .initiate_signing(
            request_id,
            RingConfig {
                ring_id: String::new(),
                ring_pk_bytes,
                peer_ids: peer_ids.clone(),
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
            invalid_message.to_vec(),
            SignContext::Bulletin {
                object_id: "invalid-bulletin-post".to_string(),
            },
            SigningOptions::default(),
        )
        .await;

    // Signing should fail because responders can't deserialize the BulletinPost
    assert!(
        sign_result.is_err(),
        "Signing should fail with invalid BulletinPost message"
    );

    println!("SUCCESS! Signing correctly failed with invalid BulletinPost");

    network
        .shutdown_routers()
        .await
        .expect("Failed to shutdown");
    for path in &db_paths {
        cleanup_db(path);
    }
}

/// Test that signing fails when the BulletinPost doesn't exist on the bulletin
#[tokio::test]
#[serial_test::serial]
async fn test_sign_fails_post_not_on_bulletin() {
    let db_name = "test_sign_fails_post_not_on_bulletin";
    let db_paths = [
        test_db_path(&format!("{}_1", db_name)),
        test_db_path(&format!("{}_2", db_name)),
        test_db_path(&format!("{}_3", db_name)),
    ];

    println!("=== Starting Sign Fails Post Not On Bulletin Test ===\n");

    let mut network = setup_three_node_network_with_sign(true, true, true, db_name).await;
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

    let (ring_payload, ring_id) = wait_for_dkg_completion(&network).await;

    let ring_pk_bytes = hex::decode(&ring_payload.ring_pk).expect("decode ring_pk hex");

    // Create a valid BulletinPost but DON'T post it to the bulletin
    let doc_payload = DocumentPayload {
        ring_id: ring_id.clone(),
        document: "fake_document".to_string(),
        proof: "test_proof".to_string(),
        policy_id: "fake_policy".to_string(),
        resource: "fake_resource".to_string(),
        permission: "read".to_string(),
        tier: None,
        timestamp: None,
    };

    let payload_bytes: Vec<u8> = doc_payload.try_into().expect("serialize DocumentPayload");

    // Create a fake BulletinPost that was never posted
    let fake_bulletin_post = BulletinPost {
        id: "fake_post_id_that_doesnt_exist".to_string(),
        payload: payload_bytes,
    };

    let fake_message: Vec<u8> = fake_bulletin_post
        .try_into()
        .expect("serialize BulletinPost");

    let sign_coordinator = SignCoordinator::<DkgImpl, SignImpl>::with_routes(
        Arc::new(network.alice.app_state.clone()),
        &::network::V0,
    );

    let request_id = format!(
        "sign-not-posted-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    );

    let sign_result = sign_coordinator
        .initiate_signing(
            request_id,
            RingConfig {
                ring_id: String::new(),
                ring_pk_bytes,
                peer_ids: peer_ids.clone(),
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
            fake_message,
            SignContext::Bulletin {
                object_id: "fake_post_id_that_doesnt_exist".to_string(),
            },
            SigningOptions::default(),
        )
        .await;

    // Signing should fail because the post doesn't exist on the bulletin
    assert!(
        sign_result.is_err(),
        "Signing should fail when BulletinPost doesn't exist on bulletin"
    );

    println!("SUCCESS! Signing correctly failed when post not on bulletin");

    network
        .shutdown_routers()
        .await
        .expect("Failed to shutdown");
    for path in &db_paths {
        cleanup_db(path);
    }
}

/// Test that signing fails when the payload is tampered (doesn't match bulletin)
#[tokio::test]
#[serial_test::serial]
async fn test_sign_fails_tampered_payload() {
    let db_name = "test_sign_fails_tampered_payload";
    let db_paths = [
        test_db_path(&format!("{}_1", db_name)),
        test_db_path(&format!("{}_2", db_name)),
        test_db_path(&format!("{}_3", db_name)),
    ];

    println!("=== Starting Sign Fails Tampered Payload Test ===\n");

    let mut network = setup_three_node_network_with_sign(true, true, true, db_name).await;
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

    let (ring_payload, ring_id) = wait_for_dkg_completion(&network).await;

    let ring_pk_bytes = hex::decode(&ring_payload.ring_pk).expect("decode ring_pk hex");

    // First, create and post a legitimate document
    let original_doc = DocumentPayload {
        ring_id: ring_id.clone(),
        document: "original_document".to_string(),
        proof: "test_proof".to_string(),
        policy_id: "test_policy".to_string(),
        resource: "test_resource".to_string(),
        permission: "read".to_string(),
        tier: None,
        timestamp: None,
    };

    let original_payload: Vec<u8> = original_doc.try_into().expect("serialize");
    // Post the original document
    let post_id = network
        .alice
        .app_state
        .bulletin
        .post(BulletinWriteKind::Document, original_payload.clone())
        .await
        .expect("post to bulletin");

    // Now create a tampered BulletinPost with same ID but different payload
    let tampered_doc = DocumentPayload {
        ring_id: ring_id.clone(),
        document: "TAMPERED_document".to_string(), // Different content!
        proof: "test_proof".to_string(),
        policy_id: "test_policy".to_string(),
        resource: "test_resource".to_string(),
        permission: "read".to_string(),
        tier: None,
        timestamp: None,
    };

    let tampered_payload: Vec<u8> = tampered_doc.try_into().expect("serialize");

    let tampered_bulletin_post = BulletinPost {
        id: post_id.clone(),       // Same ID as the posted one
        payload: tampered_payload, // But different payload!
    };

    let tampered_message: Vec<u8> = tampered_bulletin_post
        .try_into()
        .expect("serialize BulletinPost");

    let sign_coordinator = SignCoordinator::<DkgImpl, SignImpl>::with_routes(
        Arc::new(network.alice.app_state.clone()),
        &::network::V0,
    );

    let request_id = format!(
        "sign-tampered-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    );

    let sign_result = sign_coordinator
        .initiate_signing(
            request_id,
            RingConfig {
                ring_id: String::new(),
                ring_pk_bytes,
                peer_ids: peer_ids.clone(),
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
            tampered_message,
            SignContext::Bulletin { object_id: post_id },
            SigningOptions::default(),
        )
        .await;

    // Signing should fail because the payload doesn't match what's on bulletin
    assert!(
        sign_result.is_err(),
        "Signing should fail when payload is tampered"
    );

    println!("SUCCESS! Signing correctly failed with tampered payload");

    network
        .shutdown_routers()
        .await
        .expect("Failed to shutdown");
    for path in &db_paths {
        cleanup_db(path);
    }
}

/// Test that signing fails when ring_id references a non-existent ring
#[tokio::test]
#[serial_test::serial]
async fn test_sign_fails_invalid_ring_id() {
    let db_name = "test_sign_fails_invalid_ring_id";
    let db_paths = [
        test_db_path(&format!("{}_1", db_name)),
        test_db_path(&format!("{}_2", db_name)),
        test_db_path(&format!("{}_3", db_name)),
    ];

    println!("=== Starting Sign Fails Invalid Ring ID Test ===\n");

    let mut network = setup_three_node_network_with_sign(true, true, true, db_name).await;
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

    let (ring_payload, _ring_id) = wait_for_dkg_completion(&network).await;

    let ring_pk_bytes = hex::decode(&ring_payload.ring_pk).expect("decode ring_pk hex");

    // Create a document with a fake ring_id that doesn't exist
    let doc_with_fake_ring = DocumentPayload {
        ring_id: "fake_ring_id_that_doesnt_exist_on_bulletin".to_string(),
        document: "test_document".to_string(),
        proof: "test_proof".to_string(),
        policy_id: "test_policy".to_string(),
        resource: "test_resource".to_string(),
        permission: "read".to_string(),
        tier: None,
        timestamp: None,
    };

    let payload_bytes: Vec<u8> = doc_with_fake_ring.try_into().expect("serialize");
    // Post this document (it will be on bulletin, but ring_id is invalid)
    let post_id = network
        .alice
        .app_state
        .bulletin
        .post(BulletinWriteKind::Document, payload_bytes.clone())
        .await
        .expect("post to bulletin");

    let bulletin_post = BulletinPost {
        id: post_id.clone(),
        payload: payload_bytes,
    };

    let message: Vec<u8> = bulletin_post.try_into().expect("serialize BulletinPost");

    let sign_coordinator = SignCoordinator::<DkgImpl, SignImpl>::with_routes(
        Arc::new(network.alice.app_state.clone()),
        &::network::V0,
    );

    let request_id = format!(
        "sign-invalid-ring-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    );

    let sign_result = sign_coordinator
        .initiate_signing(
            request_id,
            RingConfig {
                ring_id: String::new(),
                ring_pk_bytes,
                peer_ids: peer_ids.clone(),
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
            message,
            SignContext::Bulletin { object_id: post_id },
            SigningOptions::default(),
        )
        .await;

    // Signing should fail because the ring_id doesn't exist on bulletin
    assert!(
        sign_result.is_err(),
        "Signing should fail when ring_id references non-existent ring"
    );

    println!("SUCCESS! Signing correctly failed with invalid ring_id");

    network
        .shutdown_routers()
        .await
        .expect("Failed to shutdown");
    for path in &db_paths {
        cleanup_db(path);
    }
}

// ============================================================================
// Policy pathway tests (SignContext::Policy)
// ============================================================================

const POLICY_TEST_DERIVATION_ID: &str = "test-key-derivation";
const POLICY_TEST_DERIVATION: &str = "test-derivation-path";
const POLICY_TEST_POLICY_ID: &str = "test-policy";
const POLICY_TEST_RESOURCE: &str = "test-resource";
const POLICY_TEST_PERMISSION: &str = "test-permission";

/// Stores a `KeyDerivation` entry in the DummyBulletin so that `fetch_bulletin_payloads`
/// can find it under `(namespace, derivation_id)`.
fn setup_key_derivation_in_bulletin(
    dummy_bulletin: &DummyBulletin,
    ring_id: &str,
) -> KeyDerivation {
    let key_derivation = KeyDerivation {
        ring_id: ring_id.to_string(),
        derivation: POLICY_TEST_DERIVATION.to_string(),
        policy_id: POLICY_TEST_POLICY_ID.to_string(),
        resource: POLICY_TEST_RESOURCE.to_string(),
        permission: POLICY_TEST_PERMISSION.to_string(),
    };
    let payload = serde_json::to_vec(&key_derivation).expect("serialize KeyDerivation");
    let post = BulletinPost {
        id: POLICY_TEST_DERIVATION_ID.to_string(),
        payload,
    };
    dummy_bulletin.set_post(POLICY_TEST_DERIVATION_ID.to_string(), post);
    key_derivation
}

/// End-to-end test for the Policy signing pathway:
/// DKG → post KeyDerivation → sign arbitrary message with JWT auth → success.
#[tokio::test]
#[serial_test::serial]
async fn test_delegated_dkg_then_sign_policy_end_to_end() {
    let db_name = "test_delegated_dkg_then_sign_policy_end_to_end";
    let db_paths = [
        test_db_path(&format!("{}_1", db_name)),
        test_db_path(&format!("{}_2", db_name)),
        test_db_path(&format!("{}_3", db_name)),
    ];

    println!("=== Starting Policy Sign End-to-End Test ===\n");

    let relay = TestKeyPair::new();
    let actor_id = "did:opk:alice";
    let mut network =
        setup_three_node_network_with_sign_and_trusted_relays(db_name, vec![relay.did_uri.clone()])
            .await;
    let peer_ids = network.get_all_peer_ids();

    // Run DKG
    let node1_service =
        DkgServiceImpl::<DkgImpl>::with_routes(network.alice.app_state.clone(), &network::V0);
    let token = relay
        .sign_for_actor(
            actor_id.to_string(),
            DkgClaims {
                ring_id: TEST_FRESH_DKG_RING_ID.to_string(),
            },
            Duration::from_secs(60),
        )
        .expect("create DKG JWT");
    let result = node1_service
        .start_dkg(
            create_authenticated_request(
                StartDkgRequest {
                    ring_id: TEST_FRESH_DKG_RING_ID.to_string(),
                },
                &token,
            )
            .unwrap(),
        )
        .await;
    assert!(
        result.is_ok(),
        "start_dkg should succeed: {:?}",
        result.err()
    );

    let (ring_payload, ring_id) = wait_for_dkg_completion(&network).await;

    let ring_pk_bytes = hex::decode(&ring_payload.ring_pk).expect("decode ring_pk hex");

    // Post KeyDerivation to bulletin
    let dummy_bulletin = network
        .dummy_bulletin
        .as_ref()
        .expect("requires DummyBulletin");
    let key_derivation = setup_key_derivation_in_bulletin(dummy_bulletin, &ring_id);
    let message = b"Hello, Policy Signing World!".to_vec();

    // Create valid sign JWT
    let sign_token = relay
        .sign_for_actor(
            actor_id.to_string(),
            SignClaims {
                derivation_id: POLICY_TEST_DERIVATION_ID.to_string(),
                message_sha256: Sha256::digest(&message).to_vec(),
            },
            Duration::from_secs(60),
        )
        .expect("create sign JWT");

    let sign_coordinator = SignCoordinator::<DkgImpl, SignImpl>::with_routes(
        Arc::new(network.alice.app_state.clone()),
        &::network::V0,
    );

    let request_id = format!(
        "sign-policy-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    );

    let sign_response_bytes = sign_coordinator
        .initiate_signing(
            request_id,
            RingConfig {
                ring_id: String::new(),
                ring_pk_bytes: ring_pk_bytes.clone(),
                peer_ids: peer_ids.clone(),
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
            message.clone(),
            SignContext::Policy(Box::new(PolicyContext {
                token_string: sign_token,
                derivation_id: POLICY_TEST_DERIVATION_ID.to_string(),
                valid_window: None,
                key_derivation,
                relay_statement: None,
                relay_signature: Vec::new(),
            })),
            SigningOptions::default(),
        )
        .await
        .expect("Policy signing should succeed");

    let sign_response: SignResponse =
        serde_json::from_slice(&sign_response_bytes).expect("deserialize SignResponse");
    assert!(
        !sign_response.signature.is_empty(),
        "Signature should be non-empty"
    );

    // =========================================================================
    // Verify signature against the DERIVED public key (not the root key)
    // =========================================================================
    let aggregate_pk =
        <DkgImpl as Dkg>::PublicKey::from_bytes(&ring_pk_bytes).expect("deserialize root pk");

    let metadata = SignImpl::encode_metadata(
        POLICY_TEST_POLICY_ID,
        POLICY_TEST_RESOURCE,
        POLICY_TEST_PERMISSION,
    );
    let derived_pk = SignImpl::derive_public_key(
        &aggregate_pk,
        POLICY_TEST_DERIVATION.as_bytes(),
        Some(&metadata),
    )
    .expect("derive public key");

    let signature_bytes = hex::decode(&sign_response.signature).expect("decode signature hex");
    let signature = <SignImpl as ThresholdSigner>::Signature::from_bytes(&signature_bytes)
        .expect("deserialize signature");

    let signer = SignImpl::new();

    // Must verify against the derived key
    let verify_derived = signer.verify(&derived_pk, &message, &signature);
    assert!(
        verify_derived.is_ok(),
        "Signature must verify against derived public key: {:?}",
        verify_derived.err()
    );

    // Must NOT verify against the root (underived) key
    let verify_root = signer.verify(&aggregate_pk, &message, &signature);
    assert!(
        verify_root.is_err(),
        "Signature must not verify against root public key (wrong derivation)"
    );

    println!(
        "SUCCESS! Policy signing completed and verified against derived key, signature: {}...",
        &sign_response.signature[..16]
    );
    println!("\n=== Policy Sign End-to-End Test Completed Successfully ===");

    network
        .shutdown_routers()
        .await
        .expect("Failed to shutdown routers");
    for path in &db_paths {
        cleanup_db(path);
    }
}

/// Policy signing should fail when the JWT token string is garbage (not a valid JWT).
#[tokio::test]
#[serial_test::serial]
async fn test_sign_policy_fails_invalid_jwt() {
    let db_name = "test_sign_policy_fails_invalid_jwt";
    let db_paths = [
        test_db_path(&format!("{}_1", db_name)),
        test_db_path(&format!("{}_2", db_name)),
        test_db_path(&format!("{}_3", db_name)),
    ];

    let mut network = setup_three_node_network_with_sign(true, true, true, db_name).await;
    let peer_ids = network.get_all_peer_ids();

    let node1_service =
        DkgServiceImpl::<DkgImpl>::with_routes(network.alice.app_state.clone(), &network::V0);
    let test_keys = TestKeyPair::new();
    let token = test_keys
        .create_dkg_jwt(TEST_FRESH_DKG_RING_ID)
        .expect("create DKG JWT");
    let result = node1_service
        .start_dkg(
            create_authenticated_request(
                StartDkgRequest {
                    ring_id: TEST_FRESH_DKG_RING_ID.to_string(),
                },
                &token,
            )
            .unwrap(),
        )
        .await;
    assert!(result.is_ok());

    let (ring_payload, ring_id) = wait_for_dkg_completion(&network).await;

    let ring_pk_bytes = hex::decode(&ring_payload.ring_pk).expect("decode ring_pk hex");

    let dummy_bulletin = network
        .dummy_bulletin
        .as_ref()
        .expect("requires DummyBulletin");
    let key_derivation = setup_key_derivation_in_bulletin(dummy_bulletin, &ring_id);

    let sign_coordinator = SignCoordinator::<DkgImpl, SignImpl>::with_routes(
        Arc::new(network.alice.app_state.clone()),
        &::network::V0,
    );

    let sign_result = sign_coordinator
        .initiate_signing(
            format!(
                "req-{}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_millis()
            ),
            RingConfig {
                ring_id: String::new(),
                ring_pk_bytes,
                peer_ids: peer_ids.clone(),
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
            b"some message".to_vec(),
            SignContext::Policy(Box::new(PolicyContext {
                token_string: "this.is.not.a.valid.jwt".to_string(),
                derivation_id: POLICY_TEST_DERIVATION_ID.to_string(),
                valid_window: None,
                key_derivation,
                relay_statement: None,
                relay_signature: Vec::new(),
            })),
            SigningOptions::default(),
        )
        .await;

    assert!(sign_result.is_err(), "Should fail with invalid JWT");
    let err = sign_result.unwrap_err().to_string();
    assert!(
        err.contains("Insufficient") || err.contains("Timeout"),
        "Error should indicate peers rejected the request: {}",
        err
    );

    println!("SUCCESS! Policy signing correctly failed with invalid JWT");

    network
        .shutdown_routers()
        .await
        .expect("Failed to shutdown");
    for path in &db_paths {
        cleanup_db(path);
    }
}

/// Policy signing should fail when the JWT derivation_id claim does not match the request.
#[tokio::test]
#[serial_test::serial]
async fn test_sign_policy_fails_wrong_derivation_id() {
    let db_name = "test_sign_policy_fails_wrong_derivation_id";
    let db_paths = [
        test_db_path(&format!("{}_1", db_name)),
        test_db_path(&format!("{}_2", db_name)),
        test_db_path(&format!("{}_3", db_name)),
    ];

    let mut network = setup_three_node_network_with_sign(true, true, true, db_name).await;
    let peer_ids = network.get_all_peer_ids();

    let node1_service =
        DkgServiceImpl::<DkgImpl>::with_routes(network.alice.app_state.clone(), &network::V0);
    let test_keys = TestKeyPair::new();
    let token = test_keys
        .create_dkg_jwt(TEST_FRESH_DKG_RING_ID)
        .expect("create DKG JWT");
    let result = node1_service
        .start_dkg(
            create_authenticated_request(
                StartDkgRequest {
                    ring_id: TEST_FRESH_DKG_RING_ID.to_string(),
                },
                &token,
            )
            .unwrap(),
        )
        .await;
    assert!(result.is_ok());

    let (ring_payload, ring_id) = wait_for_dkg_completion(&network).await;

    let ring_pk_bytes = hex::decode(&ring_payload.ring_pk).expect("decode ring_pk hex");

    let dummy_bulletin = network
        .dummy_bulletin
        .as_ref()
        .expect("requires DummyBulletin");
    let key_derivation = setup_key_derivation_in_bulletin(dummy_bulletin, &ring_id);

    // JWT claims a different derivation_id than the request
    let sign_token = test_keys
        .create_sign_jwt("wrong-derivation-id", b"test message")
        .expect("create sign JWT");

    let sign_coordinator = SignCoordinator::<DkgImpl, SignImpl>::with_routes(
        Arc::new(network.alice.app_state.clone()),
        &::network::V0,
    );

    let sign_result = sign_coordinator
        .initiate_signing(
            format!(
                "req-{}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_millis()
            ),
            RingConfig {
                ring_id: String::new(),
                ring_pk_bytes,
                peer_ids: peer_ids.clone(),
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
            b"some message".to_vec(),
            SignContext::Policy(Box::new(PolicyContext {
                token_string: sign_token,
                derivation_id: POLICY_TEST_DERIVATION_ID.to_string(),
                valid_window: None,
                key_derivation,
                relay_statement: None,
                relay_signature: Vec::new(),
            })),
            SigningOptions::default(),
        )
        .await;

    assert!(
        sign_result.is_err(),
        "Should fail with mismatched derivation_id"
    );
    let err = sign_result.unwrap_err().to_string();
    assert!(
        err.contains("Insufficient") || err.contains("Timeout"),
        "Error should indicate peers rejected the request: {}",
        err
    );

    println!("SUCCESS! Policy signing correctly failed with wrong derivation_id claim");

    network
        .shutdown_routers()
        .await
        .expect("Failed to shutdown");
    for path in &db_paths {
        cleanup_db(path);
    }
}

/// Regression test: check_policy_access must propagate authz denial as an error.
#[tokio::test]
async fn test_sign_policy_check_policy_access_enforces_authz_denial() {
    struct DenyAuthZ;

    #[async_trait::async_trait]
    impl authz::r#trait::Authz for DenyAuthZ {
        async fn check(&self, _: Vec<u8>, _: &str) -> authz::error::Result<bool> {
            Ok(false)
        }
        async fn check_at(&self, _: Vec<u8>, _: &str, _: &str) -> authz::error::Result<bool> {
            Ok(false)
        }
        async fn current_anchor(&self) -> authz::error::Result<String> {
            Ok("0".to_string())
        }
        async fn anchor_time(&self, _: &str) -> authz::error::Result<u64> {
            Ok(0)
        }
    }

    let key_derivation = KeyDerivation {
        ring_id: "ring-1".to_string(),
        derivation: "some-derivation".to_string(),
        policy_id: "policy-1".to_string(),
        resource: "document".to_string(),
        permission: "sign".to_string(),
    };

    let result = check_policy_access(
        &DenyAuthZ,
        &key_derivation,
        POLICY_TEST_DERIVATION_ID,
        "did:key:test",
        None,
    )
    .await;

    assert!(result.is_err(), "Denied authz should return Err");
    assert!(
        matches!(result.unwrap_err(), SignError::Unauthorized(_)),
        "Denial should be SignError::Unauthorized"
    );
}

#[tokio::test]
async fn test_sign_policy_check_policy_access_at_uses_supplied_timestamp() {
    struct TimestampAuthZ {
        expected_timestamp: u64,
    }

    #[async_trait::async_trait]
    impl authz::r#trait::Authz for TimestampAuthZ {
        async fn check(&self, permission: Vec<u8>, _: &str) -> authz::error::Result<bool> {
            let req = AccessCheckRequest::from_bytes(&permission)
                .expect("deserialize AccessCheckRequest");
            assert_eq!(req.timestamp, Some(self.expected_timestamp));
            Ok(true)
        }
        async fn check_at(
            &self,
            permission: Vec<u8>,
            subject: &str,
            _: &str,
        ) -> authz::error::Result<bool> {
            self.check(permission, subject).await
        }
        async fn current_anchor(&self) -> authz::error::Result<String> {
            Ok("1".to_string())
        }
        async fn anchor_time(&self, _: &str) -> authz::error::Result<u64> {
            Ok(self.expected_timestamp)
        }
    }

    let key_derivation = KeyDerivation {
        ring_id: "ring-1".to_string(),
        derivation: "some-derivation".to_string(),
        policy_id: "policy-1".to_string(),
        resource: "document".to_string(),
        permission: "sign".to_string(),
    };
    let timestamp = 1_700_000_123;
    let valid_window = Some(ValidWindow {
        start: timestamp - 10,
        end: timestamp + 10,
    });

    check_policy_access_at(
        &TimestampAuthZ {
            expected_timestamp: timestamp,
        },
        &key_derivation,
        POLICY_TEST_DERIVATION_ID,
        "did:key:test",
        valid_window,
        Some(timestamp),
    )
    .await
    .expect("policy check should use supplied timestamp");
}

/// check_policy_access must deny access when the current time falls outside the valid_window.
///
/// The authz mock here validates the window exactly as SourceHubAuth does — it deserializes
/// the AccessCheckRequest and returns false when `now < window.start || now > window.end`.
/// Passing `end: 1` (epoch + 1 s) guarantees the window is in the past.
#[tokio::test]
async fn test_sign_policy_check_policy_access_expired_valid_window() {
    struct WindowCheckAuthZ;

    #[async_trait::async_trait]
    impl authz::r#trait::Authz for WindowCheckAuthZ {
        async fn check(&self, permission: Vec<u8>, _: &str) -> authz::error::Result<bool> {
            let req = AccessCheckRequest::from_bytes(&permission)
                .expect("deserialize AccessCheckRequest");
            if let (Some(window), Some(ts)) = (&req.valid_window, &req.timestamp) {
                if ts < &window.start || ts > &window.end {
                    return Ok(false);
                }
            }
            Ok(true)
        }
        async fn check_at(
            &self,
            permission: Vec<u8>,
            subject: &str,
            _: &str,
        ) -> authz::error::Result<bool> {
            self.check(permission, subject).await
        }
        async fn current_anchor(&self) -> authz::error::Result<String> {
            Ok("0".to_string())
        }
        async fn anchor_time(&self, _: &str) -> authz::error::Result<u64> {
            Ok(0)
        }
    }

    let key_derivation = KeyDerivation {
        ring_id: "ring-1".to_string(),
        derivation: "some-derivation".to_string(),
        policy_id: "policy-1".to_string(),
        resource: "document".to_string(),
        permission: "sign".to_string(),
    };

    // Window ended at unix second 1 — guaranteed to be in the past.
    let expired_window = Some(ValidWindow { start: 0, end: 1 });

    let result = check_policy_access(
        &WindowCheckAuthZ,
        &key_derivation,
        POLICY_TEST_DERIVATION_ID,
        "did:key:test",
        expired_window,
    )
    .await;

    assert!(result.is_err(), "Expired valid_window should return Err");
    assert!(
        matches!(result.unwrap_err(), SignError::Unauthorized(_)),
        "Expired window denial should be SignError::Unauthorized"
    );
}

/// The service must reject messages that exceed MAX_SIGN_MESSAGE_BYTES before
/// doing any JWT work. The check must fire before token resolution so that a
/// malformed or missing token does not mask the real rejection reason.
#[tokio::test]
async fn test_sign_service_rejects_oversized_message() {
    let db_name = "test_sign_service_rejects_oversized_message";
    let app_state = create_test_app_state(true, true, db_name).await;
    let service = SignServiceImpl::<DkgImpl, SignImpl>::with_routes(app_state, &network::V0);

    let oversized_message = vec![0u8; MAX_SIGN_MESSAGE_BYTES + 1];

    // No auth header — the size check must fire before JWT extraction.
    let request = tonic::Request::new(StartSignRequest {
        derivation_id: "test-derivation".to_string(),
        message: oversized_message,
        valid_window: None,
    });

    let result = service.start_sign(request).await;

    assert!(result.is_err(), "Oversized message should be rejected");
    let status = result.unwrap_err();
    assert_eq!(
        status.code(),
        tonic::Code::InvalidArgument,
        "Expected InvalidArgument, got: {:?}",
        status
    );
    assert!(
        status.message().contains("Message too large"),
        "Error message should describe the size limit: {}",
        status.message()
    );

    cleanup_db(&test_db_path(db_name));
}

#[cfg(feature = "decaf377")]
#[tokio::test]
#[serial_test::serial]
async fn test_failed_round_two_consumes_nonce_state() {
    let db_name = "test_failed_round_two_consumes_nonce_state";
    let db_path = test_db_path(db_name);
    let app_state = create_test_app_state(true, true, db_name).await;
    let sender_peer_id = app_state.network.local_peer_id().clone();
    let request_id = "failed-round-two";
    let nonce_key = format!("nonce-{request_id}");

    assert!(
        app_state
            .sign_response_state
            .store_nonce(
                nonce_key.clone(),
                vec![1, 2, 3],
                "bulletin:test-object".to_string(),
                sender_peer_id.as_bytes().to_vec(),
            )
            .await
    );

    let coordinator = SignCoordinator::<DkgImpl, SignImpl>::with_routes(
        Arc::new(app_state.clone()),
        &::network::V0,
    );
    let result = coordinator
        .handle_message(
            SignMessage::SignRequest(SignRequest {
                request_id: request_id.to_string(),
                from_node_id: 0,
                message: vec![0; MAX_SIGN_MESSAGE_BYTES + 1],
                all_commitments: Vec::new(),
                context: SignContext::Bulletin {
                    object_id: "test-object".to_string(),
                },
            }),
            &sender_peer_id,
        )
        .await;

    assert!(
        matches!(result, Err(SignError::InvalidInput(_))),
        "oversized Round 2 should fail validation, got: {result:?}"
    );
    assert!(
        app_state
            .sign_response_state
            .consume_nonce_for_sign_request(&nonce_key, sender_peer_id.as_bytes())
            .await
            .is_none(),
        "failed Round 2 must release its nonce slot"
    );

    cleanup_db(&db_path);
}

/// Policy signing should fail when the JWT was created for a different message than what is sent.
#[tokio::test]
#[serial_test::serial]
async fn test_sign_policy_fails_wrong_message_digest() {
    let db_name = "test_sign_policy_fails_wrong_message_digest";
    let db_paths = [
        test_db_path(&format!("{}_1", db_name)),
        test_db_path(&format!("{}_2", db_name)),
        test_db_path(&format!("{}_3", db_name)),
    ];

    let mut network = setup_three_node_network_with_sign(true, true, true, db_name).await;
    let peer_ids = network.get_all_peer_ids();

    let node1_service =
        DkgServiceImpl::<DkgImpl>::with_routes(network.alice.app_state.clone(), &network::V0);
    let test_keys = TestKeyPair::new();
    let token = test_keys
        .create_dkg_jwt(TEST_FRESH_DKG_RING_ID)
        .expect("create DKG JWT");
    let result = node1_service
        .start_dkg(
            create_authenticated_request(
                StartDkgRequest {
                    ring_id: TEST_FRESH_DKG_RING_ID.to_string(),
                },
                &token,
            )
            .unwrap(),
        )
        .await;
    assert!(result.is_ok());

    let (ring_payload, ring_id) = wait_for_dkg_completion(&network).await;

    let ring_pk_bytes = hex::decode(&ring_payload.ring_pk).expect("decode ring_pk hex");

    let dummy_bulletin = network
        .dummy_bulletin
        .as_ref()
        .expect("requires DummyBulletin");
    let key_derivation = setup_key_derivation_in_bulletin(dummy_bulletin, &ring_id);

    // JWT is signed for "original message"
    let original_message = b"original message".to_vec();
    let sign_token = test_keys
        .create_sign_jwt(POLICY_TEST_DERIVATION_ID, &original_message)
        .expect("create sign JWT");

    let sign_coordinator = SignCoordinator::<DkgImpl, SignImpl>::with_routes(
        Arc::new(network.alice.app_state.clone()),
        &::network::V0,
    );

    // But the request sends a different message
    let different_message = b"completely different message".to_vec();
    let sign_result = sign_coordinator
        .initiate_signing(
            format!(
                "req-{}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_millis()
            ),
            RingConfig {
                ring_id: String::new(),
                ring_pk_bytes,
                peer_ids: peer_ids.clone(),
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
            different_message,
            SignContext::Policy(Box::new(PolicyContext {
                token_string: sign_token,
                derivation_id: POLICY_TEST_DERIVATION_ID.to_string(),
                valid_window: None,
                key_derivation,
                relay_statement: None,
                relay_signature: Vec::new(),
            })),
            SigningOptions::default(),
        )
        .await;

    assert!(
        sign_result.is_err(),
        "Should fail when request message differs from JWT digest"
    );
    let err = sign_result.unwrap_err().to_string();
    assert!(
        err.contains("Insufficient") || err.contains("Timeout"),
        "Error should indicate peers rejected the request: {}",
        err
    );

    println!("SUCCESS! Policy signing correctly failed when message doesn't match JWT digest");

    network
        .shutdown_routers()
        .await
        .expect("Failed to shutdown");
    for path in &db_paths {
        cleanup_db(path);
    }
}
