//! Sign End-to-End Tests
//!
//! This module contains end-to-end tests for the threshold BLS signing protocol.
//! These tests verify the complete flow: DKG → Sign message → Verify signature.

use crate::constants::BULLETIN_PLACEHOLDER_PROOF;
use crate::helpers::test_helpers::{
    cleanup_db, create_authenticated_request, get_test_ring_post,
    setup_three_node_network_with_sign, test_db_path, TestKeyPair,
};
use crate::sign::coordinator::{SignCoordinator, SignResponse};
use crate::sign::messages::SignVerification;
use crate::DkgServiceImpl;
use bulletin::r#trait::{Bulletin, BulletinPost, DocumentPayload, RingPayload};
use crypto::r#trait::{CryptoDeserialize, Dkg, ThresholdSigner};
use crypto::{DkgImpl, SignImpl};
use proto::dkg_service::{dkg_service_server::DkgService, StartDkgRequest};
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
    let tonic_request = create_authenticated_request(request, &token).unwrap();
    let result = node1_service.start_dkg(tonic_request).await;
    assert!(
        result.is_ok(),
        "start_dkg should succeed: {:?}",
        result.err()
    );

    // Wait for DKG to complete and get the ring payload from bulletin
    println!("Waiting for DKG to complete...");
    let (ring_payload, ring_id) = wait_for_dkg_completion(
        &network,
        result.unwrap().into_inner().session_id.parse().unwrap(),
    )
    .await;

    // Deserialize the aggregate public key from the ring payload
    let ring_pk_bytes = hex::decode(&ring_payload.ring_pk).expect("decode ring_pk hex");
    let aggregate_pk =
        <DkgImpl as Dkg>::PublicKey::from_bytes(&ring_pk_bytes).expect("deserialize public key");
    println!("DKG completed! Aggregate public key obtained.");

    // =========================================================================
    // Step 3: Create a document, post it to bulletin, and get the message to sign
    // =========================================================================
    println!("\nStep 3: Creating document and posting to bulletin...");

    let test_namespace = "test_sign_namespace";
    let message =
        create_test_document_and_post(&network.alice.app_state.bulletin, &ring_id, test_namespace)
            .await;

    println!(
        "Document posted to bulletin, message length: {} bytes",
        message.len()
    );

    // =========================================================================
    // Step 4: Initiate threshold signing
    // =========================================================================
    println!("\nStep 4: Initiating threshold signing...");

    // Create a Sign coordinator using node1's app state
    let sign_coordinator =
        SignCoordinator::<DkgImpl, SignImpl>::new(Arc::new(network.alice.app_state.clone()));

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
            ring_pk_bytes.clone(),
            message.clone(),
            &sign_peer_ids,
            ring_payload.threshold as usize,
            ring_payload.peer_ids.len(),
            &ring_payload.public_polynomial,
            ring_id.clone(),
            SignVerification::Bulletin,
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
    _session_id: u64,
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
    namespace: &str,
) -> Vec<u8> {
    // Create a test DocumentPayload
    let doc_payload = DocumentPayload {
        ring_id: ring_id.to_string(),
        document: "test_encrypted_document".to_string(),
        proof: "test_proof".to_string(),
        policy_id: "test_policy".to_string(),
        resource: "test_resource".to_string(),
        permission: "read".to_string(),
    };

    // Serialize DocumentPayload to bytes
    let payload_bytes: Vec<u8> = doc_payload
        .clone()
        .try_into()
        .expect("serialize DocumentPayload");

    // Compute the post ID
    let full_namespace = format!("bulletin/{}", namespace);
    let post_id = bulletin
        .get_post_id(&full_namespace, &payload_bytes)
        .expect("compute post_id");

    // Post to bulletin
    let proof = BULLETIN_PLACEHOLDER_PROOF.to_vec();
    bulletin
        .post(
            namespace.to_string(),
            payload_bytes.clone(),
            proof.clone(),
            None,
        )
        .await
        .expect("post to bulletin");

    // Create the BulletinPost that was stored (this is what gets signed)
    let bulletin_post = BulletinPost {
        id: post_id,
        namespace: namespace.to_string(),
        payload: payload_bytes,
        proof,
    };

    // Serialize BulletinPost to bytes
    bulletin_post.try_into().expect("serialize BulletinPost")
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
        .start_dkg(create_authenticated_request(request, &token).unwrap())
        .await;
    assert!(result.is_ok());

    let (ring_payload, ring_id) = wait_for_dkg_completion(
        &network,
        result.unwrap().into_inner().session_id.parse().unwrap(),
    )
    .await;

    let ring_pk_bytes = hex::decode(&ring_payload.ring_pk).expect("decode ring_pk hex");
    let aggregate_pk =
        <DkgImpl as Dkg>::PublicKey::from_bytes(&ring_pk_bytes).expect("deserialize public key");

    // Sign two different documents
    let namespaces = ["test_namespace_1", "test_namespace_2"];

    for (i, namespace) in namespaces.iter().enumerate() {
        // Create and post a document for each message
        let message =
            create_test_document_and_post(&network.alice.app_state.bulletin, &ring_id, namespace)
                .await;

        let sign_coordinator =
            SignCoordinator::<DkgImpl, SignImpl>::new(Arc::new(network.alice.app_state.clone()));

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
                ring_pk_bytes.clone(),
                message.clone(),
                &peer_ids,
                ring_payload.threshold as usize,
                ring_payload.peer_ids.len(),
                &ring_payload.public_polynomial,
                ring_id.clone(),
                SignVerification::Bulletin,
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
        .start_dkg(create_authenticated_request(request, &token).unwrap())
        .await;
    assert!(result.is_ok());

    let (ring_payload, ring_id) = wait_for_dkg_completion(
        &network,
        result.unwrap().into_inner().session_id.parse().unwrap(),
    )
    .await;

    let ring_pk_bytes = hex::decode(&ring_payload.ring_pk).expect("decode ring_pk hex");
    let aggregate_pk =
        <DkgImpl as Dkg>::PublicKey::from_bytes(&ring_pk_bytes).expect("deserialize public key");

    // Create and post a document, then sign it
    let original_message = create_test_document_and_post(
        &network.alice.app_state.bulletin,
        &ring_id,
        "test_wrong_msg_namespace",
    )
    .await;

    let sign_coordinator =
        SignCoordinator::<DkgImpl, SignImpl>::new(Arc::new(network.alice.app_state.clone()));

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
            ring_pk_bytes.clone(),
            original_message.clone(),
            &peer_ids,
            ring_payload.threshold as usize,
            ring_payload.peer_ids.len(),
            &ring_payload.public_polynomial,
            ring_id.clone(),
            SignVerification::Bulletin,
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
        .start_dkg(create_authenticated_request(request, &token).unwrap())
        .await;
    assert!(result.is_ok());

    let (ring_payload, ring_id) = wait_for_dkg_completion(
        &network,
        result.unwrap().into_inner().session_id.parse().unwrap(),
    )
    .await;

    let ring_pk_bytes = hex::decode(&ring_payload.ring_pk).expect("decode ring_pk hex");

    // Create and post a document, then sign it
    let message = create_test_document_and_post(
        &network.alice.app_state.bulletin,
        &ring_id,
        "test_cleanup_namespace",
    )
    .await;

    let sign_coordinator =
        SignCoordinator::<DkgImpl, SignImpl>::new(Arc::new(network.alice.app_state.clone()));

    let request_id = format!(
        "sign-cleanup-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    );

    let _sign_response_bytes = sign_coordinator
        .initiate_signing(
            request_id.clone(),
            ring_pk_bytes.clone(),
            message,
            &peer_ids,
            ring_payload.threshold as usize,
            ring_payload.peer_ids.len(),
            &ring_payload.public_polynomial,
            ring_id.clone(),
            SignVerification::Bulletin,
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
        .start_dkg(create_authenticated_request(request, &token).unwrap())
        .await;
    assert!(result.is_ok());

    let (ring_payload, _ring_id) = wait_for_dkg_completion(
        &network,
        result.unwrap().into_inner().session_id.parse().unwrap(),
    )
    .await;

    let ring_pk_bytes = hex::decode(&ring_payload.ring_pk).expect("decode ring_pk hex");

    // Try to sign with invalid message (not a valid BulletinPost)
    let invalid_message = b"this is not a valid BulletinPost JSON";

    let sign_coordinator =
        SignCoordinator::<DkgImpl, SignImpl>::new(Arc::new(network.alice.app_state.clone()));

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
            ring_pk_bytes,
            invalid_message.to_vec(),
            &peer_ids,
            ring_payload.threshold as usize,
            ring_payload.peer_ids.len(),
            &ring_payload.public_polynomial,
            "fake_ring_id".to_string(),
            SignVerification::Bulletin,
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
        .start_dkg(create_authenticated_request(request, &token).unwrap())
        .await;
    assert!(result.is_ok());

    let (ring_payload, ring_id) = wait_for_dkg_completion(
        &network,
        result.unwrap().into_inner().session_id.parse().unwrap(),
    )
    .await;

    let ring_pk_bytes = hex::decode(&ring_payload.ring_pk).expect("decode ring_pk hex");

    // Create a valid BulletinPost but DON'T post it to the bulletin
    let doc_payload = DocumentPayload {
        ring_id: ring_id.clone(),
        document: "fake_document".to_string(),
        proof: "test_proof".to_string(),
        policy_id: "fake_policy".to_string(),
        resource: "fake_resource".to_string(),
        permission: "read".to_string(),
    };

    let payload_bytes: Vec<u8> = doc_payload.try_into().expect("serialize DocumentPayload");

    // Create a fake BulletinPost that was never posted
    let fake_bulletin_post = BulletinPost {
        id: "fake_post_id_that_doesnt_exist".to_string(),
        namespace: "fake_namespace".to_string(),
        payload: payload_bytes,
        proof: BULLETIN_PLACEHOLDER_PROOF.to_vec(),
    };

    let fake_message: Vec<u8> = fake_bulletin_post
        .try_into()
        .expect("serialize BulletinPost");

    let sign_coordinator =
        SignCoordinator::<DkgImpl, SignImpl>::new(Arc::new(network.alice.app_state.clone()));

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
            ring_pk_bytes,
            fake_message,
            &peer_ids,
            ring_payload.threshold as usize,
            ring_payload.peer_ids.len(),
            &ring_payload.public_polynomial,
            ring_id.clone(),
            SignVerification::Bulletin,
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
        .start_dkg(create_authenticated_request(request, &token).unwrap())
        .await;
    assert!(result.is_ok());

    let (ring_payload, ring_id) = wait_for_dkg_completion(
        &network,
        result.unwrap().into_inner().session_id.parse().unwrap(),
    )
    .await;

    let ring_pk_bytes = hex::decode(&ring_payload.ring_pk).expect("decode ring_pk hex");

    // First, create and post a legitimate document
    let namespace = "test_tamper_namespace";
    let original_doc = DocumentPayload {
        ring_id: ring_id.clone(),
        document: "original_document".to_string(),
        proof: "test_proof".to_string(),
        policy_id: "test_policy".to_string(),
        resource: "test_resource".to_string(),
        permission: "read".to_string(),
    };

    let original_payload: Vec<u8> = original_doc.try_into().expect("serialize");
    let full_namespace = format!("bulletin/{}", namespace);
    let post_id = network
        .alice
        .app_state
        .bulletin
        .get_post_id(&full_namespace, &original_payload)
        .expect("get post_id");

    // Post the original document
    network
        .alice
        .app_state
        .bulletin
        .post(
            namespace.to_string(),
            original_payload.clone(),
            BULLETIN_PLACEHOLDER_PROOF.to_vec(),
            None,
        )
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
    };

    let tampered_payload: Vec<u8> = tampered_doc.try_into().expect("serialize");

    let tampered_bulletin_post = BulletinPost {
        id: post_id, // Same ID as the posted one
        namespace: namespace.to_string(),
        payload: tampered_payload, // But different payload!
        proof: BULLETIN_PLACEHOLDER_PROOF.to_vec(),
    };

    let tampered_message: Vec<u8> = tampered_bulletin_post
        .try_into()
        .expect("serialize BulletinPost");

    let sign_coordinator =
        SignCoordinator::<DkgImpl, SignImpl>::new(Arc::new(network.alice.app_state.clone()));

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
            ring_pk_bytes,
            tampered_message,
            &peer_ids,
            ring_payload.threshold as usize,
            ring_payload.peer_ids.len(),
            &ring_payload.public_polynomial,
            ring_id.clone(),
            SignVerification::Bulletin,
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
        .start_dkg(create_authenticated_request(request, &token).unwrap())
        .await;
    assert!(result.is_ok());

    let (ring_payload, _ring_id) = wait_for_dkg_completion(
        &network,
        result.unwrap().into_inner().session_id.parse().unwrap(),
    )
    .await;

    let ring_pk_bytes = hex::decode(&ring_payload.ring_pk).expect("decode ring_pk hex");

    // Create a document with a fake ring_id that doesn't exist
    let namespace = "test_invalid_ring_namespace";
    let doc_with_fake_ring = DocumentPayload {
        ring_id: "fake_ring_id_that_doesnt_exist_on_bulletin".to_string(),
        document: "test_document".to_string(),
        proof: "test_proof".to_string(),
        policy_id: "test_policy".to_string(),
        resource: "test_resource".to_string(),
        permission: "read".to_string(),
    };

    let payload_bytes: Vec<u8> = doc_with_fake_ring.try_into().expect("serialize");
    let full_namespace = format!("bulletin/{}", namespace);
    let post_id = network
        .alice
        .app_state
        .bulletin
        .get_post_id(&full_namespace, &payload_bytes)
        .expect("get post_id");

    // Post this document (it will be on bulletin, but ring_id is invalid)
    network
        .alice
        .app_state
        .bulletin
        .post(
            namespace.to_string(),
            payload_bytes.clone(),
            BULLETIN_PLACEHOLDER_PROOF.to_vec(),
            None,
        )
        .await
        .expect("post to bulletin");

    let bulletin_post = BulletinPost {
        id: post_id,
        namespace: namespace.to_string(),
        payload: payload_bytes,
        proof: BULLETIN_PLACEHOLDER_PROOF.to_vec(),
    };

    let message: Vec<u8> = bulletin_post.try_into().expect("serialize BulletinPost");

    let sign_coordinator =
        SignCoordinator::<DkgImpl, SignImpl>::new(Arc::new(network.alice.app_state.clone()));

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
            ring_pk_bytes,
            message,
            &peer_ids,
            ring_payload.threshold as usize,
            ring_payload.peer_ids.len(),
            &ring_payload.public_polynomial,
            "fake_ring_id_that_doesnt_exist_on_bulletin".to_string(),
            SignVerification::Bulletin,
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
