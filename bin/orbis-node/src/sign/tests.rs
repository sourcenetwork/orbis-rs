//! Sign End-to-End Tests
//!
//! This module contains end-to-end tests for the threshold BLS signing protocol.
//! These tests verify the complete flow: DKG → Sign message → Verify signature.

use crate::helpers::test_helpers::{
    cleanup_db, create_authenticated_request, get_test_bulletin,
    setup_three_node_network_with_sign, test_db_path, TestKeyPair,
};
use crate::sign::coordinator::{SignCoordinator, SignResponse};
use crate::DkgServiceImpl;
use bulletin::r#trait::RingPayload;
use crypto::bls12_381::dkg::DKGNode;
use crypto::bls12_381::sign::ThresholdBlsSigner;
use crypto::r#trait::{CryptoDeserialize, Dkg, ThresholdSigner};
use proto::dkg_service::{dkg_service_server::DkgService, StartDkgRequest};
use std::sync::Arc;
use tokio::time::{sleep, Duration};

// Type aliases for tests
type DkgImpl = DKGNode;
type SignImpl = ThresholdBlsSigner;

/// End-to-end test: DKG → Sign message → Verify signature
///
/// This test demonstrates the complete threshold BLS signing flow:
/// 1. Three nodes (node1, node2, node3) run DKG to generate a shared public key
/// 2. A message hash is created to sign
/// 3. The nodes perform threshold signing to produce signature shares
/// 4. The signature shares are combined into a full signature
/// 5. The signature is verified against the aggregate public key
#[tokio::test]
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
    let ring_payload = wait_for_dkg_completion(
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
    // Step 3: Create a message to sign
    // =========================================================================
    println!("\nStep 3: Creating message to sign...");

    let message = b"Hello, threshold BLS signing!";

    println!("Message: {:?}", String::from_utf8_lossy(message));

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
            message.to_vec(),
            &sign_peer_ids,
            ring_payload.threshold as usize,
            ring_payload.peer_ids.len(),
            &ring_payload.public_polynomial,
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
    let verify_result = signer.verify(&aggregate_pk, message, &signature);

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

/// Helper function to wait for DKG completion and return the RingPayload
async fn wait_for_dkg_completion(
    network: &crate::helpers::test_helpers::ThreeNodeNetwork,
    _session_id: u64,
) -> RingPayload {
    let check_interval = Duration::from_millis(500);
    let max_wait = Duration::from_secs(60);
    let start = std::time::Instant::now();

    loop {
        // Check if ring payload has been posted to bulletin (indicates Phase 4 complete)
        let post = get_test_bulletin(&network.alice.app_state.bulletin).await;

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

/// Test signing with different message hashes
#[tokio::test]
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

    let ring_payload = wait_for_dkg_completion(
        &network,
        result.unwrap().into_inner().session_id.parse().unwrap(),
    )
    .await;

    let ring_pk_bytes = hex::decode(&ring_payload.ring_pk).expect("decode ring_pk hex");
    let aggregate_pk =
        <DkgImpl as Dkg>::PublicKey::from_bytes(&ring_pk_bytes).expect("deserialize public key");

    // Sign two different messages
    let messages: [&[u8]; 2] = [b"First message", b"Second message"];

    for (i, message) in messages.iter().enumerate() {
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
                message.to_vec(),
                &peer_ids,
                ring_payload.threshold as usize,
                ring_payload.peer_ids.len(),
                &ring_payload.public_polynomial,
            )
            .await
            .expect("Signing should succeed");

        let sign_response: SignResponse = serde_json::from_slice(&sign_response_bytes).unwrap();

        let signature_bytes = hex::decode(&sign_response.signature).unwrap();
        let signature =
            <SignImpl as ThresholdSigner>::Signature::from_bytes(&signature_bytes).unwrap();

        let signer = SignImpl::new();
        assert!(
            signer.verify(&aggregate_pk, *message, &signature).is_ok(),
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

    let ring_payload = wait_for_dkg_completion(
        &network,
        result.unwrap().into_inner().session_id.parse().unwrap(),
    )
    .await;

    let ring_pk_bytes = hex::decode(&ring_payload.ring_pk).expect("decode ring_pk hex");
    let aggregate_pk =
        <DkgImpl as Dkg>::PublicKey::from_bytes(&ring_pk_bytes).expect("deserialize public key");

    // Sign a message
    let original_message = b"Original message";

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
            original_message.to_vec(),
            &peer_ids,
            ring_payload.threshold as usize,
            ring_payload.peer_ids.len(),
            &ring_payload.public_polynomial,
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
            .verify(&aggregate_pk, original_message, &signature)
            .is_ok(),
        "Signature should verify with correct message"
    );

    // Verify with a different message should fail
    let wrong_message = b"Wrong message";

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

    let ring_payload = wait_for_dkg_completion(
        &network,
        result.unwrap().into_inner().session_id.parse().unwrap(),
    )
    .await;

    let ring_pk_bytes = hex::decode(&ring_payload.ring_pk).expect("decode ring_pk hex");

    // Sign a message
    let message = b"Test message for cleanup";

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
            message.to_vec(),
            &peer_ids,
            ring_payload.threshold as usize,
            ring_payload.peer_ids.len(),
            &ring_payload.public_polynomial,
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
