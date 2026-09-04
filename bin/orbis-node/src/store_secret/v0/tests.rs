//! StoreSecret Tests
//!
//! This module contains tests for the StoreSecret service.
//! Tests verify authentication, validation, and error handling.

use crate::helpers::test_helpers::{
    cleanup_db, create_authenticated_request, create_test_app_state_default,
    create_test_app_state_with_bulletin, test_db_path, TestKeyPair,
};
use crate::ring_state::RingIndexEntry;
use crate::store_secret::StoreSecretServiceImpl;
use authn::StoreSecretClaims;
use bulletin::dummy::DummyBulletin;
use bulletin::r#trait::RingPayload;
use crypto::r#trait::{CryptoSerialize, ThresholdDealer};
use crypto::{DkgImpl, PreImpl as ThresholdDealerNode, SignImpl};
use local_storage::r#trait::{LocalStorage, LocalStorageKeys};
use proto::v0::store_secret::{
    store_secret_service_server::StoreSecretService, StoreSecretRequest,
};
use sha2::{Digest, Sha256};
use std::{sync::Arc, time::Duration};
use tonic::Request;

/// Default test values for StoreSecret requests
const TEST_ENCRYPTED_DOC: &str = "{}";
const TEST_ENC_CMT: &str = "00";
const TEST_RING_ID: &str = "test-ring";
const TEST_POLICY_ID: &str = "test-policy";
const TEST_RESOURCE: &str = "test-resource";
const TEST_PERMISSION: &str = "test-permission";
const TEST_CHALLENGE: &str = "test-challenge";
const TEST_RESPONSE: &str = "test-response";

/// A valid hex-encoded group point for testing (curve-specific generator).
/// This is computed at runtime using the selected curve's generator.
fn test_ring_pk_hex() -> String {
    use crypto::CryptoSerialize;

    // For both curves, use the generic helper to generate a keypair and
    // take the public key as a valid group element.
    let (_sk, pk) = crypto::helpers::generate_keypair().expect("generate test keypair");
    let bytes = CryptoSerialize::to_bytes(&pk).expect("serialize generator");
    hex::encode(bytes)
}

/// Helper to create an AppState with a pre-configured test ring in the bulletin
async fn create_app_state_with_ring(db_name: &str) -> crate::app_state::AppState<DkgImpl> {
    let bulletin = DummyBulletin::new()
        .await
        .expect("Failed to create DummyBulletin");

    // Create a test RingPayload using curve-specific generator
    let ring_payload = RingPayload {
        upgrade_info: Default::default(),
        ring_pk: test_ring_pk_hex(),
        peer_node_keys: vec!["peer1".to_string()],
        new_peer_node_keys: None,
        new_threshold: None,
        threshold: 1,
        pss_interval: 86400,
        block_number_nonce: 0,
        policy_id: None,
        trusted_auth_relay_dids: None,
        reporting: Default::default(),
    };

    bulletin
        .set_ring(TEST_RING_ID.to_string(), ring_payload)
        .expect("seed ring");

    let app_state = create_test_app_state_with_bulletin(true, Arc::new(bulletin), db_name).await;

    // Write RingIndexEntry so service can resolve the ring from local storage.
    let ring_index = vec![RingIndexEntry {
        ring_pk_str: TEST_RING_ID.to_string(),
        bulletin_post_id: TEST_RING_ID.to_string(),
        indexed_at_secs: 0,
    }];
    app_state
        .local_storage
        .set(
            LocalStorageKeys::RingIndex,
            serde_json::to_vec(&ring_index).unwrap(),
        )
        .unwrap();

    app_state
}

/// Helper to create a dummy StoreSecretRequest for auth tests.
/// These tests fail at auth stage, so encrypted_document and enc_cmt can be dummy values.
fn create_dummy_request() -> StoreSecretRequest {
    StoreSecretRequest {
        encrypted_document: TEST_ENCRYPTED_DOC.as_bytes().to_vec(),
        enc_cmt: TEST_ENC_CMT.as_bytes().to_vec(),
        ring_id: TEST_RING_ID.to_string(),
        policy_id: TEST_POLICY_ID.to_string(),
        resource: TEST_RESOURCE.to_string(),
        permission: TEST_PERMISSION.to_string(),
        challenge: TEST_CHALLENGE.as_bytes().to_vec(),
        response: TEST_RESPONSE.as_bytes().to_vec(),
        with_proof: false,
        tier: None,
        timestamp: None,
    }
}

/// Helper to create a JWT with all required fields using the test constants
fn create_test_jwt(test_keys: &TestKeyPair) -> String {
    test_keys
        .create_store_secret_jwt(
            TEST_ENCRYPTED_DOC.as_bytes(),
            TEST_ENC_CMT.as_bytes().to_vec(),
            TEST_RING_ID,
            TEST_POLICY_ID,
            TEST_RESOURCE,
            TEST_PERMISSION,
            TEST_CHALLENGE.into(),
            TEST_RESPONSE.into(),
            false,
            None,
            None,
        )
        .expect("Failed to create JWT")
}

/// Test that StoreSecret fails when Authorization header is missing
#[tokio::test]
async fn test_store_secret_fails_missing_auth_header() {
    let db_name = "test_store_secret_fails_missing_auth_header";
    let db_path = test_db_path(db_name);
    let app_state = create_test_app_state_default(db_name).await;
    let service = StoreSecretServiceImpl::<DkgImpl, SignImpl>::with_routes(app_state, &network::V0);

    let request = create_dummy_request();

    // Create request WITHOUT authentication header
    let tonic_request = Request::new(request);

    let result = service.store_secret(tonic_request).await;

    assert!(
        result.is_err(),
        "store_secret should fail when Authorization header is missing"
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

/// Test that StoreSecret fails with malformed JWT
#[tokio::test]
async fn test_store_secret_fails_malformed_jwt() {
    let db_name = "test_store_secret_fails_malformed_jwt";
    let db_path = test_db_path(db_name);
    let app_state = create_test_app_state_default(db_name).await;
    let service = StoreSecretServiceImpl::<DkgImpl, SignImpl>::with_routes(app_state, &network::V0);

    let request = create_dummy_request();

    // Create request with malformed JWT (not a valid JWT structure)
    let tonic_request = create_authenticated_request(request, "not-a-valid-jwt-token").unwrap();

    let result = service.store_secret(tonic_request).await;

    assert!(
        result.is_err(),
        "store_secret should fail with malformed JWT token"
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
async fn test_store_secret_rejects_delegated_actor() {
    let db_name = "test_store_secret_rejects_delegated_actor";
    let db_path = test_db_path(db_name);
    let relay = TestKeyPair::new();
    let app_state = create_test_app_state_default(db_name).await;
    let service = StoreSecretServiceImpl::<DkgImpl, SignImpl>::with_routes(app_state, &network::V0);
    let request = create_dummy_request();
    let token = relay
        .sign_for_actor(
            "did:opk:user".to_string(),
            StoreSecretClaims {
                encrypted_document_sha256: Sha256::digest(&request.encrypted_document).to_vec(),
                enc_cmt: request.enc_cmt.clone(),
                ring_id: request.ring_id.clone(),
                policy_id: request.policy_id.clone(),
                resource: request.resource.clone(),
                permission: request.permission.clone(),
                challenge: request.challenge.clone(),
                response: request.response.clone(),
                with_proof: request.with_proof,
                tier: request.tier.clone(),
                timestamp: request.timestamp,
            },
            Duration::from_secs(60),
        )
        .expect("sign delegated JWT");

    let result = service
        .store_secret(create_authenticated_request(request, &token).unwrap())
        .await;

    let status = result.expect_err("delegated StoreSecret must fail");
    assert_eq!(status.code(), tonic::Code::Unauthenticated);
    assert!(status.message().contains("Vera signer"));
    cleanup_db(&db_path);
}

/// Test that StoreSecret fails when JWT claims don't match request
#[tokio::test]
async fn test_store_secret_fails_claims_mismatch() {
    let db_name = "test_store_secret_fails_claims_mismatch";
    let db_path = test_db_path(db_name);
    let app_state = create_test_app_state_default(db_name).await;
    let service = StoreSecretServiceImpl::<DkgImpl, SignImpl>::with_routes(app_state, &network::V0);

    // Create JWT with one ring_id but request with different ring_id
    let test_keys = TestKeyPair::new();
    let token = test_keys
        .create_store_secret_jwt(
            TEST_ENCRYPTED_DOC.as_bytes(),
            TEST_ENC_CMT.as_bytes().to_vec(),
            "jwt-ring-id", // Different ring_id in JWT
            TEST_POLICY_ID,
            TEST_RESOURCE,
            TEST_PERMISSION,
            TEST_CHALLENGE.into(),
            TEST_RESPONSE.into(),
            false,
            None,
            None,
        )
        .expect("Failed to create JWT");

    // Request uses TEST_RING_ID which doesn't match "jwt-ring-id"
    let request = create_dummy_request();

    let tonic_request = create_authenticated_request(request, &token).unwrap();

    let result = service.store_secret(tonic_request).await;

    assert!(
        result.is_err(),
        "store_secret should fail when ring_id doesn't match JWT claim"
    );

    let status = result.unwrap_err();
    assert_eq!(
        status.code(),
        tonic::Code::Unauthenticated,
        "Error code should be Unauthenticated for claim mismatch"
    );

    assert!(
        status.message().contains("ring_id"),
        "Error message should mention ring_id mismatch: {}",
        status.message()
    );
    cleanup_db(&db_path);
}

/// Test that StoreSecret fails with invalid encrypted document (validation error)
#[tokio::test]
async fn test_store_secret_fails_invalid_encrypted_document() {
    let db_name = "test_store_secret_fails_invalid_encrypted_document";
    let db_path = test_db_path(db_name);
    let app_state = create_app_state_with_ring(db_name).await;
    let service = StoreSecretServiceImpl::<DkgImpl, SignImpl>::with_routes(app_state, &network::V0);

    // Use invalid encrypted_document that will fail validation
    let invalid_encrypted_doc = b"not valid json";

    // Create valid JWT with matching claims (including invalid doc)
    let test_keys = TestKeyPair::new();
    let token = test_keys
        .create_store_secret_jwt(
            invalid_encrypted_doc,
            TEST_ENC_CMT.as_bytes().to_vec(),
            TEST_RING_ID,
            TEST_POLICY_ID,
            TEST_RESOURCE,
            TEST_PERMISSION,
            TEST_CHALLENGE.into(),
            TEST_RESPONSE.into(),
            false,
            None,
            None,
        )
        .expect("Failed to create JWT");

    // Create request with invalid encrypted_document (not valid Secret JSON)
    let request = StoreSecretRequest {
        encrypted_document: invalid_encrypted_doc.to_vec(),
        enc_cmt: TEST_ENC_CMT.as_bytes().to_vec(),
        ring_id: TEST_RING_ID.to_string(),
        policy_id: TEST_POLICY_ID.to_string(),
        resource: TEST_RESOURCE.to_string(),
        permission: TEST_PERMISSION.to_string(),
        challenge: TEST_CHALLENGE.as_bytes().to_vec(),
        response: TEST_RESPONSE.as_bytes().to_vec(),
        with_proof: false,
        tier: None,
        timestamp: None,
    };

    let tonic_request = create_authenticated_request(request, &token).unwrap();

    let result = service.store_secret(tonic_request).await;

    assert!(
        result.is_err(),
        "store_secret should fail with invalid encrypted document"
    );

    let status = result.unwrap_err();
    assert_eq!(
        status.code(),
        tonic::Code::InvalidArgument,
        "Error code should be InvalidArgument for validation failure"
    );

    assert!(
        status.message().contains("Validation"),
        "Error message should indicate validation error: {}",
        status.message()
    );
    cleanup_db(&db_path);
}

/// Test that StoreSecret fails with tampered JWT signature
#[tokio::test]
async fn test_store_secret_fails_wrong_signature() {
    let db_name = "test_store_secret_fails_wrong_signature";
    let db_path = test_db_path(db_name);
    let app_state = create_test_app_state_default(db_name).await;
    let service = StoreSecretServiceImpl::<DkgImpl, SignImpl>::with_routes(app_state, &network::V0);

    // Create a valid JWT
    let key_pair = TestKeyPair::new();
    let valid_token = create_test_jwt(&key_pair);

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

    let request = create_dummy_request();

    let tonic_request = create_authenticated_request(request, &tampered_token).unwrap();

    let result = service.store_secret(tonic_request).await;

    assert!(
        result.is_err(),
        "store_secret should fail with tampered JWT signature"
    );

    let status = result.unwrap_err();
    assert_eq!(
        status.code(),
        tonic::Code::Unauthenticated,
        "Error code should be Unauthenticated for invalid signature"
    );
    cleanup_db(&db_path);
}

/// Test that StoreSecret is idempotent - storing the same secret twice should succeed
/// and not create duplicate posts on the bulletin
#[tokio::test]
async fn test_store_secret_idempotent() {
    let db_name = "test_store_secret_idempotent";
    let db_path = test_db_path(db_name);

    // Create bulletin and keep a reference for verification
    let bulletin = Arc::new(
        DummyBulletin::new()
            .await
            .expect("Failed to create DummyBulletin"),
    );

    // Create a valid ring with real crypto using the generic curve implementation
    let (_sk, ring_pk) = ThresholdDealerNode::generate_keypair();
    let ring_pk_bytes = CryptoSerialize::to_bytes(&ring_pk).expect("serialize ring_pk");
    let ring_pk_hex = hex::encode(&ring_pk_bytes);

    let ring_payload = RingPayload {
        upgrade_info: Default::default(),
        ring_pk: ring_pk_hex.clone(),
        peer_node_keys: vec!["peer1".to_string()],
        new_peer_node_keys: None,
        new_threshold: None,
        threshold: 1,
        pss_interval: 86400,
        block_number_nonce: 0,
        policy_id: None,
        trusted_auth_relay_dids: None,
        reporting: Default::default(),
    };

    let ring_id = "test-store-secret-valid-ring".to_string();
    bulletin
        .set_ring(ring_id.clone(), ring_payload)
        .expect("seed ring");

    // Create app state with this bulletin
    let app_state = create_test_app_state_with_bulletin(true, bulletin.clone(), db_name).await;

    // Write RingIndexEntry so service can resolve the ring.
    let ring_index = vec![RingIndexEntry {
        ring_pk_str: ring_id.clone(),
        bulletin_post_id: ring_id.clone(),
        indexed_at_secs: 0,
    }];
    app_state
        .local_storage
        .set(
            LocalStorageKeys::RingIndex,
            serde_json::to_vec(&ring_index).unwrap(),
        )
        .unwrap();

    let service = StoreSecretServiceImpl::<DkgImpl, SignImpl>::with_routes(app_state, &network::V0);

    // Generate valid encryption proof using ThresholdDealerNode
    let plaintext = b"test secret data";
    let policy_id = "test_policy";
    let resource = "test_resource";
    let permission = "read";
    let ciphertext_context = crypto::context::CiphertextContext {
        ring_pk: ring_pk_bytes.clone(),
        policy_id: policy_id.to_string(),
        resource: resource.to_string(),
        permission: permission.to_string(),
        tier: None,
        timestamp: None,
        salt: None,
    };
    let (_enc_cmt, secret, proof) =
        ThresholdDealerNode::encrypt_secret(&ring_pk, plaintext, None, &ciphertext_context)
            .expect("encrypt with proof");

    let encrypted_doc = serde_json::to_vec(&secret).expect("serialize Secret");
    let enc_cmt_bytes = secret.enc_cmt.clone();
    let challenge_bytes = proof.challenge.clone();
    let response_bytes = proof.response.clone();

    // Create JWT and request
    let test_keys = TestKeyPair::new();
    let token = test_keys
        .create_store_secret_jwt(
            &encrypted_doc,
            enc_cmt_bytes.clone(),
            &ring_id,
            policy_id,
            resource,
            permission,
            challenge_bytes.clone(),
            response_bytes.clone(),
            false,
            None,
            None,
        )
        .expect("Failed to create JWT");

    let request1 = StoreSecretRequest {
        encrypted_document: encrypted_doc.clone(),
        enc_cmt: enc_cmt_bytes.clone(),
        ring_id: ring_id.clone(),
        policy_id: policy_id.to_string(),
        resource: resource.to_string(),
        permission: permission.to_string(),
        challenge: challenge_bytes.clone(),
        response: response_bytes.clone(),
        with_proof: false,
        tier: None,
        timestamp: None,
    };

    // Snapshot post count before any store_secret call. The bulletin already holds
    // whatever the test setup and create_test_app_state_with_bulletin seeded (ring,
    // NodeInfo, etc.). We assert relative to this baseline so the count stays correct
    // regardless of what the helper seeds in future.
    let posts_before = bulletin.get_posts().len();

    // First store - should succeed
    let tonic_request1 = create_authenticated_request(request1, &token).unwrap();
    let result1 = service.store_secret(tonic_request1).await;
    assert!(
        result1.is_ok(),
        "First store_secret should succeed: {:?}",
        result1.err()
    );
    let response1 = result1.unwrap().into_inner();
    let object_id = response1.object_id.clone();
    println!("First store succeeded with object_id: {}", object_id);

    // Exactly one new document post should have been added.
    let posts_after_first = bulletin.get_posts().len();
    assert_eq!(
        posts_after_first,
        posts_before + 1,
        "Should have exactly one new post after first store"
    );

    // Second store with same data - should also succeed (idempotent)
    let request2 = StoreSecretRequest {
        encrypted_document: encrypted_doc.clone(),
        enc_cmt: enc_cmt_bytes.clone(),
        ring_id: ring_id.clone(),
        policy_id: policy_id.to_string(),
        resource: resource.to_string(),
        permission: permission.to_string(),
        challenge: challenge_bytes.clone(),
        response: response_bytes.clone(),
        with_proof: false,
        tier: None,
        timestamp: None,
    };

    let tonic_request2 = create_authenticated_request(request2, &token).unwrap();
    let result2 = service.store_secret(tonic_request2).await;
    assert!(
        result2.is_ok(),
        "Second store_secret should succeed (idempotent): {:?}",
        result2.err()
    );
    let response2 = result2.unwrap().into_inner();
    println!(
        "Second store succeeded with object_id: {}",
        response2.object_id
    );

    // Verify same object_id returned
    assert_eq!(
        response1.object_id, response2.object_id,
        "Both stores should return the same object_id"
    );

    // No new post should have been created by the second store.
    let posts_after_second = bulletin.get_posts().len();
    assert_eq!(
        posts_after_second,
        posts_before + 1,
        "Should still have exactly one new post after second store (no duplicate)"
    );

    println!("SUCCESS! StoreSecret is idempotent - second call didn't create duplicate post");

    cleanup_db(&db_path);
}

/// Test that StoreSecret fails when the encrypted_document in the request differs from
/// the one that was hashed when creating the JWT.
#[tokio::test]
async fn test_store_secret_fails_encrypted_document_mismatch() {
    let db_name = "test_store_secret_fails_encrypted_document_mismatch";
    let db_path = test_db_path(db_name);
    let app_state = create_test_app_state_default(db_name).await;
    let service = StoreSecretServiceImpl::<DkgImpl, SignImpl>::with_routes(app_state, &network::V0);

    let test_keys = TestKeyPair::new();
    // JWT is created for TEST_ENCRYPTED_DOC
    let token = create_test_jwt(&test_keys);

    // Request sends a different encrypted_document
    let mut request = create_dummy_request();
    request.encrypted_document = b"different encrypted document".to_vec();

    let tonic_request = create_authenticated_request(request, &token).unwrap();
    let result = service.store_secret(tonic_request).await;

    assert!(
        result.is_err(),
        "store_secret should fail when encrypted_document doesn't match JWT digest"
    );

    let status = result.unwrap_err();
    assert_eq!(
        status.code(),
        tonic::Code::Unauthenticated,
        "Error code should be Unauthenticated for digest mismatch"
    );
    assert!(
        status.message().contains("encrypted_document_sha256"),
        "Error message should mention encrypted_document_sha256: {}",
        status.message()
    );
    cleanup_db(&db_path);
}
