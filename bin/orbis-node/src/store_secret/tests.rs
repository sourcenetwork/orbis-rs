//! StoreSecret Tests
//!
//! This module contains tests for the StoreSecret service.
//! Tests verify authentication, validation, and error handling.

use crate::constants::BULLETIN_RING_NAMESPACE;
use crate::helpers::test_helpers::{
    cleanup_db, create_authenticated_request, create_test_app_state_default,
    create_test_app_state_with_bulletin, test_db_path, TestKeyPair,
};
use crate::store_secret::StoreSecretServiceImpl;
use bulletin::dummy::DummyBulletin;
use bulletin::r#trait::{Bulletin, BulletinPost, RingPayload};
use crypto::helpers::generate_policy_metadata;
use crypto::r#trait::{CryptoSerialize, ThresholdDealer};
use crypto::{DkgImpl, PreImpl as ThresholdDealerNode, SignImpl};
use proto::store_secret_service::{
    store_secret_service_server::StoreSecretService, StoreSecretRequest,
};
use std::sync::Arc;
use tonic::Request;

/// Default test values for StoreSecret requests
const TEST_ENCRYPTED_DOC: &str = "{}";
const TEST_ENC_CMT: &str = "00";
const TEST_RING_ID: &str = "test-ring";
const TEST_NAMESPACE: &str = "test-namespace";
const TEST_POLICY_ID: &str = "test-policy";
const TEST_RESOURCE: &str = "test-resource";
const TEST_PERMISSION: &str = "test-permission";
const TEST_SHARED_POINT: &str = "test-shared-point";
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
        ring_pk: test_ring_pk_hex(),
        peer_ids: vec!["peer1".to_string()],
        threshold: 1,
        public_polynomial: "00".to_string(),
    };

    // Serialize and set in bulletin
    let payload_bytes: Vec<u8> = ring_payload.try_into().expect("serialize RingPayload");
    let post = BulletinPost {
        id: TEST_RING_ID.to_string(),
        namespace: BULLETIN_RING_NAMESPACE.to_string(),
        payload: payload_bytes,
        proof: vec![],
    };
    bulletin.set_post(
        BULLETIN_RING_NAMESPACE.to_string(),
        TEST_RING_ID.to_string(),
        post,
    );

    create_test_app_state_with_bulletin(None, true, Arc::new(bulletin), db_name).await
}

/// Helper to create a dummy StoreSecretRequest for auth tests.
/// These tests fail at auth stage, so encrypted_document and enc_cmt can be dummy values.
fn create_dummy_request() -> StoreSecretRequest {
    StoreSecretRequest {
        encrypted_document: TEST_ENCRYPTED_DOC.to_string(),
        enc_cmt: TEST_ENC_CMT.to_string(),
        ring_id: TEST_RING_ID.to_string(),
        namespace: TEST_NAMESPACE.to_string(),
        policy_id: TEST_POLICY_ID.to_string(),
        resource: TEST_RESOURCE.to_string(),
        permission: TEST_PERMISSION.to_string(),
        shared_point: TEST_SHARED_POINT.as_bytes().to_vec(),
        challenge: TEST_CHALLENGE.as_bytes().to_vec(),
        response: TEST_RESPONSE.as_bytes().to_vec(),
        derived_pk: None,
        with_proof: false,
    }
}

/// Helper to create a JWT with all required fields using the test constants
fn create_test_jwt(test_keys: &TestKeyPair) -> String {
    test_keys
        .create_store_secret_jwt(
            TEST_ENCRYPTED_DOC,
            TEST_ENC_CMT,
            TEST_RING_ID,
            TEST_NAMESPACE,
            TEST_POLICY_ID,
            TEST_RESOURCE,
            TEST_PERMISSION,
            TEST_SHARED_POINT.into(),
            TEST_CHALLENGE.into(),
            TEST_RESPONSE.into(),
            None,
            false,
        )
        .expect("Failed to create JWT")
}

/// Test that StoreSecret fails when Authorization header is missing
#[tokio::test]
async fn test_store_secret_fails_missing_auth_header() {
    let db_name = "test_store_secret_fails_missing_auth_header";
    let db_path = test_db_path(db_name);
    let app_state = create_test_app_state_default(db_name).await;
    let service = StoreSecretServiceImpl::<DkgImpl, SignImpl>::new(app_state);

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
    let service = StoreSecretServiceImpl::<DkgImpl, SignImpl>::new(app_state);

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

/// Test that StoreSecret fails when JWT claims don't match request
#[tokio::test]
async fn test_store_secret_fails_claims_mismatch() {
    let db_name = "test_store_secret_fails_claims_mismatch";
    let db_path = test_db_path(db_name);
    let app_state = create_test_app_state_default(db_name).await;
    let service = StoreSecretServiceImpl::<DkgImpl, SignImpl>::new(app_state);

    // Create JWT with one ring_id but request with different ring_id
    let test_keys = TestKeyPair::new();
    let token = test_keys
        .create_store_secret_jwt(
            TEST_ENCRYPTED_DOC,
            TEST_ENC_CMT,
            "jwt-ring-id", // Different ring_id in JWT
            TEST_NAMESPACE,
            TEST_POLICY_ID,
            TEST_RESOURCE,
            TEST_PERMISSION,
            TEST_SHARED_POINT.into(),
            TEST_CHALLENGE.into(),
            TEST_RESPONSE.into(),
            None,
            false,
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

/// Test that StoreSecret fails when namespace in JWT claims doesn't match request
#[tokio::test]
async fn test_store_secret_fails_namespace_mismatch() {
    let db_name = "test_store_secret_fails_namespace_mismatch";
    let db_path = test_db_path(db_name);
    let app_state = create_test_app_state_default(db_name).await;
    let service = StoreSecretServiceImpl::<DkgImpl, SignImpl>::new(app_state);

    // Create JWT with one namespace but request with different namespace
    let test_keys = TestKeyPair::new();
    let token = test_keys
        .create_store_secret_jwt(
            TEST_ENCRYPTED_DOC,
            TEST_ENC_CMT,
            TEST_RING_ID,
            "jwt-namespace", // Different namespace in JWT
            TEST_POLICY_ID,
            TEST_RESOURCE,
            TEST_PERMISSION,
            TEST_SHARED_POINT.into(),
            TEST_CHALLENGE.into(),
            TEST_RESPONSE.into(),
            None,
            false,
        )
        .expect("Failed to create JWT");

    // Request uses TEST_NAMESPACE which doesn't match "jwt-namespace"
    let request = create_dummy_request();

    let tonic_request = create_authenticated_request(request, &token).unwrap();

    let result = service.store_secret(tonic_request).await;

    assert!(
        result.is_err(),
        "store_secret should fail when namespace doesn't match JWT claim"
    );

    let status = result.unwrap_err();
    assert_eq!(
        status.code(),
        tonic::Code::Unauthenticated,
        "Error code should be Unauthenticated for namespace mismatch"
    );

    assert!(
        status.message().contains("namespace"),
        "Error message should mention namespace mismatch: {}",
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
    let service = StoreSecretServiceImpl::<DkgImpl, SignImpl>::new(app_state);

    // Use invalid encrypted_document that will fail validation
    let invalid_encrypted_doc = "not valid json";

    // Create valid JWT with matching claims (including invalid doc)
    let test_keys = TestKeyPair::new();
    let token = test_keys
        .create_store_secret_jwt(
            invalid_encrypted_doc,
            TEST_ENC_CMT,
            TEST_RING_ID,
            TEST_NAMESPACE,
            TEST_POLICY_ID,
            TEST_RESOURCE,
            TEST_PERMISSION,
            TEST_SHARED_POINT.into(),
            TEST_CHALLENGE.into(),
            TEST_RESPONSE.into(),
            None,
            false,
        )
        .expect("Failed to create JWT");

    // Create request with invalid encrypted_document (not valid Secret JSON)
    let request = StoreSecretRequest {
        encrypted_document: invalid_encrypted_doc.to_string(),
        enc_cmt: TEST_ENC_CMT.to_string(),
        ring_id: TEST_RING_ID.to_string(),
        namespace: TEST_NAMESPACE.to_string(),
        policy_id: TEST_POLICY_ID.to_string(),
        resource: TEST_RESOURCE.to_string(),
        permission: TEST_PERMISSION.to_string(),
        shared_point: TEST_SHARED_POINT.as_bytes().to_vec(),
        challenge: TEST_CHALLENGE.as_bytes().to_vec(),
        response: TEST_RESPONSE.as_bytes().to_vec(),
        derived_pk: None,
        with_proof: false,
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

/// Test that StoreSecret fails when encryption proof verification fails
#[tokio::test]
async fn test_store_secret_fails_invalid_encryption_proof() {
    let db_name = "test_store_secret_fails_invalid_encryption_proof";
    let db_path = test_db_path(db_name);
    let app_state = create_app_state_with_ring(db_name).await;
    let service = StoreSecretServiceImpl::<DkgImpl, SignImpl>::new(app_state);

    // Create a valid Secret struct with enc_cmt matching the ring_pk format
    let enc_cmt_bytes = hex::decode(test_ring_pk_hex()).expect("decode TEST_RING_PK");
    let secret = crypto::r#trait::Secret {
        enc_cmt: enc_cmt_bytes.clone(),
        encrypted_data: vec![0u8; 32],
        nonce: vec![0u8; 12], // 12 bytes for AES-GCM
    };
    let encrypted_doc = serde_json::to_string(&secret).expect("serialize Secret");
    let enc_cmt_hex = hex::encode(&enc_cmt_bytes);

    // Malformed proof - invalid bytes that won't deserialize as valid curve points
    let invalid_shared_point = vec![0xffu8; 48]; // Invalid G1 point bytes

    let test_keys = TestKeyPair::new();
    let token = test_keys
        .create_store_secret_jwt(
            &encrypted_doc,
            &enc_cmt_hex,
            TEST_RING_ID,
            TEST_NAMESPACE,
            TEST_POLICY_ID,
            TEST_RESOURCE,
            TEST_PERMISSION,
            invalid_shared_point.clone(),
            TEST_CHALLENGE.into(),
            TEST_RESPONSE.into(),
            None,
            false,
        )
        .expect("Failed to create JWT");

    let request = StoreSecretRequest {
        encrypted_document: encrypted_doc,
        enc_cmt: enc_cmt_hex,
        ring_id: TEST_RING_ID.to_string(),
        namespace: TEST_NAMESPACE.to_string(),
        policy_id: TEST_POLICY_ID.to_string(),
        resource: TEST_RESOURCE.to_string(),
        permission: TEST_PERMISSION.to_string(),
        shared_point: invalid_shared_point,
        challenge: TEST_CHALLENGE.as_bytes().to_vec(),
        response: TEST_RESPONSE.as_bytes().to_vec(),
        derived_pk: None,
        with_proof: false,
    };

    let tonic_request = create_authenticated_request(request, &token).unwrap();
    let result = service.store_secret(tonic_request).await;

    assert!(
        result.is_err(),
        "store_secret should fail with invalid encryption proof"
    );

    let status = result.unwrap_err();
    assert!(
        status.message().contains("encryption"),
        "Error message should mention encryption verification failure: {}",
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
    let service = StoreSecretServiceImpl::<DkgImpl, SignImpl>::new(app_state);

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
        ring_pk: ring_pk_hex.clone(),
        peer_ids: vec!["peer1".to_string()],
        threshold: 1,
        public_polynomial: "00".to_string(),
    };

    // Compute the ring_id (deterministic hash of the ring payload)
    let ring_payload_bytes: Vec<u8> = ring_payload
        .clone()
        .try_into()
        .expect("serialize RingPayload");
    let full_ring_namespace = format!("bulletin/{}", BULLETIN_RING_NAMESPACE);
    let ring_id = bulletin
        .get_post_id(&full_ring_namespace, &ring_payload_bytes)
        .expect("compute ring_id");

    // Set ring in bulletin
    let ring_post = BulletinPost {
        id: ring_id.clone(),
        namespace: BULLETIN_RING_NAMESPACE.to_string(),
        payload: ring_payload_bytes,
        proof: vec![],
    };
    bulletin.set_post(
        BULLETIN_RING_NAMESPACE.to_string(),
        ring_id.clone(),
        ring_post,
    );

    // Create app state with this bulletin
    let app_state =
        create_test_app_state_with_bulletin(None, true, bulletin.clone(), db_name).await;
    let service = StoreSecretServiceImpl::<DkgImpl, SignImpl>::new(app_state);

    // Generate valid encryption proof using ThresholdDealerNode
    let plaintext = b"test secret data";
    let namespace = "test_idempotent_namespace";
    let policy_id = "test_policy";
    let resource = "test_resource";
    let permission = "read";
    let metadata = generate_policy_metadata(policy_id, resource, permission);
    let (_enc_cmt, secret, proof) =
        ThresholdDealerNode::encrypt_secret(&ring_pk, plaintext, None, Some(&metadata))
            .expect("encrypt with proof");

    let encrypted_doc = serde_json::to_string(&secret).expect("serialize Secret");
    let enc_cmt_hex = hex::encode(secret.enc_cmt.clone());
    let shared_point_bytes = proof.shared_point.clone();
    let challenge_bytes = proof.challenge.clone();
    let response_bytes = proof.response.clone();

    // Create JWT and request
    let test_keys = TestKeyPair::new();
    let token = test_keys
        .create_store_secret_jwt(
            &encrypted_doc,
            &enc_cmt_hex,
            &ring_id,
            namespace,
            policy_id,
            resource,
            permission,
            shared_point_bytes.clone(),
            challenge_bytes.clone(),
            response_bytes.clone(),
            None,
            false,
        )
        .expect("Failed to create JWT");

    let request1 = StoreSecretRequest {
        encrypted_document: encrypted_doc.clone(),
        enc_cmt: enc_cmt_hex.clone(),
        ring_id: ring_id.clone(),
        namespace: namespace.to_string(),
        policy_id: policy_id.to_string(),
        resource: resource.to_string(),
        permission: permission.to_string(),
        shared_point: shared_point_bytes.clone(),
        challenge: challenge_bytes.clone(),
        response: response_bytes.clone(),
        derived_pk: None,
        with_proof: false,
    };

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

    // Check bulletin has 1 post in the namespace (plus the ring post in orbis namespace)
    let posts_after_first = bulletin.get_posts_by_namespace(namespace);
    assert_eq!(
        posts_after_first.len(),
        1,
        "Should have exactly 1 post after first store"
    );

    // Second store with same data - should also succeed (idempotent)
    let request2 = StoreSecretRequest {
        encrypted_document: encrypted_doc.clone(),
        enc_cmt: enc_cmt_hex.clone(),
        ring_id: ring_id.clone(),
        namespace: namespace.to_string(),
        policy_id: policy_id.to_string(),
        resource: resource.to_string(),
        permission: permission.to_string(),
        shared_point: shared_point_bytes.clone(),
        challenge: challenge_bytes.clone(),
        response: response_bytes.clone(),
        derived_pk: None,
        with_proof: false,
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

    // Check bulletin still has only 1 post (didn't create duplicate)
    let posts_after_second = bulletin.get_posts_by_namespace(namespace);
    assert_eq!(
        posts_after_second.len(),
        1,
        "Should still have exactly 1 post after second store (no duplicate)"
    );

    println!("SUCCESS! StoreSecret is idempotent - second call didn't create duplicate post");

    cleanup_db(&db_path);
}

/// Test that StoreSecret fails when wrong derived_pk is provided
#[tokio::test]
async fn test_store_secret_fails_wrong_derived_pk() {
    let db_name = "test_store_secret_fails_wrong_derived_pk";
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
        ring_pk: ring_pk_hex.clone(),
        peer_ids: vec!["peer1".to_string()],
        threshold: 1,
        public_polynomial: "00".to_string(),
    };

    // Compute the ring_id (deterministic hash of the ring payload)
    let ring_payload_bytes: Vec<u8> = ring_payload
        .clone()
        .try_into()
        .expect("serialize RingPayload");
    let full_ring_namespace = format!("bulletin/{}", BULLETIN_RING_NAMESPACE);
    let ring_id = bulletin
        .get_post_id(&full_ring_namespace, &ring_payload_bytes)
        .expect("compute ring_id");

    // Set ring in bulletin
    let ring_post = BulletinPost {
        id: ring_id.clone(),
        namespace: BULLETIN_RING_NAMESPACE.to_string(),
        payload: ring_payload_bytes,
        proof: vec![],
    };
    bulletin.set_post(
        BULLETIN_RING_NAMESPACE.to_string(),
        ring_id.clone(),
        ring_post,
    );

    // Create app state with this bulletin
    let app_state =
        create_test_app_state_with_bulletin(None, true, bulletin.clone(), db_name).await;
    let service = StoreSecretServiceImpl::<DkgImpl, SignImpl>::new(app_state);

    // Generate valid encryption with derivation
    let plaintext = b"test secret data with derivation";
    let derivation = b"test_derivation_path";
    let namespace = "test_wrong_derived_pk_namespace";
    let policy_id = "test_policy";
    let resource = "test_resource";
    let permission = "read";
    let metadata = generate_policy_metadata(policy_id, resource, permission);
    let (_enc_cmt, secret, proof) =
        ThresholdDealerNode::encrypt_secret(&ring_pk, plaintext, Some(derivation), Some(&metadata))
            .expect("encrypt with derivation");

    let encrypted_doc = serde_json::to_string(&secret).expect("serialize Secret");
    let enc_cmt_hex = hex::encode(secret.enc_cmt.clone());
    let shared_point_bytes = proof.shared_point.clone();
    let challenge_bytes = proof.challenge.clone();
    let response_bytes = proof.response.clone();

    // Create a WRONG derived_pk (use a different derivation path)
    let wrong_derivation = b"wrong_derivation_path";
    let wrong_derived_pk = ThresholdDealerNode::derive_public_key(&ring_pk, wrong_derivation)
        .expect("derive wrong pk");
    let wrong_derived_pk_bytes = wrong_derived_pk
        .to_bytes()
        .expect("serialize wrong derived_pk");

    // Create JWT and request with WRONG derived_pk
    let test_keys = TestKeyPair::new();
    let token = test_keys
        .create_store_secret_jwt(
            &encrypted_doc,
            &enc_cmt_hex,
            &ring_id,
            namespace,
            policy_id,
            resource,
            permission,
            shared_point_bytes.clone(),
            challenge_bytes.clone(),
            response_bytes.clone(),
            Some(wrong_derived_pk_bytes.clone()), // Wrong derived_pk
            false,
        )
        .expect("Failed to create JWT");

    let request = StoreSecretRequest {
        encrypted_document: encrypted_doc.clone(),
        enc_cmt: enc_cmt_hex.clone(),
        ring_id: ring_id.clone(),
        namespace: namespace.to_string(),
        policy_id: policy_id.to_string(),
        resource: resource.to_string(),
        permission: permission.to_string(),
        shared_point: shared_point_bytes.clone(),
        challenge: challenge_bytes.clone(),
        response: response_bytes.clone(),
        derived_pk: Some(wrong_derived_pk_bytes), // Wrong derived_pk
        with_proof: false,
    };

    let tonic_request = create_authenticated_request(request, &token).unwrap();
    let result = service.store_secret(tonic_request).await;

    assert!(
        result.is_err(),
        "store_secret should fail with wrong derived_pk"
    );

    let status = result.unwrap_err();
    assert_eq!(
        status.code(),
        tonic::Code::InvalidArgument,
        "Error code should be InvalidArgument for wrong derived_pk"
    );

    assert_eq!(
        status.message(),
        "Validation error: Failed to Validate secret encryption: ElGamal error: Encryption proof verification failed",
    );

    cleanup_db(&db_path);
}

/// Test that StoreSecret fails when the encryption proof has been tampered with
///
/// This verifies that the node rejects a store request where the proof bytes
/// (challenge) have been modified, even though the encrypted document and enc_cmt
/// are valid. The Chaum-Pedersen verification should catch the mismatch.
#[tokio::test]
async fn test_store_secret_fails_with_tampered_proof() {
    let db_name = "test_store_secret_fails_with_tampered_proof";
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
        ring_pk: ring_pk_hex.clone(),
        peer_ids: vec!["peer1".to_string()],
        threshold: 1,
        public_polynomial: "00".to_string(),
    };

    // Compute the ring_id (deterministic hash of the ring payload)
    let ring_payload_bytes: Vec<u8> = ring_payload
        .clone()
        .try_into()
        .expect("serialize RingPayload");
    let full_ring_namespace = format!("bulletin/{}", BULLETIN_RING_NAMESPACE);
    let ring_id = bulletin
        .get_post_id(&full_ring_namespace, &ring_payload_bytes)
        .expect("compute ring_id");

    // Set ring in bulletin
    let ring_post = BulletinPost {
        id: ring_id.clone(),
        namespace: BULLETIN_RING_NAMESPACE.to_string(),
        payload: ring_payload_bytes,
        proof: vec![],
    };
    bulletin.set_post(
        BULLETIN_RING_NAMESPACE.to_string(),
        ring_id.clone(),
        ring_post,
    );

    // Create app state with this bulletin
    let app_state =
        create_test_app_state_with_bulletin(None, true, bulletin.clone(), db_name).await;
    let service = StoreSecretServiceImpl::<DkgImpl, SignImpl>::new(app_state);

    // Generate valid encryption proof using ThresholdDealerNode
    let plaintext = b"test secret with tampered proof";
    let namespace = "test_tampered_proof_namespace";
    let policy_id = "test_policy";
    let resource = "test_resource";
    let permission = "read";
    let metadata = generate_policy_metadata(policy_id, resource, permission);
    let (_enc_cmt, secret, proof) =
        ThresholdDealerNode::encrypt_secret(&ring_pk, plaintext, None, Some(&metadata))
            .expect("encrypt with proof");

    let encrypted_doc = serde_json::to_string(&secret).expect("serialize Secret");
    let enc_cmt_hex = hex::encode(secret.enc_cmt.clone());
    let shared_point_bytes = proof.shared_point.clone();
    let response_bytes = proof.response.clone();

    // Tamper with the challenge by flipping a byte
    let mut tampered_challenge = proof.challenge.clone();
    if let Some(byte) = tampered_challenge.first_mut() {
        *byte ^= 0xFF;
    }

    // Create JWT and request with the TAMPERED challenge
    let test_keys = TestKeyPair::new();
    let token = test_keys
        .create_store_secret_jwt(
            &encrypted_doc,
            &enc_cmt_hex,
            &ring_id,
            namespace,
            policy_id,
            resource,
            permission,
            shared_point_bytes.clone(),
            tampered_challenge.clone(),
            response_bytes.clone(),
            None,
            false,
        )
        .expect("Failed to create JWT");

    let request = StoreSecretRequest {
        encrypted_document: encrypted_doc,
        enc_cmt: enc_cmt_hex,
        ring_id: ring_id.clone(),
        namespace: namespace.to_string(),
        policy_id: policy_id.to_string(),
        resource: resource.to_string(),
        permission: permission.to_string(),
        shared_point: shared_point_bytes,
        challenge: tampered_challenge,
        response: response_bytes,
        derived_pk: None,
        with_proof: false,
    };

    let tonic_request = create_authenticated_request(request, &token).unwrap();
    let result = service.store_secret(tonic_request).await;

    assert!(
        result.is_err(),
        "store_secret should fail with tampered proof challenge"
    );

    let status = result.unwrap_err();
    assert_eq!(
        status.code(),
        tonic::Code::InvalidArgument,
        "Error code should be InvalidArgument for tampered proof"
    );

    assert_eq!(
        status.message(),
        "Validation error: Failed to Validate secret encryption: ElGamal error: Encryption proof verification failed",
    );

    cleanup_db(&db_path);
}
