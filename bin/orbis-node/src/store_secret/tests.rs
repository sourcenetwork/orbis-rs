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
use ark_bls12_381::G1Affine;
use ark_ec::AffineRepr;
use ark_serialize::CanonicalDeserialize;
use bulletin::dummy::DummyBulletin;
use bulletin::r#trait::{Bulletin, BulletinPost, RingPayload};
use crypto::bls12_381::pre::ThresholdDealerNode;
use crypto::bls12_381::sign::ThresholdBlsSigner;
use crypto::r#trait::{CryptoSerialize, ThresholdDealer};
use proto::store_secret_service::{
    store_secret_service_server::StoreSecretService, StoreSecretRequest,
};
use std::sync::Arc;
use tonic::Request;
// Concrete crypto implementations for tests
use crypto::bls12_381::dkg::DKGNode;
type DkgImpl = DKGNode;
pub type SignImpl = ThresholdBlsSigner;

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
/// A valid hex-encoded G1 point for testing (generator point)
const TEST_RING_PK: &str = "97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb";

/// Helper to create an AppState with a pre-configured test ring in the bulletin
async fn create_app_state_with_ring(db_name: &str) -> crate::app_state::AppState<DkgImpl> {
    let bulletin = DummyBulletin::new()
        .await
        .expect("Failed to create DummyBulletin");

    // Create a test RingPayload
    let ring_payload = RingPayload {
        ring_pk: TEST_RING_PK.to_string(),
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

    // Create a valid Secret struct with enc_cmt matching TEST_RING_PK format
    let enc_cmt_bytes = hex::decode(TEST_RING_PK).expect("decode TEST_RING_PK");
    let secret = crypto::r#trait::Secret {
        enc_cmt: enc_cmt_bytes.clone(),
        encrypted_data: vec![0u8; 32], // includes AES-GCM auth tag
        nonce: vec![0u8; 12],          // 12 bytes for AES-GCM
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

    // Create a valid ring with real crypto
    let ring_pk = G1Affine::generator();
    let ring_pk_bytes = ring_pk.to_bytes().expect("serialize ring_pk");
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
    let (_enc_cmt, secret, proof) =
        ThresholdDealerNode::encrypt_secret(&ring_pk, plaintext, None).expect("encrypt with proof");

    let encrypted_doc = serde_json::to_string(&secret).expect("serialize Secret");
    let enc_cmt_hex = hex::encode(secret.enc_cmt.clone());
    let shared_point_bytes = proof.shared_point.clone();
    let challenge_bytes = proof.challenge.clone();
    let response_bytes = proof.response.clone();

    let namespace = "test_idempotent_namespace";
    let policy_id = "test_policy";
    let resource = "test_resource";
    let permission = "read";

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

/// Test that StoreSecret fails when derivation is wrong, then succeeds with correct derivation
#[tokio::test]
async fn test_store_secret_derivation_validation() {
    let db_name = "test_store_secret_derivation_validation";
    let db_path = test_db_path(db_name);

    // Create bulletin and keep a reference for verification
    let bulletin = Arc::new(
        DummyBulletin::new()
            .await
            .expect("Failed to create DummyBulletin"),
    );

    // Create a valid ring with real crypto
    let ring_pk = G1Affine::generator();
    let ring_pk_bytes = ring_pk.to_bytes().expect("serialize ring_pk");
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

    let plaintext = b"test secret with derivation";
    let correct_derivation = b"correct-derivation";
    let wrong_derivation = b"wrong-derivation";

    let namespace = "test_derivation_namespace";
    let policy_id = "test_policy";
    let resource = "test_resource";
    let permission = "read";
    let test_keys = TestKeyPair::new();

    // Step 1: Encrypt with WRONG derivation and try to store - should fail
    // We'll create a proof that's invalid by using wrong derivation's encryption
    // but claiming it was encrypted with correct derivation (tampered derived_pk)
    println!("Step 1: Encrypting with wrong derivation and tampering proof...");

    let (_enc_cmt_wrong, secret_wrong, proof_wrong) =
        ThresholdDealerNode::encrypt_secret(&ring_pk, plaintext, Some(wrong_derivation))
            .expect("encrypt with wrong derivation");

    // Get the correct derived_pk by encrypting with correct derivation
    let (_enc_cmt_correct_temp, _secret_correct_temp, proof_correct_temp) =
        ThresholdDealerNode::encrypt_secret(&ring_pk, plaintext, Some(correct_derivation))
            .expect("encrypt with correct derivation to get derived_pk");

    // Create a tampered proof: encryption was done with wrong_derivation,
    // but we claim it was done with correct_derivation by using correct derived_pk
    // This will cause verification to fail because shared_point doesn't match derived_pk
    let mut tampered_proof = proof_wrong.clone();
    tampered_proof.derived_pk = proof_correct_temp.derived_pk.clone();

    // Verify that the tampered proof fails verification
    let enc_cmt_wrong_point =
        G1Affine::deserialize_compressed(&secret_wrong.enc_cmt[..]).expect("deserialize enc_cmt");
    let verify_result =
        ThresholdDealerNode::verify_encryption(&ring_pk, &enc_cmt_wrong_point, &tampered_proof);
    assert!(
        verify_result.is_err(),
        "Tampered proof should fail verification: {:?}",
        verify_result
    );

    // Try to store with the tampered proof - should fail
    let encrypted_doc_wrong = serde_json::to_string(&secret_wrong).expect("serialize Secret");
    let enc_cmt_hex_wrong = hex::encode(secret_wrong.enc_cmt.clone());

    let token_wrong = test_keys
        .create_store_secret_jwt(
            &encrypted_doc_wrong,
            &enc_cmt_hex_wrong,
            &ring_id,
            namespace,
            policy_id,
            resource,
            permission,
            tampered_proof.shared_point.clone(),
            tampered_proof.challenge.clone(),
            tampered_proof.response.clone(),
            tampered_proof.derived_pk.clone(),
            false,
        )
        .expect("Failed to create JWT");

    let request_wrong = StoreSecretRequest {
        encrypted_document: encrypted_doc_wrong,
        enc_cmt: enc_cmt_hex_wrong,
        ring_id: ring_id.clone(),
        namespace: namespace.to_string(),
        policy_id: policy_id.to_string(),
        resource: resource.to_string(),
        permission: permission.to_string(),
        shared_point: tampered_proof.shared_point.clone(),
        challenge: tampered_proof.challenge.clone(),
        response: tampered_proof.response.clone(),
        derived_pk: tampered_proof.derived_pk.clone(),
        with_proof: false,
    };

    let tonic_request_wrong = create_authenticated_request(request_wrong, &token_wrong).unwrap();
    let result_wrong = service.store_secret(tonic_request_wrong).await;

    // This should fail because the proof verification will detect the mismatch
    assert!(
        result_wrong.is_err(),
        "store_secret with wrong derivation (tampered proof) should fail: {:?}",
        result_wrong
    );

    let status_wrong = result_wrong.unwrap_err();
    assert!(
        status_wrong.message().contains("encryption")
            || status_wrong.message().contains("Validation"),
        "Error should mention encryption or validation failure: {}",
        status_wrong.message()
    );
    println!("Step 1: Correctly failed with wrong derivation");

    // Step 2: Encrypt with CORRECT derivation and store - should succeed
    println!("Step 2: Encrypting with correct derivation...");
    let (_enc_cmt_correct, secret_correct, proof_correct) =
        ThresholdDealerNode::encrypt_secret(&ring_pk, plaintext, Some(correct_derivation))
            .expect("encrypt with correct derivation");

    let encrypted_doc_correct = serde_json::to_string(&secret_correct).expect("serialize Secret");
    let enc_cmt_hex_correct = hex::encode(secret_correct.enc_cmt.clone());

    let token_correct = test_keys
        .create_store_secret_jwt(
            &encrypted_doc_correct,
            &enc_cmt_hex_correct,
            &ring_id,
            namespace,
            policy_id,
            resource,
            permission,
            proof_correct.shared_point.clone(),
            proof_correct.challenge.clone(),
            proof_correct.response.clone(),
            proof_correct_temp.derived_pk.clone(),
            false,
        )
        .expect("Failed to create JWT");

    let request_correct = StoreSecretRequest {
        encrypted_document: encrypted_doc_correct,
        enc_cmt: enc_cmt_hex_correct,
        ring_id: ring_id.clone(),
        namespace: namespace.to_string(),
        policy_id: policy_id.to_string(),
        resource: resource.to_string(),
        permission: permission.to_string(),
        shared_point: proof_correct.shared_point.clone(),
        challenge: proof_correct.challenge.clone(),
        response: proof_correct.response.clone(),
        derived_pk: proof_correct_temp.derived_pk.clone(),
        with_proof: false,
    };

    let tonic_request_correct =
        create_authenticated_request(request_correct, &token_correct).unwrap();
    let result_correct = service.store_secret(tonic_request_correct).await;

    assert!(
        result_correct.is_ok(),
        "store_secret with correct derivation should succeed: {:?}",
        result_correct.err()
    );

    let response_correct = result_correct.unwrap().into_inner();
    println!(
        "Step 2: Succeeded with object_id: {}",
        response_correct.object_id
    );

    // Verify the secret was stored
    let posts_after = bulletin.get_posts_by_namespace(namespace);
    assert_eq!(
        posts_after.len(),
        1,
        "Should have exactly 1 post after storing with correct derivation"
    );

    println!(
        "SUCCESS! StoreSecret correctly rejected wrong derivation and accepted correct derivation"
    );

    cleanup_db(&db_path);
}
