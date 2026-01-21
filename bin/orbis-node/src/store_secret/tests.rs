//! StoreSecret Tests
//!
//! This module contains tests for the StoreSecret service.
//! Tests verify authentication, validation, and error handling.

use crate::helpers::test_helpers::{
    cleanup_db, create_authenticated_request, create_test_app_state_default, test_db_path,
    TestKeyPair,
};
use crate::store_secret::StoreSecretServiceImpl;
use proto::store_secret_service::{
    store_secret_service_server::StoreSecretService, StoreSecretRequest,
};
use tonic::Request;

// Concrete crypto implementations for tests
use crypto::bls12_381::dkg::DKGNode;
type DkgImpl = DKGNode;

/// Default test values for StoreSecret requests
const TEST_ENCRYPTED_DOC: &str = "{}";
const TEST_ENC_CMT: &str = "00";
const TEST_RING_ID: &str = "test-ring";
const TEST_NAMESPACE: &str = "test-namespace";
const TEST_POLICY_ID: &str = "test-policy";
const TEST_RESOURCE: &str = "test-resource";
const TEST_PERMISSION: &str = "test-permission";

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
        )
        .expect("Failed to create JWT")
}

/// Test that StoreSecret fails when Authorization header is missing
#[tokio::test]
async fn test_store_secret_fails_missing_auth_header() {
    let db_name = "test_store_secret_fails_missing_auth_header";
    let db_path = test_db_path(db_name);
    let app_state = create_test_app_state_default(db_name).await;
    let service = StoreSecretServiceImpl::<DkgImpl>::new(app_state);

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
    let service = StoreSecretServiceImpl::<DkgImpl>::new(app_state);

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
    let service = StoreSecretServiceImpl::<DkgImpl>::new(app_state);

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
    let service = StoreSecretServiceImpl::<DkgImpl>::new(app_state);

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
    let app_state = create_test_app_state_default(db_name).await;
    let service = StoreSecretServiceImpl::<DkgImpl>::new(app_state);

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
    let service = StoreSecretServiceImpl::<DkgImpl>::new(app_state);

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
