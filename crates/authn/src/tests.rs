use super::*;
use crate::jwt_builder::JwtSigner;
use did_key::{generate, Ed25519KeyPair as DidEd25519KeyPair, Fingerprint};

const TEST_MAX_LIFETIME: u64 = 86400; // 24 hours, mirrors the node constant
const TEST_MAX_JWT_BYTES: usize = 16 * 1024; // mirrors the node constant
const TEST_CLOCK_SKEW_LEEWAY: u64 = 16 * 60; // mirrors the node clock-skew leeway

/// Helper to create a test JWT with PreClaims
fn create_test_jwt_with_pre_claims(
    key_pair: &did_key::PatchedKeyPair,
    token: &BearerToken<PreClaims>,
) -> String {
    JwtSigner::sign_bearer_token_with_key_pair(key_pair, token).unwrap()
}

/// Helper to create a test JWT with PreClaims and an explicit nbf value
fn create_test_jwt_with_nbf(
    key_pair: &did_key::PatchedKeyPair,
    token: &BearerToken<PreClaims>,
    not_before: Option<u64>,
) -> String {
    let mut token = token.clone();
    token.not_before = not_before;
    JwtSigner::sign_bearer_token_with_key_pair(key_pair, &token).unwrap()
}

/// Helper to create a test JWT with no custom claims (for DKG)
fn create_test_jwt_no_claims(
    key_pair: &did_key::PatchedKeyPair,
    token: &BearerToken<DkgClaims>,
) -> String {
    JwtSigner::sign_bearer_token_with_key_pair(key_pair, token).unwrap()
}

#[test]
fn test_resolve_jwt_did_with_pre_claims() {
    let key_pair = generate::<DidEd25519KeyPair>(None);
    let did_uri = format!("did:key:{}", key_pair.fingerprint());

    let current_time = 1000;
    let token = BearerToken {
        issuer_id: did_uri,
        issued_time: 900,
        expiration_time: 2000,
        not_before: None,
        claims: PreClaims {
            rdr_pk: b"test_rdr_pk".to_vec(),
            object_id: "".to_string(),
            namespace: "".to_string(),
            derivation: None,
            salt: None,
        },
    };

    let jwt = create_test_jwt_with_pre_claims(&key_pair, &token);
    let result: Result<BearerToken<PreClaims>> =
        resolve_jwt_did(&jwt, current_time, TEST_MAX_LIFETIME, TEST_MAX_JWT_BYTES, 0);

    assert!(result.is_ok(), "Expected Ok, got: {:?}", result);
    let decoded = result.unwrap();
    assert_eq!(decoded.claims.rdr_pk, b"test_rdr_pk".to_vec());
}

#[test]
fn test_resolve_jwt_did_with_dkg_claims() {
    let key_pair = generate::<DidEd25519KeyPair>(None);
    let did_uri = format!("did:key:{}", key_pair.fingerprint());

    let current_time = 1000;
    let token = BearerToken {
        issuer_id: did_uri.clone(),
        issued_time: 900,
        expiration_time: 2000,
        not_before: None,
        claims: DkgClaims {
            peer_ids: vec![],
            threshold: 2,
            pss_interval: None,
            policy_id: None,
            namespace: "test_namespace".to_string(),
            ring_id: "ring-1".to_string(),
        },
    };

    let jwt = create_test_jwt_no_claims(&key_pair, &token);
    let result: Result<BearerToken<DkgClaims>> =
        resolve_jwt_did(&jwt, current_time, TEST_MAX_LIFETIME, TEST_MAX_JWT_BYTES, 0);

    assert!(result.is_ok(), "Expected Ok, got: {:?}", result);
    let decoded = result.unwrap();
    assert_eq!(decoded.issuer_id, did_uri);
    assert_eq!(decoded.claims.namespace, "test_namespace");
}

#[test]
fn test_resolve_jwt_did_expired() {
    let key_pair = generate::<DidEd25519KeyPair>(None);
    let did_uri = format!("did:key:{}", key_pair.fingerprint());

    let current_time = 3000; // After expiration
    let token = BearerToken {
        issuer_id: did_uri,
        issued_time: 900,
        expiration_time: 2000,
        not_before: None,
        claims: PreClaims {
            rdr_pk: b"test_rdr_pk".to_vec(),
            object_id: "".to_string(),
            namespace: "".to_string(),
            derivation: None,
            salt: None,
        },
    };

    let jwt = create_test_jwt_with_pre_claims(&key_pair, &token);
    let result: Result<BearerToken<PreClaims>> =
        resolve_jwt_did(&jwt, current_time, TEST_MAX_LIFETIME, TEST_MAX_JWT_BYTES, 0);

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), AuthNError::JwtError(_)));
}

#[test]
fn test_resolve_jwt_did_future_issued_time() {
    let key_pair = generate::<DidEd25519KeyPair>(None);
    let did_uri = format!("did:key:{}", key_pair.fingerprint());

    let current_time = 500; // Before issued_time
    let token = BearerToken {
        issuer_id: did_uri,
        issued_time: 900,
        expiration_time: 2000,
        not_before: None,
        claims: PreClaims {
            rdr_pk: b"test_rdr_pk".to_vec(),
            object_id: "".to_string(),
            namespace: "".to_string(),
            derivation: None,
            salt: None,
        },
    };

    let jwt = create_test_jwt_with_pre_claims(&key_pair, &token);
    let result: Result<BearerToken<PreClaims>> =
        resolve_jwt_did(&jwt, current_time, TEST_MAX_LIFETIME, TEST_MAX_JWT_BYTES, 0);

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), AuthNError::JwtError(_)));
}

#[test]
fn test_resolve_jwt_did_accepts_future_issued_time_with_clock_skew() {
    let key_pair = generate::<DidEd25519KeyPair>(None);
    let did_uri = format!("did:key:{}", key_pair.fingerprint());

    let current_time = 1000;
    let token = BearerToken {
        issuer_id: did_uri,
        issued_time: current_time + TEST_CLOCK_SKEW_LEEWAY,
        expiration_time: current_time + TEST_CLOCK_SKEW_LEEWAY + 1000,
        not_before: None,
        claims: PreClaims::default(),
    };

    let jwt = create_test_jwt_with_pre_claims(&key_pair, &token);
    let result: Result<BearerToken<PreClaims>> = resolve_jwt_did(
        &jwt,
        current_time,
        TEST_MAX_LIFETIME,
        TEST_MAX_JWT_BYTES,
        TEST_CLOCK_SKEW_LEEWAY,
    );

    assert!(result.is_ok(), "Expected Ok, got: {:?}", result);
}

#[test]
fn test_resolve_jwt_did_rejects_future_issued_time_beyond_clock_skew() {
    let key_pair = generate::<DidEd25519KeyPair>(None);
    let did_uri = format!("did:key:{}", key_pair.fingerprint());

    let current_time = 1000;
    let token = BearerToken {
        issuer_id: did_uri,
        issued_time: current_time + TEST_CLOCK_SKEW_LEEWAY + 1,
        expiration_time: current_time + TEST_CLOCK_SKEW_LEEWAY + 1000,
        not_before: None,
        claims: PreClaims::default(),
    };

    let jwt = create_test_jwt_with_pre_claims(&key_pair, &token);
    let result: Result<BearerToken<PreClaims>> = resolve_jwt_did(
        &jwt,
        current_time,
        TEST_MAX_LIFETIME,
        TEST_MAX_JWT_BYTES,
        TEST_CLOCK_SKEW_LEEWAY,
    );

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        matches!(&err, AuthNError::JwtError(msg) if msg.contains("future")),
        "Expected future-issued error, got: {:?}",
        err
    );
}

#[test]
fn test_token_lifetime_at_limit() {
    let key_pair = generate::<DidEd25519KeyPair>(None);
    let did_uri = format!("did:key:{}", key_pair.fingerprint());

    let issued_time = 1000;
    let current_time = 1001;
    // Exactly MAX_TOKEN_LIFETIME_SECS (86400) — should be accepted
    let token = BearerToken {
        issuer_id: did_uri,
        issued_time,
        not_before: None,
        expiration_time: issued_time + TEST_MAX_LIFETIME,
        claims: PreClaims {
            rdr_pk: b"test_rdr_pk".to_vec(),
            object_id: "".to_string(),
            namespace: "".to_string(),
            derivation: None,
            salt: None,
        },
    };

    let jwt = create_test_jwt_with_pre_claims(&key_pair, &token);
    let result: Result<BearerToken<PreClaims>> =
        resolve_jwt_did(&jwt, current_time, TEST_MAX_LIFETIME, TEST_MAX_JWT_BYTES, 0);

    assert!(
        result.is_ok(),
        "Token at exactly the lifetime limit should be accepted, got: {:?}",
        result
    );
}

#[test]
fn test_token_lifetime_one_second_over_limit() {
    let key_pair = generate::<DidEd25519KeyPair>(None);
    let did_uri = format!("did:key:{}", key_pair.fingerprint());

    let issued_time = 1000;
    let current_time = 1001;
    // One second over MAX_TOKEN_LIFETIME_SECS — should be rejected
    let token = BearerToken {
        issuer_id: did_uri,
        issued_time,
        not_before: None,
        expiration_time: issued_time + TEST_MAX_LIFETIME + 1,
        claims: PreClaims {
            rdr_pk: b"test_rdr_pk".to_vec(),
            object_id: "".to_string(),
            namespace: "".to_string(),
            derivation: None,
            salt: None,
        },
    };

    let jwt = create_test_jwt_with_pre_claims(&key_pair, &token);
    let result: Result<BearerToken<PreClaims>> =
        resolve_jwt_did(&jwt, current_time, TEST_MAX_LIFETIME, TEST_MAX_JWT_BYTES, 0);

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        matches!(&err, AuthNError::JwtError(msg) if msg.contains("lifetime")),
        "Expected lifetime error, got: {:?}",
        err
    );
}

#[test]
fn test_token_lifetime_far_future() {
    let key_pair = generate::<DidEd25519KeyPair>(None);
    let did_uri = format!("did:key:{}", key_pair.fingerprint());

    let issued_time = 1_000_000;
    let current_time = 1_000_001;
    // Expiration decades away — should be rejected
    let token = BearerToken {
        issuer_id: did_uri,
        issued_time,
        not_before: None,
        expiration_time: issued_time + (365 * 24 * 60 * 60 * 10), // 10 years
        claims: PreClaims {
            rdr_pk: b"test_rdr_pk".to_vec(),
            object_id: "".to_string(),
            namespace: "".to_string(),
            derivation: None,
            salt: None,
        },
    };

    let jwt = create_test_jwt_with_pre_claims(&key_pair, &token);
    let result: Result<BearerToken<PreClaims>> =
        resolve_jwt_did(&jwt, current_time, TEST_MAX_LIFETIME, TEST_MAX_JWT_BYTES, 0);

    assert!(result.is_err());
    assert!(
        matches!(result.unwrap_err(), AuthNError::JwtError(_)),
        "Expected JwtError for far-future expiry"
    );
}

#[test]
fn test_resolve_jwt_did_invalid_signature() {
    let key_pair1 = generate::<DidEd25519KeyPair>(None);
    let key_pair2 = generate::<DidEd25519KeyPair>(None);
    let did_uri = format!("did:key:{}", key_pair1.fingerprint());

    let current_time = 1000;
    let token = BearerToken {
        issuer_id: did_uri,
        issued_time: 900,
        expiration_time: 2000,
        not_before: None,
        claims: PreClaims {
            rdr_pk: b"test_rdr_pk".to_vec(),
            object_id: "".to_string(),
            namespace: "".to_string(),
            derivation: None,
            salt: None,
        },
    };

    // Sign with key_pair2 but claim issuer is key_pair1
    let jwt = create_test_jwt_with_pre_claims(&key_pair2, &token);
    let result: Result<BearerToken<PreClaims>> =
        resolve_jwt_did(&jwt, current_time, TEST_MAX_LIFETIME, TEST_MAX_JWT_BYTES, 0);

    assert!(result.is_err());
}

#[test]
fn test_nbf_in_future_rejected() {
    let key_pair = generate::<DidEd25519KeyPair>(None);
    let did_uri = format!("did:key:{}", key_pair.fingerprint());

    let current_time = 1000;
    let token = BearerToken {
        issuer_id: did_uri,
        issued_time: 900,
        expiration_time: 2000,
        not_before: Some(1500),
        claims: PreClaims::default(),
    };

    let jwt = create_test_jwt_with_nbf(&key_pair, &token, Some(1500));
    let result: Result<BearerToken<PreClaims>> =
        resolve_jwt_did(&jwt, current_time, TEST_MAX_LIFETIME, TEST_MAX_JWT_BYTES, 0);

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        matches!(&err, AuthNError::JwtError(msg) if msg.contains("nbf")),
        "Expected nbf error, got: {:?}",
        err
    );
}

#[test]
fn test_nbf_in_past_accepted() {
    let key_pair = generate::<DidEd25519KeyPair>(None);
    let did_uri = format!("did:key:{}", key_pair.fingerprint());

    let current_time = 1000;
    let token = BearerToken {
        issuer_id: did_uri,
        issued_time: 900,
        expiration_time: 2000,
        not_before: Some(950),
        claims: PreClaims::default(),
    };

    let jwt = create_test_jwt_with_nbf(&key_pair, &token, Some(950));
    let result: Result<BearerToken<PreClaims>> =
        resolve_jwt_did(&jwt, current_time, TEST_MAX_LIFETIME, TEST_MAX_JWT_BYTES, 0);

    assert!(result.is_ok(), "Expected Ok, got: {:?}", result);
}

#[test]
fn test_nbf_within_clock_skew_accepted() {
    let key_pair = generate::<DidEd25519KeyPair>(None);
    let did_uri = format!("did:key:{}", key_pair.fingerprint());

    let current_time = 1000;
    let token = BearerToken {
        issuer_id: did_uri,
        issued_time: 900,
        expiration_time: 3000,
        not_before: Some(current_time + TEST_CLOCK_SKEW_LEEWAY),
        claims: PreClaims::default(),
    };

    let jwt = create_test_jwt_with_nbf(&key_pair, &token, token.not_before);
    let result: Result<BearerToken<PreClaims>> = resolve_jwt_did(
        &jwt,
        current_time,
        TEST_MAX_LIFETIME,
        TEST_MAX_JWT_BYTES,
        TEST_CLOCK_SKEW_LEEWAY,
    );

    assert!(result.is_ok(), "Expected Ok, got: {:?}", result);
}

#[test]
fn test_expiration_within_clock_skew_accepted() {
    let key_pair = generate::<DidEd25519KeyPair>(None);
    let did_uri = format!("did:key:{}", key_pair.fingerprint());

    let expiration_time = 2000;
    let current_time = expiration_time + TEST_CLOCK_SKEW_LEEWAY - 1;
    let token = BearerToken {
        issuer_id: did_uri,
        issued_time: 1000,
        expiration_time,
        not_before: None,
        claims: PreClaims::default(),
    };

    let jwt = create_test_jwt_with_pre_claims(&key_pair, &token);
    let result: Result<BearerToken<PreClaims>> = resolve_jwt_did(
        &jwt,
        current_time,
        TEST_MAX_LIFETIME,
        TEST_MAX_JWT_BYTES,
        TEST_CLOCK_SKEW_LEEWAY,
    );

    assert!(result.is_ok(), "Expected Ok, got: {:?}", result);
}

#[test]
fn test_oversized_token_rejected_before_decoding() {
    // Build a token that exceeds MAX_JWT_BYTES by padding it with trailing garbage.
    // We don't need a valid JWT structure — the check fires before any parsing.
    let oversized = "x".repeat(TEST_MAX_JWT_BYTES + 1);
    let result: Result<BearerToken<PreClaims>> =
        resolve_jwt_did(&oversized, 1000, TEST_MAX_LIFETIME, TEST_MAX_JWT_BYTES, 0);

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        matches!(&err, AuthNError::JwtError(msg) if msg.contains("too large")),
        "Expected 'too large' error, got: {:?}",
        err
    );
}

#[test]
fn test_token_at_max_size_reaches_normal_validation() {
    // A valid small JWT produced by JwtSigner is well under MAX_JWT_BYTES.
    // Verify that a legitimately sized token is not rejected by the size check
    // (it will still fail or pass based on its content — here we use a real valid token).
    let signer = JwtSigner::new();
    let token = signer
        .create_sign_jwt("my-namespace", "my-derivation-id", b"hello world")
        .expect("create JWT");

    assert!(
        token.len() < TEST_MAX_JWT_BYTES,
        "Normal sign JWT ({} bytes) should be well under TEST_MAX_JWT_BYTES ({})",
        token.len(),
        TEST_MAX_JWT_BYTES
    );

    // resolve_jwt_did will fail with a clock/iat error (the builder sets iat to now),
    // but it must NOT fail with a size error.
    let result: Result<BearerToken<SignClaims>> =
        resolve_jwt_did(&token, u64::MAX, TEST_MAX_LIFETIME, TEST_MAX_JWT_BYTES, 0);

    assert!(
        !matches!(&result, Err(AuthNError::JwtError(msg)) if msg.contains("too large")),
        "Normal-sized JWT should not be rejected by the size check, got: {:?}",
        result
    );
}
