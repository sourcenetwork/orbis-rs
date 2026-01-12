use super::*;
use did_key::{generate, Ed25519KeyPair as DidEd25519KeyPair, Fingerprint, KeyMaterial};
use jwt_simple::prelude::*;

/// Helper to create a test JWT with PreClaims
fn create_test_jwt_with_pre_claims(
    key_pair: &did_key::PatchedKeyPair,
    token: &BearerToken<PreClaims>,
) -> String {
    // jwt-simple expects 64 bytes: seed (32) + public key (32)
    let mut keypair_bytes = key_pair.private_key_bytes();
    keypair_bytes.extend(key_pair.public_key_bytes());

    let signing_key = Ed25519KeyPair::from_bytes(&keypair_bytes).unwrap();

    let custom = PreClaims {
        rdr_pk: token.claims.rdr_pk.clone(),
        object_id: "".to_string(),
        namespace: "".to_string(),
    };

    let mut jwt_claims =
        Claims::with_custom_claims(custom, Duration::from_secs(0)).with_issuer(&token.issuer_id);
    jwt_claims.issued_at = Some(UnixTimeStamp::from_secs(token.issued_time));
    jwt_claims.expires_at = Some(UnixTimeStamp::from_secs(token.expiration_time));

    signing_key.sign(jwt_claims).unwrap()
}

/// Helper to create a test JWT with no custom claims (for DKG)
fn create_test_jwt_no_claims(
    key_pair: &did_key::PatchedKeyPair,
    token: &BearerToken<DkgClaims>,
) -> String {
    let mut keypair_bytes = key_pair.private_key_bytes();
    keypair_bytes.extend(key_pair.public_key_bytes());

    let signing_key = Ed25519KeyPair::from_bytes(&keypair_bytes).unwrap();

    let mut jwt_claims = Claims::with_custom_claims(
        DkgClaims {
            peer_ids: "".to_string(),
            threshold: 2,
        },
        Duration::from_secs(0),
    )
    .with_issuer(&token.issuer_id);
    jwt_claims.issued_at = Some(UnixTimeStamp::from_secs(token.issued_time));
    jwt_claims.expires_at = Some(UnixTimeStamp::from_secs(token.expiration_time));

    signing_key.sign(jwt_claims).unwrap()
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
        claims: PreClaims {
            rdr_pk: "test_rdr_pk".to_string(),
            object_id: "".to_string(),
            namespace: "".to_string(),
        },
    };

    let jwt = create_test_jwt_with_pre_claims(&key_pair, &token);
    let result: Result<BearerToken<PreClaims>> = resolve_jwt_did(&jwt, current_time);

    assert!(result.is_ok(), "Expected Ok, got: {:?}", result);
    let decoded = result.unwrap();
    assert_eq!(decoded.claims.rdr_pk, "test_rdr_pk");
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
        claims: DkgClaims {
            peer_ids: "".to_string(),
            threshold: 2,
        },
    };

    let jwt = create_test_jwt_no_claims(&key_pair, &token);
    let result: Result<BearerToken<DkgClaims>> = resolve_jwt_did(&jwt, current_time);

    assert!(result.is_ok(), "Expected Ok, got: {:?}", result);
    let decoded = result.unwrap();
    assert_eq!(decoded.issuer_id, did_uri);
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
        claims: PreClaims {
            rdr_pk: "test_rdr_pk".to_string(),
            object_id: "".to_string(),
            namespace: "".to_string(),
        },
    };

    let jwt = create_test_jwt_with_pre_claims(&key_pair, &token);
    let result: Result<BearerToken<PreClaims>> = resolve_jwt_did(&jwt, current_time);

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
        claims: PreClaims {
            rdr_pk: "test_rdr_pk".to_string(),
            object_id: "".to_string(),
            namespace: "".to_string(),
        },
    };

    let jwt = create_test_jwt_with_pre_claims(&key_pair, &token);
    let result: Result<BearerToken<PreClaims>> = resolve_jwt_did(&jwt, current_time);

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), AuthNError::JwtError(_)));
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
        claims: PreClaims {
            rdr_pk: "test_rdr_pk".to_string(),
            object_id: "".to_string(),
            namespace: "".to_string(),
        },
    };

    // Sign with key_pair2 but claim issuer is key_pair1
    let jwt = create_test_jwt_with_pre_claims(&key_pair2, &token);
    let result: Result<BearerToken<PreClaims>> = resolve_jwt_did(&jwt, current_time);

    assert!(result.is_err());
}
