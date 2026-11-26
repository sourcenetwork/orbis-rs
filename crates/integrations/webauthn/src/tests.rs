use super::*;
use p256::ecdsa::SigningKey;

const RP_ID: &str = "example.test";
const ORIGIN: &str = "https://example.test";

fn signing_key() -> SigningKey {
    let mut scalar = [0u8; 32];
    scalar[31] = 7;
    SigningKey::from_bytes((&scalar).into()).expect("small nonzero scalar is valid")
}

fn compressed_public_key(key: &SigningKey) -> [u8; 33] {
    key.verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .expect("compressed P-256 point is 33 bytes")
}

#[test]
fn verifies_a_well_formed_assertion() {
    let key = signing_key();
    let pubkey = compressed_public_key(&key);
    let challenge = b"the exact operation bytes";
    let assertion = build_test_assertion(&key, RP_ID, ORIGIN, challenge);

    verify_assertion(&pubkey, &assertion, RP_ID, ORIGIN, challenge)
        .expect("well-formed assertion must verify");
}

#[test]
fn rejects_mismatched_challenge() {
    let key = signing_key();
    let pubkey = compressed_public_key(&key);
    let assertion = build_test_assertion(&key, RP_ID, ORIGIN, b"the real operation");

    let result = verify_assertion(&pubkey, &assertion, RP_ID, ORIGIN, b"a different operation");
    assert!(matches!(result, Err(VerifyError::ChallengeMismatch)));
}

#[test]
fn rejects_mismatched_origin() {
    let key = signing_key();
    let pubkey = compressed_public_key(&key);
    let challenge = b"the exact operation bytes";
    let assertion = build_test_assertion(&key, RP_ID, "https://attacker.test", challenge);

    let result = verify_assertion(&pubkey, &assertion, RP_ID, ORIGIN, challenge);
    assert!(matches!(result, Err(VerifyError::OriginMismatch)));
}

#[test]
fn rejects_cross_origin_assertion() {
    use p256::ecdsa::signature::Signer;

    let key = signing_key();
    let pubkey = compressed_public_key(&key);
    let challenge = b"the exact operation bytes";

    // Same shape `build_test_assertion` produces, but with `crossOrigin:
    // true` added — `origin` still matches `ORIGIN` exactly, simulating a
    // ceremony that ran inside an iframe whose top-level page did not.
    let mut authenticator_data = Sha256::digest(RP_ID.as_bytes()).to_vec();
    authenticator_data.push(0b0000_0001);
    authenticator_data.extend_from_slice(&[0u8; 4]);
    let client_data_json = serde_json::json!({
        "type": "webauthn.get",
        "challenge": base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            challenge,
        ),
        "origin": ORIGIN,
        "crossOrigin": true,
    })
    .to_string()
    .into_bytes();
    let client_data_hash = Sha256::digest(&client_data_json);
    let mut verification_data = authenticator_data.clone();
    verification_data.extend_from_slice(&client_data_hash);
    let signature: p256::ecdsa::Signature = key.sign(&verification_data);
    let assertion = RawAssertion {
        authenticator_data,
        client_data_json,
        signature: signature.to_der().as_bytes().to_vec(),
    };

    let result = verify_assertion(&pubkey, &assertion, RP_ID, ORIGIN, challenge);
    assert!(matches!(result, Err(VerifyError::CrossOriginNotAllowed)));
}

#[test]
fn rejects_wrong_signing_key() {
    let key = signing_key();
    let mut other_scalar = [0u8; 32];
    other_scalar[31] = 9;
    let other_key =
        SigningKey::from_bytes((&other_scalar).into()).expect("small nonzero scalar is valid");
    let wrong_pubkey = compressed_public_key(&other_key);

    let challenge = b"the exact operation bytes";
    let assertion = build_test_assertion(&key, RP_ID, ORIGIN, challenge);

    let result = verify_assertion(&wrong_pubkey, &assertion, RP_ID, ORIGIN, challenge);
    assert!(matches!(result, Err(VerifyError::SignatureInvalid)));
}

struct ToyOperation {
    value: &'static str,
}

impl orbis_integration_core::CanonicalOperation for ToyOperation {
    fn canonical_bytes(&self) -> Vec<u8> {
        self.value.as_bytes().to_vec()
    }
}

fn evidence_for(
    key: &SigningKey,
    did: &str,
    operation: &ToyOperation,
    expiry: u64,
) -> WebAuthnEvidence {
    let assertion = build_test_assertion(key, RP_ID, ORIGIN, &operation.canonical_bytes());
    WebAuthnEvidence {
        issuer_did: did.to_string(),
        authenticator_data: assertion.authenticator_data,
        client_data_json: assertion.client_data_json,
        signature: assertion.signature,
        issued_at: 1_700_000_000,
        expiry,
        nonce: vec![1; 16],
    }
}

#[test]
fn verify_and_build_token_returns_a_usable_bearer_token() {
    let key = signing_key();
    let did = authn::did_from_p256_public_key(&compressed_public_key(&key));
    let operation = ToyOperation { value: "op-1" };
    let evidence = evidence_for(&key, &did, &operation, 2_000_000_000);

    let token = verify_and_build_token(
        &evidence,
        ToyOperation { value: "op-1" },
        "claims-value",
        Some(RP_ID),
        Some(ORIGIN),
        1_700_000_100,
        u64::MAX,
    )
    .expect("well-formed evidence must verify");

    assert_eq!(token.issuer_id, did);
    assert_eq!(token.claims, "claims-value");
    assert_eq!(token.jwt_id, hex::encode(&evidence.nonce));
}

#[test]
fn verify_and_build_token_rejects_when_not_configured() {
    let key = signing_key();
    let did = authn::did_from_p256_public_key(&compressed_public_key(&key));
    let operation = ToyOperation { value: "op-1" };
    let evidence = evidence_for(&key, &did, &operation, 2_000_000_000);

    let result = verify_and_build_token(
        &evidence,
        ToyOperation { value: "op-1" },
        "claims-value",
        None,
        Some(ORIGIN),
        1_700_000_100,
        u64::MAX,
    );
    assert!(matches!(result, Err(WebAuthnAuthError::NotConfigured)));
}

#[test]
fn verify_and_build_token_rejects_expired_evidence() {
    let key = signing_key();
    let did = authn::did_from_p256_public_key(&compressed_public_key(&key));
    let operation = ToyOperation { value: "op-1" };
    let evidence = evidence_for(&key, &did, &operation, 1_000);

    let result = verify_and_build_token(
        &evidence,
        ToyOperation { value: "op-1" },
        "claims-value",
        Some(RP_ID),
        Some(ORIGIN),
        1_700_000_100,
        u64::MAX,
    );
    assert!(matches!(result, Err(WebAuthnAuthError::Expired)));
}

#[test]
fn verify_and_build_token_rejects_evidence_whose_lifetime_exceeds_the_cap() {
    let key = signing_key();
    let did = authn::did_from_p256_public_key(&compressed_public_key(&key));
    let operation = ToyOperation { value: "op-1" };
    // Not expired (expiry is still ahead of current_time), but the gap
    // between them exceeds max_lifetime_secs.
    let evidence = evidence_for(&key, &did, &operation, 1_700_001_000);

    let result = verify_and_build_token(
        &evidence,
        ToyOperation { value: "op-1" },
        "claims-value",
        Some(RP_ID),
        Some(ORIGIN),
        1_700_000_100,
        100,
    );
    assert!(matches!(result, Err(WebAuthnAuthError::LifetimeTooLong)));
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
struct ToyClaims {
    value: String,
}

struct ToyEndpoint;

impl authn::endpoints::EndpointAuth for ToyEndpoint {
    type Claims = ToyClaims;
    type Fields = &'static str;

    fn validate_claims(
        token: &authn::BearerToken<ToyClaims>,
        fields: &&'static str,
    ) -> authn::error::Result<()> {
        if token.claims.value != *fields {
            return Err(authn::error::AuthNError::Unauthorized(
                "claims mismatch".to_string(),
            ));
        }
        Ok(())
    }
}

impl WebAuthnEndpoint for ToyEndpoint {
    type Operation = ToyOperation;

    fn claims(fields: &&'static str) -> ToyClaims {
        ToyClaims {
            value: fields.to_string(),
        }
    }

    fn operation(
        fields: &&'static str,
        _issued_at: u64,
        _expiry: u64,
        _nonce: [u8; 16],
    ) -> ToyOperation {
        ToyOperation { value: fields }
    }
}

#[test]
fn verify_endpoint_auth_dispatches_through_the_webauthn_endpoint_trait() {
    let key = signing_key();
    let did = authn::did_from_p256_public_key(&compressed_public_key(&key));
    let operation = ToyOperation { value: "op-1" };
    let evidence = evidence_for(&key, &did, &operation, 2_000_000_000);

    let token = verify_endpoint_auth::<ToyEndpoint>(
        &"op-1",
        &evidence,
        Some(RP_ID),
        Some(ORIGIN),
        1_700_000_100,
        u64::MAX,
    )
    .expect("well-formed WebAuthn evidence must resolve");

    assert_eq!(token.issuer_id, did);
    assert_eq!(token.claims.value, "op-1");
}

#[test]
fn verify_endpoint_auth_rejects_short_nonce() {
    let key = signing_key();
    let did = authn::did_from_p256_public_key(&compressed_public_key(&key));
    let operation = ToyOperation { value: "op-1" };
    let mut evidence = evidence_for(&key, &did, &operation, 2_000_000_000);
    evidence.nonce = vec![1, 2, 3, 4];

    let result = verify_endpoint_auth::<ToyEndpoint>(
        &"op-1",
        &evidence,
        Some(RP_ID),
        Some(ORIGIN),
        1_700_000_100,
        u64::MAX,
    );
    assert!(matches!(result, Err(WebAuthnAuthError::InvalidNonce)));
}
