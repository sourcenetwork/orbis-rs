//! Passkey and FIDO2 security-key integration for Orbis flows.
//!
//! [`verify_assertion`] verifies a raw WebAuthn assertion directly against
//! a caller-supplied P-256 credential public key and an exact, expected
//! challenge — no session/ceremony state, no credential storage.
//!
//! This deliberately bypasses `webauthn-rs`'s higher-level ceremony API
//! (`Webauthn`/`AuthenticationState`): that API always generates its own
//! random challenge internally — there is no public way to pin a
//! caller-chosen one — which doesn't fit a model where the identity *is*
//! the credential's own public key and the challenge must be an exact,
//! independently-recomputable commitment to the operation being authorized
//! (see `orbis_integration_core::SignOperation`). The actual cryptographic
//! verification (`COSEKey::verify_signature`) is still reused directly from
//! `webauthn-rs-core`, not reimplemented — only the orchestration of the
//! handful of WebAuthn checks it would otherwise do internally is ours.
//!
//! Node-side verification must call this directly and independently; a
//! verification result produced by one party (a coordinator, an example
//! app) is never proof for another.
//!
//! [`verify_and_build_token`] wraps [`verify_assertion`] with the
//! operation-binding and identity-resolution steps every protocol needs
//! identically, generic over that protocol's own operation
//! (`orbis_integration_core::CanonicalOperation`) and claims types.
//! [`verify_endpoint_auth`] goes one step further: generic over
//! [`WebAuthnEndpoint`] (an endpoint's own extension of
//! `authn::endpoints::EndpointAuth`), it's the complete WebAuthn
//! authentication path for one endpoint. This crate deliberately has no
//! notion of a JWT fallback or of any other authentication mechanism —
//! see `authn::endpoints`'s own doc comment for why that composition
//! belongs to the caller (`orbis-node`), not to any one mechanism's
//! crate.

use orbis_integration_core::CanonicalOperation;
use sha2::{Digest, Sha256};
use webauthn_rs_core::proto::{COSEAlgorithm, COSEEC2Key, COSEKey, COSEKeyType, ECDSACurve};

/// Authentication evidence authorizing a request in place of a JWT: a
/// WebAuthn assertion plus the fields needed to resolve an identity from it
/// and bind it to an exact operation. The passkey's own credential public
/// key *is* that identity — `issuer_did` is the `did:key` it decodes to,
/// and ACP grants/revokes that DID directly; there is no separate
/// enrollment registry.
///
/// Plain fields, not a generated proto type: each protocol's own wire
/// format converts into this via a trivial `From` impl at its own
/// boundary, and this is what actually travels through the P2P network's
/// own (non-proto) wire encoding, the way every other internal context
/// payload in this codebase does.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WebAuthnEvidence {
    pub issuer_did: String,
    pub authenticator_data: Vec<u8>,
    pub client_data_json: Vec<u8>,
    pub signature: Vec<u8>,
    /// Unix seconds, client-chosen. Some protocols (PRE's reader-key
    /// proof-of-possession) cryptographically bind this into a signature
    /// the client produces before the server ever sees the request, so it
    /// has to be a value both sides already agree on — never "now" at
    /// verification time, even for a protocol that doesn't strictly need
    /// it.
    pub issued_at: u64,
    /// Unix seconds; rejected once `now` passes this.
    pub expiry: u64,
    pub nonce: Vec<u8>,
}

/// The raw components of a WebAuthn assertion (`navigator.credentials.get()`
/// output), carried over the wire — e.g. as the `WebAuthnAssertion` proto
/// message.
#[derive(Debug, Clone)]
pub struct RawAssertion {
    pub authenticator_data: Vec<u8>,
    pub client_data_json: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("malformed authenticatorData")]
    MalformedAuthenticatorData,
    #[error("malformed clientDataJSON: {0}")]
    MalformedClientData(String),
    #[error("unexpected clientDataJSON.type: {0}")]
    UnexpectedType(String),
    #[error("clientDataJSON.challenge did not match the expected operation")]
    ChallengeMismatch,
    #[error("clientDataJSON.origin did not match the expected origin")]
    OriginMismatch,
    #[error("authenticatorData rpIdHash did not match the expected RP ID")]
    RpIdMismatch,
    #[error("authenticatorData's User Present flag was not set")]
    UserNotPresent,
    #[error("invalid P-256 public key")]
    InvalidPublicKey,
    #[error("signature verification failed")]
    SignatureInvalid,
}

/// Verifies a WebAuthn assertion against a caller-supplied compressed SEC1
/// P-256 public key (33 bytes) and an exact expected challenge.
///
/// Checks, in order: `clientDataJSON.type == "webauthn.get"`, the challenge
/// matches exactly, the origin matches exactly, the authenticatorData's
/// `rpIdHash` matches `expected_rp_id`, the User Present flag is set, and
/// the ECDSA signature verifies over `authenticatorData || SHA-256(clientDataJSON)`.
///
/// `expected_challenge` is the caller's own exact, recomputed commitment to
/// the operation being authorized — not something this function generates
/// or stores.
pub fn verify_assertion(
    credential_public_key: &[u8; 33],
    assertion: &RawAssertion,
    expected_rp_id: &str,
    expected_origin: &str,
    expected_challenge: &[u8],
) -> Result<(), VerifyError> {
    let client_data: serde_json::Value = serde_json::from_slice(&assertion.client_data_json)
        .map_err(|e| VerifyError::MalformedClientData(e.to_string()))?;

    let client_data_type = client_data
        .get("type")
        .and_then(|v| v.as_str())
        .ok_or_else(|| VerifyError::MalformedClientData("missing type".to_string()))?;
    if client_data_type != "webauthn.get" {
        return Err(VerifyError::UnexpectedType(client_data_type.to_string()));
    }

    let challenge_b64 = client_data
        .get("challenge")
        .and_then(|v| v.as_str())
        .ok_or_else(|| VerifyError::MalformedClientData("missing challenge".to_string()))?;
    let challenge = base64::Engine::decode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        challenge_b64,
    )
    .map_err(|e| VerifyError::MalformedClientData(e.to_string()))?;
    if challenge != expected_challenge {
        return Err(VerifyError::ChallengeMismatch);
    }

    let origin = client_data
        .get("origin")
        .and_then(|v| v.as_str())
        .ok_or_else(|| VerifyError::MalformedClientData("missing origin".to_string()))?;
    if origin != expected_origin {
        return Err(VerifyError::OriginMismatch);
    }

    // authenticatorData layout (WebAuthn L2 §6.1): rpIdHash(32) || flags(1) || counter(4) || ...
    if assertion.authenticator_data.len() < 37 {
        return Err(VerifyError::MalformedAuthenticatorData);
    }
    let rp_id_hash = &assertion.authenticator_data[0..32];
    let expected_rp_id_hash = Sha256::digest(expected_rp_id.as_bytes());
    if rp_id_hash != expected_rp_id_hash.as_slice() {
        return Err(VerifyError::RpIdMismatch);
    }
    const USER_PRESENT: u8 = 0b0000_0001;
    if assertion.authenticator_data[32] & USER_PRESENT == 0 {
        return Err(VerifyError::UserNotPresent);
    }

    let client_data_hash = Sha256::digest(&assertion.client_data_json);
    let mut verification_data = assertion.authenticator_data.clone();
    verification_data.extend_from_slice(&client_data_hash);

    let cose_key = decompress_p256_cose_key(credential_public_key)?;
    let verified = cose_key
        .verify_signature(&assertion.signature, &verification_data)
        .map_err(|_| VerifyError::InvalidPublicKey)?;
    if !verified {
        return Err(VerifyError::SignatureInvalid);
    }

    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum WebAuthnAuthError {
    #[error("WebAuthn-authorized requests are not configured on this node")]
    NotConfigured,
    #[error("WebAuthn evidence has expired")]
    Expired,
    #[error("WebAuthn evidence nonce must be 16 bytes")]
    InvalidNonce,
    #[error("invalid issuer_did: {0}")]
    InvalidIssuerDid(String),
    #[error("WebAuthn verification failed: {0}")]
    Verification(#[from] VerifyError),
}

/// Independently verifies `evidence` against `operation` and this node's
/// configured relying-party ID/origin, and returns a `BearerToken` carrying
/// `claims` on success — the same shape a verified JWT already produces, so
/// every downstream check in a protocol's request pipeline (actor
/// resolution, ACP, single-use enforcement via `jwt_id`, relay attribution)
/// runs unchanged regardless of which authentication method was used.
///
/// Generic over the operation (`SignOperation`, `PreOperation`, ...) and
/// claims (`SignClaims`, `PreClaims`, ...) types, so each protocol only
/// supplies its own values here — never a second copy of this control
/// flow.
///
/// `rp_id`/`origin` being absent (node not configured for passkey
/// authentication) is a hard rejection, not a silent fallback.
pub fn verify_and_build_token<Op, Claims>(
    evidence: &WebAuthnEvidence,
    operation: Op,
    claims: Claims,
    rp_id: Option<&str>,
    origin: Option<&str>,
    current_time: u64,
) -> Result<authn::BearerToken<Claims>, WebAuthnAuthError>
where
    Op: CanonicalOperation,
{
    let (rp_id, origin) = match (rp_id, origin) {
        (Some(rp_id), Some(origin)) => (rp_id, origin),
        _ => return Err(WebAuthnAuthError::NotConfigured),
    };
    if current_time > evidence.expiry {
        return Err(WebAuthnAuthError::Expired);
    }

    let credential_public_key = authn::p256_public_key_from_did(&evidence.issuer_did)
        .map_err(|e| WebAuthnAuthError::InvalidIssuerDid(e.to_string()))?;
    let raw_assertion = RawAssertion {
        authenticator_data: evidence.authenticator_data.clone(),
        client_data_json: evidence.client_data_json.clone(),
        signature: evidence.signature.clone(),
    };
    verify_assertion(
        &credential_public_key,
        &raw_assertion,
        rp_id,
        origin,
        &operation.canonical_bytes(),
    )?;

    Ok(authn::BearerToken {
        issuer_id: evidence.issuer_did.clone(),
        subject_id: None,
        issued_time: evidence.issued_at,
        expiration_time: evidence.expiry,
        not_before: None,
        jwt_id: hex::encode(&evidence.nonce),
        claims,
    })
}

/// Extends an endpoint's normal (JWT) authentication shape
/// (`authn::endpoints::EndpointAuth`) with what WebAuthn needs on top:
/// the canonically-encodable operation a WebAuthn assertion's challenge
/// must commit to, and how to synthesize that endpoint's claims directly
/// from `Fields` (never checked against anything, since the WebAuthn
/// signature already covers `operation`'s encoding of those same fields —
/// unlike the JWT path, there is no pre-existing token to extract claims
/// from).
///
/// This lives here, not on `EndpointAuth` itself, because it's specific
/// to this one mechanism: a future mechanism (e.g. a DKIM-verified email
/// flow) binds its own evidence to a request in its own way and would
/// define its own extension trait in its own crate, never this one.
/// `endpoints/` holds one file per endpoint with that endpoint's
/// `impl WebAuthnEndpoint`, mirroring `authn::endpoints`' own layout.
pub trait WebAuthnEndpoint: authn::endpoints::EndpointAuth {
    /// The canonically-encodable operation a WebAuthn assertion's
    /// challenge must commit to for this endpoint.
    type Operation: CanonicalOperation;

    /// Builds the claims a WebAuthn-authorized request's synthetic token
    /// carries, from `fields` alone.
    fn claims(fields: &Self::Fields) -> Self::Claims;

    /// Builds the operation a WebAuthn assertion's challenge must commit
    /// to for this exact request. `issued_at` is only meaningful to an
    /// endpoint whose own claims get cryptographically bound into a
    /// further signature the client produces before the server ever sees
    /// the request (PRE's reader-key proof-of-possession is the one
    /// example today) — an endpoint without that concern just ignores it.
    fn operation(
        fields: &Self::Fields,
        issued_at: u64,
        expiry: u64,
        nonce: [u8; 16],
    ) -> Self::Operation;
}

pub mod endpoints;

/// Verifies WebAuthn evidence for one endpoint `E` and returns a
/// `BearerToken` carrying its synthesized claims — the complete WebAuthn
/// authentication path for one endpoint, self-contained in this crate.
/// This function has no notion of a JWT fallback: a caller that wants to
/// support both decides, for itself, which of this or `authn`'s own
/// `resolve_jwt_auth` applies to a given request (see
/// `authn::endpoints`'s own doc comment for where that decision belongs).
pub fn verify_endpoint_auth<E: WebAuthnEndpoint>(
    fields: &E::Fields,
    evidence: &WebAuthnEvidence,
    rp_id: Option<&str>,
    origin: Option<&str>,
    current_time: u64,
) -> Result<authn::BearerToken<E::Claims>, WebAuthnAuthError> {
    let nonce: [u8; 16] = evidence
        .nonce
        .as_slice()
        .try_into()
        .map_err(|_| WebAuthnAuthError::InvalidNonce)?;
    let operation = E::operation(fields, evidence.issued_at, evidence.expiry, nonce);
    let claims = E::claims(fields);
    verify_and_build_token(evidence, operation, claims, rp_id, origin, current_time)
}

/// Builds a WebAuthn assertion directly from a raw P-256 signing key —
/// for tests and command-line tooling that can't drive a real browser and
/// authenticator. **Never use this in place of an actual WebAuthn ceremony
/// in a real client**; it exists only so test/CLI code can exercise the
/// exact wire format [`verify_assertion`] checks, with a key it already
/// controls directly rather than one behind a hardware/platform
/// authenticator.
pub fn build_test_assertion(
    signing_key: &p256::ecdsa::SigningKey,
    rp_id: &str,
    origin: &str,
    challenge: &[u8],
) -> RawAssertion {
    use p256::ecdsa::signature::Signer;

    let mut authenticator_data = Sha256::digest(rp_id.as_bytes()).to_vec();
    authenticator_data.push(0b0000_0001); // flags: User Present
    authenticator_data.extend_from_slice(&[0u8; 4]); // counter

    let client_data_json = serde_json::json!({
        "type": "webauthn.get",
        "challenge": base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            challenge,
        ),
        "origin": origin,
    })
    .to_string()
    .into_bytes();

    let client_data_hash = Sha256::digest(&client_data_json);
    let mut verification_data = authenticator_data.clone();
    verification_data.extend_from_slice(&client_data_hash);

    let signature: p256::ecdsa::Signature = signing_key.sign(&verification_data);

    RawAssertion {
        authenticator_data,
        client_data_json,
        signature: signature.to_der().as_bytes().to_vec(),
    }
}

/// Decompresses a SEC1-compressed P-256 point into the uncompressed x/y
/// form `webauthn-rs-core`'s `COSEKey` needs — it stores EC2 keys as
/// separate coordinates, not a compressed point.
fn decompress_p256_cose_key(compressed: &[u8; 33]) -> Result<COSEKey, VerifyError> {
    let verifying_key = p256::ecdsa::VerifyingKey::from_sec1_bytes(compressed)
        .map_err(|_| VerifyError::InvalidPublicKey)?;
    let uncompressed = verifying_key.to_encoded_point(false);
    let bytes = uncompressed.as_bytes();
    if bytes.len() != 65 || bytes[0] != 0x04 {
        return Err(VerifyError::InvalidPublicKey);
    }
    Ok(COSEKey {
        type_: COSEAlgorithm::ES256,
        key: COSEKeyType::EC_EC2(COSEEC2Key {
            curve: ECDSACurve::SECP256R1,
            x: bytes[1..33].to_vec().into(),
            y: bytes[33..65].to_vec().into(),
        }),
    })
}

#[cfg(test)]
mod tests {
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
        );
        assert!(matches!(result, Err(WebAuthnAuthError::Expired)));
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
        );
        assert!(matches!(result, Err(WebAuthnAuthError::InvalidNonce)));
    }
}
