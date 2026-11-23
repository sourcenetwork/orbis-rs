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

use sha2::{Digest, Sha256};
use webauthn_rs_core::proto::{COSEAlgorithm, COSEEC2Key, COSEKey, COSEKeyType, ECDSACurve};

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
}
