//! Internal JWT assembly, signed through a [`crate::identity::JwtIdentitySigner`]
//! instead of a key this crate holds itself.
//!
//! `jsonwebtoken::encode` can't be used directly here — it demands an
//! `EncodingKey` built from raw private key bytes, which is exactly what
//! this crate must never receive. So this assembles the token by hand:
//! `base64url(header) + "." + base64url(payload)`, signed by the trait, with
//! the signature appended the same way. Reusing `authn::BearerToken`
//! directly for the payload (rather than a local shadow type) guarantees
//! the result is byte-for-byte what `authn::resolve_jwt_did` already knows
//! how to verify — see this module's own tests.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::Serialize;

use crate::error::{Result, SdkError};
use crate::identity::JwtIdentitySigner;

/// Every JWT this crate mints is valid for one hour — matching
/// `authn::JwtSigner`'s own `TOKEN_TTL`.
pub const JWT_TTL: Duration = Duration::from_secs(60 * 60);

/// Signs `claims` as a JWT issued by `signer`'s identity, valid for
/// `duration`. Returns the signed token plus the claims-independent
/// metadata (`jti`/timestamps) a caller needs to build a further,
/// cryptographically-bound transcript from the exact same values (PRE's
/// `ReaderAuthorizationContext` is the one case that needs this) without
/// re-parsing the token it just signed.
pub(crate) fn sign_jwt<T: Serialize>(
    signer: &impl JwtIdentitySigner,
    claims: T,
    duration: Duration,
) -> Result<(String, authn::TokenMetadata)> {
    let issued_time = now_unix()?;
    let expiration_time = issued_time
        .checked_add(duration.as_secs())
        .ok_or_else(|| SdkError::InvalidInput("JWT expiration overflow".to_string()))?;
    let jwt_id = generate_jwt_id();

    let token = authn::BearerToken {
        issuer_id: signer.did().to_string(),
        subject_id: None,
        issued_time,
        expiration_time,
        not_before: None,
        jwt_id: jwt_id.clone(),
        claims,
    };
    let signed = sign_bearer_token(signer, &token)?;
    let metadata = authn::TokenMetadata {
        jwt_id,
        issued_time,
        expiration_time,
        not_before: None,
    };
    Ok((signed, metadata))
}

fn sign_bearer_token<T: Serialize>(
    signer: &impl JwtIdentitySigner,
    token: &authn::BearerToken<T>,
) -> Result<String> {
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::EdDSA);
    header.typ = Some("JWT".to_string());

    let header_json =
        serde_json::to_vec(&header).map_err(|e| SdkError::Encoding(format!("JWT header: {e}")))?;
    let payload_json =
        serde_json::to_vec(token).map_err(|e| SdkError::Encoding(format!("JWT payload: {e}")))?;

    let signing_input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header_json),
        URL_SAFE_NO_PAD.encode(payload_json)
    );
    let signature = signer.sign(signing_input.as_bytes());
    Ok(format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(signature)
    ))
}

/// A random 128-bit token id, hex-encoded (32 chars) — mirrors
/// `authn::JwtSigner`'s own `generate_jwt_id`, so every issued token gets a
/// fresh one a verifier can enforce single use against.
fn generate_jwt_id() -> String {
    format!("{:032x}", rand::random::<u128>())
}

/// The current Unix time in seconds — shared by every module that needs a
/// fresh `issued_at` (JWT assembly here, and each protocol's own evidence
/// challenge).
pub(crate) fn now_unix() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| SdkError::InvalidInput(format!("system clock before Unix epoch: {e}")))
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    use super::*;
    use crate::identity::InMemoryEd25519Signer;

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    struct TestClaims {
        value: String,
    }

    #[test]
    fn sign_jwt_produces_a_token_authn_can_independently_verify() {
        let signer = InMemoryEd25519Signer::from_seed_str("alice");
        let (token, metadata) = sign_jwt(
            &signer,
            TestClaims {
                value: "hi".to_string(),
            },
            Duration::from_secs(300),
        )
        .expect("sign_jwt should succeed");

        // The real server-side verifier, from `authn` — this is the thing
        // that actually matters: a token this module assembles has to be
        // independently verifiable by orbis-node, not just self-consistent.
        let verified: authn::BearerToken<TestClaims> =
            authn::resolve_jwt_did(&token, metadata.issued_time, 300, token.len() + 1, 0)
                .expect("a JWT signed through JwtIdentitySigner must independently verify");

        assert_eq!(verified.issuer_id, signer.did());
        assert_eq!(
            verified.claims,
            TestClaims {
                value: "hi".to_string()
            }
        );
        assert_eq!(verified.jwt_id, metadata.jwt_id);
        assert_eq!(verified.expiration_time, metadata.expiration_time);
    }

    #[test]
    fn sign_jwt_rejects_a_tampered_payload() {
        let signer = InMemoryEd25519Signer::from_seed_str("alice");
        let (token, metadata) = sign_jwt(
            &signer,
            TestClaims {
                value: "hi".to_string(),
            },
            Duration::from_secs(300),
        )
        .expect("sign_jwt should succeed");

        let mut parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3);
        parts[1] = "dGFtcGVyZWQ"; // base64url("tampered"), wrong payload entirely
        let tampered = parts.join(".");

        let result: std::result::Result<authn::BearerToken<TestClaims>, _> =
            authn::resolve_jwt_did(&tampered, metadata.issued_time, 300, tampered.len() + 1, 0);
        assert!(result.is_err(), "a tampered JWT must not verify");
    }
}
