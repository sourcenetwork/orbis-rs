pub mod error;
use did_key::{resolve, KeyMaterial};
use error::{AuthNError, Result};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::fmt::Debug;

/// Base JWT claims that are always present and validated.
/// Custom claims are flattened into the same JSON object.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BearerToken<T = ()> {
    /// DID URI of the issuer (e.g., did:key:z6Mk...)
    #[serde(rename = "iss")]
    pub issuer_id: String,
    /// Issued at timestamp (Unix epoch seconds)
    #[serde(rename = "iat")]
    pub issued_time: u64,
    /// Expiration timestamp (Unix epoch seconds)
    #[serde(rename = "exp")]
    pub expiration_time: u64,
    /// Custom claims specific to the endpoint
    #[serde(flatten)]
    pub claims: T,
}

/// Claims for PRE (Proxy Re-Encryption) endpoints
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct PreClaims {
    /// Reader's public key - validated against request
    pub rdr_pk: String,
    pub ring_pk: String,
    pub peer_ids: String,
}

/// Claims for DKG endpoints
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct DkgClaims {
    pub threshold: u32,
    pub peer_ids: String,
}

/// Resolves and verifies a JWT token, returning the decoded BearerToken with custom claims.
///
/// # Type Parameters
/// * `T` - The custom claims type. Use `()` for no custom claims, `PreClaims` for PRE endpoints, etc.
///
/// # Examples
/// ```ignore
/// // For PRE endpoint with rdr_pk claim
/// let token: BearerToken<PreClaims> = resolve_jwt_did(token_str, current_time)?;
/// assert_eq!(token.claims.rdr_pk, request.rdr_pk);
///
/// // For DKG endpoint with no custom claims
/// let token: BearerToken<DkgClaims> = resolve_jwt_did(token_str, current_time)?;
///
/// // Or simply use unit type for basic auth
/// let token: BearerToken<()> = resolve_jwt_did(token_str, current_time)?;
/// ```
pub fn resolve_jwt_did<T>(token_str: &str, current_time: u64) -> Result<BearerToken<T>>
where
    T: DeserializeOwned + Debug,
{
    // First, decode the header to check algorithm
    let header = decode_header(token_str)
        .map_err(|e| AuthNError::JwtError(format!("Failed to decode JWT header: {}", e)))?;

    // Ensure EdDSA algorithm is used (Ed25519)
    if header.alg != Algorithm::EdDSA {
        return Err(AuthNError::JwtError(format!(
            "Unsupported algorithm: {:?}, expected EdDSA",
            header.alg
        )));
    }

    // Decode without verification first to get the issuer
    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.insecure_disable_signature_validation();
    validation.validate_exp = false;
    validation.required_spec_claims.clear();

    let unverified =
        decode::<BearerToken<T>>(token_str, &DecodingKey::from_secret(&[]), &validation)
            .map_err(|e| AuthNError::JwtError(format!("Failed to decode JWT claims: {}", e)))?;

    let claims = unverified.claims;

    // Resolve the DID to get the public key
    let key = resolve(&claims.issuer_id)
        .map_err(|_| AuthNError::DidError("Error resolving did_uri".to_string()))?;

    // Extract the public key bytes from the resolved DID key
    let public_key_bytes = key.public_key_bytes();

    // Now verify with the actual public key
    // Ed25519 public keys are 32 bytes raw
    let decoding_key = DecodingKey::from_ed_der(&public_key_bytes);
    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.validate_exp = false; // We'll check expiration manually
    validation.required_spec_claims.clear();

    let verified = decode::<BearerToken<T>>(token_str, &decoding_key, &validation)
        .map_err(|e| AuthNError::JwtError(format!("JWT signature verification failed: {}", e)))?;

    let bearer_token = verified.claims;

    // Check expiration
    if current_time >= bearer_token.expiration_time {
        return Err(AuthNError::JwtError("Token has expired".to_string()));
    }

    // Check issued time is not in the future
    if bearer_token.issued_time > current_time {
        return Err(AuthNError::JwtError(
            "Token issued in the future".to_string(),
        ));
    }

    // Check that issued_time is before expiration_time
    if bearer_token.issued_time > bearer_token.expiration_time {
        return Err(AuthNError::JwtError(
            "Invalid token: issued after expiration".to_string(),
        ));
    }

    Ok(bearer_token)
}

#[cfg(test)]
mod test {
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
            peer_ids: "".to_string(),
            ring_pk: "".to_string(),
        };

        let mut jwt_claims = Claims::with_custom_claims(custom, Duration::from_secs(0))
            .with_issuer(&token.issuer_id);
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
                peer_ids: "".to_string(),
                ring_pk: "".to_string(),
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
                peer_ids: "".to_string(),
                ring_pk: "".to_string(),
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
                peer_ids: "".to_string(),
                ring_pk: "".to_string(),
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
                peer_ids: "".to_string(),
                ring_pk: "".to_string(),
            },
        };

        // Sign with key_pair2 but claim issuer is key_pair1
        let jwt = create_test_jwt_with_pre_claims(&key_pair2, &token);
        let result: Result<BearerToken<PreClaims>> = resolve_jwt_did(&jwt, current_time);

        assert!(result.is_err());
    }
}
