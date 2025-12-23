pub mod error;
use did_key::{resolve, KeyMaterial};
use error::{AuthNError, Result};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BearerToken {
    /// DID URI of the issuer (e.g., did:key:z6Mk...)
    #[serde(rename = "iss")]
    pub issuer_id: String,
    /// Reader's public key
    pub reader_pk: String,
    /// Issued at timestamp (Unix epoch seconds)
    #[serde(rename = "iat")]
    pub issued_time: u64,
    /// Expiration timestamp (Unix epoch seconds)
    #[serde(rename = "exp")]
    pub expiration_time: u64,
}

/// Resolves and verifies a JWT token, returning the decoded BearerToken claims
pub fn resolve_jwt_did(token_str: &str, current_time: u64) -> Result<BearerToken> {
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

    let unverified = decode::<BearerToken>(token_str, &DecodingKey::from_secret(&[]), &validation)
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

    let verified = decode::<BearerToken>(token_str, &decoding_key, &validation)
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

    // Check that issued_time is before expiration_time (sanity check)
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

    /// Custom claims for JWT (excludes standard claims iss/iat/exp which jwt_simple handles)
    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct CustomClaims {
        reader_pk: String,
    }

    fn create_test_jwt(key_pair: &did_key::PatchedKeyPair, claims: &BearerToken) -> String {
        // jwt-simple expects 64 bytes: seed (32) + public key (32)
        let mut keypair_bytes = key_pair.private_key_bytes();
        keypair_bytes.extend(key_pair.public_key_bytes());

        let signing_key = Ed25519KeyPair::from_bytes(&keypair_bytes).unwrap();

        let custom = CustomClaims {
            reader_pk: claims.reader_pk.clone(),
        };

        let mut jwt_claims = Claims::with_custom_claims(custom, Duration::from_secs(0))
            .with_issuer(&claims.issuer_id);
        jwt_claims.issued_at = Some(UnixTimeStamp::from_secs(claims.issued_time));
        jwt_claims.expires_at = Some(UnixTimeStamp::from_secs(claims.expiration_time));

        signing_key.sign(jwt_claims).unwrap()
    }

    #[test]
    fn test_resolve_jwt_did_success() {
        let key_pair = generate::<DidEd25519KeyPair>(None);
        let did_uri = format!("did:key:{}", key_pair.fingerprint());

        let current_time = 1000;
        let claims = BearerToken {
            issuer_id: did_uri,
            reader_pk: "test_reader_pk".to_string(),
            issued_time: 900,
            expiration_time: 2000,
        };

        let token = create_test_jwt(&key_pair, &claims);
        let result = resolve_jwt_did(&token, current_time);

        assert!(result.is_ok(), "Expected Ok, got: {:?}", result);
        let decoded = result.unwrap();
        assert_eq!(decoded.reader_pk, "test_reader_pk");
    }

    #[test]
    fn test_resolve_jwt_did_expired() {
        let key_pair = generate::<DidEd25519KeyPair>(None);
        let did_uri = format!("did:key:{}", key_pair.fingerprint());

        let current_time = 3000; // After expiration
        let claims = BearerToken {
            issuer_id: did_uri,
            reader_pk: "test_reader_pk".to_string(),
            issued_time: 900,
            expiration_time: 2000,
        };

        let token = create_test_jwt(&key_pair, &claims);
        let result = resolve_jwt_did(&token, current_time);

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AuthNError::JwtError(_)));
    }

    #[test]
    fn test_resolve_jwt_did_future_issued_time() {
        let key_pair = generate::<DidEd25519KeyPair>(None);
        let did_uri = format!("did:key:{}", key_pair.fingerprint());

        let current_time = 500; // Before issued_time
        let claims = BearerToken {
            issuer_id: did_uri,
            reader_pk: "test_reader_pk".to_string(),
            issued_time: 900,
            expiration_time: 2000,
        };

        let token = create_test_jwt(&key_pair, &claims);
        let result = resolve_jwt_did(&token, current_time);

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AuthNError::JwtError(_)));
    }

    #[test]
    fn test_resolve_jwt_did_invalid_signature() {
        let key_pair1 = generate::<DidEd25519KeyPair>(None);
        let key_pair2 = generate::<DidEd25519KeyPair>(None);
        let did_uri = format!("did:key:{}", key_pair1.fingerprint());

        let current_time = 1000;
        let claims = BearerToken {
            issuer_id: did_uri,
            reader_pk: "test_reader_pk".to_string(),
            issued_time: 900,
            expiration_time: 2000,
        };

        // Sign with key_pair2 but claim issuer is key_pair1
        let token = create_test_jwt(&key_pair2, &claims);
        let result = resolve_jwt_did(&token, current_time);

        assert!(result.is_err());
    }
}
