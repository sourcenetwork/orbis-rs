pub mod error;
pub mod jwt_builder;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use did_key::{resolve, KeyMaterial};
use error::{AuthNError, Result};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt::Debug;

// Re-export commonly used items from jwt_builder
pub use jwt_builder::{
    add_auth_header, create_authenticated_request, extract_bearer_token, JwtSigner,
};

#[cfg(test)]
mod tests;

/// Base JWT claims that are always present and validated.
/// Custom claims are flattened into the same JSON object.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BearerToken<T = ()> {
    /// DID URI of the issuer (e.g., did:key:z6Mk...)
    #[serde(rename = "iss")]
    pub issuer_id: String,
    /// Actor delegated by a configured trusted relay.
    #[serde(rename = "sub", skip_serializing_if = "Option::is_none")]
    pub subject_id: Option<String>,
    /// Issued at timestamp (Unix epoch seconds)
    #[serde(rename = "iat")]
    pub issued_time: u64,
    /// Expiration timestamp (Unix epoch seconds)
    #[serde(rename = "exp")]
    pub expiration_time: u64,
    /// Not-before timestamp (Unix epoch seconds); token is invalid before this time
    #[serde(rename = "nbf", skip_serializing_if = "Option::is_none")]
    pub not_before: Option<u64>,
    /// Custom claims specific to the endpoint
    #[serde(flatten)]
    pub claims: T,
}

/// Returns the actor represented by a verified token.
pub fn resolve_actor_id<'a, T>(
    token: &'a BearerToken<T>,
    trusted_relay_issuers: &HashSet<String>,
) -> Result<&'a str> {
    let Some(subject_id) = token.subject_id.as_deref() else {
        return Ok(&token.issuer_id);
    };
    if !trusted_relay_issuers.contains(&token.issuer_id) {
        return Err(AuthNError::Unauthorized(
            "token issuer is not allowed to delegate an actor".to_string(),
        ));
    }
    let mut parts = subject_id.splitn(3, ':');
    let valid_did = parts.next() == Some("did")
        && parts.next().is_some_and(|method| {
            !method.is_empty()
                && method
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        })
        && parts
            .next()
            .is_some_and(|identifier| !identifier.is_empty());
    if subject_id.len() > 255
        || !valid_did
        || subject_id
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
    {
        return Err(AuthNError::Unauthorized(
            "delegated actor must be a valid DID".to_string(),
        ));
    }
    Ok(subject_id)
}

/// Validates a relay issuer DID accepted by the JWT verifier.
pub fn validate_relay_issuer(issuer_id: &str) -> Result<()> {
    let key = resolve(issuer_id)
        .map_err(|_| AuthNError::DidError("unable to resolve relay issuer DID".to_string()))?;
    if key.public_key_bytes().len() != 32 {
        return Err(AuthNError::DidError(
            "relay issuer must contain a 32-byte Ed25519 public key".to_string(),
        ));
    }
    Ok(())
}

/// Claims for PRE (Proxy Re-Encryption) endpoints
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct PreClaims {
    /// Reader's public key (compressed G1 point bytes)
    pub rdr_pk: Vec<u8>,
    /// Secret object Id to re-encrypt
    pub object_id: String,
    /// Optional derivation path
    pub derivation: Option<Vec<u8>>,
    /// Optional salt for proof
    pub salt: Option<String>,
}

/// Claims for Sign (threshold signing) endpoints
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct SignClaims {
    /// Object ID of the key derivation entry on the bulletin
    pub derivation_id: String,
    /// SHA-256 digest of the message to sign
    pub message_sha256: Vec<u8>,
}

/// Claims for DKG endpoints
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct DkgClaims {
    /// Pre-created blank ring entry targeted by this DKG.
    pub ring_id: String,
}

/// Claims for StoreSecret endpoints
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct StoreSecretClaims {
    /// SHA-256 digest of the encrypted document
    pub encrypted_document_sha256: Vec<u8>,
    /// The encryption commitment (compressed G1 point bytes)
    pub enc_cmt: Vec<u8>,
    /// Ring ID to use for encryption
    pub ring_id: String,
    /// Policy ID for access control
    pub policy_id: String,
    /// Resource type for the policy
    pub resource: String,
    /// Permission required for the policy
    pub permission: String,
    /// rsG - the shared point used for key derivation
    pub shared_point: Vec<u8>,
    /// Fiat-Shamir challenge
    pub challenge: Vec<u8>,
    /// proof response (s = k + c*r)
    pub response: Vec<u8>,
    /// Add a proof to the store secret call
    pub with_proof: bool,
    /// tier required for policy
    pub tier: Option<String>,
    /// timestamp required for policy
    pub timestamp: Option<u64>,
}

/// Resolves and verifies a JWT token, returning the decoded BearerToken with custom claims.
///
/// # Type Parameters
/// * `T` - The custom claims type. Use `()` for no custom claims, `PreClaims` for PRE endpoints, etc.
///
/// `clock_skew_leeway_secs` is applied to wall-clock comparisons for `exp`, `iat`,
/// and `nbf`, but it does not expand the token's maximum allowed lifetime.
///
/// # Examples
/// ```ignore
/// // For PRE endpoint with rdr_pk claim
/// let token: BearerToken<PreClaims> =
///     resolve_jwt_did(token_str, current_time, max_lifetime, max_jwt_bytes, clock_skew)?;
/// assert_eq!(token.claims.rdr_pk, request.rdr_pk);
///
/// // For DKG endpoint with no custom claims
/// let token: BearerToken<DkgClaims> =
///     resolve_jwt_did(token_str, current_time, max_lifetime, max_jwt_bytes, clock_skew)?;
///
/// // Or simply use unit type for basic auth
/// let token: BearerToken<()> =
///     resolve_jwt_did(token_str, current_time, max_lifetime, max_jwt_bytes, clock_skew)?;
/// ```
pub fn resolve_jwt_did<T>(
    token_str: &str,
    current_time: u64,
    max_token_lifetime_secs: u64,
    max_jwt_bytes: usize,
    clock_skew_leeway_secs: u64,
) -> Result<BearerToken<T>>
where
    T: DeserializeOwned + Debug,
{
    if token_str.len() > max_jwt_bytes {
        return Err(AuthNError::JwtError(format!(
            "Token too large: {} bytes exceeds maximum {}",
            token_str.len(),
            max_jwt_bytes
        )));
    }

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

    if public_key_bytes.len() != 32 {
        return Err(AuthNError::DidError(format!(
            "Expected 32-byte Ed25519 public key, got {} bytes",
            public_key_bytes.len()
        )));
    }

    // from_ed_components accepts the base64url-encoded raw key x-component (JWK form).
    let decoding_key = DecodingKey::from_ed_components(&URL_SAFE_NO_PAD.encode(&public_key_bytes))
        .map_err(|e| AuthNError::JwtError(format!("Failed to build decoding key: {}", e)))?;
    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.validate_exp = false; // We'll check expiration manually
    validation.required_spec_claims.clear();

    let verified = decode::<BearerToken<T>>(token_str, &decoding_key, &validation)
        .map_err(|e| AuthNError::JwtError(format!("JWT signature verification failed: {}", e)))?;

    let bearer_token = verified.claims;

    // Check expiration
    if current_time.saturating_sub(clock_skew_leeway_secs) >= bearer_token.expiration_time {
        return Err(AuthNError::JwtError("Token has expired".to_string()));
    }

    // Check issued time is not in the future
    if bearer_token.issued_time > current_time.saturating_add(clock_skew_leeway_secs) {
        return Err(AuthNError::JwtError(
            "Token issued in the future".to_string(),
        ));
    }

    // Check not-before claim (nbf): token must not be used before this time
    if let Some(nbf) = bearer_token.not_before {
        if current_time.saturating_add(clock_skew_leeway_secs) < nbf {
            return Err(AuthNError::JwtError(
                "Token not yet valid (nbf)".to_string(),
            ));
        }
    }

    // Check that issued_time is before expiration_time
    if bearer_token.issued_time > bearer_token.expiration_time {
        return Err(AuthNError::JwtError(
            "Invalid token: issued after expiration".to_string(),
        ));
    }

    // Check that token lifetime does not exceed the maximum allowed
    if bearer_token.expiration_time - bearer_token.issued_time > max_token_lifetime_secs {
        return Err(AuthNError::JwtError(
            "Token lifetime exceeds maximum".to_string(),
        ));
    }

    Ok(bearer_token)
}
