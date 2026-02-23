pub mod error;
pub mod jwt_builder;

use did_key::{resolve, KeyMaterial};
use error::{AuthNError, Result};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
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
    /// Reader's public key
    pub rdr_pk: String,
    /// Serect object Id to re-encrypt
    pub object_id: String,
    /// Serect object namespace
    pub namespace: String,
    /// Optional derivation path
    pub derivation: Option<Vec<u8>>,
    /// Optional salt for proof
    pub salt: Option<String>,
}

/// Claims for DKG endpoints
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct DkgClaims {
    /// Threshold to be set
    pub threshold: u32,
    /// Peer Id of nodes in ring
    pub peer_ids: String,
}

/// Claims for StoreSecret endpoints
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct StoreSecretClaims {
    /// The encrypted document (JSON-serialized Secret struct)
    pub encrypted_document: String,
    /// The encryption commitment (hex-encoded G1 point)
    pub enc_cmt: String,
    /// Ring ID to use for encryption
    pub ring_id: String,
    /// Namespace for storing the document
    pub namespace: String,
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
    /// Optional derived public key
    pub derived_pk: Option<Vec<u8>>,
    /// Add a proof to the store secret call
    pub with_proof: bool,
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
