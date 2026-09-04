//! JWT Builder utilities for creating and extracting JWT tokens.
//!
//! This module provides utilities for:
//! - Creating signed JWT tokens with DID-based key pairs
//! - Extracting bearer tokens from gRPC request metadata

use crate::error::{AuthNError, Result};
use crate::{BearerToken, DkgClaims, PreClaims, SignClaims, StoreSecretClaims};
use did_key::{generate, Ed25519KeyPair as DidEd25519KeyPair, Fingerprint, KeyMaterial};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use pkcs8::{
    der::{asn1::OctetStringRef, Encode},
    AlgorithmIdentifierRef, ObjectIdentifier, PrivateKeyInfo,
};
use serde::{de::DeserializeOwned, Serialize};
use sha2::{Digest, Sha256};
use std::fmt::Debug;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tonic::Request;

const TOKEN_TTL: Duration = Duration::from_secs(60 * 60);
const ED25519_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");

/// A DID-based key pair for signing JWTs.
///
/// This struct wraps a DID key pair and provides methods for creating
/// signed JWT tokens with various claim types.
pub struct JwtSigner {
    key_pair: did_key::PatchedKeyPair,
    /// The DID URI for this key pair (e.g., did:key:z6Mk...)
    pub did_uri: String,
}

impl JwtSigner {
    /// Generate a new key pair for JWT signing.
    ///
    /// Creates a new Ed25519 key pair and derives the DID URI from it.
    pub fn new() -> Self {
        let key_pair = generate::<DidEd25519KeyPair>(None);
        let did_uri = format!("did:key:{}", key_pair.fingerprint());
        Self { key_pair, did_uri }
    }

    /// Create a new JwtSigner from an existing key pair.
    pub fn from_key_pair(key_pair: did_key::PatchedKeyPair) -> Self {
        let did_uri = format!("did:key:{}", key_pair.fingerprint());
        Self { key_pair, did_uri }
    }

    fn ed25519_seed_to_pkcs8_der(seed: &[u8]) -> Result<zeroize::Zeroizing<Vec<u8>>> {
        if seed.len() != 32 {
            return Err(AuthNError::JwtError(format!(
                "Invalid Ed25519 private key length: {}",
                seed.len()
            )));
        }

        // RFC 8410 stores Ed25519 seeds inside an algorithm-specific OCTET STRING,
        // which is then wrapped by PKCS#8 PrivateKeyInfo.
        let private_key = zeroize::Zeroizing::new(
            OctetStringRef::new(seed)
                .and_then(|seed| seed.to_der())
                .map_err(|e| {
                    AuthNError::JwtError(format!("Failed to encode Ed25519 seed: {}", e))
                })?,
        );
        let private_key_info = PrivateKeyInfo::new(
            AlgorithmIdentifierRef {
                oid: ED25519_OID,
                parameters: None,
            },
            private_key.as_slice(),
        );
        private_key_info
            .to_der()
            .map(zeroize::Zeroizing::new)
            .map_err(|e| {
                AuthNError::JwtError(format!("Failed to encode Ed25519 PKCS#8 key: {}", e))
            })
    }

    /// Get the signing key for jsonwebtoken/ring.
    fn signing_key_for(key_pair: &did_key::PatchedKeyPair) -> Result<EncodingKey> {
        let seed = zeroize::Zeroizing::new(key_pair.private_key_bytes());
        let pkcs8 = Self::ed25519_seed_to_pkcs8_der(&seed)?;
        Ok(EncodingKey::from_ed_der(&pkcs8))
    }

    fn get_signing_key(&self) -> Result<EncodingKey> {
        Self::signing_key_for(&self.key_pair)
    }

    fn current_unix_time() -> Result<u64> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .map_err(|e| AuthNError::JwtError(format!("System clock before Unix epoch: {}", e)))
    }

    /// A random 128-bit token id, hex-encoded (32 chars). Every issued token gets
    /// a fresh one so a verifier can enforce single use.
    fn generate_jwt_id() -> String {
        format!("{:032x}", rand::random::<u128>())
    }

    pub(crate) fn sign_bearer_token<T>(&self, token: &BearerToken<T>) -> Result<String>
    where
        T: Serialize,
    {
        Self::sign_bearer_token_with_key(&self.get_signing_key()?, token)
    }

    #[cfg(test)]
    pub(crate) fn sign_bearer_token_with_key_pair<T>(
        key_pair: &did_key::PatchedKeyPair,
        token: &BearerToken<T>,
    ) -> Result<String>
    where
        T: Serialize,
    {
        Self::sign_bearer_token_with_key(&Self::signing_key_for(key_pair)?, token)
    }

    fn sign_bearer_token_with_key<T>(key: &EncodingKey, token: &BearerToken<T>) -> Result<String>
    where
        T: Serialize,
    {
        let mut header = Header::new(Algorithm::EdDSA);
        header.typ = Some("JWT".to_string());
        encode(&header, token, key)
            .map_err(|e| AuthNError::JwtError(format!("Failed to sign JWT: {}", e)))
    }

    /// Create a signed JWT with custom claims.
    ///
    /// # Arguments
    /// * `claims` - The custom claims to include in the JWT
    /// * `duration` - How long the token should be valid
    ///
    /// # Returns
    /// The signed JWT string
    pub fn sign<T>(&self, claims: T, duration: Duration) -> Result<String>
    where
        T: Serialize + DeserializeOwned,
    {
        let issued_time = Self::current_unix_time()?;
        let expiration_time = issued_time
            .checked_add(duration.as_secs())
            .ok_or_else(|| AuthNError::JwtError("JWT expiration overflow".to_string()))?;
        let token = BearerToken {
            issuer_id: self.did_uri.clone(),
            subject_id: None,
            issued_time,
            expiration_time,
            not_before: None,
            jwt_id: Self::generate_jwt_id(),
            claims,
        };
        self.sign_bearer_token(&token)
    }

    /// Create a signed JWT that delegates the request to an actor DID.
    pub fn sign_for_actor<T>(
        &self,
        actor_id: String,
        claims: T,
        duration: Duration,
    ) -> Result<String>
    where
        T: Serialize + DeserializeOwned,
    {
        let issued_time = Self::current_unix_time()?;
        let expiration_time = issued_time
            .checked_add(duration.as_secs())
            .ok_or_else(|| AuthNError::JwtError("JWT expiration overflow".to_string()))?;
        self.sign_bearer_token(&BearerToken {
            issuer_id: self.did_uri.clone(),
            subject_id: Some(actor_id),
            issued_time,
            expiration_time,
            not_before: None,
            jwt_id: Self::generate_jwt_id(),
            claims,
        })
    }

    /// Create a JWT with DKG claims.
    ///
    /// # Arguments
    /// * `ring_id` - Pre-created blank ring entry targeted by this DKG
    /// # Returns
    /// The signed JWT string valid for 1 hour
    pub fn create_dkg_jwt(&self, ring_id: &str) -> Result<String> {
        let claims = DkgClaims {
            ring_id: ring_id.to_string(),
        };
        self.sign(claims, TOKEN_TTL)
    }

    /// Create a JWT with PRE claims.
    ///
    /// # Arguments
    /// * `rdr_pk` - Reader's public key
    /// * `object_id` - secret id
    /// * `derivation` - Optional derivation path
    /// * `salt` - Optional salt for proof
    ///
    /// # Returns
    /// The signed JWT string valid for 1 hour
    pub fn create_pre_jwt(
        &self,
        rdr_pk: Vec<u8>,
        object_id: &str,
        derivation: Option<Vec<u8>>,
        salt: Option<String>,
    ) -> Result<String> {
        let claims = PreClaims {
            rdr_pk,
            object_id: object_id.to_string(),
            derivation,
            salt,
        };
        self.sign(claims, TOKEN_TTL)
    }

    /// Create a JWT with Sign (threshold signing) claims.
    ///
    /// # Arguments
    /// * `derivation_id` - Object ID of the key derivation entry
    /// * `message` - Bytes to sign; stored as SHA-256 digest in the claim
    ///
    /// # Returns
    /// The signed JWT string valid for 1 hour
    pub fn create_sign_jwt(&self, derivation_id: &str, message: &[u8]) -> Result<String> {
        let claims = SignClaims {
            derivation_id: derivation_id.to_string(),
            message_sha256: Sha256::digest(message).to_vec(),
        };
        self.sign(claims, TOKEN_TTL)
    }

    /// Create a JWT with StoreSecret claims.
    ///
    /// # Arguments
    /// * `encrypted_document` - The encrypted document bytes; stored as SHA-256 digest in the claim
    /// * `enc_cmt` - The encryption commitment (hex-encoded G1 point)
    /// * `ring_id` - The ring ID to use for encryption
    /// * `policy_id` - Policy ID for access control
    /// * `resource` - Resource type for the policy
    /// * `permission` - Permission required for the policy
    /// * `challenge` - c - Fiat-Shamir challenge (Schnorr PoK)
    /// * `response` - z - proof response (z = k + c*r)
    /// * `with_proof` - If a proof should be returned
    /// * `tier` - Optional tier for policy
    /// * `timestamp` - Optional timestamp for policy
    ///
    /// # Returns
    /// The signed JWT string valid for 1 hour
    pub fn create_store_secret_jwt(
        &self,
        encrypted_document: &[u8],
        enc_cmt: Vec<u8>,
        ring_id: &str,
        policy_id: &str,
        resource: &str,
        permission: &str,
        challenge: Vec<u8>,
        response: Vec<u8>,
        with_proof: bool,
        tier: Option<String>,
        timestamp: Option<u64>,
    ) -> Result<String> {
        let claims = StoreSecretClaims {
            encrypted_document_sha256: Sha256::digest(encrypted_document).to_vec(),
            enc_cmt,
            ring_id: ring_id.to_string(),
            policy_id: policy_id.to_string(),
            resource: resource.to_string(),
            permission: permission.to_string(),
            challenge,
            response,
            with_proof,
            tier,
            timestamp,
        };
        self.sign(claims, TOKEN_TTL)
    }
}

impl Default for JwtSigner {
    fn default() -> Self {
        Self::new()
    }
}

impl Debug for JwtSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JwtSigner")
            .field("did_uri", &self.did_uri)
            .finish()
    }
}

/// Extracts the bearer token from the Authorization header of a gRPC request.
///
/// # Arguments
/// * `request` - The tonic gRPC request
///
/// # Returns
/// The JWT token string (without the "Bearer " prefix)
///
/// # Errors
/// Returns an error if:
/// - The authorization header is missing
/// - The header value is not valid UTF-8
/// - The header doesn't start with "Bearer "
pub fn extract_bearer_token<T>(request: &Request<T>) -> Result<&str> {
    let auth_header = request
        .metadata()
        .get("authorization")
        .ok_or_else(|| AuthNError::Unauthorized("Missing authorization header".to_string()))?
        .to_str()
        .map_err(|_| {
            AuthNError::Unauthorized("Invalid authorization header encoding".to_string())
        })?;

    auth_header
        .strip_prefix("Bearer ")
        .ok_or_else(|| AuthNError::Unauthorized("Invalid authorization header format".to_string()))
}

/// Adds an authorization header to a tonic request.
///
/// # Arguments
/// * `request` - The tonic gRPC request to modify
/// * `token` - The JWT token to add
///
/// # Returns
/// Ok(()) on success, or an error if the token contains invalid header characters
pub fn add_auth_header<T>(request: &mut Request<T>, token: &str) -> Result<()> {
    use tonic::metadata::MetadataValue;
    let header_value = format!("Bearer {}", token);
    let metadata_value = MetadataValue::try_from(&header_value)
        .map_err(|e| AuthNError::JwtError(format!("Invalid token for header: {}", e)))?;
    request
        .metadata_mut()
        .insert("authorization", metadata_value);
    Ok(())
}

/// Creates a tonic request with an authorization header.
///
/// # Arguments
/// * `inner` - The request payload
/// * `token` - The JWT token to add
///
/// # Returns
/// A new tonic Request with the authorization header set, or an error if the token is invalid
pub fn create_authenticated_request<T>(inner: T, token: &str) -> Result<Request<T>> {
    let mut request = Request::new(inner);
    add_auth_header(&mut request, token)?;
    Ok(request)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jwt_signer_new() {
        let signer = JwtSigner::new();
        assert!(signer.did_uri.starts_with("did:key:"));
    }

    #[test]
    fn test_ed25519_seed_to_pkcs8_der() {
        let seed = [7u8; 32];
        let der = JwtSigner::ed25519_seed_to_pkcs8_der(&seed).unwrap();
        let private_key_info = PrivateKeyInfo::try_from(der.as_slice()).unwrap();
        let expected_private_key = OctetStringRef::new(&seed).unwrap().to_der().unwrap();

        assert_eq!(private_key_info.algorithm.oid, ED25519_OID);
        assert_eq!(private_key_info.algorithm.parameters, None);
        assert_eq!(
            private_key_info.private_key,
            expected_private_key.as_slice()
        );
    }

    #[test]
    fn test_create_pre_jwt() {
        let signer = JwtSigner::new();
        let token = signer.create_pre_jwt(b"rdr_pk_value".to_vec(), "object_id", None, None);
        assert!(token.is_ok());
    }

    #[test]
    fn test_create_store_secret_jwt() {
        let signer = JwtSigner::new();
        let token = signer.create_store_secret_jwt(
            b"encrypted_doc",
            b"enc_cmt_bytes".to_vec(),
            "ring_id_value",
            "policy_id",
            "resource",
            "permission",
            b"challenge".to_vec(),
            b"response".to_vec(),
            false,
            None,
            None,
        );
        assert!(token.is_ok());

        // Token should have 3 parts (header.payload.signature)
        let token_str = token.unwrap();
        assert_eq!(token_str.split('.').count(), 3);
    }
}
