//! JWT Builder utilities for creating and extracting JWT tokens.
//!
//! This module provides utilities for:
//! - Creating signed JWT tokens with DID-based key pairs
//! - Extracting bearer tokens from gRPC request metadata

use crate::error::{AuthNError, Result};
use crate::{DkgClaims, PreClaims, SignClaims, StoreSecretClaims};
use did_key::{generate, Ed25519KeyPair as DidEd25519KeyPair, Fingerprint, KeyMaterial};
use jwt_simple::prelude::*;
use serde::{de::DeserializeOwned, Serialize};
use std::fmt::Debug;
use tonic::Request;

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

    /// Get the signing key for jwt-simple.
    fn get_signing_key(&self) -> Result<Ed25519KeyPair> {
        let mut keypair_bytes = self.key_pair.private_key_bytes();
        keypair_bytes.extend(self.key_pair.public_key_bytes());
        Ed25519KeyPair::from_bytes(&keypair_bytes)
            .map_err(|e| AuthNError::JwtError(format!("Failed to create signing key: {}", e)))
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
        let signing_key = self.get_signing_key()?;
        let jwt_claims = Claims::with_custom_claims(claims, duration).with_issuer(&self.did_uri);
        signing_key
            .sign(jwt_claims)
            .map_err(|e| AuthNError::JwtError(format!("Failed to sign JWT: {}", e)))
    }

    /// Create a JWT with DKG claims.
    ///
    /// # Arguments
    /// * `threshold` - The threshold value for DKG
    /// * `peer_ids` - List of peer IDs
    ///
    /// # Returns
    /// The signed JWT string valid for 1 hour
    pub fn create_dkg_jwt(&self, threshold: u32, peer_ids: &[String]) -> Result<String> {
        let claims = DkgClaims {
            threshold,
            peer_ids: peer_ids.to_vec(),
        };
        self.sign(claims, Duration::from_hours(1))
    }

    /// Create a JWT with PRE claims.
    ///
    /// # Arguments
    /// * `rdr_pk` - Reader's public key
    /// * `object_id` - secret id
    /// * `peer_ids` - List of peer IDs (will be joined with commas)
    /// * `derivation` - Optional derivation path
    /// * `salt` - Optional salt for proof
    ///
    /// # Returns
    /// The signed JWT string valid for 1 hour
    pub fn create_pre_jwt(
        &self,
        rdr_pk: Vec<u8>,
        namespace: &str,
        object_id: &str,
        derivation: Option<Vec<u8>>,
        salt: Option<String>,
    ) -> Result<String> {
        let claims = PreClaims {
            rdr_pk,
            object_id: object_id.to_string(),
            namespace: namespace.to_string(),
            derivation,
            salt,
        };
        self.sign(claims, Duration::from_hours(1))
    }

    /// Create a JWT with Sign (threshold signing) claims.
    ///
    /// # Arguments
    /// * `namespace` - Namespace of the key derivation entry on the bulletin
    /// * `derivation_id` - Object ID of the key derivation entry
    /// * `message` - Bytes to sign
    ///
    /// # Returns
    /// The signed JWT string valid for 1 hour
    pub fn create_sign_jwt(
        &self,
        namespace: &str,
        derivation_id: &str,
        message: &Vec<u8>,
    ) -> Result<String> {
        let claims = SignClaims {
            namespace: namespace.to_string(),
            derivation_id: derivation_id.to_string(),
            message: message.clone(),
            ..Default::default()
        };
        self.sign(claims, Duration::from_hours(1))
    }

    /// Create a JWT with Sign claims for the UtilityService pathway.
    ///
    /// Uses ring_id + optional derivation + ACP fields instead of namespace/derivation_id.
    pub fn create_utility_sign_jwt(
        &self,
        ring_id: &str,
        message: Vec<u8>,
        derivation: Option<Vec<u8>>,
        policy_id: &str,
        resource: &str,
        object_id: &str,
        permission: &str,
    ) -> Result<String> {
        let claims = SignClaims {
            ring_id: ring_id.to_string(),
            message,
            derivation,
            policy_id: policy_id.to_string(),
            resource: resource.to_string(),
            object_id: object_id.to_string(),
            permission: permission.to_string(),
            decision_id: String::new(),
            ..Default::default()
        };
        self.sign(claims, Duration::from_hours(1))
    }

    /// Create a JWT with StoreSecret claims.
    ///
    /// # Arguments
    /// * `encrypted_document` - The encrypted document (JSON-serialized Secret struct)
    /// * `enc_cmt` - The encryption commitment (hex-encoded G1 point)
    /// * `ring_id` - The ring ID to use for encryption
    /// * `namespace` - The namespace for storing the document
    /// * `policy_id` - Policy ID for access control
    /// * `resource` - Resource type for the policy
    /// * `permission` - Permission required for the policy
    /// * `shared_point`- rsG - the shared point used for key derivation
    /// * `challenge` - c - Fiat-Shamir challenge
    /// * `response` - s - proof response (s = k + c*r)
    /// * `with_proof` - If a proof should be returned
    /// * `tier` - Optional tier for policy
    /// * `timestamp` - Optional timestamp for policy
    /// * `metadata_hash` - If salt used pass metadata hash
    ///
    /// # Returns
    /// The signed JWT string valid for 1 hour
    pub fn create_store_secret_jwt(
        &self,
        encrypted_document: Vec<u8>,
        enc_cmt: Vec<u8>,
        ring_id: &str,
        namespace: &str,
        policy_id: &str,
        resource: &str,
        permission: &str,
        shared_point: Vec<u8>,
        challenge: Vec<u8>,
        response: Vec<u8>,
        derived_pk: Option<Vec<u8>>,
        with_proof: bool,
        tier: Option<String>,
        timestamp: Option<u64>,
        metadata_hash: Option<Vec<u8>>,
    ) -> Result<String> {
        let claims = StoreSecretClaims {
            encrypted_document,
            enc_cmt,
            ring_id: ring_id.to_string(),
            namespace: namespace.to_string(),
            policy_id: policy_id.to_string(),
            resource: resource.to_string(),
            permission: permission.to_string(),
            shared_point: shared_point,
            challenge: challenge,
            response: response,
            derived_pk,
            with_proof,
            tier,
            timestamp,
            metadata_hash,
        };
        self.sign(claims, Duration::from_hours(1))
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
    fn test_create_dkg_jwt() {
        let signer = JwtSigner::new();
        let peer_ids = vec!["peer1".to_string(), "peer2".to_string()];
        let token = signer.create_dkg_jwt(2, &peer_ids);
        assert!(token.is_ok());

        // Token should have 3 parts (header.payload.signature)
        let token_str = token.unwrap();
        assert_eq!(token_str.split('.').count(), 3);
    }

    #[test]
    fn test_create_pre_jwt() {
        let signer = JwtSigner::new();
        let token = signer.create_pre_jwt(
            b"rdr_pk_value".to_vec(),
            "namespace",
            "object_id",
            None,
            None,
        );
        assert!(token.is_ok());
    }

    #[test]
    fn test_create_store_secret_jwt() {
        let signer = JwtSigner::new();
        let token = signer.create_store_secret_jwt(
            b"encrypted_doc".to_vec(),
            b"enc_cmt_bytes".to_vec(),
            "ring_id_value",
            "namespace",
            "policy_id",
            "resource",
            "permission",
            b"shared_point".to_vec(),
            b"challenge".to_vec(),
            b"response".to_vec(),
            None,
            false,
            None,
            None,
            None,
        );
        assert!(token.is_ok());

        // Token should have 3 parts (header.payload.signature)
        let token_str = token.unwrap();
        assert_eq!(token_str.split('.').count(), 3);
    }
}
