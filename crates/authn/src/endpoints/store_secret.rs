//! StoreSecret's [`EndpointAuth`] shape.

use super::EndpointAuth;
use crate::error::{AuthNError, Result};
use crate::BearerToken;
use orbis_integration_core::StoreSecretOperation;
use serde::{Deserialize, Serialize};

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
    /// Fiat-Shamir challenge (Schnorr PoK of the encryption randomness)
    pub challenge: Vec<u8>,
    /// Proof response `z = k + c*r`
    pub response: Vec<u8>,
    /// Add a proof to the store secret call
    pub with_proof: bool,
    /// tier required for policy
    pub tier: Option<String>,
    /// timestamp required for policy
    pub timestamp: Option<u64>,
}

/// Fields a StoreSecret request needs for claims-matching and
/// operation-building, already pulled out of `StoreSecretRequest` by the
/// caller — `encrypted_document_sha256` is a digest the caller computes
/// once from the request's raw `encrypted_document`, mirroring Sign's own
/// `message_sha256` field.
pub struct StoreSecretFields {
    pub encrypted_document_sha256: Vec<u8>,
    pub enc_cmt: Vec<u8>,
    pub ring_id: String,
    pub policy_id: String,
    pub resource: String,
    pub permission: String,
    pub challenge: Vec<u8>,
    pub response: Vec<u8>,
    pub with_proof: bool,
    pub tier: Option<String>,
    pub timestamp: Option<u64>,
}

/// Marker type selecting StoreSecret's authentication shape — pass this
/// as `orbis_webauthn::resolve_request_auth`'s generic parameter.
pub struct StoreSecretEndpoint;

impl EndpointAuth for StoreSecretEndpoint {
    type Claims = StoreSecretClaims;
    type Operation = StoreSecretOperation;
    type Fields = StoreSecretFields;

    fn claims(fields: &StoreSecretFields) -> StoreSecretClaims {
        StoreSecretClaims {
            encrypted_document_sha256: fields.encrypted_document_sha256.clone(),
            enc_cmt: fields.enc_cmt.clone(),
            ring_id: fields.ring_id.clone(),
            policy_id: fields.policy_id.clone(),
            resource: fields.resource.clone(),
            permission: fields.permission.clone(),
            challenge: fields.challenge.clone(),
            response: fields.response.clone(),
            with_proof: fields.with_proof,
            tier: fields.tier.clone(),
            timestamp: fields.timestamp,
        }
    }

    fn validate_claims(
        token: &BearerToken<StoreSecretClaims>,
        fields: &StoreSecretFields,
    ) -> Result<()> {
        if token.claims.encrypted_document_sha256 != fields.encrypted_document_sha256 {
            return Err(AuthNError::Unauthorized(
                "Token encrypted_document_sha256 does not match request encrypted_document"
                    .to_string(),
            ));
        }
        if token.claims.enc_cmt != fields.enc_cmt {
            return Err(AuthNError::Unauthorized(
                "Token enc_cmt does not match request".to_string(),
            ));
        }
        if token.claims.ring_id != fields.ring_id {
            return Err(AuthNError::Unauthorized(format!(
                "Token ring_id '{}' does not match request ring_id '{}'",
                token.claims.ring_id, fields.ring_id
            )));
        }
        if token.claims.policy_id != fields.policy_id {
            return Err(AuthNError::Unauthorized(format!(
                "Token policy_id '{}' does not match request policy_id '{}'",
                token.claims.policy_id, fields.policy_id
            )));
        }
        if token.claims.resource != fields.resource {
            return Err(AuthNError::Unauthorized(format!(
                "Token resource '{}' does not match request resource '{}'",
                token.claims.resource, fields.resource
            )));
        }
        if token.claims.permission != fields.permission {
            return Err(AuthNError::Unauthorized(format!(
                "Token permission '{}' does not match request permission '{}'",
                token.claims.permission, fields.permission
            )));
        }
        if token.claims.challenge != fields.challenge {
            return Err(AuthNError::Unauthorized(
                "Token challenge does not match request challenge".to_string(),
            ));
        }
        if token.claims.response != fields.response {
            return Err(AuthNError::Unauthorized(
                "Token response does not match request response".to_string(),
            ));
        }
        if token.claims.with_proof != fields.with_proof {
            return Err(AuthNError::Unauthorized(format!(
                "Token with_proof '{:?}' does not match request with_proof '{:?}'",
                token.claims.with_proof, fields.with_proof
            )));
        }
        if token.claims.tier != fields.tier {
            return Err(AuthNError::Unauthorized(format!(
                "Token tier '{:?}' does not match request tier '{:?}'",
                token.claims.tier, fields.tier
            )));
        }
        if token.claims.timestamp != fields.timestamp {
            return Err(AuthNError::Unauthorized(format!(
                "Token timestamp '{:?}' does not match request timestamp '{:?}'",
                token.claims.timestamp, fields.timestamp
            )));
        }
        Ok(())
    }

    /// Nothing downstream cryptographically binds this request's
    /// `issued_time` into a further signature (unlike PRE's reader-key
    /// proof-of-possession) — `issued_at` is unused here, same as Sign.
    fn operation(
        fields: &StoreSecretFields,
        _issued_at: u64,
        expiry: u64,
        nonce: [u8; 16],
    ) -> StoreSecretOperation {
        StoreSecretOperation {
            encrypted_document_sha256: fields.encrypted_document_sha256.clone(),
            enc_cmt: fields.enc_cmt.clone(),
            ring_id: fields.ring_id.clone(),
            policy_id: fields.policy_id.clone(),
            resource: fields.resource.clone(),
            permission: fields.permission.clone(),
            challenge: fields.challenge.clone(),
            response: fields.response.clone(),
            with_proof: fields.with_proof,
            tier: fields.tier.clone(),
            timestamp: fields.timestamp,
            expiry,
            nonce,
        }
    }
}
