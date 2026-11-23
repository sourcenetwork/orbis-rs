//! PRE's [`EndpointAuth`] shape.

use super::EndpointAuth;
use crate::error::{AuthNError, Result};
use crate::BearerToken;
use orbis_integration_core::PreOperation;
use serde::{Deserialize, Serialize};

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

/// Fields a PRE request needs for claims-matching and operation-building,
/// already pulled out of `StartPreRequest` by the caller.
pub struct PreFields {
    pub object_id: String,
    pub rdr_pk: Vec<u8>,
    pub derivation: Option<Vec<u8>>,
    pub salt: Option<String>,
}

/// Marker type selecting PRE's authentication shape — pass this as
/// `orbis_webauthn::resolve_request_auth`'s generic parameter.
pub struct PreEndpoint;

impl EndpointAuth for PreEndpoint {
    type Claims = PreClaims;
    type Operation = PreOperation;
    type Fields = PreFields;

    fn claims(fields: &PreFields) -> PreClaims {
        PreClaims {
            rdr_pk: fields.rdr_pk.clone(),
            object_id: fields.object_id.clone(),
            derivation: fields.derivation.clone(),
            salt: fields.salt.clone(),
        }
    }

    fn validate_claims(token: &BearerToken<PreClaims>, fields: &PreFields) -> Result<()> {
        if token.claims.rdr_pk != fields.rdr_pk {
            return Err(AuthNError::Unauthorized(
                "Token rdr_pk does not match request rdr_pk".to_string(),
            ));
        }
        if token.claims.object_id != fields.object_id {
            return Err(AuthNError::Unauthorized(format!(
                "Token object_id '{}' does not match request object_id '{}'",
                token.claims.object_id, fields.object_id
            )));
        }
        if token.claims.derivation != fields.derivation {
            return Err(AuthNError::Unauthorized(
                "Token derivation does not match request derivation".to_string(),
            ));
        }
        if token.claims.salt != fields.salt {
            return Err(AuthNError::Unauthorized(
                "Token salt does not match request salt".to_string(),
            ));
        }
        Ok(())
    }

    /// `issued_at` matters here specifically — PRE's reader-key
    /// proof-of-possession (`ReaderAuthorizationContext`) binds this
    /// request's synthetic token's `issued_time` into a signature the
    /// client produces before the server ever sees the request, so it
    /// has to be client-chosen and bound into what the WebAuthn
    /// signature covers too, not just carried unbound alongside it.
    fn operation(fields: &PreFields, issued_at: u64, expiry: u64, nonce: [u8; 16]) -> PreOperation {
        PreOperation {
            object_id: fields.object_id.clone(),
            rdr_pk: fields.rdr_pk.clone(),
            derivation: fields.derivation.clone(),
            salt: fields.salt.clone(),
            issued_at,
            expiry,
            nonce,
        }
    }
}
