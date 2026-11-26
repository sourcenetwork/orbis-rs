//! PRE's [`EndpointAuth`] shape — the normal (JWT) path only. WebAuthn
//! support for PRE is layered on top in `orbis-webauthn`'s own
//! `impl WebAuthnEndpoint for PreEndpoint` — see this module's parent's
//! doc comment for why that split exists.

use super::EndpointAuth;
use crate::error::{AuthNError, Result};
use crate::BearerToken;
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

/// Fields a PRE request needs for claims-matching, already pulled out of
/// `StartPreRequest` by the caller.
pub struct PreFields {
    pub object_id: String,
    pub rdr_pk: Vec<u8>,
    pub derivation: Option<Vec<u8>>,
    pub salt: Option<String>,
}

/// Marker type selecting PRE's authentication shape.
pub struct PreEndpoint;

impl EndpointAuth for PreEndpoint {
    type Claims = PreClaims;
    type Fields = PreFields;

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
}
