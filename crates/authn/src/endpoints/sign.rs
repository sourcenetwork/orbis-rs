//! Sign's [`EndpointAuth`] shape.

use super::EndpointAuth;
use crate::error::{AuthNError, Result};
use crate::BearerToken;
use orbis_integration_core::SignOperation;
use serde::{Deserialize, Serialize};

/// Claims for Sign (threshold signing) endpoints
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct SignClaims {
    /// Object ID of the key derivation entry on the bulletin
    pub derivation_id: String,
    /// SHA-256 digest of the message to sign
    pub message_sha256: Vec<u8>,
}

/// Fields a Sign request needs for claims-matching and operation-building,
/// already pulled out of `StartSignRequest` by the caller.
pub struct SignFields {
    pub derivation_id: String,
    pub message_sha256: Vec<u8>,
}

/// Marker type selecting Sign's authentication shape — pass this as
/// `orbis_webauthn::resolve_request_auth`'s generic parameter.
pub struct SignEndpoint;

impl EndpointAuth for SignEndpoint {
    type Claims = SignClaims;
    type Operation = SignOperation;
    type Fields = SignFields;

    fn claims(fields: &SignFields) -> SignClaims {
        SignClaims {
            derivation_id: fields.derivation_id.clone(),
            message_sha256: fields.message_sha256.clone(),
        }
    }

    fn validate_claims(token: &BearerToken<SignClaims>, fields: &SignFields) -> Result<()> {
        if token.claims.derivation_id != fields.derivation_id {
            return Err(AuthNError::Unauthorized(format!(
                "Token derivation_id '{}' does not match request derivation_id '{}'",
                token.claims.derivation_id, fields.derivation_id
            )));
        }
        if token.claims.message_sha256 != fields.message_sha256 {
            return Err(AuthNError::Unauthorized(
                "Token message_sha256 does not match request message".to_string(),
            ));
        }
        Ok(())
    }

    fn operation(
        fields: &SignFields,
        _issued_at: u64,
        expiry: u64,
        nonce: [u8; 16],
    ) -> SignOperation {
        SignOperation {
            derivation_id: fields.derivation_id.clone(),
            message_sha256: fields.message_sha256.clone(),
            expiry,
            nonce,
        }
    }
}
