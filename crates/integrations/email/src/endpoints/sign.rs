//! Sign's [`super::super::EmailEndpoint`] shape — identical to
//! `orbis_webauthn::endpoints::sign`'s.

use crate::EmailEndpoint;
use authn::endpoints::sign::{SignClaims, SignEndpoint, SignFields};
use orbis_integration_core::SignOperation;

impl EmailEndpoint for SignEndpoint {
    type Operation = SignOperation;

    fn claims(fields: &SignFields) -> SignClaims {
        SignClaims {
            derivation_id: fields.derivation_id.clone(),
            message_sha256: fields.message_sha256.clone(),
        }
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
