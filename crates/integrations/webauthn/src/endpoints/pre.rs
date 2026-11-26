//! PRE's [`super::super::WebAuthnEndpoint`] shape.

use crate::WebAuthnEndpoint;
use authn::endpoints::pre::{PreClaims, PreEndpoint, PreFields};
use orbis_integration_core::PreOperation;

impl WebAuthnEndpoint for PreEndpoint {
    type Operation = PreOperation;

    fn claims(fields: &PreFields) -> PreClaims {
        PreClaims {
            rdr_pk: fields.rdr_pk.clone(),
            object_id: fields.object_id.clone(),
            derivation: fields.derivation.clone(),
            salt: fields.salt.clone(),
        }
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
