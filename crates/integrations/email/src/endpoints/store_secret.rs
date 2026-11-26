//! StoreSecret's [`super::super::EmailEndpoint`] shape — identical to
//! `orbis_webauthn::endpoints::store_secret`'s.

use crate::EmailEndpoint;
use authn::endpoints::store_secret::{StoreSecretClaims, StoreSecretEndpoint, StoreSecretFields};
use orbis_integration_core::StoreSecretOperation;

impl EmailEndpoint for StoreSecretEndpoint {
    type Operation = StoreSecretOperation;

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
