//! Converts StoreSecret's wire-level WebAuthn assertion into the shared
//! evidence type. Authentication itself is dispatched generically — see
//! `authn::endpoints::store_secret::StoreSecretEndpoint` and
//! `orbis_webauthn::resolve_request_auth`, called directly from
//! `store_secret::v0::service`.
//!
//! Unlike Sign/PRE, StoreSecret has no peer fan-out — it's a single-node
//! write to this node's own bulletin — so there is exactly one call site,
//! not a service entry point plus an independent per-peer re-check.

use orbis_webauthn::WebAuthnEvidence;

/// Converts the wire-level proto assertion into the shared evidence type.
pub(crate) fn evidence_from_proto(
    assertion: proto::v0::store_secret::WebAuthnAssertion,
) -> WebAuthnEvidence {
    WebAuthnEvidence {
        issuer_did: assertion.issuer_did,
        authenticator_data: assertion.authenticator_data,
        client_data_json: assertion.client_data_json,
        signature: assertion.signature,
        issued_at: assertion.issued_at,
        expiry: assertion.expiry,
        nonce: assertion.nonce,
    }
}
