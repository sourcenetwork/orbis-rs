//! Converts PRE's wire-level WebAuthn assertion into the shared evidence
//! type. Authentication itself is dispatched generically — see
//! `authn::endpoints::pre::PreEndpoint` and
//! `orbis_webauthn::resolve_request_auth`, called directly from
//! `pre::v0::service::stages` and `pre::v0::coordinator::handlers`.

use orbis_webauthn::WebAuthnEvidence;

/// Converts the wire-level proto assertion into the shared evidence type
/// carried through [`crate::pre::v0::messages::PreRequestContext`].
pub(crate) fn evidence_from_proto(
    assertion: proto::v0::pre::WebAuthnAssertion,
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
