//! Evidence: the generic half of `submit_*_with_evidence`.
//!
//! [`ChallengeEvidence`] (re-exported from `orbis-integration-core`) is
//! implemented by each mechanism's own crate for its own evidence type —
//! `orbis-webauthn`'s `PasskeyAssertion` today, a future email/DKIM crate's
//! own type tomorrow — so this crate's `submit_*_with_evidence` functions
//! never need to be modified to accept a *producer* of a new mechanism.
//!
//! What they do need, generically, is a way to turn whatever `Wire` type a
//! producer came back with into the one of a small, closed set of shapes
//! orbis-node's proto messages actually carry. [`WireEvidence`] is that
//! shape. Wiring in a new mechanism means one new variant here plus one
//! `From` impl — the same bounded cost orbis-node's own server-side auth
//! orchestrator pays per mechanism (see `authn::endpoints`'s doc comment).

pub use orbis_integration_core::ChallengeEvidence;

/// The wire-level evidence shapes this crate knows how to attach to a
/// request, independent of which protocol (Sign/PRE/StoreSecret) is
/// submitting it — each protocol's own proto type gets populated from this
/// via a trivial mapping at its own boundary.
#[cfg(feature = "webauthn")]
#[derive(Debug, Clone)]
pub enum WireEvidence {
    WebAuthn(orbis_webauthn::WebAuthnEvidence),
}

#[cfg(feature = "webauthn")]
impl From<orbis_webauthn::WebAuthnEvidence> for WireEvidence {
    fn from(evidence: orbis_webauthn::WebAuthnEvidence) -> Self {
        WireEvidence::WebAuthn(evidence)
    }
}

#[cfg(feature = "webauthn")]
impl WireEvidence {
    pub(crate) fn into_pre_assertion(self) -> proto::v0::pre::WebAuthnAssertion {
        match self {
            WireEvidence::WebAuthn(e) => proto::v0::pre::WebAuthnAssertion {
                issuer_did: e.issuer_did,
                authenticator_data: e.authenticator_data,
                client_data_json: e.client_data_json,
                signature: e.signature,
                issued_at: e.issued_at,
                expiry: e.expiry,
                nonce: e.nonce,
            },
        }
    }

    pub(crate) fn into_sign_assertion(self) -> proto::v0::sign::WebAuthnAssertion {
        match self {
            WireEvidence::WebAuthn(e) => proto::v0::sign::WebAuthnAssertion {
                issuer_did: e.issuer_did,
                authenticator_data: e.authenticator_data,
                client_data_json: e.client_data_json,
                signature: e.signature,
                issued_at: e.issued_at,
                expiry: e.expiry,
                nonce: e.nonce,
            },
        }
    }

    pub(crate) fn into_store_secret_assertion(self) -> proto::v0::store_secret::WebAuthnAssertion {
        match self {
            WireEvidence::WebAuthn(e) => proto::v0::store_secret::WebAuthnAssertion {
                issuer_did: e.issuer_did,
                authenticator_data: e.authenticator_data,
                client_data_json: e.client_data_json,
                signature: e.signature,
                issued_at: e.issued_at,
                expiry: e.expiry,
                nonce: e.nonce,
            },
        }
    }
}
