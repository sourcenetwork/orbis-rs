//! Converts PRE's wire-level email assertion into the shared evidence
//! type. Authentication itself is dispatched generically — see
//! `authn::endpoints::pre::PreEndpoint` and
//! `crate::helpers::auth::resolve_request_auth`, called directly from
//! `pre::v0::service::stages` and `pre::v0::coordinator::handlers`.

use orbis_email::EmailEvidence;

/// Converts the wire-level proto assertion into the shared evidence type
/// carried through [`crate::pre::v0::messages::PreRequestContext`].
pub(crate) fn evidence_from_proto(assertion: proto::v0::pre::EmailAssertion) -> EmailEvidence {
    EmailEvidence {
        claimed_address: assertion.claimed_address,
        raw_message: assertion.raw_message,
        issued_at: assertion.issued_at,
        expiry: assertion.expiry,
        nonce: assertion.nonce,
    }
}
