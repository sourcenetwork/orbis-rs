//! Converts StoreSecret's wire-level email assertion into the shared
//! evidence type. Authentication itself is dispatched generically — see
//! `authn::endpoints::store_secret::StoreSecretEndpoint` and
//! `crate::helpers::auth::resolve_request_auth`, called directly from
//! `store_secret::v0::service`.
//!
//! Unlike Sign/PRE, StoreSecret has no peer fan-out — it's a single-node
//! write to this node's own bulletin — so there is exactly one call site,
//! not a service entry point plus an independent per-peer re-check.

use orbis_email::EmailEvidence;

/// Converts the wire-level proto assertion into the shared evidence type.
pub(crate) fn evidence_from_proto(
    assertion: proto::v0::store_secret::EmailAssertion,
) -> EmailEvidence {
    EmailEvidence {
        claimed_address: assertion.claimed_address,
        raw_message: assertion.raw_message,
        issued_at: assertion.issued_at,
        expiry: assertion.expiry,
        nonce: assertion.nonce,
    }
}
