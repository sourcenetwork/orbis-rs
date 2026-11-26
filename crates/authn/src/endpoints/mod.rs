//! One file per endpoint, each describing that endpoint's *normal*
//! (JWT) authentication shape — nothing here knows about WebAuthn, email,
//! or any other extra mechanism. An endpoint that wants one of those
//! layers it on top: see `orbis_webauthn::WebAuthnEndpoint` for how
//! WebAuthn extends this trait without this crate needing to depend on
//! `orbis-webauthn` (which already depends on this crate — the reverse
//! would be a cycle), and `orbis-node`'s `helpers::auth::resolve_request_auth`
//! for where "try JWT, then try an extra mechanism if the request carries
//! one" is actually decided. That decision deliberately does not live in
//! any one mechanism's crate: a mechanism crate only ever needs to know
//! how to verify its own evidence, never which other mechanisms exist or
//! which one takes priority. Adding a new mechanism later (e.g. a
//! DKIM-verified email flow) means writing that mechanism's own crate and
//! extending the orchestrator in `orbis-node` — this trait and its
//! `Claims`/`Fields` types don't change.

pub mod dkg;
pub mod pre;
pub mod sign;
pub mod store_secret;

use crate::error::Result;
use crate::BearerToken;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::fmt::Debug;

/// Describes one endpoint's normal (JWT) authentication shape.
pub trait EndpointAuth {
    /// Claims type carried by this endpoint's JWT.
    type Claims: DeserializeOwned + Serialize + Debug + Clone;
    /// Whatever this endpoint needs to validate claims against, already
    /// extracted from its own proto request type by the caller — this
    /// trait has no business knowing about proto, since every service's
    /// generated request type is a distinct Rust type even where their
    /// fields are identical.
    type Fields;

    /// Checks a JWT-authorized request's verified claims match `fields`.
    fn validate_claims(token: &BearerToken<Self::Claims>, fields: &Self::Fields) -> Result<()>;
}

/// Resolves and verifies a bearer JWT for `E`, then checks its claims
/// against `fields` — the complete "normal" authentication path for one
/// endpoint, self-contained in this crate. A caller with no need for any
/// extra authentication mechanism can use this directly; one that also
/// wants to support WebAuthn (or another mechanism) composes this with
/// that mechanism's own verifier instead — see this module's own doc
/// comment for where that composition happens.
pub fn resolve_jwt_auth<E: EndpointAuth>(
    token_str: &str,
    fields: &E::Fields,
    current_time: u64,
    max_token_lifetime_secs: u64,
    max_jwt_bytes: usize,
    clock_skew_leeway_secs: u64,
) -> Result<BearerToken<E::Claims>> {
    let token = crate::resolve_jwt_did(
        token_str,
        current_time,
        max_token_lifetime_secs,
        max_jwt_bytes,
        clock_skew_leeway_secs,
    )?;
    E::validate_claims(&token, fields)?;
    Ok(token)
}
