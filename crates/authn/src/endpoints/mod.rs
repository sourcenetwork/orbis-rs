//! One file per endpoint, each describing that endpoint's authentication
//! shape — generic over both the JWT and WebAuthn paths, so an endpoint's
//! node-side code needs nothing endpoint-specific beyond which marker
//! type it passes to `orbis_webauthn::resolve_request_auth`.
//!
//! `authn` can describe this shape (it already holds each endpoint's
//! claims type — `SignClaims`, `PreClaims`, `StoreSecretClaims` — so this
//! is the same level of per-endpoint specificity, not a new one) but
//! can't dispatch WebAuthn evidence itself: that needs
//! `webauthn-rs-core`/P-256 crypto, which lives in `orbis-webauthn`, a
//! crate that already depends on this one — `authn` depending back on it
//! would be a cycle. The dispatch function that actually branches between
//! the two paths lives there instead, generic over `EndpointAuth`.

pub mod dkg;
pub mod pre;
pub mod sign;
pub mod store_secret;

use crate::error::Result;
use crate::BearerToken;
use orbis_integration_core::CanonicalOperation;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::fmt::Debug;

/// Describes one endpoint's authentication shape.
pub trait EndpointAuth {
    /// Claims type carried by this endpoint's JWT — and synthesized,
    /// identically, for a WebAuthn-authorized request.
    type Claims: DeserializeOwned + Serialize + Debug + Clone;
    /// The canonically-encodable operation a WebAuthn assertion's
    /// challenge must commit to for this endpoint.
    type Operation: CanonicalOperation;
    /// Whatever this endpoint needs to validate claims and build its
    /// operation, already extracted from its own proto request type by
    /// the caller — this trait has no business knowing about proto, since
    /// every service's generated request type is a distinct Rust type
    /// even where their fields are identical (see
    /// `orbis_webauthn::WebAuthnEvidence`'s own doc comment for the same
    /// reasoning about the wire evidence itself).
    type Fields;

    /// Builds the claims a WebAuthn-authorized request's synthetic token
    /// carries, from `fields` alone — always derivable, never checked
    /// against anything, since the WebAuthn signature already covers
    /// `Self::operation`'s encoding of these same fields.
    fn claims(fields: &Self::Fields) -> Self::Claims;

    /// Checks a JWT-authorized request's verified claims match `fields` —
    /// the JWT path's analogue of the WebAuthn path's challenge binding.
    fn validate_claims(token: &BearerToken<Self::Claims>, fields: &Self::Fields) -> Result<()>;

    /// Builds the operation a WebAuthn assertion's challenge must commit
    /// to for this exact request. `issued_at` is only meaningful to an
    /// endpoint whose own claims get cryptographically bound into a
    /// further signature the client produces before the server ever sees
    /// the request (PRE's reader-key proof-of-possession is the one
    /// example today) — an endpoint without that concern just ignores it.
    fn operation(
        fields: &Self::Fields,
        issued_at: u64,
        expiry: u64,
        nonce: [u8; 16],
    ) -> Self::Operation;
}
