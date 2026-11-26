//! One file per endpoint, each implementing [`super::WebAuthnEndpoint`]
//! for that endpoint's marker type from `authn::endpoints` — mirroring
//! that module's own one-file-per-endpoint layout. Implementing a
//! foreign trait (this crate's own `WebAuthnEndpoint`) for a foreign type
//! (e.g. `authn::endpoints::sign::SignEndpoint`) here, rather than in
//! `authn` itself, is exactly what keeps `authn` free of any WebAuthn
//! dependency: the orphan rule allows it because the trait is local to
//! this crate.

mod pre;
mod sign;
mod store_secret;
