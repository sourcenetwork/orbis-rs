//! One file per endpoint, each implementing [`super::EmailEndpoint`] for
//! that endpoint's marker type from `authn::endpoints` — mirrors
//! `orbis_webauthn::endpoints`' own layout and orphan-rule reasoning
//! exactly.

mod pre;
mod sign;
mod store_secret;
