//! Typed transport contract for every DKG-backed ceremony.
//!
//! The three enums in this module are the complete DKG wire surface. Public
//! messages cannot represent credentials, secret shares, or private evidence.
//!
//! - [`types`] — the wire types themselves (ceremony/attempt identity,
//!   committee config, the three message enums, ...).
//! - [`digest`] — canonical encode/decode and every digest/ID-derivation
//!   function used to bind and authenticate those types.

mod digest;
mod types;

pub use digest::*;
pub use types::*;

#[cfg(test)]
mod tests;
