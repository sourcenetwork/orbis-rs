//! Shared helpers for DKG-backed ceremonies: commitment (de)serialization and
//! hashing, session-ID derivation, session-init validation, ring-bundle
//! persistence, and committee/key matching utilities.
//!
//! - [`commitment`] — commitment coefficient (de)serialization and hashing.
//! - [`session_ids`] — deterministic session-ID derivation.
//! - [`validation`] — session-init and node-authorization validation.
//! - [`ring_bundle`] — persisting `RingShareBundle` after DKG/refresh/reshare.
//! - [`committee`] — committee membership, node indexing, and key matching.

mod commitment;
mod committee;
mod ring_bundle;
mod session_ids;
mod validation;

pub use commitment::*;
pub use committee::*;
pub use ring_bundle::*;
pub use session_ids::*;
pub use validation::*;

#[cfg(test)]
mod tests;
