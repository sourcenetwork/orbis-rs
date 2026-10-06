//! x/orbis module types and operations.
//!
//! This module provides types and methods for interacting with Vera's Orbis module,
//! which manages typed ring, document, and key derivation state.
//!
//! Organized into submodules by role:
//! - [`types`] — wire types: on-chain domain state, transaction messages, and query
//!   request/response pairs.
//! - [`ids`] — deterministic hashing: the reshare finalize sign doc and
//!   document/key-derivation object-id derivation.
//! - [`decode`] — decoding typed responses out of Cosmos SDK ABCI broadcast results.
//!
//! Cosmos client operations are provided by the `cosmos` feature.
//!
//! Each submodule's public items are re-exported here, so external code keeps using
//! `common::blockchain::orbis::<Item>` rather than reaching into a submodule directly.

mod decode;
mod ids;
mod types;

pub use decode::*;
pub use ids::*;
pub use types::*;

#[cfg(test)]
mod tests;
