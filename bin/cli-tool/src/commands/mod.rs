//! CLI command implementations
//!
//! This module contains the actual implementation of CLI commands,
//! separated from main.rs so they can be used in integration tests.
//!
//! Split by purpose:
//! - [`node`]: commands that talk to a running orbis-node over gRPC (DKG, PRE, Sign,
//!   StoreSecret, node/ring status queries).
//! - [`crypto`]: local cryptography (encryption, key generation, DID derivation) —
//!   no network calls.
//!
//! Vera administration (policies, rings, node registration) is the
//! `vera-admin` binary.

mod crypto;
mod node;

pub use crypto::*;
pub use node::*;
