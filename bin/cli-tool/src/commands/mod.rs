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
//! - [`bulletin`]: bulletin namespace/collaborator administration and posting/reading
//!   bulletin entries.
//! - [`admin`]: chain administration (ACP policies/objects/relationships, ring
//!   lifecycle, node registration, funding).
//! - [`chain`]: shared chain-client construction and transaction-result helpers used
//!   by `admin` and `bulletin`.

mod admin;
mod bulletin;
mod chain;
mod crypto;
mod node;

pub use admin::*;
pub use bulletin::*;
pub use crypto::*;
pub use node::*;
