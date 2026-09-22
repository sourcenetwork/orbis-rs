//! Bulletin module types and operations.
//!
//! This module provides types and methods for interacting with Vera's bulletin module,
//! which manages namespaced message posting and retrieval.
//!
//! - [`types`] — message, query, and domain types.
//! - [`ids`] — the (currently unused — see its module doc) ring-reshare finalize sign
//!   doc and hash-bytes builder.
//! - [`client`] — `VeraClient` extension methods (`bulletin_*`) that call the chain.

mod client;
mod ids;
mod types;

pub use ids::*;
pub use types::*;
