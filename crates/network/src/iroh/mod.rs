//! Iroh networking implementation
//!
//! This module provides iroh-based implementations of the network traits.

pub mod base;
pub mod pubsub;
pub mod router;

pub use base::{IrohNetwork, IrohNetworkBuilder};
pub use iroh::SecretKey;
pub use pubsub::IrohPubSub;
pub use router::{IrohRouterBuilder, IrohRouterWrapper};

#[cfg(test)]
mod tests;
