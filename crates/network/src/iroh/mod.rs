//! Iroh networking implementation
//!
//! This module provides iroh-based implementations of the network traits.

pub mod base;
#[cfg(feature = "gossip")]
pub mod pubsub;
pub mod router;

pub use base::{IrohNetwork, IrohNetworkBuilder};
pub use iroh::SecretKey;
#[cfg(feature = "gossip")]
pub use pubsub::IrohPubSub;
pub use router::{IrohRouterBuilder, IrohRouterWrapper};

#[cfg(test)]
mod tests;
