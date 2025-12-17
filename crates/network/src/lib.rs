//! Network abstraction layer for Orbis
//!
//! This crate provides a trait-based networking interface that can be implemented
//! using various backends (iroh, libp2p, etc.). The primary implementation uses
//! iroh's QUIC-based networking.

pub mod error;
pub mod iroh;
pub mod protocol;
pub mod r#trait;

pub use error::{NetworkError, Result};
pub use iroh::{IrohNetwork, IrohRouterBuilder, IrohRouterWrapper};
pub use protocol::{DKG, REENCRYPT};
pub use r#trait::{Connection, Message, Network, PeerId, ProtocolHandler, Router, RouterBuilder};

#[cfg(test)]
mod tests;
