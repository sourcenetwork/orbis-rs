//! Network abstraction layer for Orbis
//!
//! This crate provides a trait-based networking interface that can be implemented
//! using various backends (iroh, libp2p, etc.). The primary implementation uses
//! iroh's QUIC-based networking.

pub mod error;
pub mod iroh;
pub mod trait_;

pub use error::{NetworkError, Result};
pub use iroh::IrohNetwork;
pub use iroh::router::Router as IrohRouter;
pub use trait_::{Connection, Message, Network, PeerId, ProtocolHandler};

