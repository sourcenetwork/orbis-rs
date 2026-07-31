//! Network abstraction layer for Orbis
//!
//! This crate provides a trait-based networking interface that can be implemented
//! using various backends (iroh, libp2p, etc.). The primary implementation uses
//! iroh's QUIC-based networking.

pub mod error;
mod ingress;
pub mod metrics;
pub mod protocol;
pub mod pubsub;
pub mod r#trait;

#[cfg(feature = "iroh")]
pub mod iroh;

pub use error::{NetworkError, Result};
pub use protocol::{routes_for_version, ProtocolRoutes, SUPPORTED_PROTOCOL_VERSIONS, V0};
pub use pubsub::{
    AuthenticatedMessage, PubSub, PubSubEvent, PubSubRejectReason, SignedPayload, Topic, TopicId,
};
pub use r#trait::{
    Connection, IngressDropReason, Message, Network, NetworkIngressLimits, PeerConnection, PeerId,
    ProtocolHandler, Router, RouterBuilder,
};

// Export the selected implementation
#[cfg(feature = "iroh")]
pub use iroh::{
    IrohNetwork as NetworkImpl, IrohNetworkBuilder, IrohRouterBuilder, IrohRouterWrapper, SecretKey,
};

#[cfg(feature = "fault-injection")]
pub mod fault;
#[cfg(feature = "fault-injection")]
pub use fault::{FaultNetwork, FaultNetworkController};

#[cfg(test)]
mod tests;
