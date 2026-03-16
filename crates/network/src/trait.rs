//! Network trait definitions
//!
//! This module defines the core networking abstractions that can be implemented
//! by various backends (iroh, libp2p, etc.).

use crate::error::Result;
use async_trait::async_trait;
use bytes::Bytes;
use std::sync::Arc;

/// A peer identifier in the network
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PeerId(Arc<[u8]>);

impl PeerId {
    pub fn new(bytes: impl Into<Arc<[u8]>>) -> Self {
        Self(bytes.into())
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(Arc::from(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// A network message that can be sent between peers
#[derive(Debug, Clone)]
pub struct Message {
    pub data: Bytes,
    pub protocol: Arc<[u8]>,
}

impl Message {
    pub fn new(data: impl Into<Bytes>, protocol: impl Into<Arc<[u8]>>) -> Self {
        Self {
            data: data.into(),
            protocol: protocol.into(),
        }
    }

    pub fn with_vec(data: Vec<u8>, protocol: Vec<u8>) -> Self {
        Self {
            data: Bytes::from(data),
            protocol: Arc::from(protocol.into_boxed_slice()),
        }
    }
}

/// A connection to a peer
#[async_trait]
pub trait Connection: Send + Sync {
    /// Send a message over this connection
    ///
    /// Takes `&self` to allow concurrent sends from multiple tasks
    async fn send(&self, message: Message) -> Result<()>;

    /// Receive a message from this connection
    ///
    /// Takes `&self` to allow concurrent receives from multiple tasks
    async fn recv(&self) -> Result<Message>;

    /// Close the connection
    async fn close(&self) -> Result<()>;

    /// Close the connection gracefully after flushing any pending outbound data.
    ///
    /// Implementations should ensure that all previously-sent bytes are made
    /// available to the remote peer before initiating connection shutdown.
    /// This is useful for protocols (such as DKG) that rely on delivery of
    /// final messages (e.g. acknowledgements) before teardown.
    async fn close_graceful(&self) -> Result<()>;

    /// Get the peer ID of the remote peer
    fn peer_id(&self) -> &PeerId;
}

/// Protocol handler for incoming connections
#[async_trait]
pub trait ProtocolHandler: Send + Sync {
    /// Handle an incoming connection for a specific protocol
    async fn handle(&self, connection: Box<dyn Connection>) -> Result<()>;
}

/// Router builder for registering multiple protocol handlers
pub trait RouterBuilder: Send + Sync {
    /// Register a protocol handler for a specific protocol identifier
    fn accept(
        self: Box<Self>,
        protocol: Vec<u8>,
        handler: Arc<dyn ProtocolHandler>,
    ) -> Box<dyn RouterBuilder>;

    /// Set the maximum message size for connections
    fn max_message_size(self: Box<Self>, size: usize) -> Box<dyn RouterBuilder>;

    /// Build and spawn the router with all registered handlers
    fn spawn(self: Box<Self>) -> Result<Box<dyn Router>>;
}

/// Router for managing multiple protocol handlers
#[async_trait]
pub trait Router: Send + Sync {
    /// Shutdown the router gracefully
    async fn shutdown(self: Box<Self>) -> Result<()>;
}

/// Network trait for establishing connections and listening
#[async_trait]
pub trait Network: Send + Sync {
    /// Connect to a peer at the given address
    async fn connect(&self, peer_id: &PeerId, protocol: &[u8]) -> Result<Box<dyn Connection>>;

    /// Start listening for incoming connections
    async fn listen(&mut self, protocol: &[u8], handler: Box<dyn ProtocolHandler>) -> Result<()>;

    /// Get the local peer ID
    fn local_peer_id(&self) -> PeerId;

    /// Get the local address/endpoint
    fn local_address(&self) -> Result<String>;

    /// Get bound socket addresses (if available)
    ///
    /// Returns a vector of socket addresses that this network is bound to.
    /// Some network implementations may not support this, in which case they
    /// should return an empty vector.
    ///
    /// This is primarily useful for testing and peer discovery.
    fn bound_addresses(&self) -> Vec<std::net::SocketAddr> {
        Vec::new() // Default implementation returns empty
    }

    /// Create a router builder for this network
    ///
    /// This allows registering multiple protocol handlers that will handle
    /// incoming connections based on protocol negotiation (e.g., ALPN).
    fn create_router_builder(&self) -> Result<Box<dyn RouterBuilder>>;
}
