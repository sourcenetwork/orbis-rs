//! Network trait definitions
//!
//! This module defines the core networking abstractions that can be implemented
//! by various backends (iroh, libp2p, etc.).

use crate::error::Result;
use async_trait::async_trait;

/// A peer identifier in the network
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PeerId(pub Vec<u8>);

impl PeerId {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// A network message that can be sent between peers
#[derive(Debug, Clone)]
pub struct Message {
    pub data: Vec<u8>,
    pub protocol: Vec<u8>,
}

impl Message {
    pub fn new(data: Vec<u8>, protocol: impl Into<Vec<u8>>) -> Self {
        Self {
            data,
            protocol: protocol.into(),
        }
    }
}

/// A connection to a peer
#[async_trait]
pub trait Connection: Send + Sync {
    /// Send a message over this connection
    async fn send(&mut self, message: Message) -> Result<()>;

    /// Receive a message from this connection
    async fn recv(&mut self) -> Result<Message>;

    /// Close the connection
    async fn close(&mut self) -> Result<()>;

    /// Get the peer ID of the remote peer
    fn peer_id(&self) -> &PeerId;
}

/// Protocol handler for incoming connections
#[async_trait]
pub trait ProtocolHandler: Send + Sync {
    /// Handle an incoming connection for a specific protocol
    async fn handle(&self, connection: Box<dyn Connection>) -> Result<()>;
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
}
