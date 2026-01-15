//! Base Iroh QUIC connection implementation
//!
//! This module implements the Network trait using iroh's QUIC-based networking.

use async_trait::async_trait;
use bytes::Bytes;
use iroh::endpoint::Connection as IrohConnection;
use iroh::{Endpoint, EndpointAddr, SecretKey};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::error::{NetworkError, Result};
use crate::iroh::router::IrohRouterBuilder;
use crate::r#trait::{
    Connection, Message, Network, PeerId, ProtocolHandler, RouterBuilder as RouterBuilderTrait,
};

/// Configuration for IrohNetwork
#[derive(Debug, Clone)]
pub struct IrohNetworkConfig {
    /// Maximum size for receiving messages (in bytes)
    pub max_message_size: usize,
}

impl Default for IrohNetworkConfig {
    fn default() -> Self {
        Self {
            max_message_size: 1024 * 1024, // 1MB default
        }
    }
}

/// Iroh-based network implementation
pub struct IrohNetwork {
    endpoint: Endpoint,
    local_peer_id: PeerId,
    config: IrohNetworkConfig,
    handlers: Arc<RwLock<HashMap<Vec<u8>, Arc<dyn ProtocolHandler>>>>,
}

impl IrohNetwork {
    /// Create a new builder for IrohNetwork
    pub fn builder() -> IrohNetworkBuilder {
        IrohNetworkBuilder::default()
    }

    /// Create a new Iroh network instance with default configuration
    pub async fn new() -> Result<Self> {
        Self::builder().build().await
    }

    /// Get a reference to the underlying iroh endpoint
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// Get the configuration
    pub fn config(&self) -> &IrohNetworkConfig {
        &self.config
    }
}

/// Builder for IrohNetwork
#[derive(Default)]
pub struct IrohNetworkBuilder {
    config: IrohNetworkConfig,
    secret_key: Option<SecretKey>,
}

impl IrohNetworkBuilder {
    /// Set the maximum message size
    pub fn max_message_size(mut self, size: usize) -> Self {
        self.config.max_message_size = size;
        self
    }

    /// Set the secret key for deterministic peer ID
    ///
    /// If not set, a random key will be generated on each startup.
    /// To persist identity across restarts, store the secret key bytes
    /// and pass them here on subsequent startups.
    pub fn secret_key(mut self, key: SecretKey) -> Self {
        self.secret_key = Some(key);
        self
    }

    /// Build the IrohNetwork instance
    pub async fn build(self) -> Result<IrohNetwork> {
        let mut builder = Endpoint::builder();

        if let Some(key) = self.secret_key {
            builder = builder.secret_key(key);
        }

        let endpoint = builder
            .bind()
            .await
            .map_err(|e| NetworkError::Connection(format!("Failed to bind endpoint: {}", e)))?;

        let node_id = endpoint.id();
        let peer_id = PeerId::from_bytes(node_id.as_bytes());

        Ok(IrohNetwork {
            endpoint,
            local_peer_id: peer_id,
            config: self.config,
            handlers: Arc::new(RwLock::new(HashMap::new())),
        })
    }
}

#[async_trait]
impl Network for IrohNetwork {
    async fn connect(&self, peer_id: &PeerId, protocol: &[u8]) -> Result<Box<dyn Connection>> {
        use iroh::PublicKey;
        use std::net::SocketAddr;
        use std::str::FromStr;

        // Convert peer_id bytes to PublicKey
        // The peer_id might be in format "node_id" or "node_id@ip:port"
        let peer_id_str = std::str::from_utf8(peer_id.as_bytes()).map_err(|_| {
            NetworkError::InvalidAddress("Invalid peer ID format - not UTF-8".to_string())
        })?;

        // Parse the address - could be "node_id" or "node_id@ip:port"
        let (node_id_str, socket_addr_opt) = if let Some((id, addr)) = peer_id_str.split_once('@') {
            (id, Some(addr))
        } else {
            (peer_id_str, None)
        };

        let public_key = PublicKey::from_str(node_id_str)
            .map_err(|e| NetworkError::InvalidAddress(format!("Invalid peer ID: {}", e)))?;

        // Create EndpointAddr from the public key
        let peer_addr = if let Some(addr_str) = socket_addr_opt {
            // First try to parse as a direct SocketAddr (IP:port)
            let socket_addr = if let Ok(addr) = addr_str.parse::<SocketAddr>() {
                addr
            } else {
                // Try to resolve as hostname:port using DNS
                tokio::net::lookup_host(addr_str)
                    .await
                    .map_err(|e| {
                        NetworkError::InvalidAddress(format!(
                            "Failed to resolve address '{}': {}",
                            addr_str, e
                        ))
                    })?
                    .next()
                    .ok_or_else(|| {
                        NetworkError::InvalidAddress(format!(
                            "No addresses found for hostname '{}'",
                            addr_str
                        ))
                    })?
            };

            // Add the IP address to the endpoint address
            EndpointAddr::new(public_key).with_ip_addr(socket_addr)
        } else {
            // No address provided - just use the node ID
            // iroh will try to discover the peer via its discovery mechanisms
            EndpointAddr::new(public_key)
        };

        let alpn = protocol.to_vec();

        // Connect to the peer
        let conn = self
            .endpoint
            .connect(peer_addr, &alpn)
            .await
            .map_err(|e| NetworkError::Connection(format!("Failed to connect: {}", e)))?;

        Ok(Box::new(IrohConnectionWrapper::new(
            conn,
            self.config.max_message_size,
        )))
    }

    async fn listen(&mut self, protocol: &[u8], handler: Box<dyn ProtocolHandler>) -> Result<()> {
        let mut handlers = self.handlers.write().await;
        handlers.insert(protocol.to_vec(), Arc::from(handler));
        Ok(())
    }

    fn local_peer_id(&self) -> PeerId {
        self.local_peer_id.clone()
    }

    fn local_address(&self) -> Result<String> {
        // Get the node ID as the address identifier
        let node_id = self.endpoint.id();
        Ok(format!("{}", node_id))
    }

    fn bound_addresses(&self) -> Vec<std::net::SocketAddr> {
        self.endpoint.bound_sockets()
    }

    fn create_router_builder(&self) -> Result<Box<dyn RouterBuilderTrait>> {
        Ok(Box::new(IrohRouterBuilder::new(self.endpoint.clone())))
    }
}

/// Wrapper around iroh Connection to implement our Connection trait
///
/// Uses QUIC's bidirectional stream multiplexing with acknowledgments.
/// Each message uses a new bi-directional stream where:
/// - Sender writes data and waits for ack (keeps connection alive)
/// - Receiver reads data and sends ack
pub struct IrohConnectionWrapper {
    conn: IrohConnection,
    peer_id: PeerId,
    protocol: Arc<[u8]>,
    max_message_size: usize,
}

impl IrohConnectionWrapper {
    pub fn new(conn: IrohConnection, max_message_size: usize) -> Self {
        // remote_id() returns a PublicKey
        let node_id = conn.remote_id();
        let peer_id = PeerId::from_bytes(node_id.as_bytes());

        // Get protocol from ALPN - cache it since it won't change
        let protocol = Arc::from(conn.alpn());

        Self {
            conn,
            peer_id,
            protocol,
            max_message_size,
        }
    }
}

#[async_trait]
impl Connection for IrohConnectionWrapper {
    async fn send(&self, message: Message) -> Result<()> {
        // Open a new bidirectional stream for this message
        let (mut send, mut recv) = self
            .conn
            .open_bi()
            .await
            .map_err(|e| NetworkError::Connection(format!("Failed to open stream: {}", e)))?;

        // Write message data
        send.write_all(&message.data)
            .await
            .map_err(|e| NetworkError::Io(e.into()))?;

        // Finish the send side to signal completion
        send.finish()
            .map_err(|e| NetworkError::Connection(format!("Failed to finish stream: {}", e)))?;

        // Wait for acknowledgment (keeps connection alive until receiver processes message)
        // This prevents connection closure before the receiver can read the data
        let _ = recv.read_to_end(64).await; // Small buffer for ack

        Ok(())
    }

    async fn recv(&self) -> Result<Message> {
        // Accept an incoming bidirectional stream
        let (mut send, mut recv) = self
            .conn
            .accept_bi()
            .await
            .map_err(|e| NetworkError::Connection(format!("Failed to accept stream: {}", e)))?;

        // Read all data from the stream (up to max_message_size)
        let buffer = recv
            .read_to_end(self.max_message_size)
            .await
            .map_err(|e| NetworkError::Connection(format!("Failed to read data: {}", e)))?;

        // Send acknowledgment to signal successful receipt
        let _ = send.write_all(&[1u8]).await; // Simple 1-byte ack
        let _ = send.finish();

        // Convert to Bytes for zero-copy efficiency
        let data = Bytes::from(buffer);

        Ok(Message {
            data,
            protocol: Arc::clone(&self.protocol),
        })
    }

    async fn close(&self) -> Result<()> {
        self.conn.close(0u32.into(), b"Goodbye");
        Ok(())
    }

    fn peer_id(&self) -> &PeerId {
        &self.peer_id
    }
}
