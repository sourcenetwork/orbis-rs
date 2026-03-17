//! Base Iroh QUIC connection implementation
//!
//! This module implements the Network trait using iroh's QUIC-based networking.

use async_trait::async_trait;
use bytes::Bytes;
use iroh::endpoint::{Connection as IrohConnection, RecvStream, SendStream};
use iroh::{Endpoint, EndpointAddr, SecretKey};
use std::collections::HashMap;
use std::net::SocketAddrV4;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{Mutex, RwLock};

use crate::error::{NetworkError, Result};
use crate::iroh::router::IrohRouterBuilder;
use crate::metrics;
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
    pub fn name() -> String {
        "network/iroh".to_string()
    }
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
    bind_addr_v4: Option<SocketAddrV4>,
    no_relay: bool,
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

    /// Bind the UDP socket to a specific IPv4 address instead of 0.0.0.0.
    /// Use `"127.0.0.1:0".parse().unwrap()` for loopback-only (test) nodes so
    /// that iroh advertises the loopback address and same-machine peers can
    /// connect without a relay.
    pub fn bind_addr_v4(mut self, addr: SocketAddrV4) -> Self {
        self.bind_addr_v4 = Some(addr);
        self
    }

    /// Disable the relay (DERP) server. Useful for in-process tests where all
    /// nodes are on the same machine and a relay would only add latency.
    pub fn no_relay(mut self) -> Self {
        self.no_relay = true;
        self
    }

    /// Build the IrohNetwork instance
    pub async fn build(self) -> Result<IrohNetwork> {
        let mut builder = Endpoint::builder();

        if let Some(key) = self.secret_key {
            builder = builder.secret_key(key);
        }

        if let Some(addr) = self.bind_addr_v4 {
            builder = builder.bind_addr_v4(addr);
        }

        if self.no_relay {
            builder = builder.relay_mode(iroh::RelayMode::Disabled);
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

        let start = Instant::now();

        // Convert peer_id bytes to PublicKey
        // The peer_id might be in format "node_id" or "node_id@ip:port"
        let peer_id_str = std::str::from_utf8(peer_id.as_bytes()).map_err(|_| {
            metrics::record_connection_failure(protocol);
            NetworkError::InvalidAddress("Invalid peer ID format - not UTF-8".to_string())
        })?;

        // Parse the address - could be "node_id" or "node_id@ip:port"
        let (node_id_str, socket_addr_opt) = if let Some((id, addr)) = peer_id_str.split_once('@') {
            (id, Some(addr))
        } else {
            (peer_id_str, None)
        };

        let public_key = PublicKey::from_str(node_id_str).map_err(|e| {
            metrics::record_connection_failure(protocol);
            NetworkError::InvalidAddress(format!("Invalid peer ID: {}", e))
        })?;

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
                        metrics::record_connection_failure(protocol);
                        NetworkError::InvalidAddress(format!(
                            "Failed to resolve address '{}': {}",
                            addr_str, e
                        ))
                    })?
                    .next()
                    .ok_or_else(|| {
                        metrics::record_connection_failure(protocol);
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
        let conn = self.endpoint.connect(peer_addr, &alpn).await.map_err(|e| {
            metrics::record_connection_failure(protocol);
            NetworkError::Connection(format!("Failed to connect: {}", e))
        })?;

        let duration = start.elapsed().as_secs_f64();
        metrics::record_connection_success(protocol, duration);

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
/// Uses a single persistent QUIC stream for all sends and a single persistent
/// stream for all receives on this connection. Messages are framed with a
/// 4-byte big-endian length prefix so multiple messages can share one stream.
///
/// QUIC guarantees ordered, reliable delivery within a single stream, so all
/// messages sent through `send()` arrive at the peer in the same order — no
/// cross-stream race conditions possible.
pub struct IrohConnectionWrapper {
    conn: IrohConnection,
    peer_id: PeerId,
    protocol: Arc<[u8]>,
    max_message_size: usize,
    /// Outbound stream — lazy-opened on first `send()`, reused for all subsequent sends.
    send_stream: Mutex<Option<SendStream>>,
    /// Inbound stream — lazy-accepted on first `recv()`, reused for all subsequent receives.
    recv_stream: Mutex<Option<RecvStream>>,
}

impl IrohConnectionWrapper {
    pub fn new(conn: IrohConnection, max_message_size: usize) -> Self {
        let node_id = conn.remote_id();
        let peer_id = PeerId::from_bytes(node_id.as_bytes());
        let protocol = Arc::from(conn.alpn());

        Self {
            conn,
            peer_id,
            protocol,
            max_message_size,
            send_stream: Mutex::new(None),
            recv_stream: Mutex::new(None),
        }
    }
}

impl Drop for IrohConnectionWrapper {
    fn drop(&mut self) {
        // Finish the send stream so the remote peer receives STREAM_FIN rather
        // than RESET_STREAM.  Dropping a quinn SendStream without calling
        // finish() sends RESET_STREAM, which causes the peer's read_exact() to
        // return an error and discard any data already in its receive buffer —
        // even data that was fully transmitted before the connection dropped.
        // Calling finish() here enqueues a proper FIN, allowing the peer to
        // read all buffered bytes before the connection closes.
        if let Ok(mut guard) = self.send_stream.try_lock() {
            if let Some(stream) = guard.as_mut() {
                let _ = stream.finish();
            }
        }
    }
}

#[async_trait]
impl Connection for IrohConnectionWrapper {
    async fn send(&self, message: Message) -> Result<()> {
        let start = Instant::now();
        let message_size = message.data.len();

        let len = message.data.len() as u32;
        let len_bytes = len.to_be_bytes();

        let mut guard = self.send_stream.lock().await;
        if guard.is_none() {
            // Lazy-open one bi-directional stream; we only need the send half.
            let (send, _recv) = self.conn.open_bi().await.map_err(|e| {
                metrics::record_send_error(&self.protocol);
                NetworkError::Connection(format!("Failed to open stream: {}", e))
            })?;
            *guard = Some(send);
        }
        let stream = guard.as_mut().unwrap();

        stream.write_all(&len_bytes).await.map_err(|e| {
            metrics::record_send_error(&self.protocol);
            NetworkError::Io(e.into())
        })?;
        stream.write_all(&message.data).await.map_err(|e| {
            metrics::record_send_error(&self.protocol);
            NetworkError::Io(e.into())
        })?;

        let duration = start.elapsed().as_secs_f64();
        metrics::record_message_sent(&self.protocol, message_size, duration);

        Ok(())
    }

    async fn recv(&self) -> Result<Message> {
        let start = Instant::now();

        let mut guard = self.recv_stream.lock().await;
        if guard.is_none() {
            // Lazy-accept one bi-directional stream; we only need the receive half.
            let (_send, recv) = self.conn.accept_bi().await.map_err(|e| {
                metrics::record_recv_error(&self.protocol);
                NetworkError::Connection(format!("Failed to accept stream: {}", e))
            })?;
            *guard = Some(recv);
        }
        let stream = guard.as_mut().unwrap();

        // Read the 4-byte length prefix.
        let mut len_bytes = [0u8; 4];
        stream.read_exact(&mut len_bytes).await.map_err(|e| {
            metrics::record_recv_error(&self.protocol);
            NetworkError::Connection(format!("Failed to read message length: {}", e))
        })?;
        let len = u32::from_be_bytes(len_bytes) as usize;

        if len > self.max_message_size {
            metrics::record_recv_error(&self.protocol);
            return Err(NetworkError::Connection(format!(
                "Message too large: {} bytes (max {})",
                len, self.max_message_size
            )));
        }

        let mut buffer = vec![0u8; len];
        stream.read_exact(&mut buffer).await.map_err(|e| {
            metrics::record_recv_error(&self.protocol);
            NetworkError::Connection(format!("Failed to read message data: {}", e))
        })?;

        let message_size = buffer.len();
        let duration = start.elapsed().as_secs_f64();
        metrics::record_message_received(&self.protocol, message_size, duration);

        Ok(Message {
            data: Bytes::from(buffer),
            protocol: Arc::clone(&self.protocol),
        })
    }

    async fn close(&self) -> Result<()> {
        metrics::record_connection_closed(&self.protocol);
        self.conn.close(0u32.into(), b"Goodbye");
        Ok(())
    }

    fn peer_id(&self) -> &PeerId {
        &self.peer_id
    }
}
