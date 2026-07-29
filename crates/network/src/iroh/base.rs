//! Base Iroh QUIC connection implementation
//!
//! This module implements the Network trait using iroh's QUIC-based networking.

use async_trait::async_trait;
use bytes::Bytes;
use iroh::endpoint::{
    Connection as IrohConnection, RecvStream, SendStream, TransportConfig, VarInt,
};
use iroh::{Endpoint, EndpointAddr, SecretKey};
use std::collections::HashMap;
use std::net::SocketAddrV4;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{Mutex, RwLock};

use crate::error::{NetworkError, Result};
use crate::iroh::pubsub::IrohPubSub;
use crate::iroh::router::IrohRouterBuilder;
use crate::metrics;
use crate::r#trait::{
    Connection, Message, Network, PeerConnection, PeerId, ProtocolHandler,
    RouterBuilder as RouterBuilderTrait,
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
    gossip: iroh_gossip::net::Gossip,
    pubsub: Arc<IrohPubSub>,
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

    #[cfg(test)]
    pub(crate) fn gossip_for_tests(&self) -> iroh_gossip::net::Gossip {
        self.gossip.clone()
    }
}

/// Builder for IrohNetwork
#[derive(Default)]
pub struct IrohNetworkBuilder {
    config: IrohNetworkConfig,
    secret_key: Option<SecretKey>,
    bind_addr_v4: Option<SocketAddrV4>,
    private_routes_only: bool,
    idle_timeout_ms: Option<u32>,
    keep_alive_interval_ms: Option<u64>,
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

    /// Disable public relays, NAT hole-punch assistance, and the default
    /// public discovery services.
    ///
    /// This does more than skip peer *discovery* — `RelayMode::Disabled` also
    /// removes Iroh's relay-assisted NAT traversal and the relayed fallback
    /// data path used when a direct UDP connection can never be established.
    /// Knowing a peer's address (e.g. from SourceHub `NodeInfo`) is not the
    /// same as that address being directly dialable: orbis-node publishes its
    /// own local bind socket with no public-IP/NAT detection, so on any
    /// topology where direct reachability isn't already guaranteed out of
    /// band, relay is the only connectivity fallback.
    ///
    /// Use this only when every peer has an authoritative *and directly
    /// UDP-reachable* route with no NAT/firewall in the path — such as an
    /// isolated Docker network or an in-process test network. Do not enable
    /// this for production deployments where committee members run on
    /// independent infrastructure (different clouds, home/office networks,
    /// etc.), since a single unreachable member permanently fails the DKG
    /// (fresh DKG has no qualified-subset fallback). The Orbis static Gossip
    /// provider remains available for explicitly supplied peer routes.
    pub fn private_routes_only(mut self) -> Self {
        self.private_routes_only = true;
        self
    }

    /// Set the maximum idle timeout for QUIC connections (milliseconds).
    ///
    /// A connection that has been idle for this long is closed, causing the
    /// next `open_stream()` call to fail and the pool to reconnect. This
    /// bounds how long a dead connection (network partition, peer crash) can
    /// block callers.
    pub fn idle_timeout_ms(mut self, ms: u32) -> Self {
        self.idle_timeout_ms = Some(ms);
        self
    }

    /// Send QUIC keep-alives while ceremony connections are active.
    pub fn keep_alive_interval_ms(mut self, ms: u64) -> Self {
        self.keep_alive_interval_ms = Some(ms);
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

        if self.private_routes_only {
            builder = builder
                .relay_mode(iroh::RelayMode::Disabled)
                .clear_discovery();
        }

        if self.idle_timeout_ms.is_some() || self.keep_alive_interval_ms.is_some() {
            let mut transport = TransportConfig::default();
            if let Some(ms) = self.idle_timeout_ms {
                transport.max_idle_timeout(Some(VarInt::from_u32(ms).into()));
            }
            if let Some(ms) = self.keep_alive_interval_ms {
                transport.keep_alive_interval(Some(std::time::Duration::from_millis(ms)));
            }
            builder = builder.transport_config(transport);
        }

        let endpoint = builder
            .bind()
            .await
            .map_err(|e| NetworkError::Connection(format!("Failed to bind endpoint: {}", e)))?;

        let node_id = endpoint.id();
        let peer_id = PeerId::from_bytes(node_id.as_bytes());

        let static_provider = iroh::discovery::static_provider::StaticProvider::new();
        endpoint.discovery().add(static_provider.clone());
        let gossip = iroh_gossip::net::Gossip::builder()
            .max_message_size(self.config.max_message_size)
            .spawn(endpoint.clone());
        let pubsub = Arc::new(IrohPubSub::new(
            endpoint.clone(),
            gossip.clone(),
            static_provider,
        ));

        Ok(IrohNetwork {
            endpoint,
            local_peer_id: peer_id,
            config: self.config,
            handlers: Arc::new(RwLock::new(HashMap::new())),
            gossip,
            pubsub,
        })
    }
}

#[async_trait]
impl Network for IrohNetwork {
    async fn connect(&self, peer_id: &PeerId, protocol: &[u8]) -> Result<Box<dyn PeerConnection>> {
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

        Ok(Box::new(IrohPeerConnection::new(
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

    fn pubsub(&self) -> Option<Arc<dyn crate::pubsub::PubSub>> {
        Some(self.pubsub.clone())
    }

    fn create_router_builder(&self) -> Result<Box<dyn RouterBuilderTrait>> {
        Ok(Box::new(IrohRouterBuilder::new(
            self.endpoint.clone(),
            Some(self.gossip.clone()),
        )))
    }
}

/// Persistent QUIC connection to a remote peer.
///
/// Implements [`PeerConnection`] — the pool holds one of these per
/// `(peer_id, protocol)`. Callers open lightweight streams via
/// [`open_stream`] rather than sending directly on the connection.
pub struct IrohPeerConnection {
    conn: IrohConnection,
    peer_id: PeerId,
    protocol: Arc<[u8]>,
    max_message_size: usize,
}

impl IrohPeerConnection {
    pub fn new(conn: IrohConnection, max_message_size: usize) -> Self {
        let node_id = conn.remote_id();
        let peer_id = PeerId::from_bytes(node_id.as_bytes());
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
impl PeerConnection for IrohPeerConnection {
    async fn open_stream(&self) -> Result<Box<dyn Connection>> {
        let (send, recv) = self.conn.open_bi().await.map_err(|e| {
            metrics::record_send_error(&self.protocol);
            NetworkError::Connection(format!("Failed to open stream: {}", e))
        })?;
        Ok(Box::new(IrohStreamWrapper::new(
            send,
            recv,
            self.peer_id.clone(),
            Arc::clone(&self.protocol),
            self.max_message_size,
        )))
    }

    fn peer_id(&self) -> &PeerId {
        &self.peer_id
    }

    async fn close(&self) -> Result<()> {
        metrics::record_connection_closed(&self.protocol);
        self.conn.close(0u32.into(), b"Goodbye");
        Ok(())
    }
}

/// A single bi-directional QUIC stream.
///
/// Implements [`Connection`] — obtained from [`IrohPeerConnection::open_stream`]
/// or handed to a [`ProtocolHandler`] by the router for each incoming stream.
/// Messages are framed with a 4-byte big-endian length prefix.
/// The send half is finished (FIN) on drop.
pub struct IrohStreamWrapper {
    send_stream: Mutex<SendStream>,
    recv_stream: Mutex<RecvStream>,
    peer_id: PeerId,
    protocol: Arc<[u8]>,
    max_message_size: usize,
}

impl IrohStreamWrapper {
    pub fn new(
        send: SendStream,
        recv: RecvStream,
        peer_id: PeerId,
        protocol: Arc<[u8]>,
        max_message_size: usize,
    ) -> Self {
        Self {
            send_stream: Mutex::new(send),
            recv_stream: Mutex::new(recv),
            peer_id,
            protocol,
            max_message_size,
        }
    }
}

impl Drop for IrohStreamWrapper {
    fn drop(&mut self) {
        // Finish the send stream so the remote peer receives STREAM_FIN rather
        // than RESET_STREAM, allowing it to read all buffered bytes before closing.
        if let Ok(mut guard) = self.send_stream.try_lock() {
            let _ = guard.finish();
        }
    }
}

#[async_trait]
impl Connection for IrohStreamWrapper {
    async fn send(&self, message: Message) -> Result<()> {
        let start = Instant::now();
        let message_size = message.data.len();

        let len = message.data.len() as u32;
        let len_bytes = len.to_be_bytes();

        let mut stream = self.send_stream.lock().await;
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

        let mut stream = self.recv_stream.lock().await;

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

    fn peer_id(&self) -> &PeerId {
        &self.peer_id
    }
}
