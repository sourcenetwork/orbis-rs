//! Network trait definitions
//!
//! This module defines the core networking abstractions that can be implemented
//! by various backends (iroh, libp2p, etc.).

use crate::error::Result;
use async_trait::async_trait;
use bytes::Bytes;
use std::sync::Arc;

use crate::ingress::{BodyReservation, IngressLease};
use crate::pubsub::PubSub;

/// Inbound work limits shared by direct protocol streams and PubSub frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkIngressLimits {
    /// Maximum inbound-request frames whose application work is executing
    /// concurrently across transports. Charged once per decoded frame (a direct
    /// request message or an authenticated PubSub frame) and released when the
    /// application finishes with it — not once per stream.
    pub max_concurrent_work: usize,
    /// Maximum reply frames (read on client-opened streams) whose application
    /// work is executing concurrently. A separate budget from
    /// `max_concurrent_work` so a request handler that fans out sub-requests and
    /// awaits their replies cannot deadlock by holding the only capacity those
    /// replies need.
    pub max_concurrent_reply_work: usize,
    /// Maximum decoded direct-stream frames and PubSub frames accepted from one
    /// immediate peer per one-second window. Charged per frame, so a single
    /// long-lived stream cannot pump unlimited messages for free. Also sizes the
    /// per-peer connection-open and stream-open rate windows.
    pub max_events_per_peer_per_second: usize,
    /// Maximum accepted-but-not-yet-closed inbound QUIC connections node-wide. A
    /// connection counts for its whole lifetime, so this bounds identities that
    /// hold connections open (kept alive by QUIC transport traffic) without ever
    /// opening an application stream.
    pub max_concurrent_connections: usize,
    /// Maximum concurrent inbound QUIC connections from one immediate peer (one
    /// endpoint key), across all ALPNs including Gossip.
    pub max_connections_per_peer: usize,
    /// Percent (0..=100) of each shared inbound budget — concurrent connections,
    /// concurrent streams, request-frame work permits, and request-frame body
    /// bytes — reserved for peers an [`AuthorizedPeers`] oracle vouches for.
    /// Unauthorized identities (a cheap self-issued endpoint key not yet a
    /// registered/committee node) are capped at `budget - budget * percent / 100`
    /// in each pool, so a Sybil flood cannot starve an authorized peer of any
    /// ingress resource. `0` (the default) disables every reservation; `100`
    /// admits unauthorized peers to nothing.
    pub authorized_reserve_percent: usize,
    /// Maximum accepted-but-not-yet-closed inbound direct streams node-wide. A
    /// stream counts from `accept_bi()` until its handler task ends; the
    /// per-frame read deadline bounds how long a stalled stream holds a slot.
    pub max_concurrent_streams: usize,
    /// Maximum concurrent inbound direct streams from one immediate peer (one
    /// endpoint key). Stops a single unauthenticated identity from occupying a
    /// large share of the node-wide stream budget.
    pub max_streams_per_peer: usize,
    /// Node-wide byte budget for inbound-request frame bodies received and not
    /// yet dropped by the application. Reserved after the length prefix is
    /// parsed but before the buffer is allocated, so a flood of large frames
    /// cannot commit gigabytes of buffers ahead of `max_concurrent_work`. Must
    /// be at least one `max_message_size`.
    pub max_inbound_request_body_bytes: usize,
    /// Node-wide byte budget for reply frame bodies (read on client-opened
    /// streams). A separate pool from `max_inbound_request_body_bytes` — the two
    /// sum to the operator's intended total — so a backlog of stalled inbound
    /// requests cannot deny an incoming MPC reply its receive buffer. Must be at
    /// least one `max_message_size`.
    pub max_inbound_reply_body_bytes: usize,
}

impl Default for NetworkIngressLimits {
    fn default() -> Self {
        Self {
            max_concurrent_work: 1024,
            max_concurrent_reply_work: 1024,
            max_events_per_peer_per_second: 512,
            max_concurrent_connections: 2048,
            max_connections_per_peer: 32,
            authorized_reserve_percent: 0,
            max_concurrent_streams: 4096,
            max_streams_per_peer: 32,
            max_inbound_request_body_bytes: 192 * 1024 * 1024,
            max_inbound_reply_body_bytes: 64 * 1024 * 1024,
        }
    }
}

/// Application-supplied oracle for whether an endpoint identity currently holds
/// an authorized role — a registered / committee node, as opposed to a cheap
/// self-issued key. Consulted through `IngressController::is_authorized` at every
/// inbound admission point that carries a reserve: connection admission, stream
/// admission, and request-frame work and body-byte reservation. An authorized
/// peer draws on the slice of each budget held back by
/// `authorized_reserve_percent`; an unauthorized one must additionally take a
/// slot in the matching shared pool, so a Sybil flood degrades availability for
/// unknown peers but never for the committee.
///
/// The answer is sampled fresh at each of those points, so a refresh can change
/// an established connection's capacity classification: streams and frames on it
/// admitted after the change are judged by the new answer. Only the connection
/// lease itself is fixed — it is classified once at accept and not re-evaluated
/// for the connection's lifetime.
///
/// The answer may be briefly stale (e.g. a peer just added by an in-flight
/// reshare); a stale "not authorized" only means that peer competes in the
/// shared pool for a short window, which is self-correcting.
pub trait AuthorizedPeers: Send + Sync {
    fn is_authorized(&self, peer: &PeerId) -> bool;
}

/// Bounded reasons why authenticated-peer ingress was dropped before
/// application processing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngressDropReason {
    RateLimit,
    ConcurrencyLimit,
}

impl IngressDropReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RateLimit => "rate_limit",
            Self::ConcurrencyLimit => "concurrency_limit",
        }
    }
}

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
    /// Holds one unit of shared ingress work capacity for a frame received from
    /// the network, released when the application drops this message (and every
    /// clone of it). `None` for a message the caller built to send.
    pub(crate) ingress_lease: Option<Arc<IngressLease>>,
    /// Holds this frame body's share of the node-wide receive-byte budget for
    /// the message's lifetime, so the budget bounds received-but-unprocessed
    /// bytes. `None` for a message the caller built to send.
    pub(crate) body_reservation: Option<Arc<BodyReservation>>,
}

impl Message {
    pub fn new(data: impl Into<Bytes>, protocol: impl Into<Arc<[u8]>>) -> Self {
        Self {
            data: data.into(),
            protocol: protocol.into(),
            ingress_lease: None,
            body_reservation: None,
        }
    }

    pub fn with_vec(data: Vec<u8>, protocol: Vec<u8>) -> Self {
        Self {
            data: Bytes::from(data),
            protocol: Arc::from(protocol.into_boxed_slice()),
            ingress_lease: None,
            body_reservation: None,
        }
    }
}

/// A single QUIC stream to a peer.
///
/// Obtained by calling [`PeerConnection::open_stream`] on a cached connection.
/// Each stream is an independent, ordered byte channel with no head-of-line
/// blocking relative to other streams on the same QUIC connection.
/// The stream is closed (FIN sent) when this value is dropped.
#[async_trait]
pub trait Connection: Send + Sync {
    /// Send a message over this stream
    async fn send(&self, message: Message) -> Result<()>;

    /// Receive a message from this stream
    async fn recv(&self) -> Result<Message>;

    /// Get the peer ID of the remote peer
    fn peer_id(&self) -> &PeerId;
}

/// A persistent QUIC connection to a peer.
///
/// One connection is kept per `(peer_id, protocol)` in the pool. Individual
/// requests and sessions open lightweight QUIC streams on top of it via
/// [`open_stream`], which avoids a new handshake per request and eliminates
/// head-of-line blocking between concurrent sessions.
#[async_trait]
pub trait PeerConnection: Send + Sync {
    /// Open a new independent QUIC stream on this connection.
    ///
    /// The returned [`Connection`] is tied to this single bi-directional stream
    /// and is dropped (sending FIN) when the caller is done.
    async fn open_stream(&self) -> Result<Box<dyn Connection>>;

    /// Get the peer ID of the remote peer
    fn peer_id(&self) -> &PeerId;

    /// Close the underlying QUIC connection
    async fn close(&self) -> Result<()>;
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
    /// Connect to a peer at the given address, returning a persistent QUIC connection.
    ///
    /// The caller should cache the returned [`PeerConnection`] and open individual
    /// streams via [`PeerConnection::open_stream`] for each request or session.
    async fn connect(&self, peer_id: &PeerId, protocol: &[u8]) -> Result<Box<dyn PeerConnection>>;

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

    /// Return the authenticated pub-sub transport, when supported by this backend.
    ///
    /// Pub-sub is deliberately a separate capability from point-to-point streams so
    /// callers must make an explicit choice about which messages are safe to publish.
    fn pubsub(&self) -> Option<Arc<dyn PubSub>> {
        None
    }

    /// Create a router builder for this network
    ///
    /// This allows registering multiple protocol handlers that will handle
    /// incoming connections based on protocol negotiation (e.g., ALPN).
    fn create_router_builder(&self) -> Result<Box<dyn RouterBuilder>>;
}
