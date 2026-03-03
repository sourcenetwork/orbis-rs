//! Fault-injection network wrapper for testing network partition scenarios.
//!
//! `FaultNetwork` wraps any `Arc<dyn Network>` and intercepts outbound
//! `connect()` calls for blocked peers, returning an immediate error instead
//! of attempting the real connection. This simulates node dropout and network
//! partition conditions in in-process integration tests.
//!
//! Only compiled when the `fault-injection` feature is enabled.

use crate::error::{NetworkError, Result};
use crate::r#trait::{Connection, Network, PeerId, ProtocolHandler, RouterBuilder};
use async_trait::async_trait;
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::RwLock;

struct FaultState {
    blocked_peers: RwLock<HashSet<String>>,
}

/// A network wrapper that can block outbound connections to specific peers.
///
/// Create via [`FaultNetwork::new`], which returns both the network and a
/// [`FaultNetworkController`] for controlling which peers are blocked.
pub struct FaultNetwork {
    inner: Arc<dyn Network>,
    state: Arc<FaultState>,
}

impl FaultNetwork {
    /// Wrap an existing network with fault-injection capabilities.
    ///
    /// Returns the wrapped network and a controller for blocking/unblocking peers.
    pub fn new(inner: Arc<dyn Network>) -> (Self, FaultNetworkController) {
        let state = Arc::new(FaultState {
            blocked_peers: RwLock::new(HashSet::new()),
        });
        let controller = FaultNetworkController {
            state: state.clone(),
        };
        (Self { inner, state }, controller)
    }
}

/// Controller for a [`FaultNetwork`] that can block/unblock specific peers.
///
/// Cheaply cloneable — all clones share the same underlying fault state.
#[derive(Clone)]
pub struct FaultNetworkController {
    state: Arc<FaultState>,
}

impl FaultNetworkController {
    /// Block outbound connections to `hex` (64-char hex node ID).
    pub async fn block_peer(&self, hex: &str) {
        self.state
            .blocked_peers
            .write()
            .await
            .insert(hex.to_string());
    }

    /// Unblock outbound connections to `hex`.
    pub async fn unblock_peer(&self, hex: &str) {
        self.state.blocked_peers.write().await.remove(hex);
    }

    /// Return the set of currently blocked peer hex IDs.
    pub async fn blocked_peers(&self) -> Vec<String> {
        self.state
            .blocked_peers
            .read()
            .await
            .iter()
            .cloned()
            .collect()
    }
}

#[async_trait]
impl Network for FaultNetwork {
    /// Connect to a peer, returning an immediate error if the peer is blocked.
    ///
    /// Peer IDs in this codebase are the ASCII bytes of `"hex64@ip:port"` or
    /// just `"hex64"`. We extract the 64-char hex prefix and check the blocked set.
    async fn connect(&self, peer_id: &PeerId, protocol: &[u8]) -> Result<Box<dyn Connection>> {
        if let Ok(peer_str) = std::str::from_utf8(peer_id.as_bytes()) {
            let hex_id = peer_str.split('@').next().unwrap_or(peer_str);
            if self.state.blocked_peers.read().await.contains(hex_id) {
                return Err(NetworkError::Connection(format!(
                    "FaultNetwork: peer {} blocked",
                    hex_id
                )));
            }
        }
        self.inner.connect(peer_id, protocol).await
    }

    /// Not used — FaultNetwork is always started via `create_router_builder`.
    async fn listen(&mut self, _protocol: &[u8], _handler: Box<dyn ProtocolHandler>) -> Result<()> {
        Err(NetworkError::Protocol(
            "FaultNetwork: use create_router_builder".to_string(),
        ))
    }

    fn local_peer_id(&self) -> PeerId {
        self.inner.local_peer_id()
    }

    fn local_address(&self) -> Result<String> {
        self.inner.local_address()
    }

    fn bound_addresses(&self) -> Vec<std::net::SocketAddr> {
        self.inner.bound_addresses()
    }

    fn create_router_builder(&self) -> Result<Box<dyn RouterBuilder>> {
        self.inner.create_router_builder()
    }
}
