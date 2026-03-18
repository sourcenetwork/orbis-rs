use crate::dkg::session_state::SessionStateManager;
use crate::pre::response_state::PreResponseManager;
use crate::sign::response_state::SignResponseManager;
use authz::r#trait::Authz;
use bulletin::r#trait::Bulletin;
use crypto::r#trait::Dkg;
use local_storage::LocalStorageImpl;
use network::{Connection, Network};
use network::{PeerConnection, PeerId};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};

/// Global per-peer, per-protocol connection pool.
///
/// Each entry is keyed by `(peer_id_str, protocol_bytes)` and holds one
/// persistent QUIC connection. Callers open lightweight QUIC streams via
/// [`PeerConnection::open_stream`] for individual requests or DKG sessions,
/// so concurrent sessions to the same peer run on independent streams with no
/// head-of-line blocking. The connection itself is never evicted — only
/// replaced on connection-level errors.
pub struct PeerConnectionPool {
    connections: RwLock<HashMap<(String, Vec<u8>), Arc<dyn PeerConnection>>>,
}

impl PeerConnectionPool {
    pub fn new() -> Self {
        Self {
            connections: RwLock::new(HashMap::new()),
        }
    }

    pub async fn get(&self, peer_id: &str, protocol: &[u8]) -> Option<Arc<dyn PeerConnection>> {
        self.connections
            .read()
            .await
            .get(&(peer_id.to_string(), protocol.to_vec()))
            .cloned()
    }

    pub async fn remove(&self, peer_id: &str, protocol: &[u8]) {
        self.connections
            .write()
            .await
            .remove(&(peer_id.to_string(), protocol.to_vec()));
    }

    /// Get a cached connection for `(peer_id, protocol)`, or open and cache a new one.
    ///
    /// The optimistic read avoids taking the write lock on the hot path. If two
    /// tasks race through the read-miss simultaneously, both will open a connection,
    /// but only one will be stored — the loser's connection is dropped harmlessly
    /// and the winner's is returned to both callers.
    pub async fn get_or_connect(
        &self,
        network: &Arc<dyn Network>,
        peer_id_str: &str,
        protocol: &[u8],
    ) -> Result<Arc<dyn PeerConnection>, network::error::NetworkError> {
        if let Some(cached) = self.get(peer_id_str, protocol).await {
            return Ok(cached);
        }
        let peer_id_obj = PeerId::new(peer_id_str.as_bytes().to_vec());
        let new_conn: Arc<dyn PeerConnection> =
            Arc::from(network.connect(&peer_id_obj, protocol).await?);
        let key = (peer_id_str.to_string(), protocol.to_vec());
        let mut map = self.connections.write().await;
        // Re-check under the write lock: another task may have inserted while we
        // were connecting. Prefer the existing entry to avoid displacing it.
        if let Some(existing) = map.get(&key) {
            return Ok(existing.clone());
        }
        map.insert(key, new_conn.clone());
        Ok(new_conn)
    }

    /// Open a QUIC stream to a peer, evicting and reconnecting if the cached
    /// connection is dead (e.g. closed by idle timeout or remote restart).
    pub async fn open_stream(
        &self,
        network: &Arc<dyn Network>,
        peer_id_str: &str,
        protocol: &[u8],
    ) -> Result<Box<dyn Connection>, network::error::NetworkError> {
        let conn = self.get_or_connect(network, peer_id_str, protocol).await?;
        match conn.open_stream().await {
            Ok(stream) => Ok(stream),
            Err(_) => {
                self.remove(peer_id_str, protocol).await;
                let fresh = self.get_or_connect(network, peer_id_str, protocol).await?;
                fresh.open_stream().await
            }
        }
    }
}

/// Shared application state accessible by all gRPC endpoints
#[derive(Clone)]
pub struct AppState<D>
where
    D: Dkg + Clone + 'static,
{
    /// Server configuration
    pub config: ServerConfig,
    /// Network for node-to-node communication
    pub network: Arc<dyn Network>,
    /// Local Storage implementation for storing items locally
    pub local_storage: LocalStorageImpl,
    /// DKG session state manager - handles both crypto state and protocol tracking
    pub dkg_session_state: Arc<SessionStateManager<D>>,
    /// PRE response state manager - handles PRE response collection
    pub pre_response_state: Arc<PreResponseManager>,
    /// Sign response state manager - handles threshold signing response collection
    /// and FROST nonce state between Round 1 and Round 2
    pub sign_response_state: Arc<SignResponseManager>,
    /// Authz implementation
    pub authz: Arc<dyn Authz + Send + Sync>,
    /// Bulletin implementation
    pub bulletin: Arc<dyn Bulletin + Send + Sync>,
    /// Serializes concurrent RingIndex read-modify-write operations in Phase 4.
    /// Without this, two simultaneous DKG completions can each read the same
    /// index and one will overwrite the other's appended entry.
    pub ring_index_lock: Arc<Mutex<()>>,
    /// Global per-peer, per-protocol connection pool shared across DKG, PRE, and Sign.
    pub peer_connection_pool: Arc<PeerConnectionPool>,
}

/// Server configuration
#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub bind_address: String,
}

impl<D> AppState<D>
where
    D: Dkg + Clone + 'static,
{
    /// Create a new AppState instance
    pub fn new(
        bind_address: String,
        network: Arc<dyn Network>,
        local_storage: LocalStorageImpl,
        authz: Arc<dyn Authz + Send + Sync>,
        bulletin: Arc<dyn Bulletin + Send + Sync>,
    ) -> Self {
        Self {
            config: ServerConfig { bind_address },
            network,
            local_storage,
            dkg_session_state: Arc::new(SessionStateManager::new()),
            pre_response_state: Arc::new(PreResponseManager::new()),
            sign_response_state: Arc::new(SignResponseManager::new()),
            authz,
            bulletin,
            ring_index_lock: Arc::new(Mutex::new(())),
            peer_connection_pool: Arc::new(PeerConnectionPool::new()),
        }
    }
}

impl<D> std::fmt::Debug for AppState<D>
where
    D: Dkg + Clone + 'static,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppState")
            .field("config", &self.config)
            .field("network", &"<Network>")
            .field("dkg_session_state", &"<SessionStateManager>")
            .field("pre_response_state", &"<PreResponseManager>")
            .field("sign_response_state", &"<SignResponseManager>")
            .finish()
    }
}
