use crate::dkg::session_state::SessionStateManager;
use crate::helpers::helpers::connect_to_peer;
use crate::pre::response_state::PreResponseManager;
use crate::sign::response_state::SignResponseManager;
use authz::r#trait::Authz;
use bulletin::r#trait::Bulletin;
use crypto::r#trait::Dkg;
use local_storage::LocalStorageImpl;
use network::{Connection, Network};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};

/// Global per-peer, per-protocol connection pool.
///
/// Each entry is keyed by `(peer_id_str, protocol_bytes)` and holds one
/// long-lived QUIC connection. Connections are opened on first use and reused
/// for all subsequent messages to that peer on that protocol, avoiding
/// repeated QUIC handshakes. Entries are evicted only on I/O errors.
pub struct PeerConnectionPool {
    connections: RwLock<HashMap<(String, Vec<u8>), Arc<Box<dyn Connection>>>>,
}

impl PeerConnectionPool {
    pub fn new() -> Self {
        Self {
            connections: RwLock::new(HashMap::new()),
        }
    }

    pub async fn get(&self, peer_id: &str, protocol: &[u8]) -> Option<Arc<Box<dyn Connection>>> {
        self.connections
            .read()
            .await
            .get(&(peer_id.to_string(), protocol.to_vec()))
            .cloned()
    }

    pub async fn insert(&self, peer_id: String, protocol: &[u8], conn: Box<dyn Connection>) {
        self.connections
            .write()
            .await
            .insert((peer_id, protocol.to_vec()), Arc::new(conn));
    }

    pub async fn remove(&self, peer_id: &str, protocol: &[u8]) {
        self.connections
            .write()
            .await
            .remove(&(peer_id.to_string(), protocol.to_vec()));
    }

    /// Get a cached connection for `peer_id_str` on `protocol`, or open and cache a new one.
    pub async fn get_or_connect(
        &self,
        network: &Arc<dyn Network>,
        peer_id_str: &str,
        protocol: &'static [u8],
    ) -> Result<Arc<Box<dyn Connection>>, network::error::NetworkError> {
        if let Some(cached) = self.get(peer_id_str, protocol).await {
            return Ok(cached);
        }
        let new_conn = Arc::new(connect_to_peer(network, peer_id_str.to_string(), protocol).await?);
        self.connections.write().await.insert(
            (peer_id_str.to_string(), protocol.to_vec()),
            new_conn.clone(),
        );
        Ok(new_conn)
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
