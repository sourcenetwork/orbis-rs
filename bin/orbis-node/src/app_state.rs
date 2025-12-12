use crypto::bls12_381::dkg::DKGNode;
use network::IrohNetwork;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Shared application state accessible by all gRPC endpoints
#[derive(Clone)]
pub struct AppState {
    /// Active DKG sessions: session_id -> Arc<RwLock<session>>
    /// Using Arc<RwLock> to avoid cloning and allow concurrent mutable access
    pub dkg_sessions: Arc<RwLock<HashMap<u64, Arc<RwLock<DKGNode>>>>>,
    /// Encryption keys: key_id -> key data
    pub encryption_keys: Arc<RwLock<HashMap<String, EncryptionKey>>>,
    /// Server configuration
    pub config: ServerConfig,
    /// Iroh network for node-to-node communication
    pub network: Arc<IrohNetwork>,
}

/// Encryption key data
#[derive(Debug, Clone)]
pub struct EncryptionKey {
    pub key_id: String,
    pub algorithm: String,
    pub created_at: i64,
    pub metadata: HashMap<String, String>,
}

/// Server configuration
#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub node_id: u32,
    pub bind_address: String,
}

impl AppState {
    /// Create a new AppState instance
    pub fn new(node_id: u32, bind_address: String, network: Arc<IrohNetwork>) -> Self {
        Self {
            dkg_sessions: Arc::new(RwLock::new(HashMap::new())),
            encryption_keys: Arc::new(RwLock::new(HashMap::new())),
            config: ServerConfig {
                node_id,
                bind_address,
            },
            network,
        }
    }

    /// Get a DKG session Arc by ID (returns shared reference, no cloning)
    pub async fn get_dkg_session(&self, session_id: &u64) -> Option<Arc<RwLock<DKGNode>>> {
        let sessions = self.dkg_sessions.read().await;
        sessions.get(session_id).cloned()
    }

    /// Store a DKG session (wraps in Arc<RwLock> if needed)
    pub async fn store_dkg_session(&self, session: DKGNode) {
        let mut sessions = self.dkg_sessions.write().await;
        let session_id = session.session_id;
        sessions.insert(session_id, Arc::new(RwLock::new(session)));
    }

    /// Execute a function with mutable access to a DKG session
    /// This is more efficient than get + modify + store
    pub async fn with_dkg_session_mut<F, R>(&self, session_id: &u64, f: F) -> Option<R>
    where
        F: FnOnce(&mut DKGNode) -> R,
    {
        let sessions = self.dkg_sessions.read().await;
        let session_lock = sessions.get(session_id)?;
        let mut session = session_lock.write().await;
        Some(f(&mut *session))
    }

    /// Execute a function with read-only access to a DKG session
    pub async fn with_dkg_session<F, R>(&self, session_id: &u64, f: F) -> Option<R>
    where
        F: FnOnce(&DKGNode) -> R,
    {
        let sessions = self.dkg_sessions.read().await;
        let session_lock = sessions.get(session_id)?;
        let session = session_lock.read().await;
        Some(f(&*session))
    }

    /// Get an encryption key by ID
    pub async fn get_encryption_key(&self, key_id: &str) -> Option<EncryptionKey> {
        let keys = self.encryption_keys.read().await;
        keys.get(key_id).cloned()
    }

    /// Store an encryption key
    pub async fn store_encryption_key(&self, key: EncryptionKey) {
        let mut keys = self.encryption_keys.write().await;
        keys.insert(key.key_id.clone(), key);
    }
}

impl std::fmt::Debug for AppState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppState")
            .field("dkg_sessions", &"<HashMap>")
            .field("encryption_keys", &"<HashMap>")
            .field("config", &self.config)
            .field("network", &"<IrohNetwork>")
            .finish()
    }
}
