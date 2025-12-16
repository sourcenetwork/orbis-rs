use crate::dkg::session_state::SessionStateManager;
use crypto::bls12_381::dkg::DKGNode;
use local_storage::{
    memory::MemoryStorage as LocalStorage,
    r#trait::{LocalStorage as OtherLocalStorage, LocalStorageKeys},
};
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
    /// Server configuration
    pub config: ServerConfig,
    /// Iroh network for node-to-node communication
    pub network: Arc<IrohNetwork>,
    /// Local Storage implementation for storing items locally
    pub local_storage: LocalStorage,
    /// Shared DKG session state manager for tracking protocol progress
    pub dkg_session_state: Arc<SessionStateManager>,
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
    pub fn new(
        node_id: u32,
        bind_address: String,
        network: Arc<IrohNetwork>,
        local_storage: LocalStorage,
    ) -> Self {
        Self {
            dkg_sessions: Arc::new(RwLock::new(HashMap::new())),
            config: ServerConfig {
                node_id,
                bind_address,
            },
            network,
            local_storage,
            dkg_session_state: Arc::new(SessionStateManager::new()),
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

    /// Get a DKG session by ring public key (for PRE)
    ///
    /// Looks up the session ID from local storage, then retrieves the session
    pub async fn get_dkg_session_by_ring_pk(&self, ring_pk: &[u8]) -> Option<Arc<RwLock<DKGNode>>> {
        // Convert ring_pk bytes to hex string for storage key
        let ring_pk_hex = hex::encode(ring_pk);

        // Retrieve session_id from local storage
        let session_id_bytes = self
            .local_storage
            .get(LocalStorageKeys::RingPkMapping(ring_pk_hex))
            .ok()??;

        // Deserialize session_id (stored as 8 bytes, u64)
        if session_id_bytes.len() != 8 {
            eprintln!(
                "Invalid session_id length in storage: expected 8, got {}",
                session_id_bytes.len()
            );
            return None;
        }

        let session_id = u64::from_le_bytes(session_id_bytes.try_into().unwrap());
        self.get_dkg_session(&session_id).await
    }

    /// Store a mapping from ring public key to DKG session ID (for PRE)
    ///
    /// This should be called after DKG completion to enable PRE lookups
    /// Stores the mapping in local storage for persistence
    pub async fn store_ring_pk_mapping(&self, ring_pk: Vec<u8>, session_id: u64) {
        // Convert ring_pk bytes to hex string for storage key
        let ring_pk_hex = hex::encode(&ring_pk);

        // Serialize session_id as 8 bytes (u64 little-endian)
        let session_id_bytes = session_id.to_le_bytes().to_vec();

        // Store in local storage
        if let Err(e) = self.local_storage.set(
            LocalStorageKeys::RingPkMapping(ring_pk_hex),
            session_id_bytes,
        ) {
            eprintln!(
                "Failed to store ring_pk mapping for session {}: {}",
                session_id, e
            );
        } else {
            println!(
                "Stored ring_pk mapping for session {} in local storage",
                session_id
            );
        }
    }
}

impl std::fmt::Debug for AppState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppState")
            .field("dkg_sessions", &"<HashMap>")
            .field("config", &self.config)
            .field("network", &"<IrohNetwork>")
            .finish()
    }
}
