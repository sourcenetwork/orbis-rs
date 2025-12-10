use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Shared application state accessible by all gRPC endpoints
#[derive(Debug, Clone)]
pub struct AppState {
    /// Active DKG sessions: session_id -> session metadata
    pub dkg_sessions: Arc<RwLock<HashMap<String, DkgSession>>>,
    /// Encryption keys: key_id -> key data
    pub encryption_keys: Arc<RwLock<HashMap<String, EncryptionKey>>>,
    /// Server configuration
    pub config: ServerConfig,
}

/// DKG session metadata
#[derive(Debug, Clone)]
pub struct DkgSession {
    pub session_id: String,
    pub threshold: u32,
    pub total_participants: u32,
    pub participant_ids: Vec<String>,
    pub status: String,
    pub created_at: i64,
    pub parameters: HashMap<String, String>,
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
    pub node_id: String,
    pub bind_address: String,
}

impl AppState {
    /// Create a new AppState instance
    pub fn new(node_id: String, bind_address: String) -> Self {
        Self {
            dkg_sessions: Arc::new(RwLock::new(HashMap::new())),
            encryption_keys: Arc::new(RwLock::new(HashMap::new())),
            config: ServerConfig {
                node_id,
                bind_address,
            },
        }
    }

    /// Get a DKG session by ID
    pub async fn get_dkg_session(&self, session_id: &str) -> Option<DkgSession> {
        let sessions = self.dkg_sessions.read().await;
        sessions.get(session_id).cloned()
    }

    /// Store a DKG session
    pub async fn store_dkg_session(&self, session: DkgSession) {
        let mut sessions = self.dkg_sessions.write().await;
        sessions.insert(session.session_id.clone(), session);
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
