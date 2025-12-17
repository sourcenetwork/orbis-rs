use crate::constants::{MAX_DKG_SESSIONS, MAX_PRE_RESPONSES, PRE_RESPONSE_TTL, SESSION_TTL};
use crate::dkg::session_state::SessionStateManager;
use crate::pre::messages::PreMessage;
use crypto::bls12_381::dkg::DKGNode;
use local_storage::{
    memory::MemoryStorage as LocalStorage,
    r#trait::{LocalStorage as OtherLocalStorage, LocalStorageKeys},
};
use network::IrohNetwork;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;

/// DKG session with metadata for lifecycle management
pub struct DkgSessionEntry {
    pub session: Arc<RwLock<DKGNode>>,
    pub created_at: Instant,
    pub completed: bool,
}

/// PRE response entry with timestamp for cleanup
pub struct PreResponseEntry {
    pub responses: Vec<PreMessage>,
    pub expected_count: usize,
    pub created_at: Instant,
}

/// Shared PRE response storage for collecting re-encryption responses
/// request_id -> PreResponseEntry
pub type PreResponseStorage = Arc<RwLock<HashMap<String, PreResponseEntry>>>;

/// Shared application state accessible by all gRPC endpoints
#[derive(Clone)]
pub struct AppState {
    /// Active DKG sessions: session_id -> DkgSessionEntry (with metadata)
    /// Using Arc<RwLock> to avoid cloning and allow concurrent mutable access
    pub dkg_sessions: Arc<RwLock<HashMap<u64, DkgSessionEntry>>>,
    /// Server configuration
    pub config: ServerConfig,
    /// Iroh network for node-to-node communication
    pub network: Arc<IrohNetwork>,
    /// Local Storage implementation for storing items locally
    pub local_storage: LocalStorage,
    /// Shared DKG session state manager for tracking protocol progress
    pub dkg_session_state: Arc<SessionStateManager>,
    /// Shared PRE response storage for collecting re-encryption responses
    pub pre_responses: PreResponseStorage,
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
    pub bind_address: String,
}

/// Error type for session limit exceeded
#[derive(Debug, Clone)]
pub struct SessionLimitError {
    pub current_count: usize,
    pub max_allowed: usize,
}

impl std::fmt::Display for SessionLimitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Session limit exceeded: {} sessions active, maximum is {}",
            self.current_count, self.max_allowed
        )
    }
}

impl std::error::Error for SessionLimitError {}

impl AppState {
    /// Create a new AppState instance
    pub fn new(
        bind_address: String,
        network: Arc<IrohNetwork>,
        local_storage: LocalStorage,
    ) -> Self {
        Self {
            dkg_sessions: Arc::new(RwLock::new(HashMap::new())),
            config: ServerConfig { bind_address },
            network,
            local_storage,
            dkg_session_state: Arc::new(SessionStateManager::new()),
            pre_responses: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Get a DKG session Arc by ID (returns shared reference, no cloning)
    pub async fn get_dkg_session(&self, session_id: &u64) -> Option<Arc<RwLock<DKGNode>>> {
        let sessions = self.dkg_sessions.read().await;
        sessions.get(session_id).map(|entry| entry.session.clone())
    }

    /// Store a DKG session with limit checking and automatic cleanup
    ///
    /// Returns an error if the session limit is exceeded after cleanup.
    pub async fn store_dkg_session(&self, session: DKGNode) -> Result<(), SessionLimitError> {
        let mut sessions = self.dkg_sessions.write().await;
        let session_id = session.session_id;

        // Run cleanup before checking limits
        Self::cleanup_sessions_internal(&mut sessions);

        // Check session limit
        if sessions.len() >= MAX_DKG_SESSIONS {
            return Err(SessionLimitError {
                current_count: sessions.len(),
                max_allowed: MAX_DKG_SESSIONS,
            });
        }

        sessions.insert(
            session_id,
            DkgSessionEntry {
                session: Arc::new(RwLock::new(session)),
                created_at: Instant::now(),
                completed: false,
            },
        );
        Ok(())
    }

    /// Mark a DKG session as completed
    pub async fn mark_session_completed(&self, session_id: &u64) {
        let mut sessions = self.dkg_sessions.write().await;
        if let Some(entry) = sessions.get_mut(session_id) {
            entry.completed = true;
        }
    }

    /// Clean up expired sessions (internal helper, requires write lock held)
    fn cleanup_sessions_internal(sessions: &mut HashMap<u64, DkgSessionEntry>) {
        let now = Instant::now();
        let before_count = sessions.len();

        sessions.retain(|session_id, entry| {
            let age = now.duration_since(entry.created_at);
            let should_keep = age < SESSION_TTL;
            if !should_keep {
                println!(
                    "Cleaning up expired DKG session {} (age: {:?})",
                    session_id, age
                );
            }
            should_keep
        });

        let removed = before_count - sessions.len();
        if removed > 0 {
            println!(
                "Cleaned up {} expired DKG sessions, {} remaining",
                removed,
                sessions.len()
            );
        }
    }

    /// Manually trigger session cleanup
    pub async fn cleanup_expired_sessions(&self) {
        let mut sessions = self.dkg_sessions.write().await;
        Self::cleanup_sessions_internal(&mut sessions);
    }

    /// Get current session count
    pub async fn session_count(&self) -> usize {
        let sessions = self.dkg_sessions.read().await;
        sessions.len()
    }

    /// Execute a function with mutable access to a DKG session
    /// This is more efficient than get + modify + store
    pub async fn with_dkg_session_mut<F, R>(&self, session_id: &u64, f: F) -> Option<R>
    where
        F: FnOnce(&mut DKGNode) -> R,
    {
        let sessions = self.dkg_sessions.read().await;
        let entry = sessions.get(session_id)?;
        let mut session = entry.session.write().await;
        Some(f(&mut *session))
    }

    /// Execute a function with read-only access to a DKG session
    pub async fn with_dkg_session<F, R>(&self, session_id: &u64, f: F) -> Option<R>
    where
        F: FnOnce(&DKGNode) -> R,
    {
        let sessions = self.dkg_sessions.read().await;
        let entry = sessions.get(session_id)?;
        let session = entry.session.read().await;
        Some(f(&*session))
    }

    /// Initialize PRE response collection with limit checking
    ///
    /// Returns false if the limit is exceeded
    pub async fn init_pre_response(&self, request_id: String, expected_count: usize) -> bool {
        let mut responses = self.pre_responses.write().await;

        // Cleanup expired responses first
        Self::cleanup_pre_responses_internal(&mut responses);

        // Check limit
        if responses.len() >= MAX_PRE_RESPONSES {
            eprintln!(
                "PRE response limit exceeded: {} pending, max {}",
                responses.len(),
                MAX_PRE_RESPONSES
            );
            return false;
        }

        responses.insert(
            request_id,
            PreResponseEntry {
                responses: Vec::new(),
                expected_count,
                created_at: Instant::now(),
            },
        );
        true
    }

    /// Store a PRE response
    pub async fn store_pre_response(&self, request_id: &str, message: PreMessage) {
        let mut responses = self.pre_responses.write().await;
        if let Some(entry) = responses.get_mut(request_id) {
            entry.responses.push(message);
        }
    }

    /// Get collected PRE responses
    pub async fn get_pre_responses(&self, request_id: &str) -> Option<Vec<PreMessage>> {
        let responses = self.pre_responses.read().await;
        responses
            .get(request_id)
            .map(|entry| entry.responses.clone())
    }

    /// Remove PRE response entry (cleanup after completion)
    pub async fn remove_pre_response(&self, request_id: &str) {
        let mut responses = self.pre_responses.write().await;
        responses.remove(request_id);
    }

    /// Clean up expired PRE responses (internal helper)
    fn cleanup_pre_responses_internal(responses: &mut HashMap<String, PreResponseEntry>) {
        let now = Instant::now();
        let before_count = responses.len();

        responses.retain(|request_id, entry| {
            let age = now.duration_since(entry.created_at);
            let should_keep = age < PRE_RESPONSE_TTL;
            if !should_keep {
                println!(
                    "Cleaning up expired PRE response {} (age: {:?})",
                    request_id, age
                );
            }
            should_keep
        });

        let removed = before_count - responses.len();
        if removed > 0 {
            println!(
                "Cleaned up {} expired PRE responses, {} remaining",
                removed,
                responses.len()
            );
        }
    }

    /// Manually trigger PRE response cleanup
    pub async fn cleanup_expired_pre_responses(&self) {
        let mut responses = self.pre_responses.write().await;
        Self::cleanup_pre_responses_internal(&mut responses);
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
