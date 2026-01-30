//! DKG Session State Management
//!
//! This module tracks the state of DKG sessions including active connections,
//! protocol phases, peer information, and the cryptographic DKG node state.
//!
//! `DkgSessionState` combines both the protocol state (phase tracking, connections,
//! message deduplication) and the cryptographic state (the DKG node itself) into
//! a single unified structure.

use crate::constants::{SESSION_EXPIRATION_CHECK_INTERVAL, SESSION_TTL};
use crate::metrics;
use crypto::r#trait::Dkg;
use network::Connection;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::mpsc;
use tokio::sync::RwLock;

/// DKG Protocol Phase
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DkgPhase {
    /// Initialization - session created, waiting to start
    Initializing,
    /// Phase 1 - Generating polynomial and broadcasting commitments
    Phase1Commitments,
    /// Phase 2 - Generating and sending shares
    Phase2Shares,
    /// Phase 3 - Verifying shares (happens automatically)
    Phase3Verification,
    /// Phase 4 - Computing final shares
    Phase4Complete,
    /// Error state
    Error,
}

/// DKG Message Type for deduplication (more efficient than String)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DkgMessageType {
    Commitment,
    Share,
    Complaint,
    SessionInit,
    Ack,
    Error,
}

/// Unified state for a DKG session combining crypto state and protocol tracking
///
/// This struct holds both:
/// - The cryptographic DKG node (polynomial, commitments, shares)
/// - Protocol state (phase, connections, message deduplication)
pub struct DkgSessionState<D: Dkg> {
    // === Crypto State (the DKG node) ===
    /// The DKG node containing cryptographic state (polynomial, commitments, shares)
    pub node: D,

    // === Metadata ===
    /// When this session was created
    pub created_at: Instant,

    // === Protocol State ===
    /// Current protocol phase
    pub phase: DkgPhase,
    /// Connection pool: peer_id_string -> connection
    /// Connections are reused for the duration of the session
    pub connections: HashMap<String, Arc<RwLock<Box<dyn Connection>>>>,
    /// Mapping of node IDs to peer IDs for efficient routing
    pub node_id_to_peer_id: HashMap<u32, String>,
    /// Mapping of peer IDs to node IDs
    pub peer_id_to_node_id: HashMap<String, u32>,
    /// List of peer IDs for this session (for sending messages)
    pub peer_ids: Vec<String>,
    /// Expected number of participants
    pub total_participants: usize,
    /// Number of commitments received
    pub commitments_received: usize,
    /// Number of shares received
    pub shares_received: usize,
    /// Processed message IDs for deduplication (session_id, from_node_id, message_type)
    pub processed_messages: std::collections::HashSet<(u64, u32, DkgMessageType)>,
}

impl<D: Dkg> DkgSessionState<D> {
    /// Create a new DKG session state with the given DKG node
    pub fn new(node: D, total_participants: usize) -> Self {
        Self {
            node,
            created_at: Instant::now(),
            phase: DkgPhase::Initializing,
            connections: HashMap::new(),
            node_id_to_peer_id: HashMap::new(),
            peer_id_to_node_id: HashMap::new(),
            peer_ids: Vec::new(),
            total_participants,
            commitments_received: 0,
            shares_received: 0,
            processed_messages: std::collections::HashSet::new(),
        }
    }

    /// Check if all commitments have been received
    pub fn all_commitments_received(&self) -> bool {
        // We need commitments from all other nodes (total - 1, excluding self)
        self.commitments_received >= (self.total_participants - 1)
    }

    /// Check if all shares have been received
    pub fn all_shares_received(&self) -> bool {
        // We need shares from all other nodes (total - 1, excluding self)
        self.shares_received >= (self.total_participants - 1)
    }
}

/// Guard that automatically cleans up a DKG session on drop unless defused.
///
/// This implements the RAII pattern for session cleanup. Create a guard when
/// starting a session operation, and call `defuse()` when the operation completes
/// successfully. If the guard is dropped without being defused (e.g., due to an
/// early return or error), it will automatically queue the session for cleanup.
///
/// # Example
/// ```ignore
/// let guard = state_manager.cleanup_guard(session_id);
/// // ... do work that might fail ...
/// guard.defuse(); // Session completed successfully, don't clean up
/// ```
pub struct SessionCleanupGuard {
    cleanup_tx: mpsc::UnboundedSender<u64>,
    session_id: u64,
    defused: Arc<AtomicBool>,
}

impl SessionCleanupGuard {
    fn new(cleanup_tx: mpsc::UnboundedSender<u64>, session_id: u64) -> Self {
        Self {
            cleanup_tx,
            session_id,
            defused: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Prevent cleanup from running when the guard is dropped.
    /// Call this when the session completes successfully.
    pub fn defuse(self) {
        self.defused.store(true, Ordering::SeqCst);
    }
}

impl Drop for SessionCleanupGuard {
    fn drop(&mut self) {
        if !self.defused.load(Ordering::SeqCst) {
            // Queue cleanup - the background task will handle it
            if self.cleanup_tx.send(self.session_id).is_err() {
                tracing::warn!(
                    session_id = self.session_id,
                    "SessionCleanupGuard: Failed to queue session cleanup (receiver dropped)"
                );
            } else {
                tracing::debug!(
                    session_id = self.session_id,
                    "SessionCleanupGuard: Queued session for cleanup on error path"
                );
            }
        }
    }
}

/// Global session state manager
pub struct SessionStateManager<D: Dkg> {
    /// session_id -> session state
    pub(crate) states: Arc<RwLock<HashMap<u64, DkgSessionState<D>>>>,
    /// Channel for queueing session cleanup requests
    cleanup_tx: mpsc::UnboundedSender<u64>,
}

impl<D: Dkg + 'static> SessionStateManager<D> {
    /// Create a new SessionStateManager and spawn background tasks
    pub fn new() -> Self {
        let (cleanup_tx, cleanup_rx) = mpsc::unbounded_channel();
        let states = Arc::new(RwLock::new(HashMap::new()));

        // Spawn background cleanup task (handles guard-triggered cleanup)
        let states_clone = states.clone();
        tokio::spawn(async move {
            Self::cleanup_worker(states_clone, cleanup_rx).await;
        });

        // Spawn background expiration task (handles abandoned sessions)
        let states_clone = states.clone();
        tokio::spawn(async move {
            Self::expiration_worker(states_clone).await;
        });

        Self { states, cleanup_tx }
    }

    /// Background task that processes cleanup requests from guards
    async fn cleanup_worker(
        states: Arc<RwLock<HashMap<u64, DkgSessionState<D>>>>,
        mut rx: mpsc::UnboundedReceiver<u64>,
    ) {
        while let Some(session_id) = rx.recv().await {
            let mut states = states.write().await;
            if let Some(state) = states.remove(&session_id) {
                tracing::debug!(
                    session_id = session_id,
                    connections = state.connections.len(),
                    "SessionStateManager: Cleaned up abandoned session"
                );
            }
        }
        tracing::debug!("SessionStateManager: Cleanup worker shutting down");
    }

    /// Background task that periodically removes expired sessions
    ///
    /// Sessions older than SESSION_TTL that haven't completed are considered
    /// abandoned and are removed to prevent memory leaks.
    async fn expiration_worker(states: Arc<RwLock<HashMap<u64, DkgSessionState<D>>>>) {
        let mut interval = tokio::time::interval(SESSION_EXPIRATION_CHECK_INTERVAL);

        loop {
            interval.tick().await;

            let now = Instant::now();
            let mut states = states.write().await;
            let initial_count = states.len();

            states.retain(|session_id, state| {
                let age = now.duration_since(state.created_at);
                if age > SESSION_TTL && state.phase != DkgPhase::Phase4Complete {
                    metrics::record_dkg_session_abandoned();
                    tracing::warn!(
                        session_id = session_id,
                        age_secs = age.as_secs(),
                        phase = ?state.phase,
                        "SessionStateManager: Removing expired DKG session"
                    );
                    false // remove
                } else {
                    true // keep
                }
            });

            let removed = initial_count - states.len();
            if removed > 0 {
                tracing::info!(
                    removed = removed,
                    remaining = states.len(),
                    "SessionStateManager: Expired session cleanup complete"
                );
            }
        }
    }

    /// Create a cleanup guard for a session.
    ///
    /// The guard will automatically clean up the session when dropped unless
    /// `defuse()` is called. Use this to ensure sessions are cleaned up on
    /// error paths without manual cleanup code.
    pub fn cleanup_guard(&self, session_id: u64) -> SessionCleanupGuard {
        SessionCleanupGuard::new(self.cleanup_tx.clone(), session_id)
    }

    /// Execute a function with read-only access to a session state
    pub async fn with_state<F, R>(&self, session_id: &u64, f: F) -> Option<R>
    where
        F: FnOnce(&DkgSessionState<D>) -> R,
    {
        let states = self.states.read().await;
        states.get(session_id).map(f)
    }

    /// Execute a function with mutable access to a session state
    pub async fn with_state_mut<F, R>(&self, session_id: &u64, f: F) -> Option<R>
    where
        F: FnOnce(&mut DkgSessionState<D>) -> R,
    {
        let mut states = self.states.write().await;
        states.get_mut(session_id).map(f)
    }

    /// Create a new DKG session
    ///
    /// Returns false if the session already exists (to avoid overwriting existing state).
    pub async fn create_session(
        &self,
        session_id: u64,
        node: D,
        total_participants: usize,
    ) -> bool {
        let mut states = self.states.write().await;

        // Check if session already exists to avoid overwriting existing state
        if states.contains_key(&session_id) {
            tracing::warn!(
                session_id = session_id,
                "DKG session already exists for session_id"
            );
            return false;
        }

        states.insert(session_id, DkgSessionState::new(node, total_participants));
        true
    }

    /// Check if a session exists
    pub async fn session_exists(&self, session_id: &u64) -> bool {
        let states = self.states.read().await;
        states.contains_key(session_id)
    }

    /// Get the number of active sessions
    pub async fn session_count(&self) -> usize {
        let states = self.states.read().await;
        states.len()
    }

    pub async fn set_peer_ids(&self, session_id: &u64, peer_ids: Vec<String>) {
        let mut states = self.states.write().await;
        if let Some(state) = states.get_mut(session_id) {
            state.peer_ids = peer_ids;
        }
    }

    pub async fn get_peer_ids(&self, session_id: &u64) -> Option<Vec<String>> {
        let states = self.states.read().await;
        states.get(session_id).map(|s| s.peer_ids.clone())
    }

    /// Add a connection to the pool for a session
    pub async fn add_connection(
        &self,
        session_id: &u64,
        peer_id_str: String,
        connection: Box<dyn Connection>,
    ) {
        let mut states = self.states.write().await;
        if let Some(state) = states.get_mut(session_id) {
            state
                .connections
                .insert(peer_id_str, Arc::new(RwLock::new(connection)));
        }
    }

    /// Get a connection from the pool (returns Arc to avoid removing from pool)
    pub async fn get_connection(
        &self,
        session_id: &u64,
        peer_id_str: &str,
    ) -> Option<Arc<RwLock<Box<dyn Connection>>>> {
        let states = self.states.read().await;
        states
            .get(session_id)?
            .connections
            .get(peer_id_str)
            .cloned()
    }

    /// Set node_id to peer_id mappings for efficient routing
    pub async fn set_node_peer_mappings(
        &self,
        session_id: &u64,
        node_id_to_peer_id: HashMap<u32, String>,
    ) {
        let mut states = self.states.write().await;
        if let Some(state) = states.get_mut(session_id) {
            // Build both maps in a single pass to avoid cloning
            let mut node_to_peer = HashMap::new();
            let mut peer_to_node = HashMap::new();
            for (node_id, peer_id) in node_id_to_peer_id {
                node_to_peer.insert(node_id, peer_id.clone());
                peer_to_node.insert(peer_id, node_id);
            }
            state.node_id_to_peer_id = node_to_peer;
            state.peer_id_to_node_id = peer_to_node;
        }
    }

    /// Get peer_id for a node_id
    pub async fn get_peer_id_for_node(&self, session_id: &u64, node_id: u32) -> Option<String> {
        let states = self.states.read().await;
        states
            .get(session_id)?
            .node_id_to_peer_id
            .get(&node_id)
            .cloned()
    }

    /// Check if a message has already been processed (for deduplication)
    pub async fn is_message_processed(
        &self,
        session_id: &u64,
        from_node_id: u32,
        message_type: DkgMessageType,
    ) -> bool {
        let states = self.states.read().await;
        if let Some(state) = states.get(session_id) {
            state
                .processed_messages
                .contains(&(*session_id, from_node_id, message_type))
        } else {
            false
        }
    }

    /// Mark a message as processed
    pub async fn mark_message_processed(
        &self,
        session_id: &u64,
        from_node_id: u32,
        message_type: DkgMessageType,
    ) {
        let mut states = self.states.write().await;
        if let Some(state) = states.get_mut(session_id) {
            state
                .processed_messages
                .insert((*session_id, from_node_id, message_type));
        }
    }

    pub async fn update_phase(&self, session_id: &u64, phase: DkgPhase) {
        let mut states = self.states.write().await;
        if let Some(state) = states.get_mut(session_id) {
            state.phase = phase;
        }
    }

    pub async fn increment_commitments(&self, session_id: &u64) {
        let mut states = self.states.write().await;
        if let Some(state) = states.get_mut(session_id) {
            state.commitments_received += 1;
        }
    }

    pub async fn increment_shares(&self, session_id: &u64) {
        let mut states = self.states.write().await;
        if let Some(state) = states.get_mut(session_id) {
            state.shares_received += 1;
        }
    }

    /// Remove a session and clean up all associated resources
    ///
    /// This should be called after DKG Phase 4 completes to free memory
    /// and close connections. The session data is no longer needed since
    /// the private share is stored in local storage and ring info is on the bulletin.
    pub async fn remove_session(&self, session_id: &u64) {
        let mut states = self.states.write().await;
        if let Some(state) = states.remove(session_id) {
            // Connections will be dropped when state goes out of scope
            tracing::debug!(
                session_id = session_id,
                connections = state.connections.len(),
                "SessionStateManager: Removed session and closed connections"
            );
        }
    }
}

impl<D: Dkg + 'static> Default for SessionStateManager<D> {
    fn default() -> Self {
        Self::new()
    }
}
