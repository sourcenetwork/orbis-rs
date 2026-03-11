//! DKG Session State Management
//!
//! This module tracks the state of DKG sessions including active connections,
//! protocol phases, peer information, and the cryptographic DKG node state.
//!
//! `DkgSessionState` combines both the protocol state (phase tracking, connections,
//! message deduplication) and the cryptographic state (the DKG node itself) into
//! a single unified structure.

use crate::constants::{
    DKG_PHASE_TIMEOUT, MAX_DKG_SESSIONS, SESSION_EXPIRATION_CHECK_INTERVAL, SESSION_TTL,
};
use crate::dkg::error::DkgError;
use crate::metrics;
use crypto::r#trait::{Dkg, DkgMode};
use network::Connection;
use std::collections::{HashMap, HashSet};
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
    /// When the current phase started (reset on every phase transition)
    pub phase_started_at: Instant,
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
    /// Set when this is a PSS refresh session; causes generate_polynomial to use DkgMode::Refresh
    pub is_refresh: bool,
    /// Local-storage key (`aggregate_pk.to_string()`) of the ring being refreshed.
    ///
    /// Present only for PSS refresh sessions. Phase 4 uses this to load the old share,
    /// add the refresh delta, and store the combined share under the same key so the
    /// ring public key and local-storage slot are unchanged.
    pub refresh_ring_key: Option<String>,
}

impl<D: Dkg> DkgSessionState<D> {
    /// Create a new DKG session state with the given DKG node
    pub fn new(node: D, total_participants: usize) -> Self {
        Self {
            node,
            created_at: Instant::now(),
            phase: DkgPhase::Initializing,
            phase_started_at: Instant::now(),
            connections: HashMap::new(),
            node_id_to_peer_id: HashMap::new(),
            peer_id_to_node_id: HashMap::new(),
            peer_ids: Vec::new(),
            total_participants,
            commitments_received: 0,
            shares_received: 0,
            processed_messages: std::collections::HashSet::new(),
            is_refresh: false,
            refresh_ring_key: None,
        }
    }

    /// Generate the polynomial for this session.
    ///
    /// Uses `DkgMode::Refresh` for PSS refresh sessions (zero constant term, same secret),
    /// otherwise uses `DkgMode::Fresh` (standard DKG).
    pub fn generate_polynomial(&mut self) -> Result<(), DkgError> {
        let mode = if self.is_refresh {
            DkgMode::Refresh
        } else {
            DkgMode::Fresh
        };
        self.node
            .generate_polynomial(mode)
            .map_err(|e| DkgError::Crypto(format!("Failed to generate polynomial: {}", e)))
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
    /// Ring public key strings that currently have an in-progress refresh session.
    /// Cleared on Phase 4 success (via unmark_ring_refreshing) or on session
    /// cleanup/expiration so that a new refresh can be initiated after failure.
    rings_refreshing: Arc<RwLock<HashSet<String>>>,
}

impl<D: Dkg + 'static> SessionStateManager<D> {
    /// Create a new SessionStateManager and spawn background tasks
    pub fn new() -> Self {
        let (cleanup_tx, cleanup_rx) = mpsc::unbounded_channel();
        let states = Arc::new(RwLock::new(HashMap::new()));
        let rings_refreshing = Arc::new(RwLock::new(HashSet::new()));

        // Spawn background cleanup task (handles guard-triggered cleanup)
        let states_clone = states.clone();
        let refreshing_clone = rings_refreshing.clone();
        tokio::spawn(async move {
            Self::cleanup_worker(states_clone, cleanup_rx, refreshing_clone).await;
        });

        // Spawn background expiration task (handles abandoned sessions)
        let states_clone = states.clone();
        let refreshing_clone = rings_refreshing.clone();
        tokio::spawn(async move {
            Self::expiration_worker(states_clone, refreshing_clone).await;
        });

        Self {
            states,
            cleanup_tx,
            rings_refreshing,
        }
    }

    /// Background task that processes cleanup requests from guards
    async fn cleanup_worker(
        states: Arc<RwLock<HashMap<u64, DkgSessionState<D>>>>,
        mut rx: mpsc::UnboundedReceiver<u64>,
        rings_refreshing: Arc<RwLock<HashSet<String>>>,
    ) {
        while let Some(session_id) = rx.recv().await {
            let mut states = states.write().await;
            if let Some(state) = states.remove(&session_id) {
                // If this was a refresh session, unblock the ring so future refreshes can proceed.
                if state.is_refresh {
                    if let Some(ring_key) = &state.refresh_ring_key {
                        rings_refreshing.write().await.remove(ring_key);
                        tracing::debug!(
                            session_id = session_id,
                            ring_key = %ring_key,
                            "SessionStateManager: Cleared in-progress refresh flag on cleanup"
                        );
                    }
                }
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
    async fn expiration_worker(
        states: Arc<RwLock<HashMap<u64, DkgSessionState<D>>>>,
        rings_refreshing: Arc<RwLock<HashSet<String>>>,
    ) {
        let mut interval = tokio::time::interval(SESSION_EXPIRATION_CHECK_INTERVAL);

        loop {
            interval.tick().await;

            let now = Instant::now();
            let mut states = states.write().await;
            let initial_count = states.len();

            // Collect refresh ring keys for sessions that are about to be removed so we
            // can clear their in-progress flags after the retain loop.
            let mut refresh_keys_to_clear: Vec<String> = Vec::new();

            states.retain(|session_id, state| {
                // Skip completed sessions — they'll be removed by remove_session()
                if state.phase == DkgPhase::Phase4Complete {
                    return true;
                }

                let age = now.duration_since(state.created_at);
                if age > SESSION_TTL {
                    metrics::record_dkg_session_abandoned();
                    tracing::warn!(
                        session_id = session_id,
                        age_secs = age.as_secs(),
                        phase = ?state.phase,
                        "SessionStateManager: Removing expired DKG session"
                    );
                    if state.is_refresh {
                        if let Some(k) = &state.refresh_ring_key {
                            refresh_keys_to_clear.push(k.clone());
                        }
                    }
                    return false;
                }

                // Phase-level timeout: if a non-initial phase has stalled, remove it
                let phase_age = now.duration_since(state.phase_started_at);
                if phase_age > DKG_PHASE_TIMEOUT && state.phase != DkgPhase::Initializing {
                    metrics::record_dkg_session_abandoned();
                    tracing::warn!(
                        session_id = session_id,
                        phase = ?state.phase,
                        phase_age_secs = phase_age.as_secs(),
                        "SessionStateManager: Removing DKG session stalled in phase"
                    );
                    if state.is_refresh {
                        if let Some(k) = &state.refresh_ring_key {
                            refresh_keys_to_clear.push(k.clone());
                        }
                    }
                    return false;
                }

                true // keep
            });

            // Clear in-progress refresh flags for expired sessions
            if !refresh_keys_to_clear.is_empty() {
                let mut refreshing = rings_refreshing.write().await;
                for key in &refresh_keys_to_clear {
                    refreshing.remove(key);
                    tracing::debug!(
                        ring_key = %key,
                        "SessionStateManager: Cleared in-progress refresh flag on expiration"
                    );
                }
            }

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

    /// Atomically check whether a ring refresh is in progress and mark it if not.
    ///
    /// Returns `true` if the ring was successfully marked (no refresh was in progress).
    /// Returns `false` if a refresh is already in progress for this ring.
    pub async fn try_mark_ring_refreshing(&self, ring_pk_hex: &str) -> bool {
        self.rings_refreshing
            .write()
            .await
            .insert(ring_pk_hex.to_string())
    }

    /// Clear the in-progress refresh flag for a ring (called on Phase 4 success).
    pub async fn unmark_ring_refreshing(&self, ring_pk_hex: &str) {
        self.rings_refreshing.write().await.remove(ring_pk_hex);
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
        if total_participants == 0 {
            tracing::warn!(
                session_id = session_id,
                "Cannot create DKG session with zero participants"
            );
            return false;
        }

        let mut states = self.states.write().await;

        // Enforce maximum concurrent session limit to prevent resource exhaustion
        if states.len() >= MAX_DKG_SESSIONS {
            tracing::warn!(
                session_id = session_id,
                active_sessions = states.len(),
                max_sessions = MAX_DKG_SESSIONS,
                "DKG session limit reached, rejecting new session"
            );
            return false;
        }

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

    /// Mark a session as a PSS refresh ceremony.
    ///
    /// Must be called before `initiate_phase1_commitments` so that
    /// `generate_polynomial` uses `DkgMode::Refresh` instead of `DkgMode::Fresh`.
    pub async fn mark_as_refresh(&self, session_id: &u64) {
        let mut states = self.states.write().await;
        if let Some(state) = states.get_mut(session_id) {
            state.is_refresh = true;
        }
    }

    /// Store the local-storage key of the ring being refreshed.
    ///
    /// Must be called before Phase 4 runs.  Phase 4 will load the old share from
    /// `RingKey(key)`, add the refresh delta, and write the result back to the
    /// same slot — preserving the ring public key.
    pub async fn set_refresh_ring_key(&self, session_id: &u64, key: String) {
        let mut states = self.states.write().await;
        if let Some(state) = states.get_mut(session_id) {
            state.refresh_ring_key = Some(key);
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
            state.phase_started_at = Instant::now();
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

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::r#trait::DkgRole;
    use crypto::DkgImpl;
    use std::sync::Arc;

    /// Create a minimal DkgImpl node for state-manager tests.
    /// The state manager stores the node but never calls protocol methods on it,
    /// so any valid construction is fine here.
    fn make_node(id: u32) -> DkgImpl {
        *DkgImpl::new(id, 2, 3, 0, DkgRole::Standard).expect("DkgImpl::new failed")
    }

    // =========================================================================
    // Session creation
    // =========================================================================

    #[tokio::test]
    async fn test_create_session_success() {
        let mgr = SessionStateManager::<DkgImpl>::new();
        let ok = mgr.create_session(1, make_node(1), 3).await;
        assert!(ok, "first create should succeed");
        assert_eq!(mgr.session_count().await, 1);
    }

    #[tokio::test]
    async fn test_create_session_rejects_duplicate_id() {
        let mgr = SessionStateManager::<DkgImpl>::new();
        assert!(mgr.create_session(42, make_node(1), 3).await);
        let dup = mgr.create_session(42, make_node(2), 3).await;
        assert!(!dup, "duplicate session_id should be rejected");
        assert_eq!(mgr.session_count().await, 1, "count must not increment");
    }

    #[tokio::test]
    async fn test_create_session_rejects_zero_participants() {
        let mgr = SessionStateManager::<DkgImpl>::new();
        let ok = mgr.create_session(1, make_node(1), 0).await;
        assert!(!ok, "zero participants should be rejected");
        assert_eq!(mgr.session_count().await, 0);
    }

    #[tokio::test]
    async fn test_session_limit_enforcement() {
        let mgr = SessionStateManager::<DkgImpl>::new();

        for i in 0..MAX_DKG_SESSIONS as u64 {
            let ok = mgr.create_session(i, make_node(1), 3).await;
            assert!(ok, "create should succeed for session {}", i);
        }

        // One beyond the limit must be rejected
        let rejected = mgr
            .create_session(MAX_DKG_SESSIONS as u64, make_node(1), 3)
            .await;
        assert!(!rejected, "create should fail at session limit");
        assert_eq!(mgr.session_count().await, MAX_DKG_SESSIONS);
    }

    // =========================================================================
    // Session existence and removal
    // =========================================================================

    #[tokio::test]
    async fn test_session_exists_and_remove() {
        let mgr = SessionStateManager::<DkgImpl>::new();
        assert!(!mgr.session_exists(&7).await);

        mgr.create_session(7, make_node(1), 3).await;
        assert!(mgr.session_exists(&7).await);

        mgr.remove_session(&7).await;
        assert!(!mgr.session_exists(&7).await);
        assert_eq!(mgr.session_count().await, 0);
    }

    #[tokio::test]
    async fn test_session_count_tracks_multiple() {
        let mgr = SessionStateManager::<DkgImpl>::new();
        mgr.create_session(1, make_node(1), 3).await;
        mgr.create_session(2, make_node(1), 3).await;
        mgr.create_session(3, make_node(1), 3).await;
        assert_eq!(mgr.session_count().await, 3);

        mgr.remove_session(&2).await;
        assert_eq!(mgr.session_count().await, 2);
    }

    // =========================================================================
    // with_state / with_state_mut
    // =========================================================================

    #[tokio::test]
    async fn test_with_state_returns_none_for_missing_session() {
        let mgr = SessionStateManager::<DkgImpl>::new();
        let result = mgr.with_state(&99, |s| s.total_participants).await;
        assert!(
            result.is_none(),
            "should return None for non-existent session"
        );
    }

    #[tokio::test]
    async fn test_with_state_returns_value_for_existing_session() {
        let mgr = SessionStateManager::<DkgImpl>::new();
        mgr.create_session(5, make_node(1), 7).await;
        let participants = mgr.with_state(&5, |s| s.total_participants).await;
        assert_eq!(participants, Some(7));
    }

    // =========================================================================
    // Phase tracking
    // =========================================================================

    #[tokio::test]
    async fn test_phase_update_changes_phase_and_resets_timer() {
        let mgr = SessionStateManager::<DkgImpl>::new();
        mgr.create_session(1, make_node(1), 3).await;

        // Capture a timestamp just before the update; monotonic time guarantees
        // phase_started_at set inside update_phase will be >= this value.
        let before_update = std::time::Instant::now();
        mgr.update_phase(&1, DkgPhase::Phase1Commitments).await;

        let (phase, started_at) = mgr
            .with_state(&1, |s| (s.phase, s.phase_started_at))
            .await
            .expect("session 1 should exist");
        assert_eq!(phase, DkgPhase::Phase1Commitments);
        assert!(
            started_at >= before_update,
            "phase_started_at should be reset to >= the time update_phase was called"
        );
    }

    // =========================================================================
    // Commitment and share counters
    // =========================================================================

    #[tokio::test]
    async fn test_increment_commitment_and_share_counters() {
        let mgr = SessionStateManager::<DkgImpl>::new();
        // 3 participants: need 2 from others (total - 1)
        mgr.create_session(1, make_node(1), 3).await;

        mgr.increment_commitments(&1).await;
        let all = mgr
            .with_state(&1, |s| s.all_commitments_received())
            .await
            .unwrap();
        assert!(!all, "one commitment is not enough for 3 participants");

        mgr.increment_commitments(&1).await;
        let all = mgr
            .with_state(&1, |s| s.all_commitments_received())
            .await
            .unwrap();
        assert!(
            all,
            "two commitments should satisfy 3-participant threshold"
        );

        mgr.increment_shares(&1).await;
        mgr.increment_shares(&1).await;
        let all_shares = mgr
            .with_state(&1, |s| s.all_shares_received())
            .await
            .unwrap();
        assert!(all_shares);
    }

    // =========================================================================
    // Peer IDs
    // =========================================================================

    #[tokio::test]
    async fn test_set_and_get_peer_ids() {
        let mgr = SessionStateManager::<DkgImpl>::new();
        mgr.create_session(1, make_node(1), 3).await;

        let peers = vec!["peer-a".to_string(), "peer-b".to_string()];
        mgr.set_peer_ids(&1, peers.clone()).await;

        let got = mgr.get_peer_ids(&1).await;
        assert_eq!(got, Some(peers));
    }

    // =========================================================================
    // Message deduplication
    // =========================================================================

    #[tokio::test]
    async fn test_message_dedup() {
        let mgr = SessionStateManager::<DkgImpl>::new();
        mgr.create_session(1, make_node(1), 3).await;

        // Not yet processed
        assert!(
            !mgr.is_message_processed(&1, 2, DkgMessageType::Commitment)
                .await
        );

        mgr.mark_message_processed(&1, 2, DkgMessageType::Commitment)
            .await;

        // Now processed
        assert!(
            mgr.is_message_processed(&1, 2, DkgMessageType::Commitment)
                .await
        );

        // Different type from same node — not processed
        assert!(!mgr.is_message_processed(&1, 2, DkgMessageType::Share).await);

        // Same type, different node — not processed
        assert!(
            !mgr.is_message_processed(&1, 3, DkgMessageType::Commitment)
                .await
        );
    }

    // =========================================================================
    // Concurrent access
    // =========================================================================

    #[tokio::test]
    async fn test_concurrent_create_same_id() {
        let mgr = Arc::new(SessionStateManager::<DkgImpl>::new());
        let m1 = mgr.clone();
        let m2 = mgr.clone();
        let node1 = make_node(1);
        let node2 = make_node(2);

        let (r1, r2) = tokio::join!(
            async move { m1.create_session(42, node1, 3).await },
            async move { m2.create_session(42, node2, 3).await },
        );

        // The RwLock serialises the two writes; exactly one must win
        assert_ne!(r1, r2, "exactly one concurrent create should succeed");
        assert_eq!(mgr.session_count().await, 1);
    }

    // =========================================================================
    // Cleanup guard (RAII)
    // =========================================================================

    #[tokio::test]
    async fn test_cleanup_guard_removes_session_on_drop() {
        let mgr = Arc::new(SessionStateManager::<DkgImpl>::new());
        mgr.create_session(10, make_node(1), 3).await;
        assert!(mgr.session_exists(&10).await);

        {
            let _guard = mgr.cleanup_guard(10);
            // guard dropped here without defuse — queues cleanup
        }

        // Yield to let the cleanup worker receive from the channel and remove the session
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;

        assert!(
            !mgr.session_exists(&10).await,
            "session should be removed after guard drop"
        );
    }

    #[tokio::test]
    async fn test_cleanup_guard_defuse_prevents_cleanup() {
        let mgr = Arc::new(SessionStateManager::<DkgImpl>::new());
        mgr.create_session(11, make_node(1), 3).await;

        let guard = mgr.cleanup_guard(11);
        guard.defuse(); // signals success — no cleanup should happen

        tokio::task::yield_now().await;
        tokio::task::yield_now().await;

        assert!(
            mgr.session_exists(&11).await,
            "session should still exist after defused guard"
        );
    }

    // =========================================================================
    // Expiration worker
    // =========================================================================

    #[tokio::test(start_paused = true)]
    async fn test_expiration_worker_removes_sessions_past_ttl() {
        let mgr = Arc::new(SessionStateManager::<DkgImpl>::new());
        mgr.create_session(20, make_node(1), 3).await;

        // Backdate created_at past SESSION_TTL (std::time::Instant, not tokio time)
        {
            let mut states = mgr.states.write().await;
            if let Some(s) = states.get_mut(&20) {
                s.created_at = Instant::now() - (SESSION_TTL + std::time::Duration::from_secs(10));
            }
        }

        // Drive the tokio interval timer past the expiration check interval
        tokio::time::advance(SESSION_EXPIRATION_CHECK_INTERVAL + std::time::Duration::from_secs(1))
            .await;
        tokio::task::yield_now().await;

        assert!(
            !mgr.session_exists(&20).await,
            "session past SESSION_TTL should be removed by the expiration worker"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_expiration_worker_removes_stalled_phase() {
        let mgr = Arc::new(SessionStateManager::<DkgImpl>::new());
        mgr.create_session(30, make_node(1), 3).await;

        // Move to a non-Initializing phase and backdate phase_started_at past DKG_PHASE_TIMEOUT
        {
            let mut states = mgr.states.write().await;
            if let Some(s) = states.get_mut(&30) {
                s.phase = DkgPhase::Phase1Commitments;
                s.phase_started_at =
                    Instant::now() - (DKG_PHASE_TIMEOUT + std::time::Duration::from_secs(10));
            }
        }

        tokio::time::advance(SESSION_EXPIRATION_CHECK_INTERVAL + std::time::Duration::from_secs(1))
            .await;
        tokio::task::yield_now().await;

        assert!(
            !mgr.session_exists(&30).await,
            "session stalled past DKG_PHASE_TIMEOUT should be removed"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_expiration_worker_keeps_completed_sessions() {
        // Phase4Complete sessions are intentionally skipped by the expiration worker
        // (they wait for explicit remove_session() after the DKG result is stored).
        let mgr = Arc::new(SessionStateManager::<DkgImpl>::new());
        mgr.create_session(40, make_node(1), 3).await;

        {
            let mut states = mgr.states.write().await;
            if let Some(s) = states.get_mut(&40) {
                s.phase = DkgPhase::Phase4Complete;
                // Backdate past SESSION_TTL — worker should still skip it
                s.created_at = Instant::now() - (SESSION_TTL + std::time::Duration::from_secs(10));
            }
        }

        tokio::time::advance(SESSION_EXPIRATION_CHECK_INTERVAL + std::time::Duration::from_secs(1))
            .await;
        tokio::task::yield_now().await;

        assert!(
            mgr.session_exists(&40).await,
            "Phase4Complete sessions should not be removed by the expiration worker"
        );
    }

    // =========================================================================
    // rings_refreshing: try_mark / unmark
    // =========================================================================

    #[tokio::test]
    async fn test_try_mark_returns_true_first_call() {
        let mgr = SessionStateManager::<DkgImpl>::new();
        assert!(
            mgr.try_mark_ring_refreshing("ring_abc").await,
            "first mark should succeed (ring not yet in progress)"
        );
    }

    #[tokio::test]
    async fn test_try_mark_returns_false_when_already_in_progress() {
        let mgr = SessionStateManager::<DkgImpl>::new();
        assert!(mgr.try_mark_ring_refreshing("ring_abc").await, "first mark");
        assert!(
            !mgr.try_mark_ring_refreshing("ring_abc").await,
            "second mark for same ring should fail"
        );
        // A different ring must not be affected.
        assert!(
            mgr.try_mark_ring_refreshing("ring_xyz").await,
            "different ring should be markable independently"
        );
    }

    #[tokio::test]
    async fn test_unmark_allows_remark() {
        let mgr = SessionStateManager::<DkgImpl>::new();
        assert!(mgr.try_mark_ring_refreshing("ring_abc").await);
        assert!(
            !mgr.try_mark_ring_refreshing("ring_abc").await,
            "still in progress"
        );
        mgr.unmark_ring_refreshing("ring_abc").await;
        assert!(
            mgr.try_mark_ring_refreshing("ring_abc").await,
            "after unmark the ring should be markable again"
        );
    }

    #[tokio::test]
    async fn test_cleanup_guard_clears_ring_refreshing_flag() {
        let mgr = Arc::new(SessionStateManager::<DkgImpl>::new());

        // Create a refresh session and mark the ring as in-progress.
        mgr.create_session(50, make_node(1), 3).await;
        mgr.mark_as_refresh(&50).await;
        mgr.set_refresh_ring_key(&50, "ring_cleanup".to_string())
            .await;
        assert!(
            mgr.try_mark_ring_refreshing("ring_cleanup").await,
            "ring should be markable before any cleanup"
        );
        assert!(
            !mgr.try_mark_ring_refreshing("ring_cleanup").await,
            "ring should be blocked while in progress"
        );

        // Drop a cleanup guard without defusing — worker removes session + flag.
        {
            let _guard = mgr.cleanup_guard(50);
        }

        tokio::task::yield_now().await;
        tokio::task::yield_now().await;

        assert!(
            mgr.try_mark_ring_refreshing("ring_cleanup").await,
            "ring_refreshing flag should be cleared after cleanup guard fires"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_expiration_clears_ring_refreshing_flag() {
        let mgr = Arc::new(SessionStateManager::<DkgImpl>::new());

        // Create a refresh session and mark the ring as in-progress.
        mgr.create_session(60, make_node(1), 3).await;
        mgr.mark_as_refresh(&60).await;
        mgr.set_refresh_ring_key(&60, "ring_expire".to_string())
            .await;
        assert!(mgr.try_mark_ring_refreshing("ring_expire").await);

        // Backdate created_at past SESSION_TTL so the expiration worker evicts it.
        {
            let mut states = mgr.states.write().await;
            if let Some(s) = states.get_mut(&60) {
                s.created_at = Instant::now() - (SESSION_TTL + std::time::Duration::from_secs(10));
            }
        }

        tokio::time::advance(SESSION_EXPIRATION_CHECK_INTERVAL + std::time::Duration::from_secs(1))
            .await;
        tokio::task::yield_now().await;

        assert!(
            !mgr.session_exists(&60).await,
            "expired session should be removed"
        );
        assert!(
            mgr.try_mark_ring_refreshing("ring_expire").await,
            "ring_refreshing flag should be cleared after session expiration"
        );
    }
}
