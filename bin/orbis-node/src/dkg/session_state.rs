//! DKG Session State Management
//!
//! This module tracks the state of DKG sessions including active connections,
//! protocol phases, peer information, and the cryptographic DKG node state.
//!
//! `DkgSessionState` combines both the protocol state (phase tracking, connections,
//! message deduplication) and the cryptographic state (the DKG node itself) into
//! a single unified structure.

use crypto::r#trait::Dkg;
use network::Connection;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
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

/// Global session state manager
pub struct SessionStateManager<D: Dkg> {
    /// session_id -> session state
    pub(crate) states: Arc<RwLock<HashMap<u64, DkgSessionState<D>>>>,
}

impl<D: Dkg> SessionStateManager<D> {
    pub fn new() -> Self {
        Self {
            states: Arc::new(RwLock::new(HashMap::new())),
        }
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

    pub async fn create_session(&self, session_id: u64, node: D, total_participants: usize) {
        let mut states = self.states.write().await;
        states.insert(session_id, DkgSessionState::new(node, total_participants));
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

impl<D: Dkg> Default for SessionStateManager<D> {
    fn default() -> Self {
        Self::new()
    }
}
