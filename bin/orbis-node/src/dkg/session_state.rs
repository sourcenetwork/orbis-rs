//! DKG Session State Management
//!
//! This module tracks the state of DKG sessions including active connections,
//! protocol phases, and peer information.

use network::Connection;
use std::collections::HashMap;
use std::sync::Arc;
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

/// State for a DKG session including connections and phase tracking
pub struct DkgSessionState {
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
    /// Processed message IDs for deduplication (session_id, from_node_id, message_type_discriminant)
    pub processed_messages: std::collections::HashSet<(u64, u32, String)>,
}

impl DkgSessionState {
    pub fn new(total_participants: usize) -> Self {
        Self {
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
pub struct SessionStateManager {
    /// session_id -> session state
    pub(crate) states: Arc<RwLock<HashMap<u64, DkgSessionState>>>,
}

impl SessionStateManager {
    pub fn new() -> Self {
        Self {
            states: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Execute a function with read-only access to a session state
    pub async fn with_state<F, R>(&self, session_id: &u64, f: F) -> Option<R>
    where
        F: FnOnce(&DkgSessionState) -> R,
    {
        let states = self.states.read().await;
        states.get(session_id).map(f)
    }

    /// Execute a function with mutable access to a session state
    pub async fn with_state_mut<F, R>(&self, session_id: &u64, f: F) -> Option<R>
    where
        F: FnOnce(&mut DkgSessionState) -> R,
    {
        let mut states = self.states.write().await;
        states.get_mut(session_id).map(f)
    }

    pub async fn create_session(&self, session_id: u64, total_participants: usize) {
        let mut states = self.states.write().await;
        states.insert(session_id, DkgSessionState::new(total_participants));
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
            state.node_id_to_peer_id = node_id_to_peer_id.clone();
            // Build reverse mapping
            state.peer_id_to_node_id = node_id_to_peer_id
                .into_iter()
                .map(|(k, v)| (v, k))
                .collect();
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
        message_type: &str,
    ) -> bool {
        let states = self.states.read().await;
        if let Some(state) = states.get(session_id) {
            state.processed_messages.contains(&(
                *session_id,
                from_node_id,
                message_type.to_string(),
            ))
        } else {
            false
        }
    }

    /// Mark a message as processed
    pub async fn mark_message_processed(
        &self,
        session_id: &u64,
        from_node_id: u32,
        message_type: String,
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
}

impl Default for SessionStateManager {
    fn default() -> Self {
        Self::new()
    }
}
