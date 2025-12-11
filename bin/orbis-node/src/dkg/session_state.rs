//! DKG Session State Management
//!
//! This module tracks the state of DKG sessions including active connections,
//! protocol phases, and peer information.

use network::{Connection, PeerId};
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
    /// Active connections to peers: peer_id_string -> connection
    pub connections: HashMap<String, Box<dyn Connection>>,
    /// Mapping of node IDs to peer IDs
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

    pub async fn get_state(&self, session_id: &u64) -> Option<DkgSessionState> {
        let states = self.states.read().await;
        // Note: We can't clone Box<dyn Connection>, so we'll need a different approach
        // For now, return None and we'll handle this differently
        None
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

    pub async fn add_connection(
        &self,
        session_id: &u64,
        peer_id_str: String,
        connection: Box<dyn Connection>,
    ) {
        let mut states = self.states.write().await;
        if let Some(state) = states.get_mut(session_id) {
            state.connections.insert(peer_id_str, connection);
        }
    }

    pub async fn get_connection(
        &self,
        session_id: &u64,
        peer_id_str: &str,
    ) -> Option<Box<dyn Connection>> {
        let mut states = self.states.write().await;
        states.get_mut(session_id)?.connections.remove(peer_id_str)
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
