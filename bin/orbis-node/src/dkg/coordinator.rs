//! DKG Session Manager
//!
//! This module implements the DKG protocol session manager for each node.
//! Each node has its own instance that manages its participation in DKG sessions.
//!
//! **Architecture: Decentralized (Peer-to-Peer)**
//!
//! This is NOT a central coordinator. Each node has its own session manager that:
//! - Manages this node's participation in DKG sessions
//! - Handles incoming messages from other nodes
//! - Maintains this node's session state
//! - Coordinates this node's protocol phases
//!
//! The DKG protocol itself is peer-to-peer with no central authority.
//! All nodes participate equally in the protocol.

use crate::app_state::AppState;
use crate::dkg::messages::DkgMessage;
use crypto::bls12_381::dkg::DKGNode;
use crypto::r#trait::Dkg;
use network::PeerId;
use std::sync::Arc;

/// DKG Session Manager
///
/// Each node has its own instance that manages this node's participation
/// in DKG sessions. This is NOT a central coordinator - the protocol is
/// decentralized with each node managing its own state.
///
/// Responsibilities:
/// - Manage this node's DKG session state
/// - Handle incoming DKG protocol messages
/// - Coordinate this node's protocol phases
/// - Use DKGNode for cryptographic operations
pub struct DkgCoordinator {
    app_state: Arc<AppState>,
}

impl DkgCoordinator {
    /// Create a new DKG session manager for this node
    ///
    /// Each node creates its own instance to manage its participation
    /// in DKG sessions. This is part of a decentralized architecture
    /// where all nodes participate equally.
    pub fn new(app_state: Arc<AppState>) -> Self {
        Self { app_state }
    }

    /// Handle an incoming DKG message
    ///
    /// Routes the message to the appropriate session and processes it
    /// according to the DKG protocol phase.
    pub async fn handle_message(
        &self,
        peer_id: &PeerId,
        message: DkgMessage,
    ) -> Result<Option<DkgMessage>, String> {
        let session_id = message.session_id();

        // Get or create the DKG session
        let session = self
            .app_state
            .get_dkg_session(&session_id)
            .await
            .ok_or_else(|| format!("DKG session {} not found", session_id))?;

        // Process the message based on its type
        let response = match message {
            DkgMessage::Commitment {
                from_node_id,
                commitment,
                ..
            } => {
                // Phase 1: Receive and store commitment
                // TODO: Deserialize commitment and call session.receive_commitment()
                println!(
                    "DKG Coordinator: Received commitment from node {} for session {}",
                    from_node_id, session_id
                );
                None // For now, no response needed
            }
            DkgMessage::Share {
                from_node_id,
                to_node_id,
                share_value,
                nonce,
                ..
            } => {
                // Phase 2: Receive and verify share
                // TODO: Deserialize share and call session.receive_share()
                println!(
                    "DKG Coordinator: Received share from node {} to node {} for session {}",
                    from_node_id, to_node_id, session_id
                );
                None // For now, no response needed
            }
            DkgMessage::Complaint {
                from_node_id,
                accused_node_id,
                reason,
                ..
            } => {
                // Phase 3: Handle complaint
                println!(
                    "DKG Coordinator: Received complaint from node {} about node {}: {}",
                    from_node_id, accused_node_id, reason
                );
                None // For now, no response needed
            }
            DkgMessage::SessionInit {
                threshold,
                total_participants,
                participant_ids: _,
                ..
            } => {
                // Initialize or update session
                println!(
                    "DKG Coordinator: Session init for session {}: threshold={}, participants={}",
                    session_id, threshold, total_participants
                );
                Some(DkgMessage::Ack {
                    session_id,
                    message_type: "SessionInit".to_string(),
                })
            }
            DkgMessage::Ack { .. } => {
                // Acknowledgment received
                println!("DKG Coordinator: Received ACK for session {}", session_id);
                None
            }
            DkgMessage::Error { error, .. } => {
                // Error received
                eprintln!("DKG Coordinator: Received error for session {}: {}", session_id, error);
                None
            }
        };

        // Save updated session state
        self.app_state.store_dkg_session(session).await;

        Ok(response)
    }

    /// Get the DKG session for a given session ID
    pub async fn get_session(&self, session_id: &u64) -> Option<DKGNode> {
        self.app_state.get_dkg_session(session_id).await
    }

    /// Create a new DKG session
    ///
    /// This is typically called when a StartDkg gRPC request is received.
    pub async fn create_session(
        &self,
        _session_id: u64,
        node_id: u32,
        threshold: usize,
        total_nodes: usize,
    ) -> Result<(), String> {
        // Create a new DKGNode for this session
        let dkg_node = DKGNode::new(node_id, threshold, total_nodes)
            .map_err(|e| format!("Failed to create DKG node: {}", e))?;

        // Store the session
        self.app_state.store_dkg_session(*dkg_node).await;

        Ok(())
    }
}
