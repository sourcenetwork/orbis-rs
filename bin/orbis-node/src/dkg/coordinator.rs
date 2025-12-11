//! DKG Coordinator
//!
//! This module implements the DKG protocol coordinator that manages sessions,
//! coordinates protocol phases, and uses DKGNode for cryptographic operations.

use crate::app_state::AppState;
use crate::dkg::messages::DkgMessage;
use crypto::bls12_381::dkg::DKGNode;
use crypto::r#trait::Dkg;
use network::PeerId;
use std::sync::Arc;

/// DKG Protocol Coordinator
///
/// Manages DKG sessions, coordinates protocol phases, and handles the
/// protocol state machine. Uses DKGNode for cryptographic operations.
pub struct DkgCoordinator {
    app_state: Arc<AppState>,
}

impl DkgCoordinator {
    /// Create a new DKG coordinator
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
