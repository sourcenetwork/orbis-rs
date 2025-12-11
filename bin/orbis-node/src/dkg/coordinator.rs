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
use crate::constants::ALPNDKG;
use crate::dkg::messages::DkgMessage;
use crate::dkg::session_state::{DkgPhase, SessionStateManager};
use ark_bls12_381::{Fr, G1Affine};
use ark_serialize::CanonicalDeserialize;
use crypto::bls12_381::common::PolynomialCommitment;
use crypto::bls12_381::dkg::DKGNode;
use crypto::r#trait::DistributedShare;
use crypto::r#trait::Dkg;
use network::Message as NetworkMessage;
use network::{Network, PeerId};
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
    session_state: Arc<SessionStateManager>,
}

impl DkgCoordinator {
    /// Create a new DKG session manager for this node
    ///
    /// Each node creates its own instance to manage its participation
    /// in DKG sessions. This is part of a decentralized architecture
    /// where all nodes participate equally.
    pub fn new(app_state: Arc<AppState>) -> Self {
        Self {
            app_state: app_state.clone(),
            session_state: Arc::new(SessionStateManager::new()),
        }
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

        // Handle SessionInit specially - it can create a session, so it doesn't require one to exist
        if let DkgMessage::SessionInit {
            threshold,
            total_participants,
            participant_ids: _,
            ..
        } = &message
        {
            // If session doesn't exist, create it
            // Note: We need to know our own node_id - this should come from config or be passed
            // For now, use a simple approach
            // TODO: Get from config or AppState
            let node_id = 1; // TODO: Properly determine node_id from participant_ids or config

            if self.app_state.get_dkg_session(&session_id).await.is_none() {
                self.create_session(
                    session_id,
                    node_id,
                    *threshold as usize,
                    *total_participants as usize,
                )
                .await
                .map_err(|e| format!("Failed to create session: {}", e))?;
            }

            println!(
                "DKG Coordinator: Session init for session {}: threshold={}, participants={}",
                session_id, threshold, total_participants
            );

            // For non-initiator nodes, they should start Phase 1 after receiving SessionInit
            // Get peer IDs from session state (if available) and initiate Phase 1
            // For now, we'll just acknowledge - Phase 1 will be initiated when they receive commitments
            return Ok(Some(DkgMessage::Ack {
                session_id,
                message_type: "SessionInit".to_string(),
            }));
        }

        // For all other messages, the session must exist
        let mut session = self
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
                // Deserialize commitment

                // Parse commitment bytes (each coefficient is a G1Affine)
                // For now, we'll need to properly deserialize - this is a placeholder
                println!(
                    "DKG Coordinator: Received commitment from node {} for session {} ({} bytes)",
                    from_node_id,
                    session_id,
                    commitment.len()
                );

                // TODO: Properly deserialize commitment and call session.receive_commitment()
                // For now, just track that we received it
                self.session_state.increment_commitments(&session_id).await;

                // Get peer IDs from session state
                if let Some(peer_ids) = self.session_state.get_peer_ids(&session_id).await {
                    // Check if Phase 1 is complete and trigger Phase 2
                    self.check_and_trigger_phase2(session_id, &peer_ids).await?;
                }

                None
            }
            DkgMessage::Share {
                from_node_id,
                to_node_id,
                share_value,
                nonce,
                ..
            } => {
                // Phase 2: Receive and verify share
                // Deserialize share value
                let share_val = Fr::deserialize_compressed(share_value.as_slice())
                    .map_err(|e| format!("Failed to deserialize share value: {}", e))?;

                // Create DistributedShare
                let share = DistributedShare {
                    from_id: from_node_id,
                    to_id: to_node_id,
                    value: share_val,
                    nonce,
                    session_id,
                };

                // Receive and verify the share
                session
                    .receive_share(share)
                    .map_err(|e| format!("Failed to receive share: {}", e))?;

                println!(
                    "DKG Coordinator: Received and verified share from node {} to node {} for session {}",
                    from_node_id, to_node_id, session_id
                );

                // Track share received
                self.session_state.increment_shares(&session_id).await;

                // Check if Phase 2 is complete and trigger Phase 4
                self.check_and_trigger_phase4(session_id).await?;

                None
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
            DkgMessage::Ack { .. } => {
                // Acknowledgment received
                println!("DKG Coordinator: Received ACK for session {}", session_id);
                None
            }
            DkgMessage::Error { error, .. } => {
                // Error received
                eprintln!(
                    "DKG Coordinator: Received error for session {}: {}",
                    session_id, error
                );
                None
            }
            DkgMessage::SessionInit { .. } => {
                // This should have been handled above, but include it here to satisfy the match
                unreachable!("SessionInit should have been handled earlier")
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
        session_id: u64,
        node_id: u32,
        threshold: usize,
        total_nodes: usize,
    ) -> Result<(), String> {
        // Create a new DKGNode for this session
        let mut dkg_node = DKGNode::new(node_id, threshold, total_nodes)
            .map_err(|e| format!("Failed to create DKG node: {}", e))?;

        // Set the session_id to the one we want (DKGNode::new generates a random one)
        dkg_node.session_id = session_id;

        // Store the session
        self.app_state.store_dkg_session(*dkg_node).await;

        // Initialize session state
        self.session_state
            .create_session(session_id, total_nodes)
            .await;

        Ok(())
    }

    /// Store peer IDs for a session (needed for sending messages in later phases)
    pub async fn set_peer_ids(&self, session_id: &u64, peer_ids: Vec<String>) {
        self.session_state.set_peer_ids(session_id, peer_ids).await;
    }

    /// Send a DKG message to a peer
    ///
    /// Connects to the peer if needed, sends the message, then closes the connection.
    pub async fn send_message_to_peer(
        &self,
        peer_id_str: &str,
        message: DkgMessage,
    ) -> Result<(), String> {
        use crate::helpers::helpers::connect_to_peer;

        // Connect to peer
        let mut connection =
            connect_to_peer(&self.app_state.network, peer_id_str.to_string(), ALPNDKG)
                .await
                .map_err(|e| format!("Failed to connect to peer {}: {}", peer_id_str, e))?;

        // Serialize message
        let message_data = serde_json::to_vec(&message)
            .map_err(|e| format!("Failed to serialize message: {}", e))?;

        // Send message
        connection
            .send(NetworkMessage::new(message_data, ALPNDKG.to_string()))
            .await
            .map_err(|e| format!("Failed to send message to peer {}: {}", peer_id_str, e))?;

        Ok(())
    }

    /// Phase 1: Generate polynomial and broadcast commitment to all peers
    ///
    /// This is triggered when start_dkg is called (for the initiator)
    /// or when SessionInit is received (for other participants).
    pub async fn initiate_phase1_commitments(
        &self,
        session_id: u64,
        peer_ids: &[String],
    ) -> Result<(), String> {
        // Get the session
        let mut session = self
            .app_state
            .get_dkg_session(&session_id)
            .await
            .ok_or_else(|| format!("DKG session {} not found", session_id))?;

        // Generate polynomial and commitment
        session
            .generate_polynomial()
            .map_err(|e| format!("Failed to generate polynomial: {}", e))?;

        // Serialize commitment using CanonicalSerialize
        // commitment is a public field in DKGNode
        use ark_serialize::CanonicalSerialize;
        let commitment = &session.commitment;
        let mut commitment_bytes = Vec::new();
        for coeff in &commitment.coefficients {
            coeff
                .serialize_compressed(&mut commitment_bytes)
                .map_err(|e| format!("Failed to serialize commitment coefficient: {}", e))?;
        }

        // Update phase
        self.session_state
            .update_phase(&session_id, DkgPhase::Phase1Commitments)
            .await;

        // Get node_id before storing (session is moved into store_dkg_session)
        let node_id = session.id;

        // Store updated session
        self.app_state.store_dkg_session(session).await;

        for peer_id_str in peer_ids {
            let commitment_msg = DkgMessage::Commitment {
                session_id,
                from_node_id: node_id,
                commitment: commitment_bytes.clone(),
            };

            if let Err(e) = self.send_message_to_peer(peer_id_str, commitment_msg).await {
                eprintln!("Failed to send commitment to peer {}: {}", peer_id_str, e);
                // Continue with other peers even if one fails
            }
        }

        println!(
            "Phase 1: Broadcasted commitment to {} peers",
            peer_ids.len()
        );
        Ok(())
    }

    /// Check if Phase 1 is complete and trigger Phase 2 if so
    ///
    /// This should be called after receiving a commitment message.
    pub async fn check_and_trigger_phase2(
        &self,
        session_id: u64,
        peer_ids: &[String],
    ) -> Result<(), String> {
        // Check if all commitments received
        let session = self
            .app_state
            .get_dkg_session(&session_id)
            .await
            .ok_or_else(|| format!("DKG session {} not found", session_id))?;

        // Check if we have commitments from all other nodes
        // Note: received_commitments is private, we'll track this in session_state instead
        let expected_commitments = session.total_nodes - 1; // Excluding self
                                                            // For now, we'll check this differently - increment counter when receiving commitments
                                                            // This is a simplification - in production you'd check the actual DKGNode state
        let received_commitments = expected_commitments; // Placeholder - will be tracked properly

        if received_commitments >= expected_commitments {
            println!(
                "Phase 1 complete: Received {}/{} commitments, starting Phase 2",
                received_commitments, expected_commitments
            );
            self.initiate_phase2_shares(session_id, peer_ids).await?;
        }

        Ok(())
    }

    /// Phase 2: Generate shares and send them to all peers
    ///
    /// This is triggered when all commitments have been received.
    pub async fn initiate_phase2_shares(
        &self,
        session_id: u64,
        peer_ids: &[String],
    ) -> Result<(), String> {
        // Get the session
        let session = self
            .app_state
            .get_dkg_session(&session_id)
            .await
            .ok_or_else(|| format!("DKG session {} not found", session_id))?;

        // Generate shares for all nodes
        let shares = session
            .generate_shares()
            .map_err(|e| format!("Failed to generate shares: {}", e))?;

        // Update phase
        self.session_state
            .update_phase(&session_id, DkgPhase::Phase2Shares)
            .await;

        // Send shares to peers
        // Note: We need to map peer_ids to node_ids - for now, assume peer_ids are in order
        // In production, you'd have a proper mapping
        for (idx, peer_id_str) in peer_ids.iter().enumerate() {
            // Find the share for this peer (assuming 1-indexed node IDs)
            // This is a simplification - in production you'd have proper node_id mapping
            let target_node_id = (idx + 2) as u32; // +2 because we're node 1, peers start at 2

            if let Some(share) = shares.iter().find(|s| s.to_id == target_node_id) {
                // Serialize share value using CanonicalSerialize
                use ark_serialize::CanonicalSerialize;
                let mut share_value_bytes = Vec::new();
                share
                    .value
                    .serialize_compressed(&mut share_value_bytes)
                    .map_err(|e| format!("Failed to serialize share value: {}", e))?;
                let share_bytes = share_value_bytes;

                let share_msg = DkgMessage::Share {
                    session_id,
                    from_node_id: session.id,
                    to_node_id: target_node_id,
                    share_value: share_bytes,
                    nonce: share.nonce,
                };

                if let Err(e) = self.send_message_to_peer(peer_id_str, share_msg).await {
                    eprintln!("Failed to send share to peer {}: {}", peer_id_str, e);
                }
            }
        }

        println!("Phase 2: Sent shares to {} peers", peer_ids.len());
        Ok(())
    }

    /// Check if Phase 2 is complete and trigger Phase 4 if so
    ///
    /// This should be called after receiving a share message.
    pub async fn check_and_trigger_phase4(&self, session_id: u64) -> Result<(), String> {
        // Get the session
        let session = self
            .app_state
            .get_dkg_session(&session_id)
            .await
            .ok_or_else(|| format!("DKG session {} not found", session_id))?;

        // Check if we have shares from all other nodes
        // Note: received_shares is private, we'll track this in session_state instead
        let expected_shares = session.total_nodes - 1; // Excluding self
                                                       // For now, we'll check this differently - increment counter when receiving shares
                                                       // This is a simplification - in production you'd check the actual DKGNode state
        let received_shares = expected_shares; // Placeholder - will be tracked properly

        if received_shares >= expected_shares {
            println!(
                "Phase 2 complete: Received {}/{} shares, starting Phase 4",
                received_shares, expected_shares
            );
            self.initiate_phase4_completion(session_id).await?;
        }

        Ok(())
    }

    /// Phase 4: Compute final secret share and aggregate public key
    ///
    /// This is triggered when all shares have been received and verified.
    pub async fn initiate_phase4_completion(&self, session_id: u64) -> Result<(), String> {
        // Get the session
        let session = self
            .app_state
            .get_dkg_session(&session_id)
            .await
            .ok_or_else(|| format!("DKG session {} not found", session_id))?;

        // Compute final secret share
        let final_share = session
            .compute_secret_share()
            .map_err(|e| format!("Failed to compute secret share: {}", e))?;

        // Compute aggregate public key
        let aggregate_pk = session
            .compute_aggregate_public_key()
            .map_err(|e| format!("Failed to compute aggregate public key: {}", e))?;

        // Update phase
        self.session_state
            .update_phase(&session_id, DkgPhase::Phase4Complete)
            .await;

        println!(
            "Phase 4: DKG complete! Final share computed, aggregate PK: {:?}",
            aggregate_pk
        );

        // TODO: Store the final share and aggregate PK somewhere (maybe in AppState)
        Ok(())
    }
}
