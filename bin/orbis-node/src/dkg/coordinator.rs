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
use network::PeerId;
use std::sync::Arc;
use tokio::sync::RwLock;

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
            app_state,
            session_state: Arc::new(SessionStateManager::new()),
        }
    }

    /// Handle an incoming DKG message
    ///
    /// Routes the message to the appropriate session and processes it
    /// according to the DKG protocol phase.
    pub async fn handle_message(
        &self,
        _peer_id: &PeerId,
        message: DkgMessage,
    ) -> Result<Option<DkgMessage>, String> {
        let session_id = message.session_id();

        // Get message type and from_node_id for deduplication
        let (message_type_str, from_node_id_opt) = match &message {
            DkgMessage::Commitment { from_node_id, .. } => ("Commitment", Some(*from_node_id)),
            DkgMessage::Share { from_node_id, .. } => ("Share", Some(*from_node_id)),
            DkgMessage::Complaint { from_node_id, .. } => ("Complaint", Some(*from_node_id)),
            DkgMessage::SessionInit { .. } => ("SessionInit", None),
            DkgMessage::Ack { .. } => ("Ack", None),
            DkgMessage::Error { .. } => ("Error", None),
        };

        // Check for duplicate messages (except SessionInit, Ack, Error)
        if let Some(from_node_id) = from_node_id_opt {
            if self
                .session_state
                .is_message_processed(&session_id, from_node_id, message_type_str)
                .await
            {
                println!(
                    "DKG Coordinator: Ignoring duplicate {} from node {} for session {}",
                    message_type_str, from_node_id, session_id
                );
                return Ok(None);
            }
        }

        // Handle SessionInit specially - it can create a session, so it doesn't require one to exist
        if let DkgMessage::SessionInit {
            threshold,
            total_participants,
            participant_ids: _,
            peer_ids,
            ..
        } = &message
        {
            // If session doesn't exist, create it
            // Use the node_id from config (now u32)
            let node_id = self.app_state.config.node_id;

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

            // Store peer_ids for this session (needed for sending messages)
            self.set_peer_ids(&session_id, peer_ids.clone()).await;

            println!(
                "DKG Coordinator: Session init for session {}: threshold={}, participants={}, peer_ids={}",
                session_id, threshold, total_participants, peer_ids.len()
            );

            // For non-initiator nodes, they should start Phase 1 after receiving SessionInit
            // They now have peer_ids, so they can send commitments when they generate their polynomial
            return Ok(Some(DkgMessage::Ack {
                session_id,
                message_type: "SessionInit".to_string(),
            }));
        }

        // For all other messages, ensure the session exists
        if self.app_state.get_dkg_session(&session_id).await.is_none() {
            return Err(format!("DKG session {} not found", session_id));
        }

        // Process the message based on its type
        let response = match message {
            DkgMessage::Commitment {
                from_node_id,
                commitment,
                ..
            } => {
                // Phase 1: Receive and store commitment
                println!(
                    "DKG Coordinator: Received commitment from node {} for session {} ({} bytes)",
                    from_node_id,
                    session_id,
                    commitment.len()
                );

                // Deserialize commitment
                use ark_serialize::CanonicalDeserialize;
                let mut commitment_coeffs = Vec::new();
                let mut offset = 0;
                // Each G1Affine is 48 bytes when compressed
                while offset < commitment.len() {
                    if offset + 48 > commitment.len() {
                        break;
                    }
                    let coeff = G1Affine::deserialize_compressed(&commitment[offset..offset + 48])
                        .map_err(|e| {
                            format!("Failed to deserialize commitment coefficient: {}", e)
                        })?;
                    commitment_coeffs.push(coeff);
                    offset += 48;
                }

                let polynomial_commitment = PolynomialCommitment {
                    coefficients: commitment_coeffs,
                };

                // Update session with commitment (no cloning needed!)
                let need_to_generate_polynomial = self
                    .app_state
                    .with_dkg_session_mut(&session_id, |session| {
                        session
                            .receive_commitment(from_node_id, polynomial_commitment)
                            .map_err(|e| format!("Failed to receive commitment: {}", e))?;

                        // Check if we need to generate our polynomial
                        Ok::<_, String>(session.commitment.coefficients.is_empty())
                    })
                    .await
                    .ok_or_else(|| format!("DKG session {} not found", session_id))??;

                // Mark message as processed
                self.session_state
                    .mark_message_processed(&session_id, from_node_id, "Commitment".to_string())
                    .await;

                // Track that we received it
                self.session_state.increment_commitments(&session_id).await;

                // If this is the first commitment we receive and we haven't generated our polynomial yet,
                // we need to generate it and send our commitment
                if need_to_generate_polynomial {
                    println!("DKG Coordinator: First commitment received, generating our polynomial and sending commitment");

                    // Generate polynomial
                    self.app_state
                        .with_dkg_session_mut(&session_id, |session| {
                            session
                                .generate_polynomial()
                                .map_err(|e| format!("Failed to generate polynomial: {}", e))
                        })
                        .await
                        .ok_or_else(|| format!("DKG session {} not found", session_id))??;

                    // Get peer IDs and node_id from session to send our commitment
                    if let Some(peer_ids) = self.session_state.get_peer_ids(&session_id).await {
                        // Serialize our commitment
                        use ark_serialize::CanonicalSerialize;
                        let (commitment_bytes, node_id) = self
                            .app_state
                            .with_dkg_session(&session_id, |session| {
                                let mut bytes = Vec::new();
                                for coeff in &session.commitment.coefficients {
                                    coeff.serialize_compressed(&mut bytes).map_err(|e| {
                                        format!("Failed to serialize commitment: {}", e)
                                    })?;
                                }
                                Ok::<_, String>((bytes, session.id))
                            })
                            .await
                            .ok_or_else(|| format!("DKG session {} not found", session_id))??;

                        let mut sent_count = 0;
                        for peer_id_str in &peer_ids {
                            let commitment_msg = DkgMessage::Commitment {
                                session_id,
                                from_node_id: node_id,
                                commitment: commitment_bytes.clone(),
                            };

                            match self.send_message_to_peer(peer_id_str, commitment_msg).await {
                                Ok(_) => sent_count += 1,
                                Err(e) => {
                                    if e.contains("ourself") {
                                        continue;
                                    }
                                    eprintln!(
                                        "Failed to send commitment to peer {}: {}",
                                        peer_id_str, e
                                    );
                                }
                            }
                        }
                        println!(
                            "DKG Coordinator: Sent our commitment to {}/{} peers",
                            sent_count,
                            peer_ids.len()
                        );
                    }
                }

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

                // Receive and verify the share (mutates session in-place, no cloning!)
                self.app_state
                    .with_dkg_session_mut(&session_id, |session| {
                        session
                            .receive_share(share)
                            .map_err(|e| format!("Failed to receive share: {}", e))
                    })
                    .await
                    .ok_or_else(|| format!("DKG session {} not found", session_id))??;

                println!(
                    "DKG Coordinator: Received and verified share from node {} to node {} for session {}",
                    from_node_id, to_node_id, session_id
                );

                // Mark message as processed
                self.session_state
                    .mark_message_processed(&session_id, from_node_id, "Share".to_string())
                    .await;

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

        Ok(response)
    }

    /// Get the DKG session Arc for a given session ID
    pub async fn get_session(&self, session_id: &u64) -> Option<Arc<RwLock<DKGNode>>> {
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
        // Generate polynomial and serialize commitment
        let (commitment_bytes, node_id) = self
            .app_state
            .with_dkg_session_mut(&session_id, |session| {
                // Generate polynomial and commitment
                session
                    .generate_polynomial()
                    .map_err(|e| format!("Failed to generate polynomial: {}", e))?;

                // Serialize commitment
                use ark_serialize::CanonicalSerialize;
                let mut bytes = Vec::new();
                for coeff in &session.commitment.coefficients {
                    coeff.serialize_compressed(&mut bytes).map_err(|e| {
                        format!("Failed to serialize commitment coefficient: {}", e)
                    })?;
                }

                Ok::<_, String>((bytes, session.id))
            })
            .await
            .ok_or_else(|| format!("DKG session {} not found", session_id))??;

        // Update phase
        self.session_state
            .update_phase(&session_id, DkgPhase::Phase1Commitments)
            .await;

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
        // Check if we've generated our polynomial and how many nodes we expect
        let (has_polynomial, expected_commitments, node_id) = self
            .app_state
            .with_dkg_session(&session_id, |session| {
                (
                    !session.commitment.coefficients.is_empty(),
                    session.total_nodes - 1, // Excluding self
                    session.id,
                )
            })
            .await
            .ok_or_else(|| format!("DKG session {} not found", session_id))?;

        // First, make sure we've generated our polynomial
        if !has_polynomial {
            // Haven't generated polynomial yet, can't proceed to Phase 2
            return Ok(());
        }

        // Get the actual count from session_state
        let received_commitments = self
            .session_state
            .with_state(&session_id, |state| state.commitments_received)
            .await
            .unwrap_or(0);

        if received_commitments >= expected_commitments {
            println!(
                "Phase 1 complete: Received {}/{} commitments, starting Phase 2 (node {})",
                received_commitments, expected_commitments, node_id
            );
            self.initiate_phase2_shares(session_id, peer_ids).await?;
        } else {
            println!(
                "Phase 1 not complete yet: Received {}/{} commitments (node {})",
                received_commitments, expected_commitments, node_id
            );
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
        // Generate shares and get node_id
        let (shares, node_id) = self
            .app_state
            .with_dkg_session_mut(&session_id, |session| {
                // Make sure we've generated our polynomial
                if session.commitment.coefficients.is_empty() {
                    println!(
                        "DKG Coordinator: Generating polynomial before Phase 2 (node {})",
                        session.id
                    );
                    session
                        .generate_polynomial()
                        .map_err(|e| format!("Failed to generate polynomial: {}", e))?;
                }

                // Generate shares for all nodes
                println!(
                    "DKG Coordinator: Generating shares for node {} (session {})",
                    session.id, session_id
                );
                let shares = session
                    .generate_shares()
                    .map_err(|e| format!("Failed to generate shares: {}", e))?;

                println!("DKG Coordinator: Generated {} shares", shares.len());
                Ok::<_, String>((shares, session.id))
            })
            .await
            .ok_or_else(|| format!("DKG session {} not found", session_id))??;

        // Update phase
        self.session_state
            .update_phase(&session_id, DkgPhase::Phase2Shares)
            .await;

        if peer_ids.is_empty() {
            eprintln!("DKG Coordinator: WARNING - No peer_ids available to send shares to!");
            return Ok(());
        }

        println!(
            "DKG Coordinator: Sending {} shares to peers (node {})",
            shares.len(),
            node_id
        );

        // Send shares to peers using O(n) routing with node_id → peer_id mapping
        // Try to get mapping first, fall back to broadcast if not available
        let mut shares_sent = 0;

        for share in shares.iter() {
            // Skip sending share to ourselves
            if share.to_id == node_id {
                continue;
            }

            // Serialize share value
            use ark_serialize::CanonicalSerialize;
            let mut share_value_bytes = Vec::new();
            share
                .value
                .serialize_compressed(&mut share_value_bytes)
                .map_err(|e| format!("Failed to serialize share value: {}", e))?;

            let share_msg = DkgMessage::Share {
                session_id,
                from_node_id: node_id,
                to_node_id: share.to_id,
                share_value: share_value_bytes,
                nonce: share.nonce,
            };

            // Try to get specific peer_id for this node_id (O(1) lookup)
            if let Some(target_peer_id) = self
                .session_state
                .get_peer_id_for_node(&session_id, share.to_id)
                .await
            {
                // Direct routing: O(n) total for all shares
                match self.send_message_to_peer(&target_peer_id, share_msg).await {
                    Ok(_) => {
                        shares_sent += 1;
                        println!(
                            "DKG Coordinator: Sent share from node {} to node {} via peer {}",
                            node_id, share.to_id, target_peer_id
                        );
                    }
                    Err(e) => {
                        eprintln!(
                            "Failed to send share to node {} via peer {}: {}",
                            share.to_id, target_peer_id, e
                        );
                    }
                }
            } else {
                // Fallback: broadcast to all peers (only if mapping not set up)
                let mut sent = false;
                for peer_id_str in peer_ids {
                    match self
                        .send_message_to_peer(peer_id_str, share_msg.clone())
                        .await
                    {
                        Ok(_) => {
                            shares_sent += 1;
                            sent = true;
                            println!(
                                "DKG Coordinator: Sent share from node {} to node {} via peer {} (broadcast)",
                                node_id, share.to_id, peer_id_str
                            );
                            break;
                        }
                        Err(e) => {
                            if e.contains("ourself") {
                                continue;
                            }
                            eprintln!("Failed to send share to peer {}: {}", peer_id_str, e);
                        }
                    }
                }
                if !sent {
                    eprintln!(
                        "DKG Coordinator: Failed to send share from node {} to node {} to any peer",
                        node_id, share.to_id
                    );
                }
            }
        }

        println!(
            "Phase 2: Sent {}/{} shares to peers (node {})",
            shares_sent,
            shares.len() - 1,
            node_id
        );
        Ok(())
    }

    /// Check if Phase 2 is complete and trigger Phase 4 if so
    ///
    /// This should be called after receiving a share message.
    pub async fn check_and_trigger_phase4(&self, session_id: u64) -> Result<(), String> {
        // Get expected shares count
        let expected_shares = self
            .app_state
            .with_dkg_session(&session_id, |session| session.total_nodes - 1)
            .await
            .ok_or_else(|| format!("DKG session {} not found", session_id))?;

        // Get the actual count from session_state
        let received_shares = self
            .session_state
            .with_state(&session_id, |state| state.shares_received)
            .await
            .unwrap_or(0);

        if received_shares >= expected_shares {
            println!(
                "Phase 2 complete: Received {}/{} shares, proceeding to Phase 4",
                received_shares, expected_shares
            );

            // Verify we have all commitments before proceeding
            let has_all_commitments = self
                .app_state
                .with_dkg_session(&session_id, |session| {
                    session.compute_aggregate_public_key().is_ok()
                })
                .await
                .ok_or_else(|| format!("DKG session {} not found", session_id))?;

            if !has_all_commitments {
                println!(
                    "DKG Coordinator: Not all commitments received yet, cannot proceed to Phase 4"
                );
                return Ok(());
            }

            println!(
                "DKG Coordinator: All commitments verified, initiating Phase 4 for session {}",
                session_id
            );
            self.initiate_phase4_completion(session_id).await?;
        }

        Ok(())
    }

    /// Phase 4: Compute final secret share and aggregate public key
    ///
    /// This is triggered when all shares have been received and verified.
    pub async fn initiate_phase4_completion(&self, session_id: u64) -> Result<(), String> {
        println!(
            "DKG Coordinator: Starting Phase 4 completion for session {}",
            session_id
        );

        // Compute final secret share and aggregate public key
        let (node_id, aggregate_pk) = self
            .app_state
            .with_dkg_session(&session_id, |session| {
                println!(
                    "DKG Coordinator: Computing secret share for node {}...",
                    session.id
                );

                // Compute final secret share
                let _final_share = session
                    .compute_secret_share()
                    .map_err(|e| format!("Failed to compute secret share: {}", e))?;

                println!(
                    "DKG Coordinator: Successfully computed secret share for node {}",
                    session.id
                );

                // Compute aggregate public key
                let aggregate_pk = session
                    .compute_aggregate_public_key()
                    .map_err(|e| format!("Failed to compute aggregate public key: {}", e))?;

                println!(
                    "DKG Coordinator: Computed aggregate public key for node {}",
                    session.id
                );

                Ok::<_, String>((session.id, aggregate_pk))
            })
            .await
            .ok_or_else(|| format!("DKG session {} not found", session_id))??;

        // Update phase
        self.session_state
            .update_phase(&session_id, DkgPhase::Phase4Complete)
            .await;

        println!(
            "Phase 4: DKG complete! Final share computed, aggregate PK: {:?} (node {})",
            aggregate_pk, node_id
        );

        // TODO: Store the final share and aggregate PK somewhere (maybe in AppState)
        Ok(())
    }
}
