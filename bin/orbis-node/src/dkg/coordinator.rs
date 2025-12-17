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
use crate::constants::{FR_COMPRESSED_SIZE, G1_COMPRESSED_SIZE, MAX_COMMITMENT_COEFFICIENTS};
use crate::dkg::error::{DkgError, Result};
use crate::dkg::messages::DkgMessage;
use crate::dkg::session_state::{DkgMessageType, DkgPhase, SessionStateManager};
use network::iroh::router::alpn::DKG;
// TODO: any crypto specific things should be generalized and come from crypto::bls12_381
use ark_bls12_381::{Fr, G1Affine};
use ark_serialize::CanonicalDeserialize;
use ark_serialize::CanonicalSerialize;
use crypto::bls12_381::common::PolynomialCommitment;
use crypto::bls12_381::dkg::DKGNode;
use crypto::r#trait::DistributedShare;
use crypto::r#trait::Dkg;
use local_storage::r#trait::{LocalStorage, LocalStorageKeys};
use network::{Message as NetworkMessage, Network, PeerId};
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
    ///
    /// The session_state is shared from AppState to ensure all coordinators
    /// (service, protocol handler, etc.) use the same state.
    pub fn new(app_state: Arc<AppState>) -> Self {
        let session_state = app_state.dkg_session_state.clone();
        Self {
            app_state,
            session_state,
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
    ) -> Result<Option<DkgMessage>> {
        let session_id = message.session_id();

        // Get message type and from_node_id for deduplication
        let (message_type, from_node_id_opt) = match &message {
            DkgMessage::Commitment { from_node_id, .. } => {
                (DkgMessageType::Commitment, Some(*from_node_id))
            }
            DkgMessage::Share { from_node_id, .. } => (DkgMessageType::Share, Some(*from_node_id)),
            DkgMessage::Complaint { from_node_id, .. } => {
                (DkgMessageType::Complaint, Some(*from_node_id))
            }
            DkgMessage::SessionInit { .. } => (DkgMessageType::SessionInit, None),
            DkgMessage::Ack { .. } => (DkgMessageType::Ack, None),
            DkgMessage::Error { .. } => (DkgMessageType::Error, None),
        };

        // Check for duplicate messages (except SessionInit, Ack, Error)
        if let Some(from_node_id) = from_node_id_opt {
            if self
                .session_state
                .is_message_processed(&session_id, from_node_id, message_type)
                .await
            {
                println!(
                    "DKG Coordinator: Ignoring duplicate {:?} from node {} for session {}",
                    message_type, from_node_id, session_id
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
            node_id_assignments,
            ..
        } = &message
        {
            // Get our assigned node_id from the initiator's assignments
            let our_peer_id_hex = hex::encode(self.app_state.network.local_peer_id().as_bytes());
            // Extract just the hex part (before @) for lookup
            let our_peer_id_key = our_peer_id_hex
                .split('@')
                .next()
                .unwrap_or(&our_peer_id_hex)
                .to_string();

            let assigned_node_id = node_id_assignments.get(&our_peer_id_key)
                .ok_or_else(|| {
                    DkgError::InvalidInput(format!(
                        "Could not find our node_id assignment in SessionInit. Our peer_id: {}, Available assignments: {:?}",
                        our_peer_id_key,
                        node_id_assignments.keys().collect::<Vec<_>>()
                    ))
                })?;

            println!(
                "DKG Coordinator: Received SessionInit - assigned node_id: {} (from initiator)",
                assigned_node_id
            );

            // If session doesn't exist, create it with assigned node_id
            if self.app_state.get_dkg_session(&session_id).await.is_none() {
                self.create_session(
                    session_id,
                    *assigned_node_id,
                    *threshold as usize,
                    *total_participants as usize,
                )
                .await?;
            }

            // Store peer_ids for this session (needed for sending messages)
            self.set_peer_ids(&session_id, peer_ids.clone()).await;

            // Store node_id to peer_id mappings for efficient routing
            let mut node_id_to_peer_id = std::collections::HashMap::new();
            for (peer_id_key, node_id) in node_id_assignments {
                // Find the full peer_id (with @address if present) from peer_ids list
                let full_peer_id = peer_ids
                    .iter()
                    .find(|pid| pid.split('@').next().unwrap_or(pid) == peer_id_key)
                    .cloned()
                    .unwrap_or_else(|| peer_id_key.clone());
                node_id_to_peer_id.insert(*node_id, full_peer_id);
            }
            self.session_state
                .set_node_peer_mappings(&session_id, node_id_to_peer_id)
                .await;

            println!(
                "DKG Coordinator: Session init for session {}: threshold={}, participants={}, peer_ids={}, our node_id={}",
                session_id, threshold, total_participants, peer_ids.len(), assigned_node_id
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
            return Err(DkgError::SessionNotFound(format!(
                "DKG session {} not found",
                session_id
            )));
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

                // Validate commitment byte length
                // Check that commitment is not empty
                if commitment.is_empty() {
                    return Err(DkgError::CommitmentVerificationFailed(
                        "Commitment cannot be empty".to_string(),
                    ));
                }

                // Check that commitment length is a multiple of G1 compressed size
                if commitment.len() % G1_COMPRESSED_SIZE != 0 {
                    return Err(DkgError::CommitmentVerificationFailed(format!(
                        "Invalid commitment length: {} bytes is not a multiple of {} (G1 compressed size)",
                        commitment.len(),
                        G1_COMPRESSED_SIZE
                    )));
                }

                let num_coefficients = commitment.len() / G1_COMPRESSED_SIZE;

                // Check reasonable bounds on number of coefficients
                if num_coefficients > MAX_COMMITMENT_COEFFICIENTS {
                    return Err(DkgError::CommitmentVerificationFailed(format!(
                        "Too many commitment coefficients: {} exceeds maximum {}",
                        num_coefficients, MAX_COMMITMENT_COEFFICIENTS
                    )));
                }

                // Get threshold from session to validate coefficient count
                let threshold = self
                    .app_state
                    .with_dkg_session(&session_id, |session| session.threshold)
                    .await
                    .ok_or_else(|| {
                        DkgError::SessionNotFound(format!("DKG session {} not found", session_id))
                    })?;

                // Polynomial commitment should have exactly threshold coefficients
                // (degree t-1 polynomial has t coefficients)
                if num_coefficients != threshold {
                    return Err(DkgError::CommitmentVerificationFailed(format!(
                        "Invalid number of commitment coefficients: got {}, expected {} (threshold)",
                        num_coefficients, threshold
                    )));
                }

                // Deserialize commitment with pre-allocated vector
                let mut commitment_coeffs = Vec::with_capacity(num_coefficients);
                for i in 0..num_coefficients {
                    let start = i * G1_COMPRESSED_SIZE;
                    let end = start + G1_COMPRESSED_SIZE;
                    let coeff =
                        G1Affine::deserialize_compressed(&commitment[start..end]).map_err(|e| {
                            DkgError::Deserialization(format!(
                                "Failed to deserialize commitment coefficient {}: {}",
                                i, e
                            ))
                        })?;
                    commitment_coeffs.push(coeff);
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
                            .map_err(|e| {
                                DkgError::Crypto(format!("Failed to receive commitment: {}", e))
                            })?;

                        // Check if we need to generate our polynomial
                        Ok::<_, DkgError>(session.commitment.coefficients.is_empty())
                    })
                    .await
                    .ok_or_else(|| {
                        DkgError::SessionNotFound(format!("DKG session {} not found", session_id))
                    })??;

                // Mark message as processed
                self.session_state
                    .mark_message_processed(&session_id, from_node_id, DkgMessageType::Commitment)
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
                            session.generate_polynomial().map_err(|e| {
                                DkgError::Crypto(format!("Failed to generate polynomial: {}", e))
                            })
                        })
                        .await
                        .ok_or_else(|| {
                            DkgError::SessionNotFound(format!(
                                "DKG session {} not found",
                                session_id
                            ))
                        })??;

                    // Get peer IDs and node_id from session to send our commitment
                    if let Some(peer_ids) = self.session_state.get_peer_ids(&session_id).await {
                        // Serialize our commitment
                        let (commitment_bytes, node_id) = self
                            .app_state
                            .with_dkg_session(&session_id, |session| {
                                let mut bytes = Vec::new();
                                for coeff in &session.commitment.coefficients {
                                    coeff.serialize_compressed(&mut bytes).map_err(|e| {
                                        DkgError::Serialization(format!(
                                            "Failed to serialize commitment: {}",
                                            e
                                        ))
                                    })?;
                                }
                                Ok::<_, DkgError>((bytes, session.id))
                            })
                            .await
                            .ok_or_else(|| {
                                DkgError::SessionNotFound(format!(
                                    "DKG session {} not found",
                                    session_id
                                ))
                            })??;

                        // Use Arc to share commitment bytes across all peers (cheap clone)
                        let commitment_bytes_arc = Arc::new(commitment_bytes);
                        let mut sent_count = 0;
                        for peer_id_str in &peer_ids {
                            let commitment_msg = DkgMessage::Commitment {
                                session_id,
                                from_node_id: node_id,
                                commitment: commitment_bytes_arc.as_ref().clone(),
                            };

                            match self.send_message_to_peer(peer_id_str, commitment_msg).await {
                                Ok(_) => sent_count += 1,
                                Err(e) => {
                                    if e.to_string().contains("ourself") {
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
                // Validate share value byte length
                if share_value.is_empty() {
                    return Err(DkgError::ShareVerificationFailed(
                        "Share value cannot be empty".to_string(),
                    ));
                }

                if share_value.len() != FR_COMPRESSED_SIZE {
                    return Err(DkgError::ShareVerificationFailed(format!(
                        "Invalid share value length: {} bytes, expected {}",
                        share_value.len(),
                        FR_COMPRESSED_SIZE
                    )));
                }

                // Validate this share is intended for us
                // Get our node_id from the session (session-specific)
                let our_node_id = self
                    .app_state
                    .with_dkg_session(&session_id, |session| session.id)
                    .await
                    .ok_or_else(|| {
                        DkgError::SessionNotFound(format!("DKG session {} not found", session_id))
                    })?;
                if to_node_id != our_node_id {
                    return Err(DkgError::ShareVerificationFailed(format!(
                        "Share intended for node {}, but we are node {}",
                        to_node_id, our_node_id
                    )));
                }

                // Deserialize share value
                let share_val =
                    Fr::deserialize_compressed(share_value.as_slice()).map_err(|e| {
                        DkgError::Deserialization(format!(
                            "Failed to deserialize share value: {}",
                            e
                        ))
                    })?;

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
                        session.receive_share(share).map_err(|e| {
                            DkgError::ShareVerificationFailed(format!(
                                "Failed to receive share: {}",
                                e
                            ))
                        })
                    })
                    .await
                    .ok_or_else(|| {
                        DkgError::SessionNotFound(format!("DKG session {} not found", session_id))
                    })??;

                println!(
                    "DKG Coordinator: Received and verified share from node {} to node {} for session {}",
                    from_node_id, to_node_id, session_id
                );

                // Mark message as processed
                self.session_state
                    .mark_message_processed(&session_id, from_node_id, DkgMessageType::Share)
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
    ) -> Result<()> {
        // Create a new DKGNode for this session
        let mut dkg_node = DKGNode::new(node_id, threshold, total_nodes)
            .map_err(|e| DkgError::Crypto(format!("Failed to create DKG node: {}", e)))?;

        // Set the session_id to the one we want (DKGNode::new generates a random one)
        dkg_node.session_id = session_id;

        // Store the session (with limit checking)
        self.app_state
            .store_dkg_session(*dkg_node)
            .await
            .map_err(|e| DkgError::ProtocolError(e.to_string()))?;

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
    pub async fn send_message_to_peer(&self, peer_id_str: &str, message: DkgMessage) -> Result<()> {
        use crate::helpers::helpers::connect_to_peer;

        // Connect to peer
        let connection = connect_to_peer(&self.app_state.network, peer_id_str.to_string(), DKG)
            .await
            .map_err(|e| {
                DkgError::NetworkConnection(format!(
                    "Failed to connect to peer {}: {}",
                    peer_id_str, e
                ))
            })?;

        // Serialize message
        let message_data = serde_json::to_vec(&message)
            .map_err(|e| DkgError::Serialization(format!("Failed to serialize message: {}", e)))?;

        // Send message
        connection
            .send(NetworkMessage::new(message_data, DKG))
            .await
            .map_err(|e| {
                DkgError::NetworkCommunication(format!(
                    "Failed to send message to peer {}: {}",
                    peer_id_str, e
                ))
            })?;

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
    ) -> Result<()> {
        // Generate polynomial and serialize commitment
        let (commitment_bytes, node_id) = self
            .app_state
            .with_dkg_session_mut(&session_id, |session| {
                // Generate polynomial and commitment
                session.generate_polynomial().map_err(|e| {
                    DkgError::Crypto(format!("Failed to generate polynomial: {}", e))
                })?;

                // Serialize commitment
                let mut bytes = Vec::new();
                for coeff in &session.commitment.coefficients {
                    coeff.serialize_compressed(&mut bytes).map_err(|e| {
                        DkgError::Serialization(format!(
                            "Failed to serialize commitment coefficient: {}",
                            e
                        ))
                    })?;
                }

                Ok::<_, DkgError>((bytes, session.id))
            })
            .await
            .ok_or_else(|| {
                DkgError::SessionNotFound(format!("DKG session {} not found", session_id))
            })??;

        // Update phase
        self.session_state
            .update_phase(&session_id, DkgPhase::Phase1Commitments)
            .await;

        // Use Arc to share commitment bytes across all peers (cheap clone)
        let commitment_bytes_arc = Arc::new(commitment_bytes);
        for peer_id_str in peer_ids {
            let commitment_msg = DkgMessage::Commitment {
                session_id,
                from_node_id: node_id,
                commitment: commitment_bytes_arc.as_ref().clone(),
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
    ) -> Result<()> {
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
            .ok_or_else(|| {
                DkgError::SessionNotFound(format!("DKG session {} not found", session_id))
            })?;

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
    pub async fn initiate_phase2_shares(&self, session_id: u64, peer_ids: &[String]) -> Result<()> {
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
                    session.generate_polynomial().map_err(|e| {
                        DkgError::Crypto(format!("Failed to generate polynomial: {}", e))
                    })?;
                }

                // Generate shares for all nodes
                println!(
                    "DKG Coordinator: Generating shares for node {} (session {})",
                    session.id, session_id
                );
                let shares = session
                    .generate_shares()
                    .map_err(|e| DkgError::Crypto(format!("Failed to generate shares: {}", e)))?;

                println!("DKG Coordinator: Generated {} shares", shares.len());
                Ok::<_, DkgError>((shares, session.id))
            })
            .await
            .ok_or_else(|| {
                DkgError::SessionNotFound(format!("DKG session {} not found", session_id))
            })??;

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
            let mut share_value_bytes = Vec::new();
            share
                .value
                .serialize_compressed(&mut share_value_bytes)
                .map_err(|e| {
                    DkgError::Serialization(format!("Failed to serialize share value: {}", e))
                })?;

            // Use Arc to share bytes if we need to broadcast (cheap clone)
            let share_value_bytes_arc = Arc::new(share_value_bytes);

            // Try to get specific peer_id for this node_id (O(1) lookup)
            if let Some(target_peer_id) = self
                .session_state
                .get_peer_id_for_node(&session_id, share.to_id)
                .await
            {
                // Direct routing: O(n) total for all shares
                let share_msg = DkgMessage::Share {
                    session_id,
                    from_node_id: node_id,
                    to_node_id: share.to_id,
                    share_value: share_value_bytes_arc.as_ref().clone(),
                    nonce: share.nonce,
                };
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
                let mut sent_count = 0;
                for peer_id_str in peer_ids {
                    let broadcast_share_msg = DkgMessage::Share {
                        session_id,
                        from_node_id: node_id,
                        to_node_id: share.to_id,
                        share_value: share_value_bytes_arc.as_ref().clone(),
                        nonce: share.nonce,
                    };
                    match self
                        .send_message_to_peer(peer_id_str, broadcast_share_msg)
                        .await
                    {
                        Ok(_) => {
                            sent_count += 1;
                            println!(
                                "DKG Coordinator: Sent share from node {} to node {} via peer {} (broadcast)",
                                node_id, share.to_id, peer_id_str
                            );
                        }
                        Err(e) => {
                            if e.to_string().contains("ourself") {
                                continue;
                            }
                            eprintln!("Failed to send share to peer {}: {}", peer_id_str, e);
                        }
                    }
                }
                if sent_count > 0 {
                    shares_sent += 1;
                } else {
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
    pub async fn check_and_trigger_phase4(&self, session_id: u64) -> Result<()> {
        // Get expected shares count
        let expected_shares = self
            .app_state
            .with_dkg_session(&session_id, |session| session.total_nodes - 1)
            .await
            .ok_or_else(|| {
                DkgError::SessionNotFound(format!("DKG session {} not found", session_id))
            })?;

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
                .ok_or_else(|| {
                    DkgError::SessionNotFound(format!("DKG session {} not found", session_id))
                })?;

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
    pub async fn initiate_phase4_completion(&self, session_id: u64) -> Result<()> {
        println!(
            "DKG Coordinator: Starting Phase 4 completion for session {}",
            session_id
        );

        // Compute final secret share and aggregate public key
        let (node_id, aggregate_pk, final_share_bytes) = self
            .app_state
            .with_dkg_session(&session_id, |session| {
                println!(
                    "DKG Coordinator: Computing secret share for node {}...",
                    session.id
                );

                // Compute final secret share
                let final_share = session.compute_secret_share().map_err(|e| {
                    DkgError::Crypto(format!("Failed to compute secret share: {}", e))
                })?;

                println!(
                    "DKG Coordinator: Successfully computed secret share for node {}",
                    session.id
                );

                // Compute aggregate public key
                let aggregate_pk = session.compute_aggregate_public_key().map_err(|e| {
                    DkgError::Crypto(format!("Failed to compute aggregate public key: {}", e))
                })?;

                println!(
                    "DKG Coordinator: Computed aggregate public key for node {}",
                    session.id
                );

                // Serialize the final share for storage
                // PriShare has fields: i (u32) and v (Fr)
                let mut final_share_bytes = Vec::new();

                // Serialize the index (4 bytes for u32)
                final_share_bytes.extend_from_slice(&final_share.i.to_le_bytes());

                // Serialize the share value (Fr)
                final_share
                    .v
                    .serialize_compressed(&mut final_share_bytes)
                    .map_err(|e| {
                        DkgError::Serialization(format!(
                            "Failed to serialize final share value: {}",
                            e
                        ))
                    })?;

                Ok::<_, DkgError>((session.id, aggregate_pk, final_share_bytes))
            })
            .await
            .ok_or_else(|| {
                DkgError::SessionNotFound(format!("DKG session {} not found", session_id))
            })??;

        // Store the serialized final share in local storage
        self.app_state
            .local_storage
            .set_encrypted(
                LocalStorageKeys::RingKey(aggregate_pk.to_string()),
                final_share_bytes.clone(),
            )
            .map_err(|e| DkgError::Storage(format!("Failed to store final share: {}", e)))?;

        println!(
            "DKG Coordinator: Stored final share for session {} in local storage",
            session_id
        );

        // Update phase
        self.session_state
            .update_phase(&session_id, DkgPhase::Phase4Complete)
            .await;

        // Store ring_pk -> session_id mapping for PRE
        let mut ring_pk_bytes = Vec::new();
        aggregate_pk
            .serialize_compressed(&mut ring_pk_bytes)
            .map_err(|e| {
                DkgError::Serialization(format!("Failed to serialize aggregate public key: {}", e))
            })?;
        self.app_state
            .store_ring_pk_mapping(ring_pk_bytes, session_id)
            .await;

        println!(
            "Phase 4: DKG complete! Final share computed, aggregate PK: {:?} (node {})",
            aggregate_pk, node_id
        );

        Ok(())
    }
}
