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
use hex;
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

                // Deserialize and store commitment
                use ark_serialize::CanonicalDeserialize;
                let mut commitment_coeffs = Vec::new();
                let mut offset = 0;
                // Each G1Affine is 48 bytes when compressed
                while offset < commitment.len() {
                    if offset + 48 > commitment.len() {
                        break;
                    }
                    let coeff = G1Affine::deserialize_compressed(&commitment[offset..offset+48])
                        .map_err(|e| format!("Failed to deserialize commitment coefficient: {}", e))?;
                    commitment_coeffs.push(coeff);
                    offset += 48;
                }
                
                let polynomial_commitment = PolynomialCommitment {
                    coefficients: commitment_coeffs,
                };
                
                // Store the commitment in the session
                session.receive_commitment(from_node_id, polynomial_commitment)
                    .map_err(|e| format!("Failed to receive commitment: {}", e))?;
                
                // Store updated session (with the new commitment)
                self.app_state.store_dkg_session(session.clone()).await;
                
                // Track that we received it
                self.session_state.increment_commitments(&session_id).await;

                // If this is the first commitment we receive and we haven't generated our polynomial yet,
                // we need to generate it and send our commitment
                if session.commitment.coefficients.is_empty() {
                    println!("DKG Coordinator: First commitment received, generating our polynomial and sending commitment");
                    // Generate polynomial
                    session.generate_polynomial()
                        .map_err(|e| format!("Failed to generate polynomial: {}", e))?;
                    
                    // Store the session with the generated polynomial BEFORE sending commitments
                    self.app_state.store_dkg_session(session.clone()).await;
                    
                    // Get peer IDs from session state to send our commitment
                    if let Some(peer_ids) = self.session_state.get_peer_ids(&session_id).await {
                        // Send our commitment to all peers (excluding ourselves)
                        use ark_serialize::CanonicalSerialize;
                        let commitment = &session.commitment;
                        let mut commitment_bytes = Vec::new();
                        for coeff in &commitment.coefficients {
                            coeff.serialize_compressed(&mut commitment_bytes)
                                .map_err(|e| format!("Failed to serialize commitment: {}", e))?;
                        }
                        
                        let node_id = session.id;
                        let mut sent_count = 0;
                        for peer_id_str in &peer_ids {
                            // Skip sending to ourselves (check if peer_id contains our node_id or matches our network peer_id)
                            // For now, just try to send - if it fails with "Connecting to ourself", that's okay
                            let commitment_msg = DkgMessage::Commitment {
                                session_id,
                                from_node_id: node_id,
                                commitment: commitment_bytes.clone(),
                            };
                            
                            match self.send_message_to_peer(peer_id_str, commitment_msg).await {
                                Ok(_) => sent_count += 1,
                                Err(e) => {
                                    if e.contains("ourself") {
                                        // Skip - we tried to connect to ourselves
                                        continue;
                                    }
                                    eprintln!("Failed to send commitment to peer {}: {}", peer_id_str, e);
                                }
                            }
                        }
                        println!("DKG Coordinator: Sent our commitment to {}/{} peers", sent_count, peer_ids.len());
                    } else {
                        println!("DKG Coordinator: Generated polynomial but no peer_ids available yet");
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
                // IMPORTANT: Re-fetch the session to ensure we have the latest version with all previous shares
                let mut session = self
                    .app_state
                    .get_dkg_session(&session_id)
                    .await
                    .ok_or_else(|| format!("DKG session {} not found", session_id))?;
                
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

                // Receive and verify the share (this mutates the session)
                session
                    .receive_share(share)
                    .map_err(|e| format!("Failed to receive share: {}", e))?;

                println!(
                    "DKG Coordinator: Received and verified share from node {} to node {} for session {}",
                    from_node_id, to_node_id, session_id
                );

                // Store updated session (with the new share)
                // IMPORTANT: We must store the session AFTER receive_share() has mutated it
                // Clone the mutated session before storing
                let session_to_store = session.clone();
                
                // Verify the share was actually stored by trying to compute secret share
                // (this will fail if we don't have all shares yet, but that's okay)
                let share_check = session_to_store.compute_secret_share();
                println!("DKG Coordinator: Stored session after receiving share from node {} (session {}). Share check: {}", 
                    from_node_id, session_id,
                    if share_check.is_ok() { "has all shares" } else { "needs more shares" });
                
                self.app_state.store_dkg_session(session_to_store).await;

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
        // IMPORTANT: For Commitment and Share messages, we've already stored the session above
        // Don't store again here as it would overwrite the session with received shares/commitments
        // For other message types (Ack, Error), the session wasn't modified, so no need to store
        // The session is only modified by receive_commitment() and receive_share(), which both
        // store the session immediately after modification

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
        // We need to check if we've generated our own polynomial AND received commitments from all others
        let expected_commitments = session.total_nodes - 1; // Excluding self
        
        // First, make sure we've generated our polynomial
        if session.commitment.coefficients.is_empty() {
            // Haven't generated polynomial yet, can't proceed to Phase 2
            return Ok(());
        }
        
        // Get the actual count from session_state (drop the lock quickly)
        let received_commitments = {
            let states = self.session_state.states.read().await;
            states.get(&session_id)
                .map(|s| s.commitments_received)
                .unwrap_or(0)
        };

        if received_commitments >= expected_commitments {
            println!(
                "Phase 1 complete: Received {}/{} commitments, starting Phase 2 (node {})",
                received_commitments, expected_commitments, session.id
            );
            self.initiate_phase2_shares(session_id, peer_ids).await?;
        } else {
            println!(
                "Phase 1 not complete yet: Received {}/{} commitments (node {})",
                received_commitments, expected_commitments, session.id
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
        // Get the session
        let mut session = self
            .app_state
            .get_dkg_session(&session_id)
            .await
            .ok_or_else(|| format!("DKG session {} not found", session_id))?;

        // Make sure we've generated our polynomial
        if session.commitment.coefficients.is_empty() {
            println!("DKG Coordinator: Generating polynomial before Phase 2 (node {})", session.id);
            session.generate_polynomial()
                .map_err(|e| format!("Failed to generate polynomial: {}", e))?;
            // Store the session with the generated polynomial BEFORE re-fetching
            let session_to_store = session.clone();
            self.app_state.store_dkg_session(session_to_store).await;
            // Re-fetch session after storing to get the latest version
            session = self
                .app_state
                .get_dkg_session(&session_id)
                .await
                .ok_or_else(|| format!("DKG session {} not found", session_id))?;
            println!("DKG Coordinator: Re-fetched session after generating polynomial (node {})", session.id);
        }

        // Generate shares for all nodes
        println!("DKG Coordinator: Generating shares for node {} (session {})", session.id, session_id);
        let shares = session
            .generate_shares()
            .map_err(|e| format!("Failed to generate shares: {}", e))?;
        
        println!("DKG Coordinator: Generated {} shares", shares.len());
        
        // IMPORTANT: Don't store the session here - it would overwrite any received shares!
        // The session is already stored when we receive shares, so we don't need to store it again
        // We only need the node_id for sending shares
        let node_id = session.id;

        // Update phase
        println!("DKG Coordinator: Updating phase to Phase2Shares");
        self.session_state
            .update_phase(&session_id, DkgPhase::Phase2Shares)
            .await;
        println!("DKG Coordinator: Phase updated");
        println!("DKG Coordinator: peer_ids.len() = {}", peer_ids.len());

        // Send shares to peers
        // For each share, send it to all peer_ids - the receiver will verify it's for them
        // This is inefficient but works without proper node_id to peer_id mapping
        let current_node_id = node_id;
        let mut shares_sent = 0;
        
        if peer_ids.is_empty() {
            eprintln!("DKG Coordinator: WARNING - No peer_ids available to send shares to!");
            return Ok(()); // Can't send shares without peer_ids
        }
        
        println!("DKG Coordinator: About to send shares - {} shares, {} peers, node {}", shares.len(), peer_ids.len(), current_node_id);
        println!("DKG Coordinator: Sending {} shares to {} peers (node {})", shares.len(), peer_ids.len(), current_node_id);
        
        for share in shares.iter() {
            // Skip sending share to ourselves
            if share.to_id == current_node_id {
                println!("DKG Coordinator: Skipping share to ourselves (node {})", current_node_id);
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

            // Send to all peer_ids - the correct receiver will accept it
            // In production, you'd have proper node_id to peer_id mapping
            let mut sent = false;
            for peer_id_str in peer_ids {
                match self.send_message_to_peer(peer_id_str, share_msg.clone()).await {
                    Ok(_) => {
                        shares_sent += 1;
                        sent = true;
                        println!("DKG Coordinator: Sent share from node {} to node {} via peer {}", 
                            node_id, share.to_id, peer_id_str);
                        break; // Successfully sent to one peer, move to next share
                    }
                    Err(e) => {
                        // If it's "ourself" error, try next peer
                        if e.contains("ourself") {
                            continue;
                        }
                        eprintln!("Failed to send share to peer {}: {}", peer_id_str, e);
                    }
                }
            }
            if !sent {
                eprintln!("DKG Coordinator: Failed to send share from node {} to node {} to any peer", 
                    node_id, share.to_id);
            }
        }

        println!("Phase 2: Sent {}/{} shares to peers (node {})", shares_sent, shares.len() - 1, node_id);
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
        // We can't access received_shares directly (it's private), so we use session_state counter
        let expected_shares = session.total_nodes - 1; // Excluding self
        // Get the actual count from session_state (drop the lock quickly)
        let received_shares = {
            let states = self.session_state.states.read().await;
            states.get(&session_id)
                .map(|s| s.shares_received)
                .unwrap_or(0)
        };

        if received_shares >= expected_shares {
            println!(
                "Phase 2 complete: Received {}/{} shares (from counter), checking actual session state before Phase 4",
                received_shares, expected_shares
            );
            // Re-fetch session to ensure we have the latest state with all shares stored
            // Add a small delay to ensure all async operations have completed
            use tokio::time::{sleep, Duration};
            sleep(Duration::from_millis(300)).await;
            
            // Retry a few times to ensure we get the latest session state
            let mut session_check = None;
            for attempt in 0..5 {
                session_check = self.app_state.get_dkg_session(&session_id).await;
                if let Some(ref sess) = session_check {
                    // Try to compute aggregate key to verify we have all commitments
                    if sess.compute_aggregate_public_key().is_ok() {
                        println!("DKG Coordinator: All commitments verified on attempt {}", attempt + 1);
                        break;
                    }
                }
                if attempt < 4 {
                    sleep(Duration::from_millis(100)).await;
                }
            }
            
            let session_check = session_check.ok_or_else(|| format!("DKG session {} not found", session_id))?;
            
            // Final check - try to compute aggregate key
            match session_check.compute_aggregate_public_key() {
                Ok(_) => {
                    println!("DKG Coordinator: All commitments verified, proceeding to Phase 4");
                }
                Err(e) => {
                    println!("DKG Coordinator: Not all commitments received yet ({}), will retry later", e);
                    return Ok(());
                }
            }
            
            println!("DKG Coordinator: Calling initiate_phase4_completion for session {}", session_id);
            self.initiate_phase4_completion(session_id).await?;
        }

        Ok(())
    }

    /// Phase 4: Compute final secret share and aggregate public key
    ///
    /// This is triggered when all shares have been received and verified.
    pub async fn initiate_phase4_completion(&self, session_id: u64) -> Result<(), String> {
        println!("DKG Coordinator: Starting Phase 4 completion for session {}", session_id);

        // Re-fetch session one more time to ensure we have the latest state
        // Retry a few times to handle race conditions where session might be overwritten
        use tokio::time::{sleep, Duration};
        let mut session = None;
        let mut last_error = None;
        for attempt in 0..15 {
            sleep(Duration::from_millis(150)).await;
            session = self.app_state.get_dkg_session(&session_id).await;
            if let Some(ref sess) = session {
                // Try to compute secret share - if it succeeds, we have all the data
                match sess.compute_secret_share() {
                    Ok(_) => {
                        println!("DKG Coordinator: Session has all shares on attempt {}", attempt + 1);
                        break;
                    }
                    Err(e) => {
                        last_error = Some(e.to_string());
                        // Continue retrying
                    }
                }
            }
        }
        
        let session = session.ok_or_else(|| format!("DKG session {} not found", session_id))?;
        
        // If we still don't have all shares after retries, log the error
        if let Some(ref err) = last_error {
            eprintln!("DKG Coordinator: After retries, session still missing data: {}", err);
        }

        println!("DKG Coordinator: Re-fetched session for Phase 4, node {}", session.id);

        // Compute final secret share
        println!("DKG Coordinator: Attempting to compute secret share for node {}...", session.id);
        let _final_share = match session.compute_secret_share() {
            Ok(share) => {
                println!("DKG Coordinator: Successfully computed secret share for node {}", session.id);
                share
            }
            Err(e) => {
                eprintln!("DKG Coordinator: Failed to compute secret share for node {}: {}", session.id, e);
                return Err(format!("Failed to compute secret share: {}", e));
            }
        };

        // Compute aggregate public key
        let aggregate_pk = session
            .compute_aggregate_public_key()
            .map_err(|e| format!("Failed to compute aggregate public key: {}", e))?;

        println!("DKG Coordinator: Computed aggregate public key for node {}", session.id);

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
