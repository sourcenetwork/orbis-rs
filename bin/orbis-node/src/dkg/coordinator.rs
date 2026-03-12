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
use crate::constants::MAX_TOKEN_LIFETIME_SECS;
use crate::constants::{
    BULLETIN_PLACEHOLDER_PROOF, BULLETIN_RING_NAMESPACE, COMMIT_WAIT_MS,
    MAX_COMMITMENT_COEFFICIENTS, MAX_COMMIT_WAIT_RETRIES,
};
use crate::dkg::error::{DkgError, Result};
use crate::dkg::helpers::{
    serialize_commitment_coefficients, session_not_found, validate_dkg_claims,
    validate_refresh_session_init,
};
use crate::dkg::messages::DkgMessage;
use crate::dkg::session_state::{DkgMessageType, DkgPhase};
use crate::helpers::helpers::{extract_node_part, is_self_peer_id};
use crate::metrics;
use crate::ring_state::RingPolyState;
use authn::{resolve_jwt_did, BearerToken, DkgClaims};
use bulletin::r#trait::RingPayload;
use crypto::r#trait::{DistributedShare, PriShare};
use crypto::r#trait::{Dkg, DkgMode, DkgRole};
use crypto::{CryptoDeserialize, CryptoSerialize};
use crypto::{GroupAffine as G1Affine, ScalarField as Fr};
use crypto::{
    PolynomialCommitmentImpl as PolynomialCommitment, GROUP_POINT_SIZE as G1_COMPRESSED_SIZE,
    SCALAR_SIZE as FR_COMPRESSED_SIZE,
};
use local_storage::r#trait::{LocalStorage, LocalStorageKeys};
use network::Message as NetworkMessage;
use network::PeerId;
use network::DKG;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

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
/// - Use generic Dkg implementation for cryptographic operations
///
/// Type parameter D must implement Dkg with ShareValue = Fr and PublicKey = G1Affine
/// for compatibility with the current serialization code.
pub struct DkgCoordinator<D>
where
    D: Dkg + Clone + 'static,
{
    app_state: Arc<AppState<D>>,
}

impl<D> DkgCoordinator<D>
where
    D: Dkg<ShareValue = Fr, PublicKey = G1Affine, PolynomialCommitment = PolynomialCommitment>
        + Clone
        + 'static,
{
    /// Create a new DKG session manager for this node
    ///
    /// Each node creates its own instance to manage its participation
    /// in DKG sessions. This is part of a decentralized architecture
    /// where all nodes participate equally.
    pub fn new(app_state: Arc<AppState<D>>) -> Self {
        Self { app_state }
    }

    /// Handle an incoming DKG message
    ///
    /// Routes the message to the appropriate session and processes it
    /// according to the DKG protocol phase.
    pub async fn handle_message(
        &self,
        message: DkgMessage,
        sender_peer_id: &PeerId,
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

        // Record message received metric
        let message_type_str = match message_type {
            DkgMessageType::SessionInit => "session_init",
            DkgMessageType::Commitment => "commitment",
            DkgMessageType::Share => "share",
            DkgMessageType::Complaint => "complaint",
            DkgMessageType::Ack => "ack",
            DkgMessageType::Error => "error",
        };
        metrics::record_dkg_message_received(message_type_str);

        // Check for duplicate messages (except SessionInit, Ack, Error)
        if let Some(from_node_id) = from_node_id_opt {
            if self
                .app_state
                .dkg_session_state
                .is_message_processed(&session_id, from_node_id, message_type)
                .await
            {
                tracing::debug!(
                    message_type = ?message_type,
                    from_node_id = from_node_id,
                    session_id = session_id,
                    "DKG Coordinator: Ignoring duplicate message"
                );
                return Ok(None);
            }
        }

        // Handle SessionInit specially - it can create a session, so it doesn't require one to exist
        if let DkgMessage::SessionInit {
            threshold,
            total_participants,
            peer_ids,
            node_id_assignments,
            token_string,
            is_refresh,
            refresh_ring_pk_hex,
            pss_interval,
            ..
        } = &message
        {
            if *is_refresh {
                let ring_pk_hex = refresh_ring_pk_hex.as_ref().ok_or_else(|| {
                    DkgError::InvalidInput(
                        "Refresh SessionInit missing refresh_ring_pk_hex".to_string(),
                    )
                })?;

                let sender_hex = hex::encode(sender_peer_id.as_bytes());
                validate_refresh_session_init(
                    ring_pk_hex,
                    &sender_hex,
                    &self.app_state.local_storage,
                )?;

                if !self
                    .app_state
                    .dkg_session_state
                    .try_mark_ring_refreshing(ring_pk_hex)
                    .await
                {
                    return Err(DkgError::Unauthorized(format!(
                        "Refresh already in progress for ring {}",
                        ring_pk_hex
                    )));
                }

                tracing::info!(
                    session_id = session_id,
                    ring_pk = %ring_pk_hex,
                    "DKG Coordinator: Refresh SessionInit validated"
                );
            } else {
                // 1. Authenticate: Validate JWT token
                let current_time = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|e| DkgError::Generic(format!("Failed to get timestamp: {}", e)))?
                    .as_secs();

                let token: BearerToken<DkgClaims> =
                    resolve_jwt_did(token_string, current_time, MAX_TOKEN_LIFETIME_SECS).map_err(
                        |e| DkgError::Unauthorized(format!("JWT validation failed: {}", e)),
                    )?;
                // TODO: use token.issuer_id as AuthZ check
                // 2. Authorize: Validate JWT claims match SessionInit fields
                validate_dkg_claims(&token, *threshold, peer_ids, *pss_interval)?;

                tracing::info!(
                    issuer = %token.issuer_id,
                    threshold = threshold,
                    "DKG Coordinator: SessionInit JWT validated successfully"
                );
            }

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

            tracing::info!(
                assigned_node_id = assigned_node_id,
                is_refresh = is_refresh,
                "DKG Coordinator: Received SessionInit - assigned node_id from initiator"
            );

            // If session doesn't exist, create it with assigned node_id
            if !self
                .app_state
                .dkg_session_state
                .session_exists(&session_id)
                .await
            {
                self.create_session(
                    session_id,
                    *assigned_node_id,
                    *threshold as usize,
                    *total_participants as usize,
                    DkgRole::Standard,
                )
                .await?;

                if *is_refresh {
                    self.app_state
                        .dkg_session_state
                        .mark_as_refresh(&session_id)
                        .await;
                    if let Some(ring_key) = refresh_ring_pk_hex {
                        self.app_state
                            .dkg_session_state
                            .set_refresh_ring_key(&session_id, ring_key.clone())
                            .await;
                    }
                }
                self.app_state
                    .dkg_session_state
                    .set_pss_interval(&session_id, *pss_interval)
                    .await;
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
            self.app_state
                .dkg_session_state
                .set_node_peer_mappings(&session_id, node_id_to_peer_id)
                .await;

            tracing::info!(
                session_id = session_id,
                threshold = threshold,
                total_participants = total_participants,
                peer_count = peer_ids.len(),
                our_node_id = assigned_node_id,
                "DKG Coordinator: Session init"
            );

            return Ok(Some(DkgMessage::Ack {
                session_id,
                message_type: "SessionInit".to_string(),
            }));
        }

        // For all other messages, ensure the session exists
        if !self
            .app_state
            .dkg_session_state
            .session_exists(&session_id)
            .await
        {
            return Err(session_not_found(session_id));
        }

        // Validate sender identity for messages that carry from_node_id
        if let Some(claimed_node_id) = from_node_id_opt {
            let sender_hex = hex::encode(sender_peer_id.as_bytes());
            // Look up the expected node_id for this peer, comparing just the hex part
            // since session state keys may include @address suffixes
            let expected_node_id = self
                .app_state
                .dkg_session_state
                .with_state(&session_id, |state| {
                    state
                        .peer_id_to_node_id
                        .iter()
                        .find(|(peer_id, _)| extract_node_part(peer_id) == sender_hex)
                        .map(|(_, node_id)| *node_id)
                })
                .await
                .flatten();

            match expected_node_id {
                Some(expected) if expected == claimed_node_id => {
                    // Identity matches - proceed
                }
                Some(expected) => {
                    tracing::warn!(
                        claimed_node_id = claimed_node_id,
                        expected_node_id = expected,
                        sender_peer = %sender_hex,
                        session_id = session_id,
                        "DKG Coordinator: Rejecting message - sender identity mismatch"
                    );
                    return Err(DkgError::Unauthorized(format!(
                        "Sender identity mismatch: peer claims node_id={}, but authenticated peer maps to node_id={}",
                        claimed_node_id, expected
                    )));
                }
                None => {
                    tracing::warn!(
                        sender_peer = %sender_hex,
                        session_id = session_id,
                        "DKG Coordinator: Rejecting message - sender peer not found in session"
                    );
                    return Err(DkgError::Unauthorized(format!(
                        "Sender peer {} not found in session peer mappings",
                        sender_hex
                    )));
                }
            }
        }

        // Process the message based on its type
        let response = match message {
            DkgMessage::Commitment {
                from_node_id,
                commitment,
                ..
            } => {
                // Phase 1: Receive and store commitment
                tracing::debug!(
                    from_node_id = from_node_id,
                    session_id = session_id,
                    commitment_bytes = commitment.len(),
                    "DKG Coordinator: Received commitment"
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
                    .dkg_session_state
                    .with_state(&session_id, |state| state.node.threshold())
                    .await
                    .ok_or_else(|| session_not_found(session_id))?;

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
                        <D::PublicKey>::from_bytes(&commitment[start..end]).map_err(|e| {
                            DkgError::Deserialization(format!(
                                "Failed to deserialize commitment coefficient {}: {}",
                                i, e
                            ))
                        })?;
                    commitment_coeffs.push(coeff);
                }

                // Create polynomial commitment
                // D is constrained to use PolynomialCommitment, so this works directly
                let polynomial_commitment = PolynomialCommitment {
                    coefficients: commitment_coeffs,
                };

                // Update session with commitment (no cloning needed!)
                let need_to_generate_polynomial = self
                    .app_state
                    .dkg_session_state
                    .with_state_mut(&session_id, |state| {
                        state
                            .node
                            .receive_commitment(from_node_id, polynomial_commitment)
                            .map_err(|e| {
                                DkgError::Crypto(format!("Failed to receive commitment: {}", e))
                            })?;

                        // Check if we need to generate our polynomial
                        Ok::<_, DkgError>(state.node.commitment().coefficients.is_empty())
                    })
                    .await
                    .ok_or_else(|| session_not_found(session_id))??;

                // Mark message as processed
                self.app_state
                    .dkg_session_state
                    .mark_message_processed(&session_id, from_node_id, DkgMessageType::Commitment)
                    .await;

                // Track that we received it
                self.app_state
                    .dkg_session_state
                    .increment_commitments(&session_id)
                    .await;

                // If this is the first commitment we receive and we haven't generated our polynomial yet,
                // we need to generate it and send our commitment
                if need_to_generate_polynomial {
                    tracing::info!("DKG Coordinator: First commitment received, generating our polynomial and sending commitment");

                    // Generate polynomial (Fresh or Reshare depending on session params)
                    self.app_state
                        .dkg_session_state
                        .with_state_mut(&session_id, |state| state.generate_polynomial())
                        .await
                        .ok_or_else(|| session_not_found(session_id))??;

                    // Get peer IDs and node_id from session to send our commitment
                    if let Some(peer_ids) = self
                        .app_state
                        .dkg_session_state
                        .get_peer_ids(&session_id)
                        .await
                    {
                        // Serialize our commitment
                        let (commitment_bytes, node_id) = self
                            .app_state
                            .dkg_session_state
                            .with_state(&session_id, |state| {
                                let bytes = serialize_commitment_coefficients(
                                    &state.node.commitment().coefficients,
                                )?;
                                Ok::<_, DkgError>((bytes, state.node.node_id()))
                            })
                            .await
                            .ok_or_else(|| session_not_found(session_id))??;

                        let mut sent_count = 0;
                        let mut expected_count = 0;
                        for peer_id_str in &peer_ids {
                            // Skip self - don't try to connect to ourselves
                            if is_self_peer_id(&self.app_state.network, peer_id_str) {
                                continue;
                            }
                            expected_count += 1;

                            let commitment_msg = DkgMessage::Commitment {
                                session_id,
                                from_node_id: node_id,
                                commitment: commitment_bytes.clone(),
                            };

                            match self.send_message_to_peer(peer_id_str, commitment_msg).await {
                                Ok(_) => sent_count += 1,
                                Err(e) => {
                                    tracing::error!(
                                        peer_id = %peer_id_str,
                                        error = %e,
                                        "Failed to send commitment to peer"
                                    );
                                }
                            }
                        }

                        tracing::info!(
                            sent = sent_count,
                            expected = expected_count,
                            "DKG Coordinator: Sent our commitment to peers"
                        );

                        // Validate ALL peers received the commitment
                        // Users expect the full redundancy they configured - partial success is a failure
                        if sent_count < expected_count {
                            tracing::error!(
                                sent = sent_count,
                                expected = expected_count,
                                session_id = session_id,
                                "DKG Coordinator: Could not send commitment to all peers - failing DKG to preserve expected redundancy"
                            );
                            // Clean up session to prevent memory leak from abandoned sessions
                            self.app_state
                                .dkg_session_state
                                .remove_session(&session_id)
                                .await;
                            tracing::debug!(
                                session_id = session_id,
                                "Cleaned up session after commitment send failure"
                            );
                            return Err(DkgError::NetworkCommunication(format!(
                                "Failed to send commitment to all peers: sent to {} of {}",
                                sent_count, expected_count
                            )));
                        }
                    }
                }

                // Get peer IDs from session state
                if let Some(peer_ids) = self
                    .app_state
                    .dkg_session_state
                    .get_peer_ids(&session_id)
                    .await
                {
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
                    .dkg_session_state
                    .with_state(&session_id, |state| state.node.node_id())
                    .await
                    .ok_or_else(|| session_not_found(session_id))?;
                if to_node_id != our_node_id {
                    return Err(DkgError::ShareVerificationFailed(format!(
                        "Share intended for node {}, but we are node {}",
                        to_node_id, our_node_id
                    )));
                }
                // TODO: Bad fix, have phases use same QUIC connection (next PR)
                // Receive and verify the share, retrying briefly if the sender's
                // Phase 1 commitment hasn't arrived yet (each message uses a fresh
                // network connection, so ordering between the commitment and the
                // share is not guaranteed).
                let mut last_err: Option<DkgError> = None;
                let mut succeeded = false;
                for attempt in 0..=MAX_COMMIT_WAIT_RETRIES {
                    // Re-deserialize share value each attempt (cheap; avoids Clone bound)
                    let share_val =
                        <D::ShareValue>::from_bytes(share_value.as_slice()).map_err(|e| {
                            DkgError::Deserialization(format!(
                                "Failed to deserialize share value: {}",
                                e
                            ))
                        })?;
                    let share = DistributedShare {
                        from_id: from_node_id,
                        to_id: to_node_id,
                        value: share_val,
                        nonce,
                        session_id,
                    };
                    let result = self
                        .app_state
                        .dkg_session_state
                        .with_state_mut(&session_id, |state| {
                            state.node.receive_share(share).map_err(|e| match e {
                                crypto::error::CryptoError::CommitmentMissing(node_id) => {
                                    DkgError::CommitmentNotYetReceived(node_id)
                                }
                                _ => DkgError::ShareVerificationFailed(format!(
                                    "Failed to receive share: {}",
                                    e
                                )),
                            })
                        })
                        .await
                        .ok_or_else(|| session_not_found(session_id))?;
                    match result {
                        Ok(_) => {
                            succeeded = true;
                            break;
                        }
                        Err(DkgError::CommitmentNotYetReceived(_))
                            if attempt < MAX_COMMIT_WAIT_RETRIES =>
                        {
                            tracing::debug!(
                                from_node_id = from_node_id,
                                attempt = attempt + 1,
                                "Share arrived before commitment; retrying after {}ms",
                                COMMIT_WAIT_MS
                            );
                            tokio::time::sleep(std::time::Duration::from_millis(COMMIT_WAIT_MS))
                                .await;
                            last_err = Some(result.unwrap_err());
                        }
                        Err(e) => return Err(e),
                    }
                }
                if !succeeded {
                    return Err(last_err.unwrap_or_else(|| {
                        DkgError::ShareVerificationFailed(
                            "Share verification failed after retries".to_string(),
                        )
                    }));
                }

                tracing::debug!(
                    from_node_id = from_node_id,
                    to_node_id = to_node_id,
                    session_id = session_id,
                    "DKG Coordinator: Received and verified share"
                );

                // Mark message as processed
                self.app_state
                    .dkg_session_state
                    .mark_message_processed(&session_id, from_node_id, DkgMessageType::Share)
                    .await;

                // Track share received
                self.app_state
                    .dkg_session_state
                    .increment_shares(&session_id)
                    .await;

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
                tracing::warn!(
                    from_node_id = from_node_id,
                    accused_node_id = accused_node_id,
                    reason = %reason,
                    "DKG Coordinator: Received complaint"
                );
                None // For now, no response needed
            }
            DkgMessage::Ack { .. } => {
                // Acknowledgment received
                tracing::debug!(session_id = session_id, "DKG Coordinator: Received ACK");
                None
            }
            DkgMessage::Error { error, .. } => {
                // Error received
                tracing::error!(
                    session_id = session_id,
                    error = %error,
                    "DKG Coordinator: Received error"
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

    /// Create a new DKG session
    ///
    /// This is typically called when a StartDkg gRPC request is received,
    /// or internally by the PSS reshare scheduler.
    pub async fn create_session(
        &self,
        session_id: u64,
        node_id: u32,
        threshold: usize,
        total_nodes: usize,
        role: DkgRole,
    ) -> Result<()> {
        // Create a new DKG node for this session using the generic Dkg trait
        let dkg_node = D::new(node_id, threshold, total_nodes, session_id, role)
            .map_err(|e| DkgError::Crypto(format!("Failed to create DKG node: {}", e)))?;

        // Create the unified session state (crypto node + protocol tracking)
        if !self
            .app_state
            .dkg_session_state
            .create_session(session_id, *dkg_node, total_nodes)
            .await
        {
            return Err(DkgError::ProtocolError(format!(
                "DKG session {} already exists",
                session_id
            )));
        }

        // Record metrics
        metrics::record_dkg_session_started();

        Ok(())
    }

    /// Store peer IDs for a session (needed for sending messages in later phases)
    pub async fn set_peer_ids(&self, session_id: &u64, peer_ids: Vec<String>) {
        self.app_state
            .dkg_session_state
            .set_peer_ids(session_id, peer_ids)
            .await;
    }

    /// Send a DKG message to a peer
    ///
    /// Connects to the peer if needed, sends the message, then closes the connection.
    pub async fn send_message_to_peer(&self, peer_id_str: &str, message: DkgMessage) -> Result<()> {
        use crate::helpers::helpers::connect_to_peer;

        // Record message type for metrics
        let message_type = match &message {
            DkgMessage::SessionInit { .. } => "session_init",
            DkgMessage::Commitment { .. } => "commitment",
            DkgMessage::Share { .. } => "share",
            DkgMessage::Complaint { .. } => "complaint",
            DkgMessage::Ack { .. } => "ack",
            DkgMessage::Error { .. } => "error",
        };

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

        // Record metrics
        metrics::record_dkg_message_sent(message_type);

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
        let (commitment_bytes, node_id, threshold) = self
            .app_state
            .dkg_session_state
            .with_state_mut(&session_id, |state| {
                // Generate polynomial (Fresh for standard DKG, Reshare if reshare_params is set)
                state.generate_polynomial()?;

                // Serialize commitment
                let bytes =
                    serialize_commitment_coefficients(&state.node.commitment().coefficients)?;

                Ok::<_, DkgError>((bytes, state.node.node_id(), state.node.threshold()))
            })
            .await
            .ok_or_else(|| session_not_found(session_id))??;

        // Update phase
        self.app_state
            .dkg_session_state
            .update_phase(&session_id, DkgPhase::Phase1Commitments)
            .await;

        let mut peers_sent = 0;
        let mut expected_peers = 0;
        for peer_id_str in peer_ids {
            // Skip self - don't try to connect to ourselves
            if is_self_peer_id(&self.app_state.network, peer_id_str) {
                tracing::debug!(peer_id = %peer_id_str, "Skipping self when broadcasting commitment");
                continue;
            }
            expected_peers += 1;

            let commitment_msg = DkgMessage::Commitment {
                session_id,
                from_node_id: node_id,
                commitment: commitment_bytes.clone(),
            };

            if let Err(e) = self.send_message_to_peer(peer_id_str, commitment_msg).await {
                tracing::error!(peer_id = %peer_id_str, error = %e, "Failed to send commitment to peer");
                // Continue with other peers even if one fails
            } else {
                peers_sent += 1;
            }
        }

        tracing::info!(
            peers_sent = peers_sent,
            expected_peers = expected_peers,
            "Phase 1: Broadcasted commitment to peers"
        );

        // Validate ALL peers received the commitment
        // Users expect the full redundancy they configured - partial success is a failure
        if peers_sent < expected_peers {
            tracing::error!(
                sent = peers_sent,
                expected = expected_peers,
                session_id = session_id,
                "DKG Coordinator: Could not broadcast commitment to all peers - failing DKG to preserve expected redundancy"
            );
            // Clean up session to prevent memory leak from abandoned sessions
            self.app_state
                .dkg_session_state
                .remove_session(&session_id)
                .await;
            tracing::debug!(
                session_id = session_id,
                "Cleaned up session after Phase 1 broadcast failure"
            );
            return Err(DkgError::InsufficientPeers {
                successful: peers_sent,
                total: expected_peers,
                threshold,
            });
        }

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
            .dkg_session_state
            .with_state(&session_id, |state| {
                (
                    !state.node.commitment().coefficients.is_empty(),
                    state.node.total_nodes() - 1, // Excluding self
                    state.node.node_id(),
                )
            })
            .await
            .ok_or_else(|| session_not_found(session_id))?;

        // First, make sure we've generated our polynomial
        if !has_polynomial {
            // Haven't generated polynomial yet, can't proceed to Phase 2
            return Ok(());
        }

        // Get the actual count from session_state
        let received_commitments = self
            .app_state
            .dkg_session_state
            .with_state(&session_id, |state| state.commitments_received)
            .await
            .ok_or_else(|| session_not_found(session_id))?;

        if received_commitments >= expected_commitments {
            tracing::info!(
                received = received_commitments,
                expected = expected_commitments,
                node_id = node_id,
                "Phase 1 complete: Starting Phase 2"
            );
            self.initiate_phase2_shares(session_id, peer_ids).await?;
        } else {
            tracing::debug!(
                received = received_commitments,
                expected = expected_commitments,
                node_id = node_id,
                "Phase 1 not complete yet"
            );
        }

        Ok(())
    }

    /// Phase 2: Generate shares and send them to all peers
    ///
    /// This is triggered when all commitments have been received.
    pub async fn initiate_phase2_shares(&self, session_id: u64, peer_ids: &[String]) -> Result<()> {
        // Generate shares and get node_id and threshold
        let (shares, node_id, threshold) =
            self.app_state
                .dkg_session_state
                .with_state_mut(&session_id, |state| {
                    // Make sure we've generated our polynomial
                    if state.node.commitment().coefficients.is_empty() {
                        tracing::debug!(
                            node_id = state.node.node_id(),
                            "DKG Coordinator: Generating polynomial before Phase 2"
                        );
                        state
                            .node
                            .generate_polynomial(DkgMode::Fresh)
                            .map_err(|e| {
                                DkgError::Crypto(format!("Failed to generate polynomial: {}", e))
                            })?;
                    }

                    // Generate shares for all nodes
                    tracing::debug!(
                        node_id = state.node.node_id(),
                        session_id = session_id,
                        "DKG Coordinator: Generating shares"
                    );
                    let shares = state.node.generate_shares().map_err(|e| {
                        DkgError::Crypto(format!("Failed to generate shares: {}", e))
                    })?;

                    tracing::debug!(
                        share_count = shares.len(),
                        "DKG Coordinator: Generated shares"
                    );
                    Ok::<_, DkgError>((shares, state.node.node_id(), state.node.threshold()))
                })
                .await
                .ok_or_else(|| session_not_found(session_id))??;

        // Update phase
        self.app_state
            .dkg_session_state
            .update_phase(&session_id, DkgPhase::Phase2Shares)
            .await;

        if peer_ids.is_empty() {
            tracing::error!("DKG Coordinator: No peer_ids available to send shares to");
            // Clean up session to prevent memory leak from abandoned sessions
            self.app_state
                .dkg_session_state
                .remove_session(&session_id)
                .await;
            tracing::debug!(
                session_id = session_id,
                "Cleaned up session - no peer_ids available"
            );
            return Err(DkgError::InsufficientPeers {
                successful: 0,
                total: 0,
                threshold,
            });
        }

        tracing::debug!(
            share_count = shares.len(),
            node_id = node_id,
            "DKG Coordinator: Sending shares to peers"
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
            let share_value_bytes = CryptoSerialize::to_bytes(&share.value).map_err(|e| {
                DkgError::Serialization(format!("Failed to serialize share value: {}", e))
            })?;

            // Try to get specific peer_id for this node_id (O(1) lookup)
            if let Some(target_peer_id) = self
                .app_state
                .dkg_session_state
                .get_peer_id_for_node(&session_id, share.to_id)
                .await
            {
                // Direct routing: O(n) total for all shares
                let share_msg = DkgMessage::Share {
                    session_id,
                    from_node_id: node_id,
                    to_node_id: share.to_id,
                    share_value: share_value_bytes.clone(),
                    nonce: share.nonce,
                };
                match self.send_message_to_peer(&target_peer_id, share_msg).await {
                    Ok(_) => {
                        shares_sent += 1;
                        tracing::debug!(
                            from_node = node_id,
                            to_node = share.to_id,
                            peer_id = %target_peer_id,
                            "DKG Coordinator: Sent share"
                        );
                    }
                    Err(e) => {
                        tracing::error!(
                            to_node = share.to_id,
                            peer_id = %target_peer_id,
                            error = %e,
                            "Failed to send share"
                        );
                    }
                }
            } else {
                // Fallback: broadcast to all peers (only if mapping not set up)
                let mut sent_count = 0;
                for peer_id_str in peer_ids {
                    // Skip self - don't try to connect to ourselves
                    if is_self_peer_id(&self.app_state.network, peer_id_str) {
                        continue;
                    }

                    let broadcast_share_msg = DkgMessage::Share {
                        session_id,
                        from_node_id: node_id,
                        to_node_id: share.to_id,
                        share_value: share_value_bytes.clone(),
                        nonce: share.nonce,
                    };
                    match self
                        .send_message_to_peer(peer_id_str, broadcast_share_msg)
                        .await
                    {
                        Ok(_) => {
                            sent_count += 1;
                            tracing::debug!(
                                from_node = node_id,
                                to_node = share.to_id,
                                peer_id = %peer_id_str,
                                "DKG Coordinator: Sent share (broadcast)"
                            );
                        }
                        Err(e) => {
                            tracing::error!(peer_id = %peer_id_str, error = %e, "Failed to send share to peer");
                        }
                    }
                }
                if sent_count > 0 {
                    shares_sent += 1;
                } else {
                    tracing::error!(
                        from_node = node_id,
                        to_node = share.to_id,
                        "DKG Coordinator: Failed to send share to any peer"
                    );
                }
            }
        }

        let expected_shares = shares.len().saturating_sub(1); // Exclude share to self
        tracing::info!(
            sent = shares_sent,
            total = expected_shares,
            node_id = node_id,
            "Phase 2: Sent shares to peers"
        );

        // Validate ALL shares were sent successfully
        // Users expect the full redundancy they configured - partial success is a failure
        if shares_sent < expected_shares {
            tracing::error!(
                sent = shares_sent,
                expected = expected_shares,
                threshold = threshold,
                "DKG Coordinator: Could not send shares to all peers - failing DKG to preserve expected redundancy"
            );
            // Clean up session to prevent memory leak from abandoned sessions
            self.app_state
                .dkg_session_state
                .remove_session(&session_id)
                .await;
            tracing::debug!(
                session_id = session_id,
                "Cleaned up session after Phase 2 share send failure"
            );
            return Err(DkgError::InsufficientPeers {
                successful: shares_sent,
                total: expected_shares,
                threshold,
            });
        }

        Ok(())
    }

    /// Check if Phase 2 is complete and trigger Phase 4 if so
    ///
    /// This should be called after receiving a share message.
    pub async fn check_and_trigger_phase4(&self, session_id: u64) -> Result<()> {
        // Get expected shares count
        let expected_shares = self
            .app_state
            .dkg_session_state
            .with_state(&session_id, |state| state.node.total_nodes() - 1)
            .await
            .ok_or_else(|| session_not_found(session_id))?;

        // Get the actual count from session_state
        let received_shares = self
            .app_state
            .dkg_session_state
            .with_state(&session_id, |state| state.shares_received)
            .await
            .ok_or_else(|| session_not_found(session_id))?;

        if received_shares >= expected_shares {
            tracing::info!(
                received = received_shares,
                expected = expected_shares,
                "Phase 2 complete: Proceeding to Phase 4"
            );

            // Verify we have all commitments before proceeding
            let has_all_commitments = self
                .app_state
                .dkg_session_state
                .with_state(&session_id, |state| {
                    state.node.compute_aggregate_public_key().is_ok()
                })
                .await
                .ok_or_else(|| session_not_found(session_id))?;

            if !has_all_commitments {
                tracing::warn!(
                    "DKG Coordinator: Not all commitments received yet, cannot proceed to Phase 4"
                );
                return Ok(());
            }

            tracing::info!(
                session_id = session_id,
                "DKG Coordinator: All commitments verified, initiating Phase 4"
            );
            self.initiate_phase4_completion(session_id).await?;
        }

        Ok(())
    }

    /// Phase 4: Compute final secret share and aggregate public key
    ///
    /// This is triggered when all shares have been received and verified.
    /// If this node is node_id == 1, it will also post the RingPayload to the bulletin.
    pub async fn initiate_phase4_completion(&self, session_id: u64) -> Result<()> {
        tracing::info!(
            session_id = session_id,
            "DKG Coordinator: Starting Phase 4 completion"
        );

        // Read session metadata before acquiring the mutable state lock.
        let (is_refresh, refresh_ring_key, pss_interval) = self
            .app_state
            .dkg_session_state
            .with_state(&session_id, |state| {
                (
                    state.is_refresh,
                    state.refresh_ring_key.clone(),
                    state.pss_interval,
                )
            })
            .await
            .ok_or_else(|| session_not_found(session_id))?;

        // Compute final secret share, aggregate public key, and gather data for bulletin
        let (node_id, aggregate_pk, final_share_bytes, threshold, pub_poly_bytes) = self
            .app_state
            .dkg_session_state
            .with_state(&session_id, |state| {
                tracing::debug!(
                    node_id = state.node.node_id(),
                    "DKG Coordinator: Computing secret share"
                );

                // Compute final secret share
                let final_share = state.node.compute_secret_share().map_err(|e| {
                    DkgError::Crypto(format!("Failed to compute secret share: {}", e))
                })?;

                tracing::debug!(
                    node_id = state.node.node_id(),
                    "DKG Coordinator: Successfully computed secret share"
                );

                // Compute aggregate public key
                let aggregate_pk = state.node.compute_aggregate_public_key().map_err(|e| {
                    DkgError::Crypto(format!("Failed to compute aggregate public key: {}", e))
                })?;

                tracing::debug!(
                    node_id = state.node.node_id(),
                    "DKG Coordinator: Computed aggregate public key"
                );

                // Serialize the final share for storage using trait method
                let final_share_bytes = CryptoSerialize::to_bytes(&final_share).map_err(|e| {
                    DkgError::Serialization(format!("Failed to serialize final share: {}", e))
                })?;

                // Compute and serialize public polynomial for bulletin
                let pub_poly = state.node.compute_public_polynomial().map_err(|e| {
                    DkgError::Crypto(format!("Failed to compute public polynomial: {}", e))
                })?;
                let pub_poly_bytes = CryptoSerialize::to_bytes(&pub_poly).map_err(|e| {
                    DkgError::Serialization(format!("Failed to serialize public polynomial: {}", e))
                })?;

                Ok::<_, DkgError>((
                    state.node.node_id(),
                    aggregate_pk,
                    final_share_bytes,
                    state.node.threshold(),
                    pub_poly_bytes,
                ))
            })
            .await
            .ok_or_else(|| session_not_found(session_id))??;

        // Determine the storage key and bytes for the final share.
        //
        // Fresh DKG: store the share under the newly-computed aggregate public key.
        // PSS Refresh: the delta share (zero constant term) must be ADDED to the
        //   existing share so the distributed secret is preserved.  Store the
        //   combined share under the ORIGINAL ring key (unchanged public key).
        let (storage_key, storage_bytes) = if is_refresh {
            match refresh_ring_key {
                Some(ring_key) => {
                    // Load the old share, add the refresh delta, store the result.
                    let old_bytes = self
                        .app_state
                        .local_storage
                        .get_encrypted(LocalStorageKeys::RingKey(ring_key.clone()))
                        .map_err(|e| {
                            DkgError::Storage(format!("Refresh: failed to read old share: {}", e))
                        })?
                        .ok_or_else(|| {
                            DkgError::Storage(
                                "Refresh: old share not found in local storage".to_string(),
                            )
                        })?;

                    let old_pri = PriShare::<Fr>::from_bytes(&old_bytes).map_err(|e| {
                        DkgError::Deserialization(format!(
                            "Refresh: failed to deserialize old share: {}",
                            e
                        ))
                    })?;
                    let delta_pri =
                        PriShare::<Fr>::from_bytes(&final_share_bytes).map_err(|e| {
                            DkgError::Deserialization(format!(
                                "Refresh: failed to deserialize delta share: {}",
                                e
                            ))
                        })?;

                    let new_pri = PriShare {
                        i: old_pri.i,
                        v: old_pri.v + delta_pri.v,
                    };
                    let new_bytes = CryptoSerialize::to_bytes(&new_pri).map_err(|e| {
                        DkgError::Serialization(format!(
                            "Refresh: failed to serialize combined share: {}",
                            e
                        ))
                    })?;

                    (ring_key, new_bytes)
                }
                None => {
                    // Refresh session without a ring key — fall back to normal storage.
                    tracing::warn!(
                        session_id = session_id,
                        "Refresh session has no ring key; storing delta as-is"
                    );
                    (aggregate_pk.to_string(), final_share_bytes.clone())
                }
            }
        } else {
            (aggregate_pk.to_string(), final_share_bytes.clone())
        };

        self.app_state
            .local_storage
            .set_encrypted(
                LocalStorageKeys::RingKey(storage_key.clone()),
                storage_bytes,
            )
            .map_err(|e| DkgError::Storage(format!("Failed to store final share: {}", e)))?;

        tracing::debug!(
            session_id = session_id,
            "DKG Coordinator: Stored final share in local storage"
        );

        // Write last-refresh timestamp so non-initiators can enforce the minimum interval
        // on future refresh requests. Written for both fresh DKG (baseline) and refresh.
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.app_state
            .local_storage
            .set(
                LocalStorageKeys::RingLastRefresh(storage_key.clone()),
                now_secs.to_le_bytes().to_vec(),
            )
            .map_err(|e| {
                DkgError::Storage(format!("Failed to store last refresh timestamp: {}", e))
            })?;

        // For fresh DKG: cache the RingPayload locally so that future refresh validation
        // can check membership without a bulletin round-trip (bulletin IDs are content-hash
        // based and not easily resolved from ring_pk alone).  Also append to RingIndex so
        // the PSS scheduler can discover this ring.
        //
        // For PSS Refresh: load the existing cached RingPayload, combine the old public
        // polynomial with the refresh delta to get the updated polynomial, write it back
        // to local storage, and (node 1 only) post the updated payload to the bulletin so
        // that PRE/sign operations keep working with the new shares.
        if !is_refresh {
            let peer_ids = self
                .app_state
                .dkg_session_state
                .get_peer_ids(&session_id)
                .await
                .unwrap_or_default();
            let ring_pk_hex_for_payload = CryptoSerialize::to_bytes(&aggregate_pk)
                .map(hex::encode)
                .unwrap_or_default();
            // Save public polynomial locally (never on the bulletin).
            let ring_poly_state = RingPolyState {
                public_polynomial: hex::encode(&pub_poly_bytes),
                refreshed_at: 0,
            };
            ring_poly_state
                .save(&self.app_state.local_storage, &ring_pk_hex_for_payload)
                .map_err(|e| DkgError::Storage(format!("Failed to store RingPolyState: {}", e)))?;

            let ring_payload_local = RingPayload {
                ring_pk: ring_pk_hex_for_payload.clone(),
                peer_ids,
                threshold: threshold as u32,
                pss_interval,
            };
            let ring_payload_bytes: Vec<u8> = ring_payload_local.try_into().map_err(|e| {
                DkgError::Serialization(format!(
                    "Failed to serialize RingPayload for local cache: {}",
                    e
                ))
            })?;
            self.app_state
                .local_storage
                .set(
                    LocalStorageKeys::RingPkMapping(storage_key.clone()),
                    ring_payload_bytes,
                )
                .map_err(|e| DkgError::Storage(format!("Failed to store RingPkMapping: {}", e)))?;

            // Update the ring index so the PSS scheduler can discover this ring.
            let mut ring_index: Vec<String> = self
                .app_state
                .local_storage
                .get(LocalStorageKeys::RingIndex)
                .ok()
                .flatten()
                .and_then(|b| serde_json::from_slice(&b).ok())
                .unwrap_or_default();
            if !ring_index.contains(&storage_key) {
                ring_index.push(storage_key.clone());
                let index_bytes = serde_json::to_vec(&ring_index).map_err(|e| {
                    DkgError::Serialization(format!("Failed to serialize RingIndex: {}", e))
                })?;
                self.app_state
                    .local_storage
                    .set(LocalStorageKeys::RingIndex, index_bytes)
                    .map_err(|e| DkgError::Storage(format!("Failed to store RingIndex: {}", e)))?;
            }
        } else {
            // PSS Refresh: compute new_pub_poly = old_pub_poly + delta_pub_poly and
            // update the locally cached RingPayload.  Node 1 also posts the updated
            // payload to the bulletin to signal that the refresh is complete.
            let old_ring_payload_bytes = self
                .app_state
                .local_storage
                .get(LocalStorageKeys::RingPkMapping(storage_key.clone()))
                .map_err(|e| {
                    DkgError::Storage(format!("Refresh: failed to read old RingPkMapping: {}", e))
                })?
                .ok_or_else(|| {
                    DkgError::Storage(format!(
                        "Refresh: old RingPkMapping not found for key {}",
                        storage_key
                    ))
                })?;

            let old_ring_payload: RingPayload = serde_json::from_slice(&old_ring_payload_bytes)
                .map_err(|e| {
                    DkgError::Deserialization(format!(
                        "Refresh: failed to deserialize old RingPayload: {}",
                        e
                    ))
                })?;

            // Load old public polynomial from local-only RingPolyState.
            let old_ring_poly_state =
                RingPolyState::load(&self.app_state.local_storage, &old_ring_payload.ring_pk)
                    .map_err(|e| {
                        DkgError::Storage(format!("Refresh: failed to load RingPolyState: {}", e))
                    })?;

            let old_poly_bytes =
                hex::decode(&old_ring_poly_state.public_polynomial).map_err(|e| {
                    DkgError::Deserialization(format!(
                        "Refresh: failed to decode old public polynomial hex: {}",
                        e
                    ))
                })?;

            let new_poly_bytes = D::combine_pub_poly_bytes(&old_poly_bytes, &pub_poly_bytes)
                .map_err(|e| {
                    DkgError::Crypto(format!(
                        "Refresh: failed to combine public polynomials: {}",
                        e
                    ))
                })?;

            // Write updated RingPolyState (polynomial + refresh timestamp) locally.
            let updated_ring_poly_state = RingPolyState {
                public_polynomial: hex::encode(&new_poly_bytes),
                refreshed_at: now_secs,
            };
            updated_ring_poly_state
                .save(&self.app_state.local_storage, &old_ring_payload.ring_pk)
                .map_err(|e| {
                    DkgError::Storage(format!(
                        "Refresh: failed to store updated RingPolyState: {}",
                        e
                    ))
                })?;

            // RingPkMapping keeps the same payload — ring_pk, peers, threshold, pss_interval
            // are all unchanged by a refresh. RingPolyState (above) is the only local entry
            // that changes. No bulletin post is needed: the ring public key and membership
            // haven't changed, and the polynomial is local-only.
            tracing::info!(
                session_id = session_id,
                ring_pk = %old_ring_payload.ring_pk,
                node_id = node_id,
                "Refresh: Phase 4 complete — RingPolyState updated locally"
            );
        }

        // For refresh: clear the in-progress flag now that Phase 4 has succeeded.
        if is_refresh {
            self.app_state
                .dkg_session_state
                .unmark_ring_refreshing(&storage_key)
                .await;
        }

        // Update phase
        self.app_state
            .dkg_session_state
            .update_phase(&session_id, DkgPhase::Phase4Complete)
            .await;

        // Serialize ring_pk for logging and bulletin post
        let ring_pk_bytes = CryptoSerialize::to_bytes(&aggregate_pk).map_err(|e| {
            DkgError::Serialization(format!("Failed to serialize aggregate public key: {}", e))
        })?;

        tracing::info!(
            aggregate_pk = ?aggregate_pk,
            ring_key_hex = hex::encode(&ring_pk_bytes),
            node_id = node_id,
            "Phase 4: DKG complete! Final share computed"
        );

        // Node 1 is responsible for posting the RingPayload to the bulletin
        if node_id == 1 && !is_refresh {
            // Get peer_ids from session state
            let peer_ids = self
                .app_state
                .dkg_session_state
                .get_peer_ids(&session_id)
                .await
                .ok_or(DkgError::Generic("Failed to get peer ids".to_string()))?;
            // Create RingPayload (public_polynomial excluded — stored locally only)
            let ring_payload = RingPayload {
                ring_pk: hex::encode(&ring_pk_bytes),
                peer_ids,
                threshold: threshold as u32,
                pss_interval,
            };

            // Serialize payload
            let payload_bytes: Vec<u8> = ring_payload.clone().try_into().map_err(|e| {
                DkgError::Serialization(format!("Failed to serialize RingPayload: {}", e))
            })?;

            self.app_state
                .bulletin
                .post(
                    BULLETIN_RING_NAMESPACE.to_string(),
                    payload_bytes,
                    BULLETIN_PLACEHOLDER_PROOF.to_vec(),
                    Some(session_id.to_string()),
                )
                .await
                .map_err(|e| DkgError::Bulletin(format!("Failed to post RingPayload: {}", e)))?;

            tracing::info!(
                ring_pk = %ring_payload.ring_pk,
                namespace = BULLETIN_RING_NAMESPACE,
                "DKG Coordinator: Successfully posted RingPayload to bulletin"
            );
        }

        // Clean up session data - no longer needed since private share is in local storage
        // and ring info is on the bulletin
        self.app_state
            .dkg_session_state
            .remove_session(&session_id)
            .await;

        // Record session completion metric
        metrics::record_dkg_session_completed();

        tracing::info!(
            session_id = session_id,
            "DKG Coordinator: Session cleanup complete"
        );

        Ok(())
    }
}
