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
    BULLETIN_PLACEHOLDER_PROOF, BULLETIN_RING_NAMESPACE, DKG_PHASE_TIMEOUT,
    DKG_SESSION_WAIT_POLL_INTERVAL, MAX_COMMITMENT_COEFFICIENTS,
};
use crate::dkg::error::{DkgError, Result};
use crate::dkg::helpers::{
    persist_ring_bundle, serialize_commitment_coefficients, session_not_found, validate_dkg_claims,
    validate_refresh_session_init, validate_reshare_session_init,
};
use crate::dkg::messages::{DkgMessage, SessionKind};
use crate::dkg::session_state::{DkgMessageType, DkgPhase, ReshareParams};
use crate::helpers::helpers::{extract_node_part, is_self_peer_id};
use crate::metrics;
use crate::ring_state::{RingIndexEntry, RingShareBundle};
use authn::{resolve_jwt_did, BearerToken, DkgClaims};
use bulletin::r#trait::RingPayload;
use crypto::r#trait::{DistributedShare, Dkg, DkgRole};
use crypto::{CryptoDeserialize, CryptoSerialize};
use crypto::{GroupAffine as G1Affine, ScalarField as Fr};
use crypto::{
    PolynomialCommitmentImpl as PolynomialCommitment, GROUP_POINT_SIZE as G1_COMPRESSED_SIZE,
    SCALAR_SIZE as FR_COMPRESSED_SIZE,
};
use local_storage::r#trait::{LocalStorage, LocalStorageKeys};
use network::Connection as NetworkConnection;
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
            DkgMessage::Error { .. } => (DkgMessageType::Error, None),
        };

        // Record message received metric
        let message_type_str = match message_type {
            DkgMessageType::SessionInit => "session_init",
            DkgMessageType::Commitment => "commitment",
            DkgMessageType::Share => "share",
            DkgMessageType::Complaint => "complaint",
            DkgMessageType::Error => "error",
        };
        metrics::record_dkg_message_received(message_type_str);

        // Check for duplicate messages (except SessionInit and Error)
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
            kind,
            pss_interval,
            ..
        } = &message
        {
            let sender_hex = hex::encode(sender_peer_id.as_bytes());

            match kind {
                SessionKind::Refresh { ring_pk_hex } => {
                    tracing::info!(
                        session_id = session_id,
                        ring_pk_hex = %ring_pk_hex,
                        sender_peer_hex = %sender_hex,
                        "DKG Coordinator: Refresh SessionInit received - pre-validation"
                    );
                    validate_refresh_session_init(
                        ring_pk_hex,
                        &sender_hex,
                        &self.app_state.local_storage,
                        &self.app_state.bulletin,
                    )
                    .await?;
                    if !self
                        .app_state
                        .dkg_session_state
                        .try_mark_ring_pss(ring_pk_hex)
                        .await
                    {
                        return Err(DkgError::Unauthorized(
                            "Refresh already in progress for this ring".to_string(),
                        ));
                    }
                    tracing::info!(
                        session_id = session_id,
                        ring_pk = %ring_pk_hex,
                        sender_peer_hex = %sender_hex,
                        "DKG Coordinator: Refresh SessionInit validated and ring marked refreshing"
                    );
                }
                SessionKind::Reshare {
                    ring_pk_hex,
                    next_peer_ids: reshare_next_peer_ids,
                    new_threshold: reshare_new_threshold,
                } => {
                    tracing::info!(
                        session_id = session_id,
                        ring_pk_hex = %ring_pk_hex,
                        sender_peer_hex = %sender_hex,
                        "DKG Coordinator: Reshare SessionInit received - pre-validation"
                    );
                    validate_reshare_session_init(
                        ring_pk_hex,
                        &sender_hex,
                        reshare_next_peer_ids,
                        *reshare_new_threshold,
                        &self.app_state.local_storage,
                        &self.app_state.bulletin,
                    )
                    .await?;
                    if !self
                        .app_state
                        .dkg_session_state
                        .try_mark_ring_pss(ring_pk_hex)
                        .await
                    {
                        return Err(DkgError::Unauthorized(
                            "Reshare already in progress for this ring".to_string(),
                        ));
                    }
                    tracing::info!(
                        session_id = session_id,
                        ring_pk = %ring_pk_hex,
                        sender_peer_hex = %sender_hex,
                        "DKG Coordinator: Reshare SessionInit validated and ring marked resharing"
                    );
                }
                SessionKind::Fresh => {
                    // 1. Authenticate: Validate JWT token
                    let current_time = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map_err(|e| DkgError::Generic(format!("Failed to get timestamp: {}", e)))?
                        .as_secs();
                    let token: BearerToken<DkgClaims> =
                        resolve_jwt_did(token_string, current_time, MAX_TOKEN_LIFETIME_SECS)
                            .map_err(|e| {
                                DkgError::Unauthorized(format!("JWT validation failed: {}", e))
                            })?;
                    // 2. Authorize: Validate JWT claims match SessionInit fields
                    validate_dkg_claims(&token, *threshold, peer_ids, *pss_interval)?;
                    tracing::info!(
                        issuer = %token.issuer_id,
                        threshold = threshold,
                        "DKG Coordinator: SessionInit JWT validated successfully"
                    );
                }
            }

            let our_peer_id_hex = hex::encode(self.app_state.network.local_peer_id().as_bytes());
            let our_node_part = extract_node_part(&our_peer_id_hex);

            // For Reshare, determine role and node_id from committee membership rather
            // than looking up node_id_assignments (which only covers the old committee).
            let (assigned_node_id, dkg_role, maybe_reshare_params) = if let SessionKind::Reshare {
                ring_pk_hex,
                next_peer_ids,
                new_threshold,
            } = kind
            {
                let mut sorted_old = peer_ids.clone();
                sorted_old.sort();
                let mut sorted_new = next_peer_ids.clone();
                sorted_new.sort();

                let in_old = sorted_old
                    .iter()
                    .any(|p| extract_node_part(p) == our_node_part);
                let in_new = sorted_new
                    .iter()
                    .any(|p| extract_node_part(p) == our_node_part);

                let role = match (in_old, in_new) {
                    (true, true) => DkgRole::DealerReceiver,
                    (true, false) => DkgRole::Dealer,
                    (false, true) => DkgRole::Receiver,
                    (false, false) => {
                        return Err(DkgError::InvalidInput(
                            "Reshare SessionInit: this node is not in either committee".to_string(),
                        ))
                    }
                };

                // Session node_id: old committee index for Dealers; new committee index for Receivers
                let node_id = if in_old {
                    sorted_old
                        .iter()
                        .position(|p| extract_node_part(p) == our_node_part)
                        .map(|i| (i + 1) as u32)
                        .unwrap()
                } else {
                    sorted_new
                        .iter()
                        .position(|p| extract_node_part(p) == our_node_part)
                        .map(|i| (i + 1) as u32)
                        .unwrap()
                };

                // Pre-load old share for Dealer/DealerReceiver nodes.
                let old_share = if in_old {
                    let bundle = RingShareBundle::load_by_ring_key(
                        &self.app_state.local_storage,
                        ring_pk_hex,
                    )
                    .map_err(|e| {
                        DkgError::Storage(format!("Reshare: failed to load old share: {}", e))
                    })?;
                    let pri = bundle.pri_share().map_err(|e| {
                        DkgError::Deserialization(format!(
                            "Reshare: failed to deserialize old share: {}",
                            e
                        ))
                    })?;
                    Some(pri.v)
                } else {
                    None
                };

                // participating_ids = all old committee node IDs (full participation).
                let participating_ids: Vec<u32> = (1..=peer_ids.len() as u32).collect();

                let new_node_id = if in_new {
                    sorted_new
                        .iter()
                        .position(|p| extract_node_part(p) == our_node_part)
                        .map(|i| (i + 1) as u32)
                } else {
                    None
                };

                let params = ReshareParams {
                    ring_key: ring_pk_hex.clone(),
                    old_share,
                    participating_ids,
                    new_threshold: *new_threshold as usize,
                    new_total_nodes: next_peer_ids.len(),
                    new_peer_ids: sorted_new,
                    new_node_id,
                };

                (node_id, role, Some(params))
            } else {
                // Fresh / Refresh: look up our node_id from the initiator's assignments.
                let our_peer_id_key = our_peer_id_hex
                    .split('@')
                    .next()
                    .unwrap_or(&our_peer_id_hex)
                    .to_string();
                let node_id = node_id_assignments
                    .get(&our_peer_id_key)
                    .copied()
                    .ok_or_else(|| {
                        DkgError::InvalidInput(format!(
                            "Could not find our node_id in SessionInit. \
                             Our peer_id: {}, assignments: {:?}",
                            our_peer_id_key,
                            node_id_assignments.keys().collect::<Vec<_>>()
                        ))
                    })?;
                (node_id, DkgRole::Standard, None)
            };

            tracing::info!(
                assigned_node_id = assigned_node_id,
                role = ?dkg_role,
                kind = ?kind,
                "DKG Coordinator: Received SessionInit - assigned node_id"
            );

            // If session doesn't exist, create it.
            // Idempotent: treat "session already exists" from a concurrent handler as success.
            if !self
                .app_state
                .dkg_session_state
                .session_exists(&session_id)
                .await
            {
                match self
                    .create_session(
                        session_id,
                        assigned_node_id,
                        *threshold as usize,
                        *total_participants as usize,
                        dkg_role,
                    )
                    .await
                {
                    Ok(()) => {}
                    Err(DkgError::SessionAlreadyExists) => {
                        tracing::debug!(
                            session_id = session_id,
                            "DKG Coordinator: Session already created by concurrent handler"
                        );
                    }
                    Err(e) => return Err(e),
                }

                // Set kind and reshare params atomically so that a commitment arriving
                // between the two writes never sees kind=Reshare with reshare_params=None.
                self.app_state
                    .dkg_session_state
                    .with_state_mut(&session_id, |state| {
                        state.kind = kind.clone();
                        if let Some(params) = maybe_reshare_params {
                            state.reshare_params = Some(params);
                        }
                    })
                    .await;

                self.app_state
                    .dkg_session_state
                    .set_pss_interval(&session_id, *pss_interval)
                    .await;
            }

            // For Reshare: peer_ids in session state = union(old, new) so that non-initiator
            // Dealer nodes know who to broadcast their commitment to.
            let session_peer_ids = if let SessionKind::Reshare { next_peer_ids, .. } = kind {
                let mut union: Vec<String> = peer_ids.clone();
                for p in next_peer_ids {
                    if !union.contains(p) {
                        union.push(p.clone());
                    }
                }
                union
            } else {
                peer_ids.clone()
            };
            self.set_peer_ids(&session_id, session_peer_ids).await;

            // Store old committee node_id → peer_id mappings for sender validation
            // (peer_id_to_node_id uses old committee IDs for all session kinds).
            let mut node_id_to_peer_id = std::collections::HashMap::new();
            for (peer_id_key, node_id) in node_id_assignments {
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
                role = ?dkg_role,
                "DKG Coordinator: Session init"
            );

            return Ok(None);
        }

        // For all other messages, ensure the session exists.
        // During PSS refresh the receiving node's SessionInit handler makes a bulletin
        // network call, so peer commitments can arrive before the
        // session is created.  Wait up to 500 ms for the session to appear before
        // rejecting so this ordering race does not stall the ceremony.
        if !self
            .app_state
            .dkg_session_state
            .session_exists(&session_id)
            .await
        {
            let session_state = self.app_state.dkg_session_state.clone();
            let found = tokio::time::timeout(DKG_PHASE_TIMEOUT, async move {
                loop {
                    tokio::time::sleep(DKG_SESSION_WAIT_POLL_INTERVAL).await;
                    if session_state.session_exists(&session_id).await {
                        return;
                    }
                }
            })
            .await;
            if found.is_err() {
                let sender_hex = hex::encode(sender_peer_id.as_bytes());
                tracing::warn!(
                    session_id = session_id,
                    sender_peer_hex = %sender_hex,
                    message_type = ?message_type,
                    "DKG Coordinator: Rejecting message - session not found on receiver"
                );
                return Err(session_not_found(session_id));
            }
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

                // Get expected commitment size from session (= new_threshold for Reshare,
                // = old threshold for Fresh/Refresh).
                let expected_coeff_count = self
                    .app_state
                    .dkg_session_state
                    .with_state(&session_id, |state| state.expected_commitment_size())
                    .await
                    .ok_or_else(|| session_not_found(session_id))?;

                // Polynomial commitment should have exactly expected_coeff_count coefficients.
                if num_coefficients != expected_coeff_count {
                    return Err(DkgError::CommitmentVerificationFailed(format!(
                        "Invalid number of commitment coefficients: got {}, expected {}",
                        num_coefficients, expected_coeff_count
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

                        // Receiver nodes never generate a polynomial — they only accumulate
                        // commitments to verify the shares they will receive.
                        let generates_polynomial = state.node.role() != DkgRole::Receiver;
                        Ok::<_, DkgError>(
                            generates_polynomial && state.node.commitment().coefficients.is_empty(),
                        )
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

                            match self
                                .send_message_to_peer(peer_id_str, commitment_msg, Some(session_id))
                                .await
                            {
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
                            self.remove_session(session_id).await;
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

                // Validate this share is intended for us.
                // For reshare, incoming shares are addressed by new-committee index;
                // for fresh/refresh, shares are addressed by the session node_id.
                let our_node_id = self
                    .app_state
                    .dkg_session_state
                    .with_state(&session_id, |state| {
                        state
                            .reshare_params
                            .as_ref()
                            .and_then(|p| p.new_node_id)
                            .unwrap_or_else(|| state.node.node_id())
                    })
                    .await
                    .ok_or_else(|| session_not_found(session_id))?;
                if to_node_id != our_node_id {
                    return Err(DkgError::ShareVerificationFailed(format!(
                        "Share intended for node {}, but we are node {}",
                        to_node_id, our_node_id
                    )));
                }
                // Commitment and share are delivered over the same persistent QUIC
                // stream (one stream per connection, opened lazily on first send).
                // QUIC guarantees in-order delivery within a stream, so the
                // commitment always arrives before the share — no retry needed.
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
                self.app_state
                    .dkg_session_state
                    .with_state_mut(&session_id, |state| {
                        state.node.receive_share(share).map_err(|e| {
                            DkgError::ShareVerificationFailed(format!(
                                "Failed to receive share: {}",
                                e
                            ))
                        })
                    })
                    .await
                    .ok_or_else(|| session_not_found(session_id))??;

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
            return Err(DkgError::SessionAlreadyExists);
        }

        // Record metrics
        metrics::record_dkg_session_started();

        Ok(())
    }

    /// Remove a DKG session from state.
    async fn remove_session(&self, session_id: u64) {
        self.app_state
            .dkg_session_state
            .remove_session(&session_id)
            .await;
    }

    /// Store peer IDs for a session (needed for sending messages in later phases)
    pub async fn set_peer_ids(&self, session_id: &u64, peer_ids: Vec<String>) {
        self.app_state
            .dkg_session_state
            .set_peer_ids(session_id, peer_ids)
            .await;
    }

    /// Send a DKG message to a peer.
    ///
    /// When `session_id` is `Some`, the stream is cached in the session state so
    /// that all messages within a session to the same peer travel on the same QUIC
    /// stream. This preserves QUIC's within-stream ordering guarantee
    /// (SessionInit → Commitment → Share arrive in order at the receiver).
    ///
    /// When `session_id` is `None` (fire-and-forget messages), a fresh stream is
    /// opened each time and dropped after the send.
    ///
    /// On connection-open failure the cached connection is evicted and a new one
    /// is established before retrying.
    pub async fn send_message_to_peer(
        &self,
        peer_id_str: &str,
        message: DkgMessage,
        session_id: Option<u64>,
    ) -> Result<()> {
        let message_type = match &message {
            DkgMessage::SessionInit { .. } => "session_init",
            DkgMessage::Commitment { .. } => "commitment",
            DkgMessage::Share { .. } => "share",
            DkgMessage::Complaint { .. } => "complaint",
            DkgMessage::Error { .. } => "error",
        };

        let message_data = serde_json::to_vec(&message)
            .map_err(|e| DkgError::Serialization(format!("Failed to serialize message: {}", e)))?;

        let session_state = &self.app_state.dkg_session_state;

        // Get or open the stream to use for this send.
        //
        // When session_id is Some, streams are cached in session state so all
        // messages within a session to the same peer travel on the same QUIC stream,
        // preserving within-stream ordering (SessionInit → Commitment → Share).
        //
        // When session_id is None, a fresh stream is opened and dropped after the send.
        let stream: Arc<dyn NetworkConnection> = if let Some(sid) = session_id {
            if let Some(cached) = session_state.get_peer_stream(&sid, peer_id_str).await {
                cached
            } else {
                let new_stream = Arc::from(self.open_stream_to_peer(peer_id_str).await?);
                session_state
                    .store_peer_stream(&sid, peer_id_str.to_string(), Arc::clone(&new_stream))
                    .await;
                new_stream
            }
        } else {
            Arc::from(self.open_stream_to_peer(peer_id_str).await?)
        };

        stream
            .send(NetworkMessage::new(message_data, DKG))
            .await
            .map_err(|e| {
                DkgError::NetworkCommunication(format!(
                    "Failed to send to peer {}: {}",
                    peer_id_str, e
                ))
            })?;

        metrics::record_dkg_message_sent(message_type);
        Ok(())
    }

    /// Open a QUIC stream to a peer, evicting and reconnecting the cached connection on failure.
    async fn open_stream_to_peer(&self, peer_id_str: &str) -> Result<Box<dyn network::Connection>> {
        self.app_state
            .peer_connection_pool
            .open_stream(&self.app_state.network, peer_id_str, DKG)
            .await
            .map_err(|e| {
                DkgError::NetworkConnection(format!(
                    "Failed to open stream to peer {}: {}",
                    peer_id_str, e
                ))
            })
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

            if let Err(e) = self
                .send_message_to_peer(peer_id_str, commitment_msg, Some(session_id))
                .await
            {
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
            self.remove_session(session_id).await;
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
        // Check polynomial readiness, expected commitment count, and our role.
        let (has_polynomial, expected_commitments, node_id, role) = self
            .app_state
            .dkg_session_state
            .with_state(&session_id, |state| {
                let role = state.node.role();
                // Receivers expect commitments from ALL old-committee dealers.
                // Dealers/DealerReceivers expect from all others (excluding self).
                let expected = match role {
                    DkgRole::Receiver => state.node.total_nodes(),
                    _ => state.node.total_nodes() - 1,
                };
                (
                    !state.node.commitment().coefficients.is_empty(),
                    expected,
                    state.node.node_id(),
                    role,
                )
            })
            .await
            .ok_or_else(|| session_not_found(session_id))?;

        // Receiver nodes never generate a polynomial — skip this gate for them.
        if role != DkgRole::Receiver && !has_polynomial {
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
            // Receiver nodes don't send shares — they just wait for incoming shares.
            if role != DkgRole::Receiver {
                self.initiate_phase2_shares(session_id, peer_ids).await?;
            }
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
        // Generate shares and get node_id, threshold, role, and reshare routing info.
        let (shares, node_id, threshold, role, reshare_new_peer_ids) =
            self.app_state
                .dkg_session_state
                .with_state_mut(&session_id, |state| {
                    // Make sure we've generated our polynomial
                    if state.node.commitment().coefficients.is_empty() {
                        tracing::debug!(
                            node_id = state.node.node_id(),
                            "DKG Coordinator: Generating polynomial before Phase 2"
                        );
                        state.generate_polynomial()?;
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
                    let reshare_peer_ids = state
                        .reshare_params
                        .as_ref()
                        .map(|p| p.new_peer_ids.clone());
                    Ok::<_, DkgError>((
                        shares,
                        state.node.node_id(),
                        state.node.threshold(),
                        state.node.role(),
                        reshare_peer_ids,
                    ))
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
            self.remove_session(session_id).await;
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

        // Send shares to peers.
        // For Reshare: route using reshare_new_peer_ids (sorted new committee, index = to_id - 1).
        // For Fresh/Refresh: use node_id_to_peer_id map, falling back to broadcast.
        let mut shares_sent = 0;

        for share in shares.iter() {
            // Skip sending share to ourselves.
            // For DealerReceiver, their new-committee node_id may differ from old-committee
            // node_id — skip if to_id maps to our own new-committee peer_id.
            let skip = if let Some(ref new_peers) = reshare_new_peer_ids {
                // Reshare: to_id is a new-committee index; check if it points to self.
                new_peers
                    .get((share.to_id - 1) as usize)
                    .map(|p| is_self_peer_id(&self.app_state.network, p))
                    .unwrap_or(false)
            } else {
                share.to_id == node_id
            };
            if skip {
                continue;
            }

            // For Reshare, route directly via sorted new committee list.
            if let Some(ref new_peers) = reshare_new_peer_ids {
                let Some(target_peer_id) = new_peers.get((share.to_id - 1) as usize) else {
                    tracing::error!(
                        to_node = share.to_id,
                        "Reshare: share to_id out of range for new committee"
                    );
                    continue;
                };
                let share_value_bytes = CryptoSerialize::to_bytes(&share.value).map_err(|e| {
                    DkgError::Serialization(format!("Failed to serialize share value: {}", e))
                })?;
                let share_msg = DkgMessage::Share {
                    session_id,
                    from_node_id: node_id,
                    to_node_id: share.to_id,
                    share_value: share_value_bytes,
                    nonce: share.nonce,
                };
                match self
                    .send_message_to_peer(target_peer_id, share_msg, Some(session_id))
                    .await
                {
                    Ok(_) => {
                        shares_sent += 1;
                        tracing::debug!(
                            from_node = node_id,
                            to_node = share.to_id,
                            peer_id = %target_peer_id,
                            "Reshare: Sent share to new committee member"
                        );
                    }
                    Err(e) => {
                        tracing::error!(
                            to_node = share.to_id,
                            peer_id = %target_peer_id,
                            error = %e,
                            "Reshare: Failed to send share"
                        );
                    }
                }
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
                match self
                    .send_message_to_peer(&target_peer_id, share_msg, Some(session_id))
                    .await
                {
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
                        .send_message_to_peer(peer_id_str, broadcast_share_msg, Some(session_id))
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
            self.remove_session(session_id).await;
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

        // Pure Dealer nodes (not in new committee) are done after distributing shares —
        // they won't receive any shares themselves, so Phase 4 must be triggered here
        // rather than from the share-receive path.
        if role == DkgRole::Dealer {
            tracing::info!(
                session_id = session_id,
                "Reshare Dealer: share distribution complete, triggering Phase 4 cleanup"
            );
            self.initiate_phase4_completion(session_id).await?;
        }

        Ok(())
    }

    /// Check if Phase 2 is complete (all shares received) and trigger Phase 4 if so.
    pub async fn check_and_trigger_phase4(&self, session_id: u64) -> Result<()> {
        // Read all relevant counters in a single lock to avoid TOCTOU races.
        // Expected share count depends on role:
        //   Receiver      → total_nodes (one from each old dealer)
        //   Standard/DealerReceiver → total_nodes - 1 (excluding self)
        //   Dealer        → 0 (handled by initiate_phase2_shares, never reaches here)
        let (expected, received_shares, phase) = self
            .app_state
            .dkg_session_state
            .with_state(&session_id, |state| {
                let expected = match state.node.role() {
                    DkgRole::Receiver => state.node.total_nodes(),
                    _ => state.node.total_nodes() - 1,
                };
                (expected, state.shares_received, state.phase)
            })
            .await
            .ok_or_else(|| session_not_found(session_id))?;

        // Guard: don't start Phase 4 again if already completed.
        if phase == DkgPhase::Phase4Complete {
            return Ok(());
        }

        if received_shares >= expected {
            tracing::info!(
                received_shares = received_shares,
                expected = expected,
                "Phase 2 complete (all shares received): Proceeding to Phase 4"
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
        let (kind, pss_interval, dkg_role, reshare_new_peer_ids) = self
            .app_state
            .dkg_session_state
            .with_state(&session_id, |state| {
                (
                    state.kind.clone(),
                    state.pss_interval,
                    state.node.role(),
                    state
                        .reshare_params
                        .as_ref()
                        .map(|p| p.new_peer_ids.clone()),
                )
            })
            .await
            .ok_or_else(|| session_not_found(session_id))?;

        // Pure Dealer nodes don't compute a secret share — they just clean up.
        // Because they are leaving the ring, delete the local secret share and
        // remove the ring from the index so the PSS scheduler ignores it.
        if dkg_role == DkgRole::Dealer {
            let ring_key = kind.ring_key().map(|k| k.to_string());
            self.app_state
                .dkg_session_state
                .update_phase(&session_id, DkgPhase::Phase4Complete)
                .await;
            if let Some(key) = &ring_key {
                self.app_state.dkg_session_state.unmark_ring_pss(key).await;

                // Delete the encrypted share bundle.
                if let Err(e) = self
                    .app_state
                    .local_storage
                    .delete(LocalStorageKeys::RingKey(key.clone()))
                {
                    tracing::warn!(
                        session_id = session_id,
                        ring_key = %key,
                        error = %e,
                        "Reshare Dealer: failed to delete share bundle (already absent?)"
                    );
                } else {
                    tracing::info!(
                        session_id = session_id,
                        ring_key = %key,
                        "Reshare Dealer: deleted share bundle — node has left the ring"
                    );
                }

                // Remove the ring from the local index so the PSS scheduler skips it.
                let storage = &self.app_state.local_storage;
                match storage.get(LocalStorageKeys::RingIndex) {
                    Ok(Some(raw)) => match serde_json::from_slice::<Vec<RingIndexEntry>>(&raw) {
                        Ok(mut index) => {
                            index.retain(|e| e.ring_pk_str != *key);
                            match serde_json::to_vec(&index) {
                                Ok(bytes) => {
                                    if let Err(e) = storage.set(LocalStorageKeys::RingIndex, bytes)
                                    {
                                        tracing::warn!(
                                            session_id = session_id,
                                            ring_key = %key,
                                            error = %e,
                                            "Reshare Dealer: failed to write updated RingIndex"
                                        );
                                    }
                                }
                                Err(e) => tracing::warn!(
                                    session_id = session_id,
                                    ring_key = %key,
                                    error = %e,
                                    "Reshare Dealer: failed to serialize RingIndex"
                                ),
                            }
                        }
                        Err(e) => tracing::warn!(
                            session_id = session_id,
                            ring_key = %key,
                            error = %e,
                            "Reshare Dealer: failed to deserialize RingIndex"
                        ),
                    },
                    Ok(None) => {}
                    Err(e) => tracing::warn!(
                        session_id = session_id,
                        ring_key = %key,
                        error = %e,
                        "Reshare Dealer: failed to read RingIndex"
                    ),
                }
            }
            self.remove_session(session_id).await;
            metrics::record_dkg_session_completed();
            tracing::info!(
                session_id = session_id,
                "Reshare Dealer: Phase 4 complete (share distribution done, secret deleted)"
            );
            return Ok(());
        }

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

        // Compute storage_key — the canonical local-storage key used by sign/pre for share lookup.
        // For Refresh and Reshare this is the ORIGINAL ring's key (unchanged secret → same pk).
        let storage_key = kind
            .ring_key()
            .map(|k| k.to_string())
            .unwrap_or_else(|| aggregate_pk.to_string());

        // Write share + polynomial as a single encrypted bundle.
        // Atomicity: both fields land in one set_encrypted call, so a crash leaves the
        // entry either fully written or absent — never partially updated.
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        persist_ring_bundle(
            &self.app_state.local_storage,
            &kind,
            &final_share_bytes,
            &pub_poly_bytes,
            &aggregate_pk,
            now_secs,
            session_id,
            |old, delta| D::combine_pub_poly_bytes(old, delta).map_err(|e| e.to_string()),
        )?;

        tracing::debug!(
            session_id = session_id,
            "DKG Coordinator: Stored RingShareBundle (share + polynomial) atomically"
        );

        // For fresh DKG: cache the RingPayload locally and append a RingIndexEntry so the
        // PSS scheduler can discover this ring.
        //
        // For Refresh: bulletin entry is unchanged; polynomial updated in RingShareBundle above.
        // For Reshare: bulletin is updated below by new-committee node 1.
        if matches!(kind, SessionKind::Fresh) {
            let peer_ids = self
                .app_state
                .dkg_session_state
                .get_peer_ids(&session_id)
                .await
                .unwrap_or_default();
            // Hex-encode the aggregate public key for byte-round-trip use in RingPayload.
            // sign/pre services hex-decode this field to reconstruct the G1Affine,
            // then call .to_string() — which recovers storage_key exactly.
            let ring_pk_hex_for_payload = CryptoSerialize::to_bytes(&aggregate_pk)
                .map(|b| hex::encode(&b))
                .map_err(|e| {
                    DkgError::Serialization(format!(
                        "Failed to serialize aggregate_pk for RingPayload: {}",
                        e
                    ))
                })?;

            let ring_payload_local = RingPayload {
                ring_pk: ring_pk_hex_for_payload.clone(),
                peer_ids,
                next_peer_ids: None,
                new_threshold: None,
                threshold: threshold as u32,
                pss_interval,
            };
            let ring_payload_bytes: Vec<u8> = ring_payload_local.try_into().map_err(|e| {
                DkgError::Serialization(format!(
                    "Failed to serialize RingPayload for local cache: {}",
                    e
                ))
            })?;

            // Compute the bulletin post_id deterministically. All nodes construct the
            // identical RingPayload so they all arrive at the same post_id.
            // get_post_id adds the "bulletin/" prefix internally.
            let bulletin_post_id = self
                .app_state
                .bulletin
                .get_post_id(BULLETIN_RING_NAMESPACE, &ring_payload_bytes)
                .map_err(|e| {
                    DkgError::Serialization(format!("Failed to compute bulletin post_id: {}", e))
                })?;

            // Append a RingIndexEntry to RingIndex so the PSS scheduler can enumerate
            // rings and the refresh validator can look up bulletin entries by ring_pk_str.
            // Hold the lock for the entire read-modify-write so concurrent Phase 4
            // completions don't overwrite each other's appended entry.
            {
                let _guard = self.app_state.ring_index_lock.lock().await;
                let mut ring_index: Vec<RingIndexEntry> = self
                    .app_state
                    .local_storage
                    .get(LocalStorageKeys::RingIndex)
                    .ok()
                    .flatten()
                    .and_then(|b| serde_json::from_slice(&b).ok())
                    .unwrap_or_default();
                if !ring_index.iter().any(|e| e.ring_pk_str == storage_key) {
                    ring_index.push(RingIndexEntry {
                        ring_pk_str: storage_key.clone(),
                        bulletin_post_id,
                    });
                    let index_bytes = serde_json::to_vec(&ring_index).map_err(|e| {
                        DkgError::Serialization(format!("Failed to serialize RingIndex: {}", e))
                    })?;
                    self.app_state
                        .local_storage
                        .set(LocalStorageKeys::RingIndex, index_bytes)
                        .map_err(|e| {
                            DkgError::Storage(format!("Failed to store RingIndex: {}", e))
                        })?;
                }
            }
        }

        // Clear the in-progress ceremony flag now that Phase 4 has succeeded.
        if let Some(ring_key) = kind.ring_key() {
            self.app_state
                .dkg_session_state
                .unmark_ring_pss(ring_key)
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

        // Node 1 of the OLD committee posts the RingPayload for fresh DKG.
        // Reshare bulletin update is handled separately below (new committee node 1).
        if node_id == 1 && matches!(kind, SessionKind::Fresh) {
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
                next_peer_ids: None,
                new_threshold: None,
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

        // For Reshare: node 1 of the NEW committee posts the updated RingPayload with the
        // new peer_ids and new threshold.  The ring_pk remains the same (same secret).
        if let SessionKind::Reshare {
            ring_pk_hex,
            next_peer_ids,
            new_threshold,
        } = &kind
        {
            // Determine our position in the new committee (sorted) to find new_node_id.
            let our_peer_id_hex = hex::encode(self.app_state.network.local_peer_id().as_bytes());
            let our_node_part = extract_node_part(&our_peer_id_hex);
            let new_node_id = reshare_new_peer_ids
                .as_ref()
                .and_then(|peers| {
                    peers
                        .iter()
                        .position(|p| extract_node_part(p) == our_node_part)
                        .map(|i| (i + 1) as u32)
                })
                .unwrap_or(0);
            // TODO: change to needing a threshold signature
            if new_node_id == 1 {
                let ring_payload = RingPayload {
                    ring_pk: ring_pk_hex.clone(),
                    peer_ids: next_peer_ids.clone(),
                    next_peer_ids: None,
                    new_threshold: None,
                    threshold: *new_threshold,
                    pss_interval,
                };
                let payload_bytes: Vec<u8> = ring_payload.clone().try_into().map_err(|e| {
                    DkgError::Serialization(format!(
                        "Reshare: failed to serialize updated RingPayload: {}",
                        e
                    ))
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
                    .map_err(|e| {
                        DkgError::Bulletin(format!(
                            "Reshare: failed to post updated RingPayload: {}",
                            e
                        ))
                    })?;

                tracing::info!(
                    ring_pk = %ring_pk_hex,
                    namespace = BULLETIN_RING_NAMESPACE,
                    new_threshold = new_threshold,
                    new_committee_size = next_peer_ids.len(),
                    "Reshare: Successfully posted updated RingPayload to bulletin"
                );
            }
        }

        // Clean up session data - no longer needed since private share is in local storage
        // and ring info is on the bulletin
        self.remove_session(session_id).await;

        // Record session completion metric
        metrics::record_dkg_session_completed();

        tracing::info!(
            session_id = session_id,
            "DKG Coordinator: Session cleanup complete"
        );

        Ok(())
    }
}
