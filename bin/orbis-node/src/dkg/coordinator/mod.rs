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
//!
//! ## Module Layout
//! - [`message_handlers`] — per-message-type handlers called from [`handle_message`]
//! - [`network`] — peer stream management and message dispatch
//! - [`phases`] — DKG phase transitions (Phase 1 → 2 → 4)

mod message_handlers;
mod network;
mod peers;
mod phases;
mod reshare;
mod ring_storage;
mod state_machine;
mod types;

use crate::app_state::AppState;
use crate::constants::{DKG_PHASE_TIMEOUT, DKG_SESSION_WAIT_POLL_INTERVAL};
use crate::dkg::error::{DkgError, Result};
use crate::dkg::helpers::session_not_found;
use crate::dkg::messages::DkgMessage;
use crate::dkg::session_state::{CreateSessionOutcome, DkgMessageType};
use crate::helpers::helpers::extract_node_part;
use crate::metrics;
use ::network::PeerId;
use crypto::r#trait::{Dkg, DkgRole};
use crypto::{
    GroupAffine as G1Affine, PolynomialCommitmentImpl as PolynomialCommitment,
    PubPolyImpl as PubPoly, ScalarField as Fr,
};
use std::sync::Arc;

/// DKG Session Manager
///
/// Each node has its own instance that manages this node's participation
/// in DKG sessions. This is NOT a central coordinator - the protocol is
/// decentralized with each node managing its own state.
///
/// Type parameter D must implement Dkg with ShareValue = Fr and PublicKey = G1Affine
/// for compatibility with the current serialization code.
pub struct DkgCoordinator<D>
where
    D: Dkg + Clone + 'static,
{
    pub(in crate::dkg::coordinator) app_state: Arc<AppState<D>>,
}

impl<D> DkgCoordinator<D>
where
    D: Dkg<
            ShareValue = Fr,
            PublicKey = G1Affine,
            PolynomialCommitment = PolynomialCommitment,
            PubPoly = PubPoly,
        > + Clone
        + 'static,
{
    /// Create a new DKG session manager for this node.
    pub fn new(app_state: Arc<AppState<D>>) -> Self {
        Self { app_state }
    }

    /// Handle an incoming DKG message.
    ///
    /// Deduplicates, validates sender identity, then routes to the appropriate
    /// per-message-type handler.  `SessionInit` is handled before the
    /// session-exists check because it creates the session.
    pub async fn handle_message(
        &self,
        message: DkgMessage,
        sender_peer_id: &PeerId,
    ) -> Result<Option<DkgMessage>> {
        let session_id = message.session_id();

        // Classify message for dedup and metrics.
        let (message_type, from_node_id_opt) = match &message {
            DkgMessage::Commitment { from_node_id, .. } => {
                (DkgMessageType::Commitment, Some(*from_node_id))
            }
            DkgMessage::Share { from_node_id, .. } => (DkgMessageType::Share, Some(*from_node_id)),
            DkgMessage::Complaint { from_node_id, .. } => {
                (DkgMessageType::Complaint, Some(*from_node_id))
            }
            DkgMessage::ReshareShareAck { .. } => (DkgMessageType::ReshareShareAck, None),
            DkgMessage::ReshareParticipantSet { from_node_id, .. } => {
                (DkgMessageType::ReshareParticipantSet, Some(*from_node_id))
            }
            DkgMessage::SessionInit { .. } => (DkgMessageType::SessionInit, None),
            DkgMessage::Error { .. } => (DkgMessageType::Error, None),
        };

        let message_type_str = match message_type {
            DkgMessageType::SessionInit => "session_init",
            DkgMessageType::Commitment => "commitment",
            DkgMessageType::Share => "share",
            DkgMessageType::ReshareShareAck => "reshare_share_ack",
            DkgMessageType::ReshareParticipantSet => "reshare_participant_set",
            DkgMessageType::Complaint => "complaint",
            DkgMessageType::Error => "error",
        };
        metrics::record_dkg_message_received(message_type_str);

        // Check for duplicate messages (except SessionInit and Error).
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

        // SessionInit can create a session — handle before the session-exists check.
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
            return message_handlers::handle_session_init(
                self,
                session_id,
                *threshold,
                *total_participants,
                peer_ids,
                node_id_assignments,
                token_string,
                kind,
                *pss_interval,
                sender_peer_id,
            )
            .await;
        }

        // All other messages require the session to exist first.
        // Wait up to DKG_PHASE_TIMEOUT to handle the race where a commitment arrives
        // before this node's SessionInit handler has finished.
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

        // Validate sender identity for messages that carry node IDs.
        let sender_hex = hex::encode(sender_peer_id.as_bytes());
        let sender_check: Option<(u32, bool)> = match &message {
            DkgMessage::Commitment { from_node_id, .. }
            | DkgMessage::Share { from_node_id, .. }
            | DkgMessage::Complaint { from_node_id, .. } => Some((*from_node_id, false)),
            DkgMessage::ReshareShareAck {
                receiver_node_id, ..
            } => Some((*receiver_node_id, true)),
            DkgMessage::ReshareParticipantSet { from_node_id, .. } => Some((*from_node_id, true)),
            DkgMessage::SessionInit { .. } | DkgMessage::Error { .. } => None,
        };

        if let Some((claimed_node_id, use_new_committee_map)) = sender_check {
            let expected_node_id = self
                .app_state
                .dkg_session_state
                .with_state(&session_id, |state| {
                    let map = if use_new_committee_map {
                        &state.reshare_new_peer_id_to_node_id
                    } else {
                        &state.peer_id_to_node_id
                    };
                    map.iter()
                        .find(|(peer_id, _)| extract_node_part(peer_id) == sender_hex)
                        .map(|(_, node_id)| *node_id)
                })
                .await
                .flatten();

            match expected_node_id {
                Some(expected) if expected == claimed_node_id => {}
                Some(expected) => {
                    tracing::warn!(
                        claimed_node_id = claimed_node_id,
                        expected_node_id = expected,
                        sender_peer = %sender_hex,
                        session_id = session_id,
                        use_new_committee_map = use_new_committee_map,
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
                        use_new_committee_map = use_new_committee_map,
                        "DKG Coordinator: Rejecting message - sender peer not found in session"
                    );
                    return Err(DkgError::Unauthorized(format!(
                        "Sender peer {} not found in session peer mappings",
                        sender_hex
                    )));
                }
            }
        }

        // Dispatch to per-message-type handlers.
        let response = match message {
            DkgMessage::Commitment {
                from_node_id,
                commitment,
                ..
            } => {
                message_handlers::handle_commitment_message(
                    self,
                    session_id,
                    from_node_id,
                    commitment,
                )
                .await?
            }
            DkgMessage::Share {
                from_node_id,
                to_node_id,
                share_value,
                nonce,
                ..
            } => {
                message_handlers::handle_share_message(
                    self,
                    session_id,
                    from_node_id,
                    to_node_id,
                    share_value,
                    nonce,
                )
                .await?
            }
            DkgMessage::Complaint {
                from_node_id,
                accused_node_id,
                reason,
                ..
            } => {
                tracing::warn!(
                    from_node_id = from_node_id,
                    accused_node_id = accused_node_id,
                    reason = %reason,
                    "DKG Coordinator: Received complaint"
                );
                None
            }
            DkgMessage::ReshareShareAck {
                receiver_node_id,
                dealer_id,
                ..
            } => {
                message_handlers::handle_reshare_share_ack(
                    self,
                    session_id,
                    receiver_node_id,
                    dealer_id,
                )
                .await?
            }
            DkgMessage::ReshareParticipantSet {
                from_node_id,
                selected_dealer_ids,
                ..
            } => {
                message_handlers::handle_reshare_participant_set(
                    self,
                    session_id,
                    from_node_id,
                    selected_dealer_ids,
                )
                .await?
            }
            DkgMessage::Error { error, .. } => {
                tracing::error!(
                    session_id = session_id,
                    error = %error,
                    "DKG Coordinator: Received error"
                );
                None
            }
            DkgMessage::SessionInit { .. } => {
                unreachable!("SessionInit handled above")
            }
        };

        Ok(response)
    }

    /// Create a new DKG session.
    ///
    /// Typically called when a `StartDkg` gRPC request is received,
    /// or internally by the PSS reshare scheduler.
    ///
    /// `init_fn` is invoked on the new session state while the state map's write lock
    /// is held, so the session is fully initialized before any other task can observe
    /// it. Pass `|_| {}` when no extra initialization is needed.
    pub async fn create_session<F>(
        &self,
        session_id: u64,
        node_id: u32,
        threshold: usize,
        total_nodes: usize,
        role: DkgRole,
        init_fn: F,
    ) -> Result<()>
    where
        F: FnOnce(&mut crate::dkg::session_state::DkgSessionState<D>),
    {
        let dkg_node = D::new(node_id, threshold, total_nodes, session_id, role)
            .map_err(|e| DkgError::Crypto(format!("Failed to create DKG node: {}", e)))?;

        match self
            .app_state
            .dkg_session_state
            .create_session(session_id, *dkg_node, total_nodes, init_fn)
            .await
        {
            CreateSessionOutcome::Created => {}
            CreateSessionOutcome::AlreadyExists => return Err(DkgError::SessionAlreadyExists),
            CreateSessionOutcome::LimitReached => return Err(DkgError::MaxSessionsReached),
        }

        metrics::record_dkg_session_started();
        Ok(())
    }

    /// Remove a DKG session from state.
    pub(in crate::dkg::coordinator) async fn remove_session(&self, session_id: u64) {
        self.app_state
            .dkg_session_state
            .remove_session(&session_id)
            .await;
    }

    /// Store peer IDs for a session (needed for sending messages in later phases).
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
    /// stream, preserving QUIC's within-stream ordering guarantee
    /// (SessionInit → Commitment → Share arrive in order at the receiver).
    ///
    /// When `session_id` is `None` (fire-and-forget messages), a fresh stream is
    /// opened each time and dropped after the send.
    pub async fn send_message_to_peer(
        &self,
        peer_id_str: &str,
        message: DkgMessage,
        session_id: Option<u64>,
    ) -> Result<()> {
        network::send_message_to_peer(self, peer_id_str, message, session_id).await
    }

    /// Open a QUIC stream to a peer, evicting and reconnecting the cached connection on failure.
    pub(in crate::dkg::coordinator) async fn open_stream_to_peer(
        &self,
        peer_id_str: &str,
    ) -> Result<Box<dyn ::network::Connection>> {
        network::open_stream_to_peer(self, peer_id_str).await
    }

    /// Phase 1: Generate polynomial and broadcast commitment to all peers.
    ///
    /// Called by the initiator after `StartDkg`, or by the PSS scheduler.
    pub async fn initiate_phase1_commitments(
        &self,
        session_id: u64,
        peer_ids: &[String],
    ) -> Result<()> {
        phases::initiate_phase1_commitments(self, session_id, peer_ids).await
    }

    /// Check if Phase 1 is complete and trigger Phase 2 if so.
    ///
    /// Called after each incoming commitment message.
    pub async fn check_and_trigger_phase2(
        &self,
        session_id: u64,
        peer_ids: &[String],
    ) -> Result<()> {
        phases::check_and_trigger_phase2(self, session_id, peer_ids).await
    }

    /// Phase 2: Generate shares and send them to all peers.
    ///
    /// Called when all commitments have been received.
    pub async fn initiate_phase2_shares(&self, session_id: u64, peer_ids: &[String]) -> Result<()> {
        phases::initiate_phase2_shares(self, session_id, peer_ids).await
    }

    /// Check if Phase 2 is complete (all shares received) and trigger Phase 4 if so.
    ///
    /// Called after each incoming share message.
    pub async fn check_and_trigger_phase4(&self, session_id: u64) -> Result<()> {
        phases::check_and_trigger_phase4(self, session_id).await
    }

    /// Phase 4: Compute final secret share and aggregate public key.
    ///
    /// If this node is node_id == 1, also posts the `RingPayload` to the bulletin.
    pub async fn initiate_phase4_completion(&self, session_id: u64) -> Result<()> {
        phases::initiate_phase4_completion(self, session_id).await
    }
}
