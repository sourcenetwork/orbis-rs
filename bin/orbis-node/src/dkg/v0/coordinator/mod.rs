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
//! - [`message_handlers`] — typed contribution and delivery handlers
//! - [`reporting`] — stalled PSS observation reporting
//! - [`phases`] — DKG phase transitions (Phase 1 → 2 → 4)

pub(crate) mod evidence;
pub(crate) mod message_handlers;
mod peers;
mod phases;
pub(crate) mod refresh_health_check;
pub(crate) mod reporting;
mod reshare;
mod ring_storage;
mod state_machine;
pub(crate) mod types;

use crate::app_state::AppState;
use crate::dkg::v0::error::{DkgError, Result};
use crate::dkg::v0::helpers::session_not_found;
use crate::dkg::v0::messages::SignedDkgShare;
use crate::dkg::v0::session_state::{
    AttemptStateError, CreateSessionOutcome, DkgSessionState, MessageProcessingClaim,
    TopicTaskDisposition, TransportMessageClaimGuard,
};
use crate::dkg::v0::transport::{AttemptKey, MessageId};
use crypto::r#trait::{Dkg, DkgRole};
use crypto::{
    GroupAffine as G1Affine, PolynomialCommitmentImpl as PolynomialCommitment,
    PubPolyImpl as PubPoly, ScalarField as Fr, SignImpl,
};
use std::sync::Arc;

use self::types::CoordinatorReportSigner;

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
    pub app_state: Arc<AppState<D>>,
    pub routes: &'static ::network::ProtocolRoutes,
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
    pub fn with_routes(
        app_state: Arc<AppState<D>>,
        routes: &'static ::network::ProtocolRoutes,
    ) -> Self {
        Self { app_state, routes }
    }

    /// Typed private-plane entrypoint. Transport authentication and scoped
    /// route validation are complete before this method is called; this layer
    /// owns attempt-scoped idempotency and cryptographic state mutation.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn accept_transport_share(
        &self,
        attempt: AttemptKey,
        message_id: MessageId,
        from_node_id: u32,
        to_node_id: u32,
        share_value: Vec<u8>,
        nonce: [u8; 16],
        report_evidence: Option<SignedDkgShare>,
    ) -> Result<bool>
    where
        SignImpl: CoordinatorReportSigner<D>,
    {
        let session_id = attempt.session_id();
        let guard = loop {
            match self
                .app_state
                .dkg_session_state
                .claim_transport_message(attempt, message_id)
                .await
            {
                MessageProcessingClaim::Claimed => {
                    break TransportMessageClaimGuard::new(
                        self.app_state.dkg_session_state.clone(),
                        attempt,
                        message_id,
                    );
                }
                MessageProcessingClaim::AlreadyProcessed => {
                    return self
                        .app_state
                        .dkg_session_state
                        .with_attempt_state(attempt, |state| {
                            state
                                .commitment_audit
                                .received_shares
                                .contains(&from_node_id)
                        })
                        .await
                        .map_err(|error| attempt_state_error(attempt, error));
                }
                MessageProcessingClaim::AlreadyProcessing => {
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
                MessageProcessingClaim::MissingSession => {
                    return Err(session_not_found(session_id));
                }
                MessageProcessingClaim::StaleAttempt => {
                    return Err(DkgError::StaleAttempt {
                        ceremony_id: session_id,
                    });
                }
            }
        };
        let result = message_handlers::accept_share_message(
            self,
            attempt,
            from_node_id,
            to_node_id,
            share_value,
            nonce,
            report_evidence,
        )
        .await;
        guard.finish(result.is_ok()).await;
        result
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
        attempt: AttemptKey,
        node_id: u32,
        threshold: usize,
        total_nodes: usize,
        role: DkgRole,
        init_fn: F,
    ) -> Result<()>
    where
        F: FnOnce(&mut DkgSessionState<D>),
    {
        let session_id = attempt.session_id();
        if total_nodes == 0 {
            return Err(DkgError::InvalidParticipantCount(total_nodes));
        }
        let dkg_node = D::new(node_id, threshold, total_nodes, session_id, role)
            .map_err(|e| DkgError::Crypto(format!("Failed to create DKG node: {}", e)))?;

        let protocol_version = self.routes.version;
        match self
            .app_state
            .dkg_session_state
            .create_session(session_id, *dkg_node, total_nodes, move |state| {
                state.protocol_version = protocol_version;
                state.transport.ceremony_id = Some(attempt.ceremony_id);
                state.transport.attempt_id = Some(attempt.attempt_id);
                init_fn(state);
            })
            .await
        {
            CreateSessionOutcome::Created => {}
            CreateSessionOutcome::AlreadyExists => return Err(DkgError::SessionAlreadyExists),
            CreateSessionOutcome::InvalidParticipantCount => {
                return Err(DkgError::InvalidParticipantCount(total_nodes))
            }
            CreateSessionOutcome::LimitReached => return Err(DkgError::MaxSessionsReached),
        }

        Ok(())
    }

    /// Abort one exact DKG attempt.
    pub(crate) async fn abort_attempt(&self, attempt: AttemptKey) {
        self.app_state
            .dkg_session_state
            .abort_transport_attempt(attempt, TopicTaskDisposition::Abort)
            .await;
    }

    /// Fresh DKG Phase 0: generate polynomial and broadcast commitment hash to all peers.
    pub async fn initiate_phase0_commitment_hashes(
        &self,
        attempt: AttemptKey,
        peer_ids: &[String],
    ) -> Result<()> {
        phases::initiate_phase0_commitment_hashes(self, attempt, peer_ids).await
    }

    /// Phase 1: Generate polynomial and broadcast commitment to all peers.
    ///
    /// Called by the initiator after `StartDkg`, or by the PSS scheduler.
    pub async fn initiate_phase1_commitments(
        &self,
        attempt: AttemptKey,
        peer_ids: &[String],
    ) -> Result<()> {
        phases::initiate_phase1_commitments(self, attempt, peer_ids).await
    }

    /// Check if Phase 1 is complete and trigger Phase 2 if so.
    ///
    /// Called after each incoming commitment message.
    pub async fn check_and_trigger_phase2(
        &self,
        attempt: AttemptKey,
        peer_ids: &[String],
    ) -> Result<()> {
        phases::check_and_trigger_phase2(self, attempt, peer_ids).await
    }

    /// Check if Phase 2 is complete (all shares received) and trigger Phase 4 if so.
    ///
    /// Called after each incoming share message.
    pub async fn check_and_trigger_phase4(&self, attempt: AttemptKey) -> Result<()> {
        phases::check_and_trigger_phase4(self, attempt).await
    }

    /// Phase 4: Compute final secret share and aggregate public key.
    ///
    /// If this node is node_id == 1, also posts the `RingPayload` to the bulletin.
    #[cfg(test)]
    pub async fn initiate_phase4_completion(&self, attempt: AttemptKey) -> Result<()> {
        phases::initiate_phase4_completion(self, attempt).await
    }
}

pub(crate) fn attempt_state_error(attempt: AttemptKey, error: AttemptStateError) -> DkgError {
    match error {
        AttemptStateError::MissingSession => session_not_found(attempt.session_id()),
        AttemptStateError::StaleAttempt => DkgError::StaleAttempt {
            ceremony_id: attempt.session_id(),
        },
    }
}
