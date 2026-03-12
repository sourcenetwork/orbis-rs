use crate::app_state::AppState;
use crate::dkg::coordinator::DkgCoordinator;
use crate::dkg::error::DkgError;
use crate::dkg::helpers::validate_dkg_claims;
use crate::dkg::messages::DkgMessage;
use crate::helpers::auth::{current_unix_time, extract_and_validate_jwt};
use crate::helpers::helpers::{connect_to_peers, extract_node_part, validate_all_peer_ids};
use crate::metrics;
use authn::DkgClaims;
use network::DKG;
use proto::dkg_service::{dkg_service_server::DkgService, StartDkgRequest, StartDkgResponse};
use rand;
use std::sync::Arc;
use std::time::Instant;
use tonic::{Request, Response, Status};

/// Implementation of the DkgService
#[derive(Debug)]
pub struct DkgServiceImpl<D>
where
    D: crypto::r#trait::Dkg + Clone + 'static,
{
    pub state: AppState<D>,
}

impl<D> DkgServiceImpl<D>
where
    D: crypto::r#trait::Dkg + Clone + 'static,
{
    /// Create a new DkgServiceImpl with shared application state
    pub fn new(state: AppState<D>) -> Self {
        Self { state }
    }
}

#[tonic::async_trait]
impl<D> DkgService for DkgServiceImpl<D>
where
    D: crypto::r#trait::Dkg<
            ShareValue = crypto::ScalarField,
            PublicKey = crypto::GroupAffine,
            PolynomialCommitment = crypto::PolynomialCommitmentImpl,
        > + Clone
        + Send
        + Sync
        + 'static,
{
    #[tracing::instrument(skip_all, fields(request))]
    async fn start_dkg(
        &self,
        request: Request<StartDkgRequest>,
    ) -> Result<Response<StartDkgResponse>, Status> {
        let start = Instant::now();

        // Get current timestamp (needed for both auth and response)
        let current_time = current_unix_time().map_err(|e| {
            metrics::record_grpc_request(
                "dkg",
                "start_dkg",
                "error",
                start.elapsed().as_secs_f64(),
            );
            Status::internal(e)
        })?;

        // 1. Authenticate: Extract and validate JWT
        let (token_str, token) = extract_and_validate_jwt::<DkgClaims, _>(&request, current_time)
            .map_err(|e| DkgError::Unauthorized(e))?;
        // TODO: use token.issuer_id as AuthZ check
        let req = request.into_inner();

        // 2. Authorize: Validate JWT claims match request fields (compare raw, pre-normalization)
        validate_dkg_claims(&token, req.threshold, &req.peer_ids, req.pss_interval)?;

        tracing::info!(
            threshold = req.threshold,
            peer_ids = ?req.peer_ids,
            issuer = %token.issuer_id,
            "Authenticated StartDkg request"
        );

        let created_at = current_time as i64;

        // Generate random session id
        let session_id: u64 = rand::random();

        // Create DKG coordinator (AppState clone is cheap - contains Arc types internally)
        let coordinator = DkgCoordinator::new(Arc::new(self.state.clone()));

        // Validate threshold and total_participants
        if req.threshold as usize > req.peer_ids.len() {
            return Err(DkgError::InvalidInput(format!(
                "Threshold ({}) cannot be greater than total participants ({})",
                req.threshold,
                req.peer_ids.len()
            ))
            .into());
        }

        if req.peer_ids.is_empty() {
            return Err(DkgError::InvalidInput("Not enough participants".to_string()).into());
        }

        // As the initiator, assign node_ids to all participants based on sorted peer list
        // This ensures all nodes agree on who has which node_id
        let our_peer_id_hex = hex::encode(self.state.network.local_peer_id().as_bytes());
        let our_peer_id_key = extract_node_part(&our_peer_id_hex);

        // Check if we're included in the peer_ids list
        // We only participate if explicitly included - otherwise we just coordinate
        let self_included = req
            .peer_ids
            .iter()
            .any(|pid| extract_node_part(pid) == our_peer_id_key);

        // Use the peer_ids exactly as given - don't auto-add ourselves
        let all_peer_ids_for_assignments: Vec<String> = req.peer_ids.clone();

        // Build node_id assignments: peer_id -> node_id (1-indexed based on sorted order)
        let mut node_id_assignments = std::collections::HashMap::new();
        let mut sorted_peer_ids = all_peer_ids_for_assignments.clone();
        sorted_peer_ids.sort();

        for (idx, peer_id) in sorted_peer_ids.iter().enumerate() {
            let assigned_node_id = (idx + 1) as u32;
            // Extract just the hex part (before @) for consistent lookup
            let peer_id_key = extract_node_part(peer_id);
            node_id_assignments.insert(peer_id_key, assigned_node_id);
        }

        // Calculate actual total participants
        let actual_total_participants = all_peer_ids_for_assignments.len();

        // Get our assigned node_id (only if we're participating)
        let our_assigned_node_id = if self_included {
            Some(*node_id_assignments.get(&our_peer_id_key).ok_or_else(|| {
                DkgError::InvalidInput(
                    "Could not determine our node_id from assignments".to_string(),
                )
            })?)
        } else {
            None
        };

        tracing::info!(
            our_node_id = ?our_assigned_node_id,
            total_participants = actual_total_participants,
            self_participating = self_included,
            "DKG Service (Coordinator): Assigned node_ids"
        );

        // Create DKG session only if we're participating
        // Create a cleanup guard that will automatically clean up the session on error
        let cleanup_guard = if let Some(node_id) = our_assigned_node_id {
            coordinator
                .create_session(
                    session_id,
                    node_id,
                    req.threshold as usize,
                    actual_total_participants,
                    crypto::r#trait::DkgRole::Standard,
                )
                .await?;
            // Guard will clean up session if we return early due to error
            Some(self.state.dkg_session_state.cleanup_guard(session_id))
        } else {
            None
        };

        // Store peer IDs in session state for later use (needed for Phase 2)
        coordinator
            .set_peer_ids(&session_id, req.peer_ids.clone())
            .await;

        // Normalize pss_interval: treat 0 as disabled (same as None).
        let pss_interval = req.pss_interval.filter(|&v| v > 0);

        // Store pss_interval so Phase 4 includes it in the RingPayload written locally.
        // (Non-initiators receive it via SessionInit; the initiator does not.)
        self.state
            .dkg_session_state
            .set_pss_interval(&session_id, pss_interval)
            .await;

        // Store node_id to peer_id mappings for efficient routing
        // We'll do this after sending SessionInit, but for now the coordinator will handle it
        // when it processes the message (for consistency)

        // Connect to peer nodes using iroh network
        // Peer IDs should be in iroh PublicKey format: either "node_id" or "node_id@ip:port"
        // where node_id is the iroh public key string representation
        if !req.peer_ids.is_empty() {
            // Validate all peer IDs before attempting connections
            if let Err((invalid_peer_id, validation_error)) = validate_all_peer_ids(&req.peer_ids) {
                return Err(DkgError::InvalidInput(format!(
                    "Invalid peer ID '{}': {}",
                    invalid_peer_id, validation_error
                ))
                .into());
            }

            let connection_summary =
                connect_to_peers(&self.state.network, req.peer_ids.clone(), DKG).await;

            // Check if we successfully connected to all requested peers
            // Note: connection_summary.total excludes self (which is skipped by connect_to_peers)
            if connection_summary.successful < connection_summary.total {
                let error_msg = format!(
                    "Failed to connect to all required peers. Connected to {}/{} peers. Failed connections: {}",
                    connection_summary.successful,
                    connection_summary.total,
                    connection_summary.failed
                );
                tracing::error!(error = %error_msg, "Failed to connect to all peers");

                // cleanup_guard will automatically clean up the session when dropped
                return Err(DkgError::NetworkConnection(error_msg).into());
            }

            // Send SessionInit message to all peers
            // Include all peer_ids (including our own) so non-initiators know who to send messages to
            // Use the deduplicated list we already built
            let all_peer_ids = all_peer_ids_for_assignments.clone();

            // Store node_id to peer_id mappings for the initiator (we don't receive our own SessionInit)
            let mut node_id_to_peer_id = std::collections::HashMap::new();
            for (peer_id_key, node_id) in &node_id_assignments {
                // Find the full peer_id (with @address if present) from all_peer_ids
                let full_peer_id = all_peer_ids
                    .iter()
                    .find(|pid| extract_node_part(pid) == *peer_id_key)
                    .cloned()
                    .unwrap_or_else(|| peer_id_key.clone());
                node_id_to_peer_id.insert(*node_id, full_peer_id);
            }
            self.state
                .dkg_session_state
                .set_node_peer_mappings(&session_id, node_id_to_peer_id)
                .await;

            let session_init_msg = DkgMessage::SessionInit {
                session_id,
                threshold: req.threshold,
                total_participants: actual_total_participants as u32,
                peer_ids: all_peer_ids.clone(), // Include all peer_ids (including our own) so receivers know all participants
                node_id_assignments: node_id_assignments.clone(), // Assignments made by initiator
                token_string: token_str.clone(), // Pass JWT to peer nodes for authentication
                is_refresh: false,
                refresh_ring_pk_hex: None,
                pss_interval,
            };

            // Send SessionInit to all peers (they will create their sessions and start Phase 1)
            for peer_id_str in &req.peer_ids {
                if let Err(e) = coordinator
                    .send_message_to_peer(peer_id_str, session_init_msg.clone())
                    .await
                {
                    tracing::error!(peer_id = %peer_id_str, error = %e, "Failed to send SessionInit to peer");
                    // Continue with other peers
                }
            }

            // Initiate Phase 1 only if we're participating
            if self_included {
                if let Err(e) = coordinator
                    .initiate_phase1_commitments(session_id, &req.peer_ids)
                    .await
                {
                    tracing::error!(error = %e, "Failed to initiate Phase 1");
                    // cleanup_guard will automatically clean up the session when dropped
                    return Err(e.into());
                }
                tracing::info!("DKG Protocol: Phase 1 initiated, commitments broadcasted");
            } else {
                tracing::info!("DKG Protocol: SessionInit sent to participants (coordinator not participating)");
            }
        }

        let response = StartDkgResponse {
            session_id: session_id.to_string(),
            status: "started".to_string(),
            message: format!(
                "DKG session started with threshold {} and {} participants",
                req.threshold, actual_total_participants
            ),
            created_at,
        };

        // Session started successfully - defuse the cleanup guard
        // The session will be cleaned up when Phase 4 completes (or by error handlers in coordinator)
        if let Some(guard) = cleanup_guard {
            guard.defuse();
        }

        // Record success metric
        metrics::record_grpc_request("dkg", "start_dkg", "ok", start.elapsed().as_secs_f64());

        Ok(Response::new(response))
    }
}
