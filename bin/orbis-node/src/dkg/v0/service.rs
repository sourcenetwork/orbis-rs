use crate::app_state::AppState;
use crate::dkg::v0::coordinator::DkgCoordinator;
use crate::dkg::v0::error::DkgError;
use crate::dkg::v0::helpers::{
    derive_fresh_dkg_session_id, validate_dkg_claims,
    validate_dkg_node_authorization_for_committee, validate_fresh_dkg_ring_payload,
};
use crate::dkg::v0::messages::{DkgMessage, SessionKind};
use crate::helpers::auth::{current_unix_time, extract_and_validate_jwt};
use crate::helpers::identity::is_self_peer_id;
use crate::helpers::node_routes::{
    canonical_node_id_assignments_from_node_keys, node_id_to_peer_id_from_routes,
    peer_ids_from_routes, resolve_node_routes,
};
use crate::helpers::protocol_version::read_ring_for_route;
use crate::metrics;
use authn::DkgClaims;
use proto::v0::dkg::{dkg_service_server::DkgService, StartDkgRequest, StartDkgResponse};
use std::sync::Arc;
use tonic::{Request, Response, Status};

/// Implementation of the v0 DkgService.
///
/// Accepts requests only for rings whose effective protocol version is 0.
/// Once a ring's activation_time passes and its effective version becomes 1,
/// callers must switch to the v1 DkgService endpoint.
#[derive(Debug)]
pub struct DkgServiceImpl<D>
where
    D: crypto::r#trait::Dkg + Clone + 'static,
{
    pub state: Arc<AppState<D>>,
    pub routes: &'static network::ProtocolRoutes,
}

impl<D> DkgServiceImpl<D>
where
    D: crypto::r#trait::Dkg + Clone + 'static,
{
    pub fn with_routes(
        state: impl Into<Arc<AppState<D>>>,
        routes: &'static network::ProtocolRoutes,
    ) -> Self {
        Self {
            state: state.into(),
            routes,
        }
    }
}

#[tonic::async_trait]
impl<D> DkgService for DkgServiceImpl<D>
where
    D: crypto::r#trait::Dkg<
            ShareValue = crypto::ScalarField,
            PublicKey = crypto::GroupAffine,
            PolynomialCommitment = crypto::PolynomialCommitmentImpl,
            PubPoly = crypto::PubPolyImpl,
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
        let grpc_metrics = metrics::GrpcRequestGuard::new("dkg", "start_dkg");

        // Get current timestamp (needed for both auth and response)
        let current_time = current_unix_time().map_err(DkgError::SystemTime)?;

        // 1. Authenticate: Extract and validate JWT
        let (token_str, token) = extract_and_validate_jwt::<DkgClaims, _>(&request, current_time)
            .map_err(DkgError::Unauthorized)?;
        let req = request.into_inner();

        // 2. Authorize the request itself. Ring parameters are read from the bulletin.
        validate_dkg_claims(&token, &req.ring_id)?;

        let ring_id = req.ring_id.clone();
        // Validates that the ring's effective protocol version matches this service (v0).
        // Returns an error with version details if the ring has migrated to a newer version.
        let ring_payload =
            read_ring_for_route(&*self.state.bulletin, &ring_id, self.routes.version)
                .await
                .map_err(DkgError::ProtocolError)?;
        validate_fresh_dkg_ring_payload(&ring_id, &ring_payload)?;

        let routes = resolve_node_routes(&self.state.bulletin, &ring_payload.peer_node_keys)
            .await
            .map_err(DkgError::Unauthorized)?;
        let peer_ids = peer_ids_from_routes(&routes);
        let node_id_assignments =
            canonical_node_id_assignments_from_node_keys(&ring_payload.peer_node_keys)
                .map_err(DkgError::InvalidInput)?;
        let node_id_to_peer_id = node_id_to_peer_id_from_routes(&routes, &node_id_assignments)
            .map_err(DkgError::InvalidInput)?;
        let threshold = ring_payload.threshold;
        let pss_interval = ring_payload.pss_interval;
        let policy_id = ring_payload.policy_id.clone();

        tracing::info!(
            threshold = threshold,
            peer_node_keys = ?ring_payload.peer_node_keys,
            peer_ids = ?peer_ids,
            policy_id = ?policy_id,
            issuer = %token.issuer_id,
            "Authenticated StartDkg request"
        );

        let created_at = current_time as i64;

        // Deterministic session_id derived from ring_id: two concurrent start_dkg calls
        // for the same ring produce the same session_id, so the second hits
        // SessionAlreadyExists and returns in_progress instead of launching a competing
        // ceremony that would deadlock finalization.
        let session_id: u128 = derive_fresh_dkg_session_id(&ring_id)?;

        // Create DKG coordinator (AppState clone is cheap - contains Arc types internally)
        let coordinator = DkgCoordinator::with_routes(self.state.clone(), self.routes);

        let our_peer_id_hex = hex::encode(self.state.network.local_peer_id().as_bytes());

        // We only participate if our chain node key is explicitly included.
        let self_included = ring_payload
            .peer_node_keys
            .iter()
            .any(|node_key| node_key == &self.state.node_key);

        if self_included {
            validate_dkg_node_authorization_for_committee(
                &self.state.bulletin,
                &self.state.node_key,
                &our_peer_id_hex,
                &ring_id,
                &ring_payload,
                &ring_payload.peer_node_keys,
                "Fresh DKG",
            )
            .await?;
        }

        // Calculate actual total participants
        let actual_total_participants = ring_payload.peer_node_keys.len();

        // Get our assigned node_id (only if we're participating)
        let our_assigned_node_id = if self_included {
            Some(
                *node_id_assignments
                    .get(&self.state.node_key)
                    .ok_or_else(|| {
                        DkgError::InvalidInput(
                            "Could not determine our node_id from assignments".to_string(),
                        )
                    })?,
            )
        } else {
            None
        };

        tracing::info!(
            our_node_id = ?our_assigned_node_id,
            total_participants = actual_total_participants,
            self_participating = self_included,
            "DKG Service (Coordinator): Assigned node_ids"
        );

        // Create DKG session only if we're participating.
        // Create a cleanup guard that will automatically clean up the session on error.
        let cleanup_guard = if let Some(node_id) = our_assigned_node_id {
            // Session already exists → DKG is in progress for this ring. Return success
            // immediately so the caller can poll wait_for_ring_finalized.
            if self
                .state
                .dkg_session_state
                .session_exists(&session_id)
                .await
            {
                grpc_metrics.success();
                return Ok(Response::new(StartDkgResponse {
                    session_id: session_id.to_string(),
                    status: "in_progress".to_string(),
                    message: format!("DKG already in progress for ring {}", ring_id),
                    created_at,
                }));
            }

            coordinator
                .create_session(
                    session_id,
                    node_id,
                    threshold as usize,
                    actual_total_participants,
                    crypto::r#trait::DkgRole::Standard,
                    {
                        let policy_id = policy_id.clone();
                        move |state| {
                            state.policy_id = policy_id;
                        }
                    },
                )
                .await?;
            // Guard will clean up session if we return early due to error
            Some(self.state.dkg_session_state.cleanup_guard(session_id))
        } else {
            None
        };

        // Store peer IDs in session state for later use (needed for Phase 2)
        coordinator
            .set_peer_ids(&session_id, peer_ids.clone())
            .await;
        self.state
            .dkg_session_state
            .set_peer_node_keys(&session_id, ring_payload.peer_node_keys.clone())
            .await;
        self.state
            .dkg_session_state
            .set_ring_id(&session_id, ring_id.clone())
            .await;

        // Store pss_interval so Phase 4 includes it in the RingPayload written locally.
        // (Non-initiators receive it via SessionInit; the initiator does not.)
        self.state
            .dkg_session_state
            .set_pss_interval(&session_id, pss_interval)
            .await;

        if !peer_ids.is_empty() {
            // Pre-warm the connection pool for all peers before starting the ceremony.
            // Using get_or_connect (rather than a raw network.connect()) means the
            // connections are cached in the pool so the subsequent open_stream calls
            // in send_message_to_peer reuse them instead of opening duplicates.
            for peer_id_str in &peer_ids {
                if is_self_peer_id(&self.state.network, peer_id_str) {
                    continue;
                }
                self.state
                    .peer_connection_pool
                    .get_or_connect(&self.state.network, peer_id_str, self.routes.dkg_alpn)
                    .await
                    .map_err(|e| {
                        DkgError::NetworkConnection(format!(
                            "Failed to connect to peer {}: {}",
                            peer_id_str, e
                        ))
                    })?;
            }

            // Send SessionInit message to all peers
            self.state
                .dkg_session_state
                .set_node_peer_mappings(&session_id, node_id_to_peer_id)
                .await;

            let session_init_msg = DkgMessage::SessionInit {
                session_id,
                threshold,
                total_participants: actual_total_participants as u32,
                peer_ids: peer_ids.clone(),
                peer_node_keys: ring_payload.peer_node_keys.clone(),
                node_id_assignments: node_id_assignments.clone(), // Assignments made by initiator
                token_string: token_str.clone(), // Pass JWT to peer nodes for authentication
                kind: SessionKind::Fresh,
                pss_interval,
                policy_id: policy_id.clone(),
                ring_id: ring_id.clone(),
            };

            // Send SessionInit to all peers (they will create their sessions and start Phase 1).
            // Use the session-cached connection when we are participating so local
            // sends to each peer stay ordered where possible. Inbound handlers still
            // tolerate valid early messages because stream replacement and cross-peer
            // delivery can expose dependent local state out of order. When we are a
            // non-participating coordinator (no session created), fall back to a
            // fresh one-shot connection.
            let init_session_id = our_assigned_node_id.map(|_| session_id);
            for peer_id_str in &peer_ids {
                if is_self_peer_id(&self.state.network, peer_id_str) {
                    continue;
                }
                let _ = coordinator
                    .send_message_to_peer(peer_id_str, session_init_msg.clone(), init_session_id)
                    .await
                    .inspect_err(|error| {
                        tracing::error!(
                            peer_id = %peer_id_str,
                            error = %error,
                            "Failed to send SessionInit to peer"
                        );
                    });
            }

            // Initiate Phase 1 only if we're participating
            if self_included {
                coordinator
                    .initiate_phase1_commitments(session_id, &peer_ids)
                    .await?;
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
                threshold, actual_total_participants
            ),
            created_at,
        };

        // Session started successfully - defuse the cleanup guard
        // The session will be cleaned up when Phase 4 completes (or by error handlers in coordinator)
        if let Some(guard) = cleanup_guard {
            guard.defuse();
        }

        grpc_metrics.success();

        Ok(Response::new(response))
    }
}
