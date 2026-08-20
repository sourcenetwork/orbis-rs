use crate::app_state::AppState;
use crate::dkg::v0::error::DkgError;
use crate::dkg::v0::helpers::{validate_dkg_claims, validate_fresh_dkg_ring_payload};
use crate::dkg::v0::network as dkg_network;
use crate::dkg::v0::transport::{DkgControlMessage, DkgSessionStatusValue};
use crate::helpers::auth::{current_unix_time, extract_and_validate_jwt, request_actor};
use crate::helpers::protocol_version::read_ring_for_route;
use crate::metrics;
use authn::DkgClaims;
use proto::v0::dkg::{
    dkg_service_server::DkgService, DkgSessionStatus, GetDkgSessionStatusRequest,
    GetDkgSessionStatusResponse, MissingDkgParticipant, StartDkgRequest, StartDkgResponse,
};
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
        let actor_id = request_actor(&token, ring_payload.trusted_auth_relay_dids.as_deref())
            .map_err(DkgError::Unauthorized)?;

        tracing::info!(
            threshold = ring_payload.threshold,
            peer_node_keys = ?ring_payload.peer_node_keys,
            policy_id = ?ring_payload.policy_id,
            issuer = %token.issuer_id,
            actor = %actor_id,
            "Authenticated StartDkg request; forwarding to canonical DKG leader"
        );

        let created_at = current_time as i64;
        let (ceremony_id, _attempt_id) =
            dkg_network::start_fresh(self.state.clone(), self.routes, ring_id.clone(), token_str)
                .await
                .inspect_err(|error| {
                    tracing::error!(ring_id = %ring_id, %error, "DKG start failed");
                })?;
        let response = StartDkgResponse {
            session_id: ceremony_id.0.to_string(),
            status: "started".to_string(),
            message: format!(
                "DKG session started with threshold {} and {} participants",
                ring_payload.threshold,
                ring_payload.peer_node_keys.len()
            ),
            created_at,
        };
        grpc_metrics.success();

        Ok(Response::new(response))
    }

    /// Fresh-DKG-only. Lets a client that called `start_dkg` learn what happened to a
    /// ceremony that failed after the RPC already returned "started" (a stalled crypto
    /// phase), or which committee member(s) caused a barrier-phase failure — neither of
    /// which `StartDkgResponse` carries any information about.
    #[tracing::instrument(skip_all, fields(request))]
    async fn get_dkg_session_status(
        &self,
        request: Request<GetDkgSessionStatusRequest>,
    ) -> Result<Response<GetDkgSessionStatusResponse>, Status> {
        let grpc_metrics = metrics::GrpcRequestGuard::new("dkg", "get_dkg_session_status");

        let current_time = current_unix_time().map_err(DkgError::SystemTime)?;
        let (token_str, token) = extract_and_validate_jwt::<DkgClaims, _>(&request, current_time)
            .map_err(DkgError::Unauthorized)?;
        let req = request.into_inner();

        validate_dkg_claims(&token, &req.ring_id)?;

        // Deliberately not `validate_fresh_dkg_ring_payload`, which rejects a ring whose
        // `ring_pk` is already set: unlike starting a ceremony, querying its status must
        // still work for a ring whose Fresh DKG has already completed.
        //
        // Deliberately not `request_actor` either: that resolves trusted-relay delegation so a
        // *mutating* endpoint (start_dkg, PRE, Sign) can attribute and gate a consequential
        // action precisely, even through a relay. This is a read-only query — it doesn't act as
        // anyone or log an actor — and `validate_dkg_claims` above already requires a validly
        // signed JWT scoped to this exact ring_id, which is the real gate on "can you ask about
        // this ring." Matches the existing read-only `GetRingState` (info/service.rs), which
        // also skips it.
        read_ring_for_route(&*self.state.bulletin, &req.ring_id, self.routes.version)
            .await
            .map_err(DkgError::ProtocolError)?;

        let response = dkg_network::fetch_dkg_session_status(
            self.state.clone(),
            self.routes,
            req.ring_id.clone(),
            token_str,
        )
        .await
        .inspect_err(|error| {
            tracing::error!(ring_id = %req.ring_id, %error, "DKG session status lookup failed");
        })?;

        let DkgControlMessage::SessionStatusResponse {
            session_id,
            status,
            stage,
            missing,
            reason,
            failed_at,
        } = response
        else {
            return Err(DkgError::ProtocolError(format!(
                "leader returned unexpected session-status response: {}",
                response.metric_label()
            ))
            .into());
        };

        grpc_metrics.success();

        Ok(Response::new(GetDkgSessionStatusResponse {
            session_id: session_id.map(|id| id.to_string()).unwrap_or_default(),
            status: proto_status(status) as i32,
            stage,
            missing_participants: missing
                .into_iter()
                .map(|(node_id, node_key)| MissingDkgParticipant { node_id, node_key })
                .collect(),
            reason,
            failed_at: failed_at.unwrap_or(0),
        }))
    }
}

fn proto_status(status: DkgSessionStatusValue) -> DkgSessionStatus {
    match status {
        DkgSessionStatusValue::InProgress => DkgSessionStatus::InProgress,
        DkgSessionStatusValue::Completed => DkgSessionStatus::Completed,
        DkgSessionStatusValue::Failed => DkgSessionStatus::Failed,
        DkgSessionStatusValue::NotFound => DkgSessionStatus::NotFound,
    }
}
