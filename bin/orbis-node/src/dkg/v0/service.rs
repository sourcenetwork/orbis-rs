use crate::app_state::AppState;
use crate::dkg::v0::error::DkgError;
use crate::dkg::v0::helpers::validate_fresh_dkg_ring_payload;
use crate::dkg::v0::network as dkg_network;
use crate::helpers::auth::current_unix_time;
use crate::helpers::protocol_version::read_ring_for_route;
use crate::metrics;
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

        let current_time = current_unix_time().map_err(DkgError::SystemTime)?;
        let req = request.into_inner();
        let ring_id = req.ring_id.clone();
        if ring_id.is_empty() {
            return Err(DkgError::InvalidInput("ring_id must not be empty".to_string()).into());
        }

        // No caller authentication here by design: ring authorization already
        // happened on-chain (policy-id ownership at ring creation, node
        // whitelisting when this node joined the committee), so this endpoint
        // is just a "someone kick this off" trigger, not an authorization
        // decision — anyone can already reach it by running their own node.
        // Every committee member independently re-validates the ring against
        // SourceHub before joining the ceremony (`validate_fresh_init`), which
        // is the actual authorization boundary.
        //
        // Validates that the ring's effective protocol version matches this service (v0).
        // Returns an error with version details if the ring has migrated to a newer version.
        let ring_payload =
            read_ring_for_route(&*self.state.bulletin, &ring_id, self.routes.version)
                .await
                .map_err(DkgError::ProtocolError)?;
        validate_fresh_dkg_ring_payload(&ring_id, &ring_payload)?;

        tracing::info!(
            threshold = ring_payload.threshold,
            peer_node_keys = ?ring_payload.peer_node_keys,
            policy_id = ?ring_payload.policy_id,
            "StartDkg request accepted; forwarding to canonical DKG leader"
        );

        let created_at = current_time as i64;
        let (ceremony_id, _attempt_id) =
            dkg_network::start_fresh(self.state.clone(), self.routes, ring_id.clone())
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
}
