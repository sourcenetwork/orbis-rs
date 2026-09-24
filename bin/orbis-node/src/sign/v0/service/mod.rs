use crate::app_state::AppState;
use crate::helpers::auth::current_unix_time;
use crate::metrics;
use crate::sign::v0::error::SignError;
use crypto::r#trait::{DistKeyShare, Dkg, PubShare, ThresholdSigner};
use crypto::SigShareInner;
use crypto::SignaturePoint;
use proto::v0::sign::{sign_service_server::SignService, StartSignRequest, StartSignResponse};
use std::sync::Arc;
use tonic::{Request, Response, Status};

mod stages;
use stages::{authenticate_sign_request, encode_sign_response, validate_sign_message_size};

/// Implementation of the v0 SignService.
///
/// Accepts requests only for rings whose effective protocol version is 0.
/// Once a ring's activation_time passes and its effective version becomes 1,
/// callers must switch to the v1 SignService endpoint.
///
/// `start_sign`'s request pipeline is a sequence of named stages defined in
/// `stages.rs` — see that module's docs for what each one does and the
/// security-sensitive ordering between the policy check and single-use JWT
/// enforcement.
#[derive(Debug)]
pub struct SignServiceImpl<D, S>
where
    D: Dkg + Clone + 'static,
    S: ThresholdSigner,
{
    pub state: Arc<AppState<D>>,
    pub routes: &'static network::ProtocolRoutes,
    _phantom: std::marker::PhantomData<S>,
}

impl<D, S> SignServiceImpl<D, S>
where
    D: Dkg + Clone + 'static,
    S: ThresholdSigner,
{
    pub fn with_routes(
        state: impl Into<Arc<AppState<D>>>,
        routes: &'static network::ProtocolRoutes,
    ) -> Self {
        Self {
            state: state.into(),
            routes,
            _phantom: std::marker::PhantomData,
        }
    }
}

#[tonic::async_trait]
impl<D, S> SignService for SignServiceImpl<D, S>
where
    D: Dkg<ShareValue = crypto::ScalarField, PublicKey = crypto::GroupAffine>
        + Clone
        + Send
        + Sync
        + 'static,
    S: ThresholdSigner<
            ShareValue = crypto::ScalarField,
            PublicKey = crypto::GroupAffine,
            DistKeyShare = DistKeyShare<crypto::ScalarField>,
            PubPoly = D::PubPoly,
            Signature = SignaturePoint,
            SigShare = PubShare<SigShareInner>,
        > + Send
        + Sync
        + 'static,
{
    #[tracing::instrument(skip_all, fields(request))]
    async fn start_sign(
        &self,
        request: Request<StartSignRequest>,
    ) -> Result<Response<StartSignResponse>, Status> {
        let grpc_metrics = metrics::GrpcRequestGuard::new("sign", "start_sign");
        let request_metrics = metrics::track_sign_request();

        // get timestamp (needed for JWT validation) ---
        let current_time = current_unix_time().map_err(SignError::RequestTimestamp)?;

        validate_sign_message_size(&request)?;

        // 1. Authentication.
        let authenticated = authenticate_sign_request(request, current_time)?;

        // 2. Bulletin reads.
        let bulletin_state = self
            .resolve_sign_bulletin_state(&authenticated.derivation_id, &authenticated.token)
            .await?;

        // 3. Policy checks (ACP, then single-use JWT enforcement — see
        //    `stages::authorize_sign_request`'s docs for the security-sensitive ordering
        //    between the ACP check and the JWT check).
        let authorized = self
            .authorize_sign_request(authenticated, bulletin_state)
            .await?;

        // 4. Relay setup.
        let setup = self.prepare_sign_relay(authorized).await?;

        // 5. Coordination.
        let result = self.coordinate_sign(setup).await?;

        // 6. Response encoding.
        let created_at = current_time as i64;
        let response = encode_sign_response(result, created_at)?;

        request_metrics.complete();
        grpc_metrics.success();

        Ok(Response::new(response))
    }
}
