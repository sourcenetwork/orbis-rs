use crate::app_state::AppState;
use crate::helpers::auth::{current_unix_time, extract_and_validate_jwt};
use crate::helpers::identity::validate_all_peer_ids;
use crate::helpers::node_routes::{peer_ids_from_routes, resolve_node_routes};
use crate::helpers::ring::RingConfig;
use crate::metrics;
use crate::ring_state::RingPolyState;
use crate::sign::v0::coordinator::{SignCoordinator, SigningOptions};
use crate::sign::v0::error::SignError;
use crate::sign::v0::helpers::{
    check_policy_access, fetch_bulletin_payloads_for_version, validate_sign_claims,
};
use crate::sign::v0::messages::{PolicyContext, SignContext};
use authn::SignClaims;
use authz::sourcehub::ValidWindow;
use crypto::r#trait::{DistKeyShare, Dkg, PubShare, ThresholdSigner};
use crypto::SigShareInner;
use crypto::SignaturePoint;
use proto::v0::sign::{sign_service_server::SignService, StartSignRequest, StartSignResponse};
use std::sync::Arc;
use tonic::{Request, Response, Status};

/// Implementation of the v0 SignService.
///
/// Accepts requests only for rings whose effective protocol version is 0.
/// Once a ring's activation_time passes and its effective version becomes 1,
/// callers must switch to the v1 SignService endpoint.
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

        // reject oversized messages before any crypto work ---
        if request.get_ref().message.len() > crate::constants::MAX_SIGN_MESSAGE_BYTES {
            return Err(SignError::InvalidInput(format!(
                "Message too large: {} bytes exceeds maximum {}",
                request.get_ref().message.len(),
                crate::constants::MAX_SIGN_MESSAGE_BYTES
            ))
            .into());
        }

        // extract and validate JWT (no IO) ---
        let (token_string, token) =
            extract_and_validate_jwt::<SignClaims, _>(&request, current_time)
                .map_err(SignError::Unauthorized)?;

        let req = request.into_inner();

        // validate JWT claims match request fields (no IO) ---
        validate_sign_claims(&token, &req.derivation_id, Some(&req.message))?;

        let valid_window = req.valid_window.map(|w| ValidWindow {
            start: w.start,
            end: w.end,
        });

        // Fetch ring and key derivation from bulletin (IO).
        // Validates that the ring's effective protocol version matches this service (v0).
        // Returns an error with version details if the ring has migrated to a newer version.
        let (key_derivation, ring_payload) = fetch_bulletin_payloads_for_version(
            &*self.state.bulletin,
            &req.derivation_id,
            true,
            self.routes.version,
        )
        .await?;

        // Authorize: check on-chain policy access (IO) ---
        check_policy_access(
            &*self.state.authz,
            &key_derivation,
            &req.derivation_id,
            &token.issuer_id,
            valid_window.clone(),
        )
        .await?;

        tracing::info!(
            derivation_id = %req.derivation_id,
            ring_id = %key_derivation.ring_id,
            ring_pk = %ring_payload.ring_pk,
            peer_node_keys = ?ring_payload.peer_node_keys,
            issuer = %token.issuer_id,
            "Authenticated StartSign request"
        );

        // Validate peers before attempting any connections (no IO) ---
        if ring_payload.peer_node_keys.is_empty() {
            return Err(
                SignError::InvalidInput("No peer node keys found for ring".to_string()).into(),
            );
        }

        let routes = resolve_node_routes(&self.state.bulletin, &ring_payload.peer_node_keys)
            .await
            .map_err(SignError::InvalidInput)?;
        let peer_ids = peer_ids_from_routes(&routes);

        validate_all_peer_ids(&peer_ids).map_err(|(invalid_peer_id, validation_error)| {
            SignError::InvalidInput(format!(
                "Invalid peer ID '{}': {}",
                invalid_peer_id, validation_error
            ))
        })?;

        let ring_pk_bytes = hex::decode(&ring_payload.ring_pk).map_err(|e| {
            SignError::Deserialization(format!("Failed to decode ring_pk hex: {}", e))
        })?;

        let request_id = rand::random::<u64>().to_string();
        let created_at = current_time as i64;

        // Initiate threshold signing (network protocol) ---
        let coordinator = SignCoordinator::<D, S>::with_routes(self.state.clone(), self.routes);
        let total_participants = peer_ids.len();
        let poly_state =
            RingPolyState::load_from_ring_pk_hex(&self.state.local_storage, &ring_payload.ring_pk)
                .map_err(|e| {
                    SignError::RingState(format!("Failed to load ring polynomial state: {}", e))
                })?;
        let ring = RingConfig {
            ring_id: key_derivation.ring_id.clone(),
            ring_pk_bytes,
            peer_ids,
            peer_node_keys: ring_payload.peer_node_keys,
            threshold: ring_payload.threshold as usize,
            total_participants,
            public_polynomial_hex: poly_state.public_polynomial,
        };

        let result = coordinator
            .initiate_signing(
                request_id,
                ring,
                req.message,
                SignContext::Policy(Box::new(PolicyContext {
                    token_string,
                    derivation_id: req.derivation_id,
                    valid_window,
                    key_derivation,
                })),
                SigningOptions::default(),
            )
            .await?;

        let sign_response: crate::sign::v0::coordinator::SignResponse =
            serde_json::from_slice(&result).map_err(|e| {
                SignError::Deserialization(format!("Failed to parse sign result: {}", e))
            })?;

        request_metrics.complete();
        grpc_metrics.success();

        Ok(Response::new(StartSignResponse {
            status: "completed".to_string(),
            message: "Sign completed successfully".to_string(),
            created_at,
            signature: sign_response.signature,
        }))
    }
}
