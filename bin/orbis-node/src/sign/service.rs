use crate::app_state::AppState;
use crate::constants::MAX_SIGN_MESSAGE_BYTES;
use crate::helpers::auth::{current_unix_time, extract_and_validate_jwt};
use crate::helpers::helpers::{validate_all_peer_ids, RingConfig};
use crate::metrics;
use crate::ring_state::RingPolyState;
use crate::sign::coordinator::SignCoordinator;
use crate::sign::error::SignError;
use crate::sign::helpers::{check_policy_access, fetch_bulletin_payloads, validate_sign_claims};
use crate::sign::messages::{PolicyContext, SignContext};
use authn::SignClaims;
use authz::sourcehub::ValidWindow;
use crypto::r#trait::{DistKeyShare, Dkg, PubShare, ThresholdSigner};
use crypto::SigShareInner;
use crypto::SignaturePoint;
use proto::sign_service::{sign_service_server::SignService, StartSignRequest, StartSignResponse};
use std::sync::Arc;
use std::time::Instant;
use tonic::{Request, Response, Status};

/// Implementation of the SignService (Policy pathway only)
#[derive(Debug)]
pub struct SignServiceImpl<D, S>
where
    D: Dkg + Clone + 'static,
    S: ThresholdSigner,
{
    pub state: AppState<D>,
    _phantom: std::marker::PhantomData<S>,
}

impl<D, S> SignServiceImpl<D, S>
where
    D: Dkg + Clone + 'static,
    S: ThresholdSigner,
{
    pub fn new(state: AppState<D>) -> Self {
        Self {
            state,
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
        let start = Instant::now();

        // get timestamp (needed for JWT validation) ---
        let current_time = current_unix_time().map_err(|e| {
            let duration = start.elapsed().as_secs_f64();
            metrics::record_grpc_request("sign", "start_sign", "error", duration);
            Status::internal(e)
        })?;

        // reject oversized messages before any crypto work ---
        if request.get_ref().message.len() > MAX_SIGN_MESSAGE_BYTES {
            return Err(SignError::InvalidInput(format!(
                "Message too large: {} bytes exceeds maximum {}",
                request.get_ref().message.len(),
                MAX_SIGN_MESSAGE_BYTES
            ))
            .into());
        }

        // extract and validate JWT (no IO) ---
        let (token_string, token) =
            extract_and_validate_jwt::<SignClaims, _>(&request, current_time)
                .map_err(SignError::Unauthorized)?;

        let req = request.into_inner();

        // validate JWT claims match request fields (no IO) ---
        validate_sign_claims(
            &token,
            &req.namespace,
            &req.derivation_id,
            Some(&req.message),
        )?;

        let valid_window = req.valid_window.map(|w| ValidWindow {
            start: w.start,
            end: w.end,
        });

        // Fetch ring and key derivation from bulletin (IO) ---
        let (key_derivation, ring_payload) = fetch_bulletin_payloads(
            &*self.state.bulletin,
            &self.state.local_storage,
            &req.namespace,
            &req.derivation_id,
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
            namespace = %req.namespace,
            derivation_id = %req.derivation_id,
            ring_id = %key_derivation.ring_id,
            ring_pk = %ring_payload.ring_pk,
            peer_ids = ?ring_payload.peer_ids,
            issuer = %token.issuer_id,
            "Authenticated StartSign request"
        );

        // Validate peers before attempting any connections (no IO) ---
        if ring_payload.peer_ids.is_empty() {
            return Err(SignError::InvalidInput("No peer IDs found for ring".to_string()).into());
        }

        if let Err((invalid_peer_id, validation_error)) =
            validate_all_peer_ids(&ring_payload.peer_ids)
        {
            return Err(SignError::InvalidInput(format!(
                "Invalid peer ID '{}': {}",
                invalid_peer_id, validation_error
            ))
            .into());
        }

        let ring_pk_bytes = hex::decode(&ring_payload.ring_pk).map_err(|e| {
            SignError::Deserialization(format!("Failed to decode ring_pk hex: {}", e))
        })?;

        let request_id = rand::random::<u64>().to_string();
        let created_at = current_time as i64;

        // Initiate threshold signing (network protocol) ---
        metrics::record_sign_request_started();
        let coordinator = SignCoordinator::<D, S>::new(Arc::new(self.state.clone()));
        let total_participants = ring_payload.peer_ids.len();
        let poly_state =
            RingPolyState::load_from_ring_pk_hex(&self.state.local_storage, &ring_payload.ring_pk)
                .map_err(|e| {
                    Status::internal(format!("Failed to load ring polynomial state: {}", e))
                })?;
        let ring = RingConfig {
            ring_pk_bytes,
            peer_ids: ring_payload.peer_ids,
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
                    namespace: req.namespace,
                    derivation_id: req.derivation_id,
                    valid_window,
                    key_derivation,
                })),
            )
            .await?;

        let sign_response: crate::sign::coordinator::SignResponse = serde_json::from_slice(&result)
            .map_err(|e| {
                SignError::Deserialization(format!("Failed to parse sign result: {}", e))
            })?;

        let duration = start.elapsed().as_secs_f64();
        metrics::record_grpc_request("sign", "start_sign", "ok", duration);
        metrics::record_sign_request_completed(duration);

        Ok(Response::new(StartSignResponse {
            status: "completed".to_string(),
            message: "Sign completed successfully".to_string(),
            created_at,
            signature: sign_response.signature,
        }))
    }
}
