use crate::app_state::AppState;
use crate::helpers::auth::{current_unix_time, extract_and_validate_jwt};
use crate::helpers::helpers::{validate_all_peer_ids, RingConfig};
use crate::helpers::node_routes::{peer_ids_from_routes, resolve_node_routes};
use crate::metrics;
use crate::pre::v0::coordinator::PreCoordinator;
use crate::pre::v0::error::PreError;
use crate::pre::v0::helpers::{
    check_policy_access, decode_ring_pk, deserialize_secret, fetch_bulletin_payloads_for_version,
    validate_pre_claims, verify_encryption_binding,
};
use crate::pre::v0::messages::PreRequestContext;
use crate::ring_state::RingPolyState;
use authn::PreClaims;
use authz::sourcehub::ValidWindow;
use crypto::r#trait::{DistKeyShare, Dkg, ReencryptReply, Secret, ThresholdDealer};
use crypto::PreImpl as ThresholdDealerNode;
use proto::v0::pre::{pre_service_server::PreService, StartPreRequest, StartPreResponse};
use std::sync::Arc;
use std::time::Instant;
use tonic::{Request, Response, Status};

/// Implementation of the PreService
#[derive(Debug)]
pub struct PreServiceImpl<D, T>
where
    D: Dkg + Clone + 'static,
    T: ThresholdDealer,
{
    pub state: AppState<D>,
    pub routes: &'static network::ProtocolRoutes,
    _phantom: std::marker::PhantomData<T>,
}

impl<D, T> PreServiceImpl<D, T>
where
    D: Dkg + Clone + 'static,
    T: ThresholdDealer,
{
    /// Create a new PreServiceImpl with shared application state
    pub fn new(state: AppState<D>) -> Self {
        Self::with_routes(state, &network::V0)
    }

    pub fn with_routes(state: AppState<D>, routes: &'static network::ProtocolRoutes) -> Self {
        Self {
            state,
            routes,
            _phantom: std::marker::PhantomData,
        }
    }
}

#[tonic::async_trait]
impl<D, T> PreService for PreServiceImpl<D, T>
where
    D: Dkg<ShareValue = crypto::ScalarField, PublicKey = crypto::GroupAffine>
        + Clone
        + Send
        + Sync
        + 'static,
    T: ThresholdDealer<
            ShareValue = crypto::ScalarField,
            PublicKey = crypto::GroupAffine,
            DistKeyShare = DistKeyShare<crypto::ScalarField>,
            Secret = Secret,
            ReencryptReply = ReencryptReply<crypto::ScalarField, crypto::GroupAffine>,
            PubPoly = D::PubPoly,
        > + Send
        + Sync
        + 'static,
{
    #[tracing::instrument(skip_all, fields(request))]
    async fn start_pre(
        &self,
        request: Request<StartPreRequest>,
    ) -> Result<Response<StartPreResponse>, Status> {
        let start = Instant::now();

        // Get current timestamp (needed for both auth and response)
        let current_time = current_unix_time().map_err(|e| {
            let duration = start.elapsed().as_secs_f64();
            metrics::record_grpc_request("pre", "start_pre", "error", duration);
            tracing::error!("Failed to get current unix time: {}", e);
            PreError::SystemTime("Failed to get current timestamp".to_string())
        })?;

        // 1. Authenticate: Extract and validate JWT
        let (token_str, token) = extract_and_validate_jwt::<PreClaims, _>(&request, current_time)
            .map_err(PreError::Unauthorized)?;

        let req = request.into_inner();

        let valid_window = req.valid_window.map(|w| ValidWindow {
            start: w.start,
            end: w.end,
        });

        let (document_payload, ring_payload) = fetch_bulletin_payloads_for_version(
            &*self.state.bulletin,
            &self.state.local_storage,
            &req.object_id,
            self.routes.version,
        )
        .await?;
        check_policy_access(
            &*self.state.authz,
            &document_payload,
            &req.object_id,
            &token.issuer_id,
            valid_window.clone(),
        )
        .await?;

        // 2. Authorize: Validate JWT claims match request fields
        validate_pre_claims(
            &token,
            &req.rdr_pk,
            &req.object_id,
            &req.derivation,
            &req.salt,
        )?;

        // Validate metadata not tampered
        // Generate policy metadata for proof binding verification (before fields are moved)
        let policy_metadata = ThresholdDealerNode::encode_metadata(
            &document_payload.policy_id,
            &document_payload.resource,
            &document_payload.permission,
            document_payload.tier.clone().as_deref(),
            document_payload.timestamp,
            req.salt.as_deref(),
        );
        let (ring_pk_bytes, ring_pk) = decode_ring_pk(&ring_payload.ring_pk)?;
        let secret = deserialize_secret(&document_payload.document)?;

        verify_encryption_binding(
            &ring_pk,
            req.derivation.as_deref(),
            document_payload.proof,
            &secret.enc_cmt,
            &policy_metadata,
        )?;

        tracing::info!(
            ring_id = %document_payload.ring_id,
            ring_pk = %ring_payload.ring_pk,
            reader_pk = ?req.rdr_pk,
            peer_node_keys = ?ring_payload.peer_node_keys,
            issuer = %token.issuer_id,
            "Authenticated StartPre request"
        );

        let created_at = current_time as i64;

        // 1. Parse inputs
        // Use original string bytes instead of re-serializing
        let secret_bytes = document_payload.document.as_bytes().to_vec();

        // 2. Validate we have peers
        if ring_payload.peer_node_keys.is_empty() {
            return Err(PreError::InvalidInput(
                "No peer node keys provided for reencryption".to_string(),
            )
            .into());
        }

        let routes = resolve_node_routes(&self.state.bulletin, &ring_payload.peer_node_keys)
            .await
            .map_err(PreError::InvalidInput)?;
        let peer_ids = peer_ids_from_routes(&routes);

        // 2b. Validate all peer IDs before attempting connections
        validate_all_peer_ids(&peer_ids).map_err(|(invalid_peer_id, validation_error)| {
            PreError::InvalidInput(format!(
                "Invalid peer ID '{}': {}",
                invalid_peer_id, validation_error
            ))
        })?;

        // 3. Generate unique request ID
        let request_id = rand::random::<u64>().to_string();

        // 4. Create coordinator and initiate reencryption
        // Per-peer connectivity is handled inside the coordinator via JoinSet tasks,
        // allowing threshold-of-n operation when some nodes are unreachable.
        metrics::record_pre_request_started();
        let coordinator =
            PreCoordinator::<D, T>::with_routes(Arc::new(self.state.clone()), self.routes);
        let total_participants = peer_ids.len();
        let poly_state = RingPolyState::load(&self.state.local_storage, &ring_pk).map_err(|e| {
            tracing::error!("Failed to load ring polynomial state: {}", e);
            PreError::RingState("Failed to load ring polynomial state".to_string())
        })?;
        let ring = RingConfig {
            ring_pk_bytes,
            peer_ids,
            peer_node_keys: ring_payload.peer_node_keys,
            threshold: ring_payload.threshold as usize,
            total_participants,
            public_polynomial_hex: poly_state.public_polynomial,
        };
        let ctx = PreRequestContext {
            rdr_pk_bytes: req.rdr_pk,
            object_id: req.object_id,
            token_string: token_str.to_string(),
            derivation: req.derivation,
            salt: req.salt,
            valid_window,
        };
        let result = coordinator
            .initiate_reencryption(request_id, ring, secret_bytes, ctx)
            .await?;

        // 6. Parse result as PreResponse and encode as JSON
        let pre_response: crate::pre::v0::coordinator::PreResponse =
            serde_json::from_slice(&result).map_err(|e| {
                PreError::Deserialization(format!("Failed to parse PRE result: {}", e))
            })?;

        let encrypted_secret = serde_json::to_vec(&pre_response)
            .map_err(|e| PreError::Serialization(format!("Failed to serialize response: {}", e)))?;

        let response = StartPreResponse {
            status: "completed".to_string(),
            message: "PRE completed successfully".to_string(),
            created_at,
            encrypted_secret,
        };

        // Record success metrics
        let duration = start.elapsed().as_secs_f64();
        metrics::record_grpc_request("pre", "start_pre", "ok", duration);
        metrics::record_pre_request_completed(duration);

        Ok(Response::new(response))
    }
}
