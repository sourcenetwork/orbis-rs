use crate::app_state::AppState;
use crate::constants::BULLETIN_RING_NAMESPACE;
use crate::helpers::helpers::{
    connect_to_peers, derive_node_id_from_peer_id_bytes, validate_all_peer_ids,
};
use crate::metrics;
use crate::pre::coordinator::PreCoordinator;
use crate::pre::error::PreError;
use authn::{extract_bearer_token, resolve_jwt_did, BearerToken, PreClaims};
use authz::sourcehub::AccessCheckRequest;
use bulletin::r#trait::{DocumentPayload, RingPayload};
use crypto::r#trait::{DistKeyShare, Dkg, ReencryptReply, Secret, ThresholdDealer};
use network::REENCRYPT;
use proto::pre_service::{pre_service_server::PreService, StartPreRequest, StartPreResponse};
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tonic::{Request, Response, Status};

/// Implementation of the PreService
#[derive(Debug)]
pub struct PreServiceImpl<D, T>
where
    D: Dkg + Clone + 'static,
    T: ThresholdDealer,
{
    pub state: AppState<D>,
    _phantom: std::marker::PhantomData<T>,
}

impl<D, T> PreServiceImpl<D, T>
where
    D: Dkg + Clone + 'static,
    T: ThresholdDealer,
{
    /// Create a new PreServiceImpl with shared application state
    pub fn new(state: AppState<D>) -> Self {
        Self {
            state,
            _phantom: std::marker::PhantomData,
        }
    }
}

#[tonic::async_trait]
impl<D, T> PreService for PreServiceImpl<D, T>
where
    D: Dkg<ShareValue = ark_bls12_381::Fr, PublicKey = ark_bls12_381::G1Affine>
        + Clone
        + Send
        + Sync
        + 'static,
    T: ThresholdDealer<
            ShareValue = ark_bls12_381::Fr,
            PublicKey = ark_bls12_381::G1Affine,
            DistKeyShare = DistKeyShare<ark_bls12_381::Fr>,
            Secret = Secret,
            ReencryptReply = ReencryptReply<ark_bls12_381::Fr, ark_bls12_381::G1Affine>,
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
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| {
                let duration = start.elapsed().as_secs_f64();
                metrics::record_grpc_request("pre", "start_pre", "error", duration);
                Status::internal(format!("Failed to get timestamp: {}", e))
            })?
            .as_secs();

        // 1. Authenticate: Extract and validate JWT
        let token_str = extract_bearer_token(&request)
            .map_err(|e| PreError::Unauthorized(e.to_string()))?
            .to_string();
        let token: BearerToken<PreClaims> = resolve_jwt_did(&token_str, current_time)
            .map_err(|e| PreError::Unauthorized(format!("JWT validation failed: {}", e)))?;

        let req = request.into_inner();
        let object_info = self
            .state
            .bulletin
            .read(req.namespace.clone(), req.object_id.clone())
            .await
            .map_err(|e| {
                PreError::Storage(format!("Failed to read object '{}': {}", req.object_id, e))
            })?;

        let document_payload = serde_json::from_slice::<DocumentPayload>(&object_info.payload)
            .map_err(|e| {
                PreError::Deserialization(format!("Failed to parse document payload: {}", e))
            })?;

        let ring_info = self
            .state
            .bulletin
            .read(
                BULLETIN_RING_NAMESPACE.to_string(),
                document_payload.ring_id.clone(),
            )
            .await
            .map_err(|e| {
                PreError::Storage(format!(
                    "Failed to read ring '{}': {}",
                    document_payload.ring_id, e
                ))
            })?;

        let ring_payload =
            serde_json::from_slice::<RingPayload>(&ring_info.payload).map_err(|e| {
                PreError::Deserialization(format!("Failed to parse ring payload: {}", e))
            })?;

        let permission = AccessCheckRequest::new(
            document_payload.policy_id.clone(),
            document_payload.resource.clone(),
            req.object_id.clone(),
            document_payload.permission.clone(),
        )
        .to_bytes()
        .map_err(|e| PreError::AuthZ(format!("Error formatting access request: {}", e)))?;
        self.state
            .authz
            .check(permission, &token.issuer_id)
            .await
            .map_err(|e| PreError::AuthZ(format!("Error in Authz request: {}", e)))?;

        // 2. Authorize: Validate JWT claims match request fields
        validate_pre_claims(
            &token,
            &req.rdr_pk,
            &req.object_id,
            &req.namespace,
            &req.derivation,
        )?;

        tracing::info!(
            ring_id = %document_payload.ring_id,
            ring_pk = %ring_payload.ring_pk,
            reader_pk = %req.rdr_pk,
            peer_ids = ?ring_payload.peer_ids,
            issuer = %token.issuer_id,
            "Authenticated StartPre request"
        );

        let created_at = current_time as i64;

        // 1. Parse JSON and hex inputs
        // ring_pk: hex-encoded compressed G1Affine bytes
        let ring_pk = hex::decode(&ring_payload.ring_pk)
            .map_err(|e| PreError::InvalidInput(format!("Invalid ring_pk hex encoding: {}", e)))?;

        // Use original string bytes instead of re-serializing
        let secret_bytes = document_payload.document.as_bytes().to_vec();

        // rdr_pk: hex-encoded compressed G1Affine bytes
        let rdr_pk = hex::decode(&req.rdr_pk)
            .map_err(|e| PreError::InvalidInput(format!("Invalid rdr_pk hex encoding: {}", e)))?;

        // 2. Validate we have peers
        if ring_payload.peer_ids.is_empty() {
            return Err(PreError::InvalidInput(
                "No peer IDs provided for reencryption".to_string(),
            )
            .into());
        }

        // 2b. Validate all peer IDs before attempting connections
        if let Err((invalid_peer_id, validation_error)) =
            validate_all_peer_ids(&ring_payload.peer_ids)
        {
            return Err(PreError::InvalidInput(format!(
                "Invalid peer ID '{}': {}",
                invalid_peer_id, validation_error
            ))
            .into());
        }

        // 3. Generate unique request ID (use peer_id hash instead of node_id since node_id is session-specific)
        let peer_id_hash =
            derive_node_id_from_peer_id_bytes(self.state.network.local_peer_id().as_bytes());
        let request_id = format!("{}-{}", peer_id_hash, created_at);

        // 4. Connect to peer nodes using iroh network
        let connection_summary = connect_to_peers(
            &self.state.network,
            ring_payload.peer_ids.clone(),
            REENCRYPT,
        )
        .await;

        // Check if we successfully connected to all requested peers
        if connection_summary.failed > 0 {
            let error_msg = format!(
                "Failed to connect to all required peers. Connected to {}/{} peers. Failed connections: {}",
                connection_summary.successful,
                connection_summary.total,
                connection_summary.failed
            );
            tracing::error!(error = %error_msg, "Failed to connect to all peers");
            return Err(PreError::NetworkConnection(error_msg).into());
        }

        tracing::info!(
            connected = connection_summary.successful,
            total = connection_summary.total,
            "PRE Service: Connected to peers"
        );

        // 5. Create coordinator and initiate reencryption
        metrics::record_pre_request_started();
        let coordinator = PreCoordinator::<D, T>::new(Arc::new(self.state.clone()));
        let total_nodes = ring_payload.peer_ids.len();
        let result = coordinator
            .initiate_reencryption(
                request_id,
                ring_pk,
                secret_bytes,
                rdr_pk,
                &ring_payload.peer_ids,
                ring_payload.threshold as usize,
                total_nodes,
                &ring_payload.public_polynomial,
                req.object_id,
                token_str.to_string(),
                req.namespace,
                req.derivation,
            )
            .await?;

        // 6. Parse result as PreResponse and encode as JSON
        let pre_response: crate::pre::coordinator::PreResponse = serde_json::from_slice(&result)
            .map_err(|e| PreError::Deserialization(format!("Failed to parse PRE result: {}", e)))?;

        let encrypted_secret = serde_json::to_string(&pre_response)
            .map_err(|e| PreError::Serialization(format!("Failed to serialize response: {}", e)))?;

        let response = StartPreResponse {
            status: "completed".to_string(),
            message: format!(
                "PRE completed successfully with {} peers",
                connection_summary.successful
            ),
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

/// Validates JWT claims against the PRE request
pub fn validate_pre_claims(
    token: &BearerToken<PreClaims>,
    rdr_pk: &String,
    object_id: &String,
    namespace: &String,
    derivation: &Option<Vec<u8>>,
) -> Result<(), PreError> {
    // Validate rdr_pk matches
    if token.claims.rdr_pk != *rdr_pk {
        return Err(PreError::Unauthorized(format!(
            "Token rdr_pk '{}' does not match request rdr_pk '{}'",
            token.claims.rdr_pk, rdr_pk
        )));
    }

    if token.claims.object_id != *object_id {
        return Err(PreError::Unauthorized(format!(
            "Token object_id '{}' does not match request object_id '{}'",
            token.claims.object_id, object_id
        )));
    }

    if token.claims.namespace != *namespace {
        return Err(PreError::Unauthorized(format!(
            "Token namespace '{}' does not match request namespace '{}'",
            token.claims.namespace, namespace
        )));
    }

    if token.claims.derivation != *derivation {
        return Err(PreError::Unauthorized(format!(
            "Token derivation '{:?}' does not match request derivation '{:?}'",
            token.claims.derivation, derivation
        )));
    }

    Ok(())
}
