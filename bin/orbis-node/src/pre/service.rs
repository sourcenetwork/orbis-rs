use crate::app_state::AppState;
use crate::constants::MAX_TOKEN_LIFETIME_SECS;
use crate::helpers::helpers::{
    connect_to_peers, derive_node_id_from_peer_id_bytes, validate_all_peer_ids,
};
use crate::metrics;
use crate::pre::coordinator::PreCoordinator;
use crate::pre::error::PreError;
use crate::pre::helpers::{
    check_policy_access, decode_ring_pk, deserialize_secret, fetch_bulletin_payloads,
    validate_pre_claims, verify_encryption_binding,
};
use authn::{extract_bearer_token, resolve_jwt_did, BearerToken, PreClaims};
use crypto::r#trait::{DistKeyShare, Dkg, ReencryptReply, Secret, ThresholdDealer};
use crypto::PreImpl as ThresholdDealerNode;
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
        let token: BearerToken<PreClaims> =
            resolve_jwt_did(&token_str, current_time, MAX_TOKEN_LIFETIME_SECS)
                .map_err(|e| PreError::Unauthorized(format!("JWT validation failed: {}", e)))?;

        let req = request.into_inner();
        let (document_payload, ring_payload) =
            fetch_bulletin_payloads(&*self.state.bulletin, &req.namespace, &req.object_id).await?;

        check_policy_access(
            &*self.state.authz,
            &document_payload,
            &req.object_id,
            &token.issuer_id,
        )
        .await?;

        // 2. Authorize: Validate JWT claims match request fields
        validate_pre_claims(
            &token,
            &req.rdr_pk,
            &req.object_id,
            &req.namespace,
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
            document_payload.timestamp.clone().as_deref(),
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
            peer_ids = ?ring_payload.peer_ids,
            issuer = %token.issuer_id,
            "Authenticated StartPre request"
        );

        let created_at = current_time as i64;

        // 1. Parse inputs
        // Use original string bytes instead of re-serializing
        let secret_bytes = document_payload.document.as_bytes().to_vec();

        // rdr_pk: compressed G1Affine bytes (received directly as bytes)
        let rdr_pk = req.rdr_pk.clone();

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
                ring_pk_bytes,
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
                req.salt,
            )
            .await?;

        // 6. Parse result as PreResponse and encode as JSON
        let pre_response: crate::pre::coordinator::PreResponse = serde_json::from_slice(&result)
            .map_err(|e| PreError::Deserialization(format!("Failed to parse PRE result: {}", e)))?;

        let encrypted_secret = serde_json::to_vec(&pre_response)
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
