use crate::app_state::AppState;
use crate::helpers::helpers::{
    connect_to_peers, derive_node_id_from_peer_id_bytes, validate_all_peer_ids,
};
use crate::pre::coordinator::PreCoordinator;
use crate::pre::error::PreError;
use authn::{extract_bearer_token, resolve_jwt_did, BearerToken, PreClaims};
use authz::sourcehub::AccessCheckRequest;
use bulletin::r#trait::Payload;
use crypto::r#trait::{DistKeyShare, Dkg, ReencryptReply, Secret, ThresholdDealer};
use network::REENCRYPT;
use proto::pre_service::{pre_service_server::PreService, StartPreRequest, StartPreResponse};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tonic::{Request, Response, Status};

/// Implementation of the PreService
#[derive(Debug)]
pub struct PreServiceImpl<D, T>
where
    D: Dkg + Clone,
    T: ThresholdDealer,
{
    pub state: AppState<D>,
    _phantom: std::marker::PhantomData<T>,
}

impl<D, T> PreServiceImpl<D, T>
where
    D: Dkg + Clone,
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
        // Get current timestamp (needed for both auth and response)
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| Status::internal(format!("Failed to get timestamp: {}", e)))?
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
            .unwrap();
        let payload = serde_json::from_slice::<Payload>(&object_info.payload).unwrap();

        let permission = AccessCheckRequest::new(
            payload.policy_id.clone(),
            payload.resource.clone(),
            req.object_id.clone(),
            payload.permission.clone(),
        )
        .to_bytes()
        .map_err(|e| PreError::AuthZ(format!("Error formatting access request: {}", e)))?;
        self.state
            .authz
            .check(permission, &token.issuer_id)
            .await
            .map_err(|e| PreError::AuthZ(format!("Error in Authz request: {}", e)))?;
        // TODO: use token.issuer_id as AuthZ check

        // 2. Authorize: Validate JWT claims match request fields
        validate_pre_claims(&token, &req.rdr_pk, &req.object_id, &req.namespace)?;

        tracing::info!(
            ring_pk = %payload.ring_pk,
            reader_pk = %req.rdr_pk,
            peer_ids = ?payload.peer_ids,
            issuer = %token.issuer_id,
            "Authenticated StartPre request"
        );

        let created_at = current_time as i64;

        // 1. Parse JSON and hex inputs
        // ring_pk: hex-encoded compressed G1Affine bytes
        let ring_pk = hex::decode(&payload.ring_pk)
            .map_err(|e| PreError::InvalidInput(format!("Invalid ring_pk hex encoding: {}", e)))?;

        // Use original string bytes instead of re-serializing
        let secret_bytes = payload.secret.as_bytes().to_vec();

        // rdr_pk: hex-encoded compressed G1Affine bytes
        let rdr_pk = hex::decode(&req.rdr_pk)
            .map_err(|e| PreError::InvalidInput(format!("Invalid rdr_pk hex encoding: {}", e)))?;

        // 2. Validate we have peers
        if payload.peer_ids.is_empty() {
            return Err(PreError::InvalidInput(
                "No peer IDs provided for reencryption".to_string(),
            )
            .into());
        }

        // 2b. Validate all peer IDs before attempting connections
        if let Err((invalid_peer_id, validation_error)) = validate_all_peer_ids(&payload.peer_ids) {
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
        let connection_summary =
            connect_to_peers(&self.state.network, payload.peer_ids.clone(), REENCRYPT).await;

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
        let coordinator = PreCoordinator::<D, T>::new(Arc::new(self.state.clone()));
        let result = coordinator
            .initiate_reencryption(
                request_id,
                ring_pk,
                secret_bytes,
                rdr_pk,
                &payload.peer_ids,
                payload.policy_id,
                payload.resource,
                req.object_id,
                payload.permission,
                token_str.to_string(),
                req.namespace,
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

        Ok(Response::new(response))
    }
}

/// Validates JWT claims against the PRE request
pub fn validate_pre_claims(
    token: &BearerToken<PreClaims>,
    rdr_pk: &String,
    object_id: &String,
    namespace: &String,
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

    Ok(())
}
