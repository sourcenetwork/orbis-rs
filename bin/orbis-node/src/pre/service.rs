use crate::app_state::AppState;
use crate::helpers::helpers::{connect_to_peers, validate_all_peer_ids};
use crate::pre::coordinator::PreCoordinator;
use crate::pre::error::PreError;
use crate::pre_service::{pre_service_server::PreService, StartPreRequest, StartPreResponse};
use crypto::r#trait::{DistKeyShare, Dkg, ReencryptReply, Secret, ThresholdDealer};
use network::REENCRYPT;
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
        let req = request.into_inner();
        // TODO: Authenticate with ACP
        println!("Received StartPre request:");
        println!("  Ring PK: {}", req.ring_pk);
        println!("  Reader PK: {}", req.rdr_pk);
        println!("  Peer IDs: {:?}", req.peer_ids);

        // Get current timestamp
        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| Status::internal(format!("Failed to get timestamp: {}", e)))?
            .as_secs() as i64;

        // 1. Parse JSON and hex inputs
        // ring_pk: hex-encoded compressed G1Affine bytes
        let ring_pk = hex::decode(&req.ring_pk)
            .map_err(|e| PreError::InvalidInput(format!("Invalid ring_pk hex encoding: {}", e)))?;

        // Use original string bytes instead of re-serializing
        let secret_bytes = req.secret.as_bytes().to_vec();

        // rdr_pk: hex-encoded compressed G1Affine bytes
        let rdr_pk = hex::decode(&req.rdr_pk)
            .map_err(|e| PreError::InvalidInput(format!("Invalid rdr_pk hex encoding: {}", e)))?;

        // 2. Validate we have peers
        if req.peer_ids.is_empty() {
            return Err(PreError::InvalidInput(
                "No peer IDs provided for reencryption".to_string(),
            )
            .into());
        }

        // 2b. Validate all peer IDs before attempting connections
        if let Err((invalid_peer_id, validation_error)) = validate_all_peer_ids(&req.peer_ids) {
            return Err(PreError::InvalidInput(format!(
                "Invalid peer ID '{}': {}",
                invalid_peer_id, validation_error
            ))
            .into());
        }

        // 3. Generate unique request ID (use peer_id hash instead of node_id since node_id is session-specific)
        let peer_id_hash = {
            use crate::helpers::helpers;
            helpers::derive_node_id_from_peer_id_bytes(
                self.state.network.local_peer_id().as_bytes(),
            )
        };
        let request_id = format!("{}-{}", peer_id_hash, created_at);

        // 4. Connect to peer nodes using iroh network
        let requested_peers = req.peer_ids.len();
        let connection_summary =
            connect_to_peers(&self.state.network, req.peer_ids.clone(), REENCRYPT).await;

        // Check if we successfully connected to all requested peers
        if connection_summary.successful < requested_peers {
            let error_msg = format!(
                "Failed to connect to all required peers. Connected to {}/{} peers. Failed connections: {}",
                connection_summary.successful,
                requested_peers,
                connection_summary.failed
            );
            eprintln!("Error: {}", error_msg);
            return Err(PreError::NetworkConnection(error_msg).into());
        }

        println!(
            "PRE Service: Connected to {}/{} peers",
            connection_summary.successful, requested_peers
        );

        // 5. Create coordinator and initiate reencryption
        let coordinator = PreCoordinator::<D, T>::new(Arc::new(self.state.clone()));
        let result = coordinator
            .initiate_reencryption(request_id, ring_pk, secret_bytes, rdr_pk, &req.peer_ids)
            .await?;

        // 6. Parse result as PreResponse and encode as JSON
        let pre_response: crate::pre::coordinator::PreResponse = serde_json::from_slice(&result)
            .map_err(|e| PreError::Deserialization(format!("Failed to parse PRE result: {}", e)))?;

        let encrypted_secret = serde_json::to_string(&pre_response)
            .map_err(|e| PreError::Serialization(format!("Failed to serialize response: {}", e)))?;

        let response = StartPreResponse {
            status: "completed".to_string(),
            message: format!("PRE completed successfully with {} peers", requested_peers),
            created_at,
            encrypted_secret,
        };

        Ok(Response::new(response))
    }
}
