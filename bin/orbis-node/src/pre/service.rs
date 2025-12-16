use crate::app_state::AppState;
use crate::helpers::helpers::connect_to_peers;
use crate::pre::coordinator::PreCoordinator;
use crate::pre_service::{pre_service_server::PreService, StartPreRequest, StartPreResponse};
use network::iroh::router::alpn::REENCRYPT;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tonic::{Request, Response, Status};

/// Implementation of the PreService
#[derive(Debug)]
pub struct PreServiceImpl {
    pub state: AppState,
}

impl PreServiceImpl {
    /// Create a new PreServiceImpl with shared application state
    pub fn new(state: AppState) -> Self {
        Self { state }
    }
}

#[tonic::async_trait]
impl PreService for PreServiceImpl {
    async fn start_pre(
        &self,
        request: Request<StartPreRequest>,
    ) -> Result<Response<StartPreResponse>, Status> {
        let req = request.into_inner();
        println!("Received StartPre request:");
        println!("  Ring PK: {}", req.ring_pk);
        println!("  Reader PK: {}", req.rdr_pk);
        println!("  Peer IDs: {:?}", req.peer_ids);

        // Get current timestamp
        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| Status::internal(format!("Failed to get timestamp: {}", e)))?
            .as_secs() as i64;

        // 1. Decode base64-encoded inputs
        let ring_pk = base64::engine::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &req.ring_pk,
        )
        .map_err(|e| Status::invalid_argument(format!("Invalid ring_pk encoding: {}", e)))?;

        let secret =
            base64::engine::Engine::decode(&base64::engine::general_purpose::STANDARD, &req.secret)
                .map_err(|e| Status::invalid_argument(format!("Invalid secret encoding: {}", e)))?;

        let rdr_pk =
            base64::engine::Engine::decode(&base64::engine::general_purpose::STANDARD, &req.rdr_pk)
                .map_err(|e| Status::invalid_argument(format!("Invalid rdr_pk encoding: {}", e)))?;

        // 2. Validate we have peers
        if req.peer_ids.is_empty() {
            return Err(Status::invalid_argument(
                "No peer IDs provided for reencryption",
            ));
        }

        // 3. Generate unique request ID
        let request_id = format!("{}-{}", self.state.config.node_id, created_at);

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
            return Err(Status::failed_precondition(error_msg));
        }

        println!(
            "PRE Service: Connected to {}/{} peers",
            connection_summary.successful, requested_peers
        );

        // 5. Create coordinator and initiate reencryption
        let coordinator = PreCoordinator::new(Arc::new(self.state.clone()));
        let result = coordinator
            .initiate_reencryption(request_id, ring_pk, secret, rdr_pk, &req.peer_ids)
            .await
            .map_err(|e| Status::internal(format!("Reencryption failed: {}", e)))?;

        // 6. Encode result as base64
        let encrypted_secret =
            base64::engine::Engine::encode(&base64::engine::general_purpose::STANDARD, &result);

        let response = StartPreResponse {
            status: "completed".to_string(),
            message: format!("PRE completed successfully with {} peers", requested_peers),
            created_at,
            encrypted_secret,
        };

        Ok(Response::new(response))
    }
}
