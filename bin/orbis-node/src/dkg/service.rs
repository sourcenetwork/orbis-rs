use crate::app_state::AppState;
use crate::crypto_service::{
    crypto_service_server::CryptoService, EncryptionRequest, EncryptionResponse, StartDkgRequest,
    StartDkgResponse,
};
use crate::{constants::ALPNDKG, helpers::helpers::connect_to_peers};
use crypto::bls12_381::dkg::DKGNode;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use tonic::{Request, Response, Status};

/// Implementation of the CryptoService
#[derive(Debug)]
pub struct CryptoServiceImpl {
    pub state: AppState,
}

impl CryptoServiceImpl {
    /// Create a new CryptoServiceImpl with shared application state
    pub fn new(state: AppState) -> Self {
        Self { state }
    }
}

impl Default for CryptoServiceImpl {
    fn default() -> Self {
        // Default implementation requires async initialization, so this is a placeholder
        // In practice, use CryptoServiceImpl::new() with a properly initialized AppState
        panic!("Default implementation not supported. Use CryptoServiceImpl::new() with initialized AppState")
    }
}

#[tonic::async_trait]
impl CryptoService for CryptoServiceImpl {
    async fn start_dkg(
        &self,
        request: Request<StartDkgRequest>,
    ) -> Result<Response<StartDkgResponse>, Status> {
        let req = request.into_inner();
        // TODO: Authentication, is user allowed to create a ring

        println!("Received StartDkg request:");
        println!("  Session ID: {}", req.session_id);
        println!("  Threshold: {}", req.threshold);
        println!("  Total Participants: {}", req.total_participants);
        println!("  Participant IDs: {:?}", req.participant_ids);
        println!("  Peer IDs: {:?}", req.peer_ids);
        println!("  Parameters: {:?}", req.parameters);

        // Get current timestamp
        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| Status::internal(format!("Failed to get timestamp: {}", e)))?
            .as_secs() as i64;

        // Connect to peer nodes using iroh network
        // Peer IDs should be in iroh PublicKey format: either "node_id" or "node_id@ip:port"
        // where node_id is the iroh public key string representation
        if !req.peer_ids.is_empty() {
            let connection_summary =
                connect_to_peers(&self.state.network, req.peer_ids.clone(), ALPNDKG).await;

            // Log summary
            if connection_summary.failed > 0 {
                eprintln!(
                    "Warning: Failed to connect to {}/{} peers",
                    connection_summary.failed, connection_summary.total
                );
            }
        }

        // // Store session in shared state
        // let session = DKGNode {
        //     session_id: req.session_id.clone(),
        //     threshold: req.threshold,
        //     total_participants: req.total_participants,
        //     participant_ids: req.participant_ids.clone(),
        //     status: "started".to_string(),
        //     created_at,
        //     parameters: req.parameters.clone(),
        // };
        // self.state.store_dkg_session(session).await;

        let response = StartDkgResponse {
            session_id: req.session_id.clone(),
            status: "started".to_string(),
            message: format!(
                "DKG session started with threshold {} and {} participants",
                req.threshold, req.total_participants
            ),
            created_at,
        };

        Ok(Response::new(response))
    }
}
