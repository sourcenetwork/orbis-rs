use crate::app_state::AppState;
use crypto::bls12_381::dkg::DKGNode;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use tonic::{Request, Response, Status};

use crate::crypto_service::{
    crypto_service_server::CryptoService, EncryptionRequest, EncryptionResponse, StartDkgRequest,
    StartDkgResponse,
};

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

        println!("Received StartDkg request:");
        println!("  Session ID: {}", req.session_id);
        println!("  Threshold: {}", req.threshold);
        println!("  Total Participants: {}", req.total_participants);
        println!("  Participant IDs: {:?}", req.participant_ids);
        println!("  Parameters: {:?}", req.parameters);

        // Get current timestamp
        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| Status::internal(format!("Failed to get timestamp: {}", e)))?
            .as_secs() as i64;

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
