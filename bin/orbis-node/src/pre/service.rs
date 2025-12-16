use crate::app_state::AppState;
use crate::pre_service::{pre_service_server::PreService, StartPreRequest, StartPreResponse};
use crypto::bls12_381::pre::ThresholdDealerNode;
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

        // Get current timestamp
        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| Status::internal(format!("Failed to get timestamp: {}", e)))?
            .as_secs() as i64;

        // Use IROH peer ids in network to make p2p channel requests to other nodes
        // Other nodes should respond and call ThresholdDealer::reencrypt() to rdr_pk in message
        // this node should ThresholdDealer::verify() these responses
        // this node ThresholdDealer::recover() and send encrypted_secret back

        let response = StartPreResponse {
            status: "started".to_string(),
            message: format!("PRE session started",),
            created_at,
            encrypted_secret: "placeholder".to_string(),
        };

        Ok(Response::new(response))
    }
}
