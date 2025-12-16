use crate::app_state::AppState;
use crate::pre_service::{pre_service_server::PreService, StartPreRequest, StartPreResponse};
use tonic::{Request, Response, Status};
use std::time::{SystemTime, UNIX_EPOCH};

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

        let response = StartPreResponse {
            session_id: req.session_id.clone(),
            status: "started".to_string(),
            message: format!("PRE session started",),
            created_at,
        };

        Ok(Response::new(response))
    }
}
