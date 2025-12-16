use crate::app_state::AppState;
use crate::pre_service::{
    StartPreRequest, StartPreResponse, pre_service_server::PreService
};
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


// #[tonic::async_trait]
// impl PreService for PreServiceImpl {

// }
