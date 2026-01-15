use crate::app_state::AppState;
use crate::helpers::launch::get_node_signer;
use crate::info::error::InfoError;
use common::blockchain::ChainConfigBuilder;
use proto::info_service::{
    info_service_server::InfoService, GetNodeInfoRequest, GetNodeInfoResponse,
};
use tonic::{Request, Response, Status};

/// Implementation of the InfoService
#[derive(Debug)]
pub struct InfoServiceImpl<D>
where
    D: crypto::r#trait::Dkg + Clone,
{
    pub state: AppState<D>,
}

impl<D> InfoServiceImpl<D>
where
    D: crypto::r#trait::Dkg + Clone,
{
    /// Create a new InfoServiceImpl with shared application state
    pub fn new(state: AppState<D>) -> Self {
        Self { state }
    }
}

#[tonic::async_trait]
impl<D> InfoService for InfoServiceImpl<D>
where
    D: crypto::r#trait::Dkg + Clone + Send + Sync + 'static,
{
    async fn get_node_info(
        &self,
        _request: Request<GetNodeInfoRequest>,
    ) -> Result<Response<GetNodeInfoResponse>, Status> {
        // Get the peer ID from the network
        let peer_id = hex::encode(self.state.network.local_peer_id().as_bytes());

        // Get the P2P connection string (peer_id@host:port)
        let socket_addr = self
            .state
            .network
            .bound_addresses()
            .first()
            .map(|addr| addr.to_string())
            .unwrap_or_else(|| "0.0.0.0:0".to_string());
        let p2p_address = format!("{}@{}", peer_id, socket_addr);

        // Get the signer address from local storage
        let config = ChainConfigBuilder::default().build();
        let public_address = get_node_signer(self.state.local_storage.clone(), config)
            .map_err(|e| InfoError::InfoError(format!("Error getting public key: {}", e)))?
            .address();

        Ok(Response::new(GetNodeInfoResponse {
            public_address,
            peer_id,
            p2p_address,
        }))
    }
}
