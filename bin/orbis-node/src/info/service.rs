use crate::app_state::AppState;
use crate::helpers::launch::get_node_signer;
use crate::info::error::InfoError;
use crate::ring_state::RingPolyState;
use common::blockchain::ChainConfigBuilder;
use proto::info_service::{
    info_service_server::InfoService, GetNodeInfoRequest, GetNodeInfoResponse, GetRingStateRequest,
    GetRingStateResponse,
};
use tonic::{Request, Response, Status};

/// Implementation of the InfoService
#[derive(Debug)]
pub struct InfoServiceImpl<D>
where
    D: crypto::r#trait::Dkg + Clone + 'static,
{
    pub state: AppState<D>,
}

impl<D> InfoServiceImpl<D>
where
    D: crypto::r#trait::Dkg + Clone + 'static,
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

    async fn get_ring_state(
        &self,
        request: Request<GetRingStateRequest>,
    ) -> Result<Response<GetRingStateResponse>, Status> {
        let ring_pk_hex = request.into_inner().ring_pk_hex;
        let state = RingPolyState::load_from_ring_pk_hex(&self.state.local_storage, &ring_pk_hex)
            .map_err(|e| Status::not_found(e))?;
        Ok(Response::new(GetRingStateResponse {
            public_polynomial: state.public_polynomial,
            refreshed_at: state.refreshed_at,
        }))
    }
}
