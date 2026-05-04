use crate::app_state::AppState;
use crate::helpers::launch::get_node_signer;
use crate::info::error::InfoError;
use crate::ring_state::RingPolyState;
use common::blockchain::ChainConfigBuilder;
use local_storage::LocalStorageImpl;
use network::Network;
use proto::info_service::{
    info_service_server::InfoService, GetNodeInfoRequest, GetNodeInfoResponse, GetRingStateRequest,
    GetRingStateResponse, NodeStatus,
};
use std::sync::{
    atomic::{AtomicI32, Ordering},
    Arc,
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
        Ok(Response::new(get_node_info_response(
            self.state.network.as_ref(),
            self.state.local_storage.clone(),
            NodeStatus::Ready as i32,
        )?))
    }

    async fn get_ring_state(
        &self,
        request: Request<GetRingStateRequest>,
    ) -> Result<Response<GetRingStateResponse>, Status> {
        let ring_pk_hex = request.into_inner().ring_pk_hex;
        Ok(Response::new(get_ring_state_response(
            &self.state.local_storage,
            &ring_pk_hex,
        )?))
    }
}

fn get_node_info_response(
    network: &dyn Network,
    local_storage: LocalStorageImpl,
    status: i32,
) -> Result<GetNodeInfoResponse, Status> {
    // Get the peer ID from the network
    let peer_id = hex::encode(network.local_peer_id().as_bytes());

    // Get the P2P connection string (peer_id@host:port)
    let socket_addr = network
        .bound_addresses()
        .first()
        .map(|addr| addr.to_string())
        .unwrap_or_else(|| "0.0.0.0:0".to_string());
    let p2p_address = format!("{}@{}", peer_id, socket_addr);

    // Get the signer address from local storage
    let config = ChainConfigBuilder::default().build();
    let public_address = get_node_signer(local_storage, config)
        .map_err(|e| InfoError::InfoError(format!("Error getting public key: {}", e)))?
        .address();

    Ok(GetNodeInfoResponse {
        public_address,
        peer_id,
        p2p_address,
        status,
    })
}

fn get_ring_state_response(
    local_storage: &LocalStorageImpl,
    ring_pk_hex: &str,
) -> Result<GetRingStateResponse, Status> {
    let state = RingPolyState::load_from_ring_pk_hex(local_storage, ring_pk_hex)
        .map_err(Status::not_found)?;
    Ok(GetRingStateResponse {
        public_polynomial: state.public_polynomial,
        last_pss: state.last_pss,
    })
}

/// InfoService used during node bootstrap, before chain funding and bulletin initialization.
pub struct BootstrapInfoServiceImpl {
    pub network: Arc<dyn Network>,
    pub local_storage: LocalStorageImpl,
    pub status: Arc<AtomicI32>,
}

impl BootstrapInfoServiceImpl {
    /// Create a bootstrap info service from the already-initialized local identity.
    pub fn new(
        network: Arc<dyn Network>,
        local_storage: LocalStorageImpl,
        status: Arc<AtomicI32>,
    ) -> Self {
        Self {
            network,
            local_storage,
            status,
        }
    }
}

#[tonic::async_trait]
impl InfoService for BootstrapInfoServiceImpl {
    async fn get_node_info(
        &self,
        _request: Request<GetNodeInfoRequest>,
    ) -> Result<Response<GetNodeInfoResponse>, Status> {
        Ok(Response::new(get_node_info_response(
            self.network.as_ref(),
            self.local_storage.clone(),
            self.status.load(Ordering::SeqCst),
        )?))
    }

    async fn get_ring_state(
        &self,
        _request: Request<GetRingStateRequest>,
    ) -> Result<Response<GetRingStateResponse>, Status> {
        Err(Status::failed_precondition(
            "node is waiting for funding; only GetNodeInfo is available",
        ))
    }
}
