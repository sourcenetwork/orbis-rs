//! Read-only discovery: node and ring state.

use proto::info_service::info_service_client::InfoServiceClient;
use proto::info_service::{
    GetNodeInfoRequest, GetPetRingStateRequest, GetRingStateRequest, NodeStatus,
};

use crate::client::OrbisClient;
use crate::error::Result;

/// Result of querying node info.
#[derive(Debug, Clone)]
pub struct NodeInfoResult {
    pub public_address: String,
    pub peer_id: String,
    pub p2p_address: String,
    pub status: NodeStatus,
    pub managed_ring_count: u32,
    /// Compressed secp256k1 pubkey hex — the node's on-chain key in
    /// x/orbis `NodeInfo`.
    pub node_key: String,
    pub supported_protocol_versions: Vec<u64>,
}

impl OrbisClient {
    /// Queries a node's own identity and status.
    pub async fn query_node_info(&self) -> Result<NodeInfoResult> {
        let mut client = InfoServiceClient::new(self.channel());
        let node_info = client
            .get_node_info(GetNodeInfoRequest {})
            .await?
            .into_inner();
        let status = NodeStatus::try_from(node_info.status).unwrap_or(NodeStatus::Unspecified);

        Ok(NodeInfoResult {
            public_address: node_info.public_address,
            peer_id: node_info.peer_id,
            p2p_address: node_info.p2p_address,
            status,
            managed_ring_count: node_info.managed_ring_count,
            node_key: node_info.node_key,
            supported_protocol_versions: node_info.supported_protocol_versions,
        })
    }

    /// Queries the local `RingPolyState` from a node (public polynomial +
    /// `last_pss` timestamp). Returns an error if `ring_pk_hex` is not
    /// found on that node.
    pub async fn query_ring_state(&self, ring_pk_hex: String) -> Result<(String, u64)> {
        let mut client = InfoServiceClient::new(self.channel());
        let response = client
            .get_ring_state(GetRingStateRequest { ring_pk_hex })
            .await?
            .into_inner();
        Ok((response.public_polynomial, response.last_pss))
    }

    /// Same as [`OrbisClient::query_ring_state`], for a ring's independent
    /// PET checking key — keyed by `ring_id` (PET has no public-key
    /// storage handle to query by). Returns an error if the ring has no
    /// PET bundle on that node.
    pub async fn query_pet_ring_state(&self, ring_id: String) -> Result<(String, u64)> {
        let mut client = InfoServiceClient::new(self.channel());
        let response = client
            .get_pet_ring_state(GetPetRingStateRequest { ring_id })
            .await?
            .into_inner();
        Ok((response.public_polynomial, response.last_pss))
    }
}
