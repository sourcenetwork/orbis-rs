//! Backend-neutral node readiness: poll an Orbis node's `InfoService` until
//! it reports [`NodeStatus::Ready`], returning its [`NodeInfo`]. Both
//! [`crate::environment::CosmosTestEnvironment`] and the native
//! `TestEnvironment` (`bin/orbis-node/tests/support/native_environment.rs`,
//! which depends on this crate) use this instead of each hand-rolling an
//! `InfoServiceClient` poll loop.
//!
//! Deliberately built directly on `proto`/`tonic` rather than
//! `cli_tool::query_node_info` (which does the same thing) — `cli-tool`
//! hardcodes a default crypto feature that would conflict with a jubjub
//! build's feature unification if pulled into this crate; see
//! `admin/cosmos.rs`'s doc comment for the same reasoning applied to ring
//! creation.

use crate::network::NodeInfo;
use proto::info_service::{info_service_client::InfoServiceClient, GetNodeInfoRequest, NodeStatus};
use std::time::Duration;
use tonic::transport::Endpoint;

/// Poll every endpoint until it reports `Ready`, in order. Panics on timeout
/// (90s per node) — matching every other "bring up the test network" helper
/// in this crate.
pub async fn wait_for_nodes_ready(endpoints: &[String]) -> Vec<NodeInfo> {
    let mut nodes = Vec::with_capacity(endpoints.len());
    for endpoint in endpoints {
        nodes.push(wait_for_node_ready(endpoint).await);
    }
    nodes
}

async fn wait_for_node_ready(endpoint: &str) -> NodeInfo {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(90);
    loop {
        if let Some(info) = query_node_info(endpoint).await {
            if info.status() == NodeStatus::Ready {
                return NodeInfo {
                    grpc_endpoint: endpoint.to_string(),
                    node_key: info.node_key,
                    peer_id: info.peer_id,
                    p2p_address: info.p2p_address,
                    public_address: info.public_address,
                };
            }
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "node at {endpoint} did not become ready within 90s"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

async fn query_node_info(endpoint: &str) -> Option<proto::info_service::GetNodeInfoResponse> {
    let channel = Endpoint::from_shared(endpoint.to_string())
        .expect("valid node endpoint")
        .timeout(Duration::from_secs(10));
    let mut client = InfoServiceClient::connect(channel).await.ok()?;
    client
        .get_node_info(GetNodeInfoRequest {})
        .await
        .ok()
        .map(tonic::Response::into_inner)
}
