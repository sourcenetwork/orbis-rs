//! Health check polling for orbis-node gRPC endpoints.
//!
//! Polls InfoService.GetNodeInfo to determine if a node is responsive.
//! Uses parallel async checks with configurable interval and timeout.

use std::time::Duration;

use proto::info_service::info_service_client::InfoServiceClient;
use proto::info_service::GetNodeInfoRequest;

/// Health check configuration.
#[derive(Clone, Debug)]
pub struct HealthCheckConfig {
    /// Poll interval between health check attempts.
    pub poll_interval: Duration,
    /// Maximum time to wait for all nodes to become healthy.
    pub timeout: Duration,
}

impl Default for HealthCheckConfig {
    fn default() -> Self {
        Self {
            poll_interval: Duration::from_millis(100),
            timeout: Duration::from_secs(10),
        }
    }
}

/// Check if a single node is healthy by calling InfoService.GetNodeInfo.
async fn check_node_health(addr: &str) -> bool {
    let Ok(mut client) = InfoServiceClient::connect(addr.to_string()).await else {
        return false;
    };
    client
        .get_node_info(GetNodeInfoRequest {})
        .await
        .is_ok()
}

/// Wait for all nodes to become healthy.
///
/// Polls each node in parallel at the configured interval until all respond
/// successfully or the timeout is reached.
pub async fn wait_all_healthy(
    grpc_addrs: &[String],
    config: &HealthCheckConfig,
) -> eyre::Result<()> {
    let deadline = tokio::time::Instant::now() + config.timeout;

    loop {
        let mut handles = Vec::with_capacity(grpc_addrs.len());
        for addr in grpc_addrs {
            let addr = addr.clone();
            handles.push(tokio::spawn(async move { check_node_health(&addr).await }));
        }

        let mut all_healthy = true;
        for handle in handles {
            if !handle.await.unwrap_or(false) {
                all_healthy = false;
            }
        }

        if all_healthy {
            return Ok(());
        }

        if tokio::time::Instant::now() >= deadline {
            // Report which nodes are unhealthy
            let mut unhealthy = Vec::new();
            for (i, addr) in grpc_addrs.iter().enumerate() {
                if !check_node_health(addr).await {
                    unhealthy.push(i);
                }
            }
            return Err(eyre::eyre!(
                "timeout ({:?}) waiting for {} nodes to become healthy. \
                 Unhealthy nodes: {:?}",
                config.timeout,
                grpc_addrs.len(),
                unhealthy,
            ));
        }

        tokio::time::sleep(config.poll_interval).await;
    }
}
