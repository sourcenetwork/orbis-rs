use crate::app_state::PeerConnectionPool;
use crate::reporting::v0::error::{ReportingError, Result};
use async_trait::async_trait;
use network::{Connection, Message, Network, ProtocolHandler};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;

const HEALTH_PROBE_ATTEMPTS: usize = 3;
const HEALTH_PROBE_TOTAL_TIMEOUT: Duration = Duration::from_secs(5);
const HEALTH_PROBE_ATTEMPT_TIMEOUT: Duration = Duration::from_millis(1_400);
const HEALTH_PROBE_RETRY_DELAY: Duration = Duration::from_millis(250);

#[derive(Debug, Clone, Serialize, Deserialize)]
enum HealthMessage {
    Challenge { nonce: [u8; 32], expires_at: u64 },
    Response { nonce: [u8; 32] },
}

pub struct HealthProtocolHandler;

#[async_trait]
impl ProtocolHandler for HealthProtocolHandler {
    async fn handle(&self, connection: Box<dyn Connection>) -> network::Result<()> {
        let request = connection.recv().await?;
        let message: HealthMessage = serde_json::from_slice(&request.data)
            .map_err(|error| network::NetworkError::Serialization(error.to_string()))?;
        let HealthMessage::Challenge { nonce, expires_at } = message else {
            return Err(network::NetworkError::Protocol(
                "reporting health stream expected a challenge".to_string(),
            ));
        };
        let now = current_unix_time().map_err(network::NetworkError::Protocol)?;
        if now > expires_at {
            return Err(network::NetworkError::Protocol(
                "reporting health challenge expired".to_string(),
            ));
        }
        let response = serde_json::to_vec(&HealthMessage::Response { nonce })
            .map_err(|error| network::NetworkError::Serialization(error.to_string()))?;
        connection
            .send(Message::new(response, request.protocol))
            .await
    }
}

pub async fn require_peer_offline(
    network: &Arc<dyn Network>,
    pool: &Arc<PeerConnectionPool>,
    peer_id: &str,
    routes: &'static network::ProtocolRoutes,
) -> Result<()> {
    let probe = async {
        for attempt in 0..HEALTH_PROBE_ATTEMPTS {
            if probe_once(network, pool, peer_id, routes.reporting_health_alpn).await {
                crate::metrics::REPORT_HEALTH_CHECKS_TOTAL
                    .with_label_values(&["reachable"])
                    .inc();
                return Err(ReportingError::TargetReachable);
            }
            if attempt + 1 < HEALTH_PROBE_ATTEMPTS {
                tokio::time::sleep(HEALTH_PROBE_RETRY_DELAY).await;
            }
        }
        crate::metrics::REPORT_HEALTH_CHECKS_TOTAL
            .with_label_values(&["offline"])
            .inc();
        Ok(())
    };

    match tokio::time::timeout(HEALTH_PROBE_TOTAL_TIMEOUT, probe).await {
        Ok(result) => result,
        Err(_) => Ok(()),
    }
}

async fn probe_once(
    network: &Arc<dyn Network>,
    pool: &Arc<PeerConnectionPool>,
    peer_id: &str,
    protocol: &[u8],
) -> bool {
    let nonce: [u8; 32] = rand::random();
    let attempt = async {
        // Give the challenge a tight per-probe expiry independent of the report TTL.
        // The nonce already prevents replay; this only guards against very stale deliveries.
        let expires_at = current_unix_time()
            .map(|now| now + HEALTH_PROBE_ATTEMPT_TIMEOUT.as_secs())
            .ok()?;
        let stream = pool.open_stream(network, peer_id, protocol).await.ok()?;
        let payload = serde_json::to_vec(&HealthMessage::Challenge { nonce, expires_at }).ok()?;
        stream.send(Message::new(payload, protocol)).await.ok()?;
        let response = stream.recv().await.ok()?;
        match serde_json::from_slice::<HealthMessage>(&response.data).ok()? {
            HealthMessage::Response {
                nonce: response_nonce,
            } if response_nonce == nonce => Some(()),
            _ => None,
        }
    };
    tokio::time::timeout(HEALTH_PROBE_ATTEMPT_TIMEOUT, attempt)
        .await
        .ok()
        .flatten()
        .is_some()
}

fn current_unix_time() -> std::result::Result<u64, String> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| format!("failed to read system clock: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use network::{NetworkImpl, Router};

    #[tokio::test]
    async fn live_health_protocol_rejects_offline_claim() {
        let target: Arc<dyn Network> = Arc::new(
            NetworkImpl::builder()
                .bind_addr_v4("127.0.0.1:0".parse().unwrap())
                .no_relay()
                .build()
                .await
                .unwrap(),
        );
        let mut builder = target.create_router_builder().unwrap();
        builder = builder.accept(
            network::V0.reporting_health_alpn.to_vec(),
            Arc::new(HealthProtocolHandler),
        );
        let router: Box<dyn Router> = builder.spawn().unwrap();

        let source: Arc<dyn Network> = Arc::new(
            NetworkImpl::builder()
                .bind_addr_v4("127.0.0.1:0".parse().unwrap())
                .no_relay()
                .build()
                .await
                .unwrap(),
        );
        let target_peer = format!(
            "{}@{}",
            hex::encode(target.local_peer_id().as_bytes()),
            target.bound_addresses()[0]
        );
        let pool = Arc::new(PeerConnectionPool::new());

        let result = require_peer_offline(&source, &pool, &target_peer, &network::V0).await;
        assert!(matches!(result, Err(ReportingError::TargetReachable)));

        router.shutdown().await.unwrap();
    }
}
