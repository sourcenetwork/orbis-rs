use crate::app_state::PeerConnectionPool;
use crate::helpers::identity::extract_node_part;
use crate::reporting::error::{ReportingError, Result};
use crate::reporting::health::require_peer_offline;
use crate::reporting::types::{
    ring_state_sha256, NodeOfflineV1, ReportEnvelope, NODE_OFFLINE_REPORT_TYPE,
    NODE_OFFLINE_REPORT_VERSION,
};
use async_trait::async_trait;
use bulletin::r#trait::{Bulletin, BulletinKind, NodeInfo, RingPayload};
use network::{Network, PeerId};
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportValidationMode {
    ReporterObservation,
    IndependentSigner { perform_health_probe: bool },
}

pub struct ReportValidationContext {
    pub local_node_key: String,
    pub requester_peer_id: Option<PeerId>,
    pub network: Arc<dyn Network>,
    pub peer_connection_pool: Arc<PeerConnectionPool>,
    pub bulletin: Arc<dyn Bulletin + Send + Sync>,
    pub routes: &'static network::ProtocolRoutes,
    pub now: u64,
    pub mode: ReportValidationMode,
}

#[async_trait]
pub trait ReportHandler: Send + Sync {
    fn report_type(&self) -> &'static str;
    fn report_version(&self) -> u16;
    async fn validate(
        &self,
        envelope: &ReportEnvelope,
        context: &ReportValidationContext,
    ) -> Result<()>;
}

pub struct ReportRegistry {
    handlers: HashMap<(String, u16), Arc<dyn ReportHandler>>,
}

impl ReportRegistry {
    pub fn with_defaults() -> Self {
        let mut registry = Self {
            handlers: HashMap::new(),
        };
        registry.register(Arc::new(NodeOfflineHandler));
        registry
    }

    pub fn register(&mut self, handler: Arc<dyn ReportHandler>) {
        self.handlers.insert(
            (handler.report_type().to_string(), handler.report_version()),
            handler,
        );
    }

    pub async fn validate(
        &self,
        envelope: &ReportEnvelope,
        context: &ReportValidationContext,
    ) -> Result<()> {
        envelope.validate_shape(context.now)?;
        let handler = self.handler_for(&envelope.report_type, envelope.report_version)?;
        handler.validate(envelope, context).await
    }

    fn handler_for(&self, report_type: &str, report_version: u16) -> Result<&dyn ReportHandler> {
        self.handlers
            .get(&(report_type.to_string(), report_version))
            .map(Arc::as_ref)
            .ok_or_else(|| ReportingError::UnsupportedReportType {
                name: report_type.to_string(),
                version: report_version,
            })
    }
}

impl Default for ReportRegistry {
    fn default() -> Self {
        Self::with_defaults()
    }
}

struct NodeOfflineHandler;

#[async_trait]
impl ReportHandler for NodeOfflineHandler {
    fn report_type(&self) -> &'static str {
        NODE_OFFLINE_REPORT_TYPE
    }

    fn report_version(&self) -> u16 {
        NODE_OFFLINE_REPORT_VERSION
    }

    async fn validate(
        &self,
        envelope: &ReportEnvelope,
        context: &ReportValidationContext,
    ) -> Result<()> {
        let payload = NodeOfflineV1::from_canonical_bytes(&envelope.payload)?;
        if payload.origin_protocol.trim().is_empty() {
            return Err(ReportingError::InvalidReport(
                "offline report origin protocol cannot be empty".to_string(),
            ));
        }

        let ring_post = context
            .bulletin
            .read(envelope.ring_id.clone(), BulletinKind::Ring)
            .await
            .map_err(|error| ReportingError::Bulletin(error.to_string()))?;
        let ring = RingPayload::try_from(ring_post)
            .map_err(|error| ReportingError::InvalidReport(error.to_string()))?;

        if envelope.chain_id != context.bulletin.chain_id() {
            return Err(ReportingError::Unauthorized(
                "report chain ID does not match the configured bulletin".to_string(),
            ));
        }
        let effective_version = ring
            .upgrade_info
            .effective_version(context.now)
            .map_err(|error| ReportingError::InvalidReport(error.to_string()))?;
        if effective_version != context.routes.version {
            return Err(ReportingError::Unauthorized(format!(
                "report protocol version {} is not effective for ring {}",
                context.routes.version, envelope.ring_id
            )));
        }

        validate_ring_and_membership(envelope, &ring)?;
        validate_node_routes(envelope, context, &ring).await?;

        if context.local_node_key == envelope.accused_node_key {
            return Err(ReportingError::Unauthorized(
                "the accused node cannot sign its own offline report".to_string(),
            ));
        }
        if !ring
            .peer_node_keys
            .iter()
            .any(|node_key| node_key == &context.local_node_key)
        {
            return Err(ReportingError::Unauthorized(
                "local signer is not in the report ring".to_string(),
            ));
        }

        if let ReportValidationMode::IndependentSigner {
            perform_health_probe: true,
        } = context.mode
        {
            require_peer_offline(
                &context.network,
                &context.peer_connection_pool,
                &envelope.accused_peer_id,
                context.routes,
                envelope.expires_at,
            )
            .await?;
        }

        Ok(())
    }
}

fn validate_ring_and_membership(envelope: &ReportEnvelope, ring: &RingPayload) -> Result<()> {
    if ring.ring_pk.is_empty() {
        return Err(ReportingError::Unauthorized(
            "offline reports require a finalized ring".to_string(),
        ));
    }
    if ring.new_peer_node_keys.is_some() || ring.new_threshold.is_some() {
        return Err(ReportingError::Unauthorized(
            "offline reports are disabled during reshare".to_string(),
        ));
    }
    if ring.ring_pk != envelope.ring_pk {
        return Err(ReportingError::Unauthorized(
            "report ring public key is stale".to_string(),
        ));
    }
    if ring_state_sha256(ring) != envelope.ring_state_sha256 {
        return Err(ReportingError::Unauthorized(
            "report ring-state digest is stale".to_string(),
        ));
    }
    if ring.threshold < 2 {
        return Err(ReportingError::Unauthorized(
            "offline reporting requires ring threshold >= 2".to_string(),
        ));
    }
    if ring.threshold as usize > ring.peer_node_keys.len().saturating_sub(1) {
        return Err(ReportingError::Unauthorized(
            "ring threshold cannot be met while excluding the accused node".to_string(),
        ));
    }
    for node_key in [&envelope.reporter_node_key, &envelope.accused_node_key] {
        if !ring.peer_node_keys.iter().any(|member| member == node_key) {
            return Err(ReportingError::Unauthorized(format!(
                "node {node_key} is not in the report ring"
            )));
        }
    }
    Ok(())
}

async fn validate_node_routes(
    envelope: &ReportEnvelope,
    context: &ReportValidationContext,
    _ring: &RingPayload,
) -> Result<()> {
    let accused_info = read_node_info(&context.bulletin, &envelope.accused_node_key).await?;
    if accused_info.peer_id != envelope.accused_peer_id {
        return Err(ReportingError::Unauthorized(
            "accused peer ID no longer matches NodeInfo".to_string(),
        ));
    }

    let reporter_info = read_node_info(&context.bulletin, &envelope.reporter_node_key).await?;
    let reporter_peer_hex = context
        .requester_peer_id
        .as_ref()
        .map(|requester| hex::encode(requester.as_bytes()))
        .unwrap_or_else(|| hex::encode(context.network.local_peer_id().as_bytes()));
    if extract_node_part(&reporter_info.peer_id) != reporter_peer_hex {
        return Err(ReportingError::Unauthorized(
            "report coordinator peer does not match reporter NodeInfo".to_string(),
        ));
    }
    Ok(())
}

async fn read_node_info(
    bulletin: &Arc<dyn Bulletin + Send + Sync>,
    node_key: &str,
) -> Result<NodeInfo> {
    let post = bulletin
        .read(node_key.to_string(), BulletinKind::NodeInfo)
        .await
        .map_err(|error| ReportingError::Bulletin(error.to_string()))?;
    NodeInfo::try_from(post).map_err(|error| ReportingError::InvalidReport(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reporting::types::{
        NodeOfflineV1, OfflineFailureStage, REPORT_DOMAIN, REPORT_FRAMEWORK_VERSION,
        REPORT_TTL_SECS,
    };
    use bulletin::r#trait::UpgradeInfo;

    fn ring_fixture(threshold: u32) -> RingPayload {
        RingPayload {
            ring_pk: "pk".to_string(),
            peer_node_keys: vec![
                "reporter".to_string(),
                "accused".to_string(),
                "validator".to_string(),
            ],
            threshold,
            pss_interval: 86_400,
            upgrade_info: UpgradeInfo {
                current_version: 0,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn envelope(ring: &RingPayload) -> ReportEnvelope {
        ReportEnvelope {
            domain: REPORT_DOMAIN.to_string(),
            framework_version: REPORT_FRAMEWORK_VERSION,
            report_type: NODE_OFFLINE_REPORT_TYPE.to_string(),
            report_version: NODE_OFFLINE_REPORT_VERSION,
            chain_id: "chain".to_string(),
            ring_id: "ring".to_string(),
            ring_pk: ring.ring_pk.clone(),
            ring_state_sha256: ring_state_sha256(ring),
            reporter_node_key: "reporter".to_string(),
            accused_node_key: "accused".to_string(),
            accused_peer_id: "aa".repeat(32),
            observed_at: 100,
            expires_at: 100 + REPORT_TTL_SECS,
            payload: NodeOfflineV1 {
                origin_protocol: "pre".to_string(),
                origin_protocol_version: 0,
                failure_stage: OfflineFailureStage::OpenStream,
            }
            .canonical_bytes(),
        }
    }

    #[test]
    fn rejects_threshold_one() {
        let ring = ring_fixture(1);
        let error = validate_ring_and_membership(&envelope(&ring), &ring).unwrap_err();
        assert!(error.to_string().contains("threshold >= 2"));
    }

    #[test]
    fn rejects_threshold_that_needs_accused() {
        let ring = ring_fixture(3);
        let error = validate_ring_and_membership(&envelope(&ring), &ring).unwrap_err();
        assert!(error.to_string().contains("excluding the accused"));
    }

    #[test]
    fn rejects_pending_reshare_and_stale_digest() {
        let mut ring = ring_fixture(2);
        let report = envelope(&ring);
        ring.new_threshold = Some(2);
        assert!(validate_ring_and_membership(&report, &ring).is_err());

        let ring = ring_fixture(2);
        let mut report = envelope(&ring);
        report.ring_state_sha256 = "00".repeat(32);
        assert!(validate_ring_and_membership(&report, &ring).is_err());
    }

    #[test]
    fn accepts_valid_report_shape_against_ring() {
        let ring = ring_fixture(2);
        validate_ring_and_membership(&envelope(&ring), &ring).unwrap();
    }

    #[test]
    fn rejects_unknown_report_type() {
        let registry = ReportRegistry::with_defaults();
        assert!(matches!(
            registry.handler_for("future_fault", 1),
            Err(ReportingError::UnsupportedReportType { .. })
        ));
    }
}
