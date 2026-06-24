use crate::reporting::error::{ReportingError, Result};
use crate::reporting::types::SignedReport;
use async_trait::async_trait;

#[async_trait]
pub trait ReportSink: Send + Sync {
    async fn submit(&self, report: SignedReport) -> Result<()>;
}

pub struct LogOnlyReportSink;

#[async_trait]
impl ReportSink for LogOnlyReportSink {
    async fn submit(&self, report: SignedReport) -> Result<()> {
        let signed_report_json = serde_json::to_string(&report)
            .map_err(|error| ReportingError::Serialization(error.to_string()))?;
        tracing::warn!(
            report_id = %report.report_id,
            report_type = %report.report.report_type,
            ring_id = %report.report.ring_id,
            reporter_node_key = %report.report.reporter_node_key,
            accused_node_key = %report.report.accused_node_key,
            accused_peer_id = %report.report.accused_peer_id,
            signature_scheme = %report.signature_scheme,
            signature = %report.signature,
            signed_report = %signed_report_json,
            "Threshold-signed MPC fault report produced; TODO submit this artifact to SourceHub"
        );
        Ok(())
    }
}
