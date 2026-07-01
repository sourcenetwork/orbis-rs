use crate::reporting::v0::error::{ReportingError, Result};
use crate::reporting::v0::types::SignedReport;
use bulletin::r#trait::{Bulletin, BulletinReportSubmission};

pub async fn submit(report: SignedReport, bulletin: &(dyn Bulletin + Send + Sync)) -> Result<()> {
    let signature_bytes = hex::decode(&report.signature)
        .map_err(|e| ReportingError::Signing(format!("hex decode signature: {e}")))?;
    bulletin
        .submit_report(BulletinReportSubmission {
            domain: report.report.domain,
            report_type: report.report.report_type,
            chain_id: report.report.chain_id,
            ring_id: report.report.ring_id,
            ring_pk: report.report.ring_pk,
            ring_state_sha256: report.report.ring_state_sha256,
            reporter_node_key: report.report.reporter_node_key,
            accused_node_key: report.report.accused_node_key,
            accused_peer_id: report.report.accused_peer_id,
            observed_at: report.report.observed_at,
            expires_at: report.report.expires_at,
            payload: report.report.payload,
            session_id: report.report.session_id,
            report_id: report.report_id,
            signature_scheme: report.signature_scheme,
            signature: signature_bytes,
        })
        .await
        .map_err(|e| ReportingError::Bulletin(e.to_string()))
}
