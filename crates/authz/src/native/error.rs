//! Errors from certified native authorization and its request boundaries.

use common::blockchain::native::DeploymentTrustError;
use vera_client::ClientError;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid deployment root or freshness bound")]
    InvalidConfiguration,
    #[error(transparent)]
    DeploymentTrust(#[from] DeploymentTrustError),
    #[error("system clock is before the Unix epoch: {0}")]
    Clock(#[source] std::time::SystemTimeError),
    #[error("authorization revision regressed")]
    RevisionRegressed,
    #[error("authorization evidence is stale or from the future")]
    StaleEvidence,
    #[error("authorization request exceeds byte limit")]
    RequestTooLarge,
    #[error("failed to decode the authorization request: {0}")]
    RequestDecode(#[source] serde_json::Error),
    #[error("invalid authorization window")]
    InvalidWindow,
    #[error("timestamp and validity window must be provided together")]
    IncompleteWindow,
    #[error("request timestamp is outside its validity window")]
    RequestOutsideWindow,
    #[error("invalid authorization subject: {0}")]
    Subject(#[source] vera_identity::Error),
    #[error("failed to verify current access: {0}")]
    VerifyCurrentAccess(#[source] ClientError),
    #[error("failed to capture current evidence: {0}")]
    CaptureEvidence(#[source] ClientError),
    #[error("failed to verify captured evidence: {0}")]
    VerifyEvidence(#[source] ClientError),
    #[error("captured evidence exceeds byte limit")]
    EvidenceTooLarge,
    #[error("failed to decode captured evidence: {0}")]
    EvidenceDecode(#[source] serde_json::Error),
    #[error("failed to encode captured evidence: {0}")]
    EvidenceEncode(#[source] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        error::Error as _,
        time::{Duration, UNIX_EPOCH},
    };

    #[test]
    fn native_errors_preserve_concrete_sources_through_the_shared_boundary() {
        let error = crate::error::AuthZError::from(Error::VerifyCurrentAccess(
            ClientError::ClientCapacityExhausted,
        ));
        let client = error
            .source()
            .unwrap()
            .downcast_ref::<ClientError>()
            .unwrap();
        assert!(matches!(client, ClientError::ClientCapacityExhausted));

        let source = UNIX_EPOCH
            .duration_since(UNIX_EPOCH + Duration::from_secs(1))
            .unwrap_err();
        let error = Error::Clock(source);
        assert!(error.source().unwrap().is::<std::time::SystemTimeError>());
    }
}
