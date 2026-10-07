//! Errors from certified native authorization and its request boundaries.

use std::{num::ParseIntError, time::SystemTimeError};
use vera_client::ClientError;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid deployment root or freshness bound")]
    InvalidConfiguration,
    #[error("failed to read the deployment revision: {0}")]
    ReadDeployment(#[source] ClientError),
    #[error("consensus proof does not bind the configured deployment")]
    DeploymentMismatch,
    #[error("system clock is before the Unix epoch: {0}")]
    Clock(#[source] SystemTimeError),
    #[error("authorization revision regressed")]
    RevisionRegressed,
    #[error("failed to read an anchored revision: {0}")]
    ReadRevision(#[source] ClientError),
    #[error("anchor does not match certified revision")]
    AnchorMismatch,
    #[error("authorization evidence is stale or from the future")]
    StaleEvidence,
    #[error("oversized revision anchor")]
    AnchorTooLarge,
    #[error("invalid revision anchor")]
    InvalidAnchor,
    #[error("invalid revision anchor height: {0}")]
    AnchorHeight(#[source] ParseIntError),
    #[error("authorization request exceeds byte limit")]
    RequestTooLarge,
    #[error("failed to decode the authorization request: {0}")]
    RequestDecode(#[source] serde_json::Error),
    #[error("invalid authorization window")]
    InvalidWindow,
    #[error("timestamp and validity window must be provided together")]
    IncompleteWindow,
    #[error("invalid authorization subject: {0}")]
    Subject(#[source] vera_identity::Error),
    #[error("failed to verify current access: {0}")]
    VerifyCurrentAccess(#[source] ClientError),
    #[error("failed to verify anchored access: {0}")]
    VerifyAnchoredAccess(#[source] ClientError),
    #[error("failed to read the current authorization anchor: {0}")]
    ReadCurrentAnchor(#[source] ClientError),
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

        let source = "not-a-height".parse::<u64>().unwrap_err();
        let error = Error::AnchorHeight(source);
        assert!(error.source().unwrap().is::<ParseIntError>());

        let source = UNIX_EPOCH
            .duration_since(UNIX_EPOCH + Duration::from_secs(1))
            .unwrap_err();
        let error = Error::Clock(source);
        assert!(error.source().unwrap().is::<SystemTimeError>());
    }
}
