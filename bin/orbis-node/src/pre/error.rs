use crate::error::{GrpcErrorClassification, GrpcServiceError};
use crate::metrics;
use thiserror::Error;

/// PRE (Proxy Re-Encryption) related errors
#[derive(Error, Debug)]
pub enum PreError {
    /// Authentication/authorization error
    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Deserialization error
    #[error("Deserialization error: {0}")]
    Deserialization(String),

    /// Network connection error
    #[error("Network connection error: {0}")]
    NetworkConnection(String),

    /// Network communication error
    #[error("Network communication error: {0}")]
    NetworkCommunication(String),

    /// Cryptographic operation error
    #[error("Cryptographic operation error: {0}")]
    Crypto(String),

    /// Verification failed
    #[error("Verification failed: {0}")]
    VerificationFailed(String),

    /// Recovery failed
    #[error("Recovery failed: {0}")]
    RecoveryFailed(String),

    /// Local storage error
    #[error("Local storage error: {0}")]
    Storage(String),

    /// DKG session not found
    #[error("DKG session not found: {0}")]
    SessionNotFound(String),

    /// Insufficient shares for recovery
    #[error("Insufficient shares: got {got}, need {need}")]
    InsufficientShares { got: usize, need: usize },

    /// Timeout waiting for responses
    #[error("Timeout waiting for responses: {0}")]
    Timeout(String),

    /// Invalid input
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    /// Invalid state
    #[error("Invalid state: {0}")]
    InvalidState(String),

    /// Protocol error (violations of protocol rules)
    #[error("Protocol error: {0}")]
    ProtocolError(String),

    /// Ring reshare is in progress or just completed; shares from different
    /// generations were mixed.  The client should retry shortly.
    #[error("Ring reshare in progress, try again shortly")]
    ReshareInProgress,

    /// Generic PRE error
    #[error("PRE error: {0}")]
    Generic(String),

    /// System time error
    #[error("{0}")]
    SystemTime(String),

    /// Failed to load local ring state for the request
    #[error("{0}")]
    RingState(String),

    /// AuthZ error
    #[error("Authz error: {0}")]
    AuthZ(String),
}

/// Result type for PRE operations
pub type Result<T> = std::result::Result<T, PreError>;

impl GrpcServiceError for PreError {
    const SERVICE: &'static str = "pre";

    fn classification(&self) -> GrpcErrorClassification {
        use tonic::Code;
        use tracing::Level;

        match self {
            PreError::Unauthorized(_) | PreError::AuthZ(_) => {
                GrpcErrorClassification::new(Code::Unauthenticated, Level::TRACE, false)
            }
            PreError::InvalidInput(_) => {
                GrpcErrorClassification::new(Code::InvalidArgument, Level::TRACE, false)
            }
            PreError::SessionNotFound(_) => {
                GrpcErrorClassification::new(Code::NotFound, Level::TRACE, false)
            }
            PreError::ReshareInProgress => {
                GrpcErrorClassification::new(Code::Unavailable, Level::TRACE, true)
            }
            PreError::InsufficientShares { .. } => {
                GrpcErrorClassification::new(Code::FailedPrecondition, Level::WARN, true)
            }
            PreError::Timeout(_) => {
                GrpcErrorClassification::new(Code::DeadlineExceeded, Level::WARN, true)
            }
            PreError::NetworkConnection(_) => {
                GrpcErrorClassification::new(Code::Unavailable, Level::WARN, true)
            }
            PreError::VerificationFailed(_) => {
                GrpcErrorClassification::new(Code::InvalidArgument, Level::WARN, true)
            }
            PreError::NetworkCommunication(_) | PreError::ProtocolError(_) => {
                GrpcErrorClassification::new(Code::Internal, Level::WARN, true)
            }
            PreError::SystemTime(_) => {
                GrpcErrorClassification::new(Code::Internal, Level::ERROR, false)
            }
            PreError::RingState(_) => {
                GrpcErrorClassification::new(Code::Internal, Level::ERROR, false)
            }
            PreError::Serialization(_)
            | PreError::Deserialization(_)
            | PreError::Crypto(_)
            | PreError::RecoveryFailed(_)
            | PreError::Storage(_)
            | PreError::InvalidState(_)
            | PreError::Generic(_) => {
                GrpcErrorClassification::new(Code::Internal, Level::ERROR, true)
            }
        }
    }

    fn record_failure_metric(&self) {
        metrics::record_pre_request_failed();
    }
}

/// Convert PreError to tonic::Status for gRPC responses
impl From<PreError> for tonic::Status {
    fn from(error: PreError) -> Self {
        error.into_status()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::GrpcServiceError;
    use tonic::Code;
    use tracing::Level;

    #[test]
    fn classifies_every_pre_error_variant() {
        let cases = vec![
            (
                PreError::Unauthorized("test".into()),
                Code::Unauthenticated,
                Level::TRACE,
                false,
            ),
            (
                PreError::Serialization("test".into()),
                Code::Internal,
                Level::ERROR,
                true,
            ),
            (
                PreError::Deserialization("test".into()),
                Code::Internal,
                Level::ERROR,
                true,
            ),
            (
                PreError::NetworkConnection("test".into()),
                Code::Unavailable,
                Level::WARN,
                true,
            ),
            (
                PreError::NetworkCommunication("test".into()),
                Code::Internal,
                Level::WARN,
                true,
            ),
            (
                PreError::Crypto("test".into()),
                Code::Internal,
                Level::ERROR,
                true,
            ),
            (
                PreError::VerificationFailed("test".into()),
                Code::InvalidArgument,
                Level::WARN,
                true,
            ),
            (
                PreError::RecoveryFailed("test".into()),
                Code::Internal,
                Level::ERROR,
                true,
            ),
            (
                PreError::Storage("test".into()),
                Code::Internal,
                Level::ERROR,
                true,
            ),
            (
                PreError::SessionNotFound("test".into()),
                Code::NotFound,
                Level::TRACE,
                false,
            ),
            (
                PreError::InsufficientShares { got: 1, need: 2 },
                Code::FailedPrecondition,
                Level::WARN,
                true,
            ),
            (
                PreError::Timeout("test".into()),
                Code::DeadlineExceeded,
                Level::WARN,
                true,
            ),
            (
                PreError::InvalidInput("test".into()),
                Code::InvalidArgument,
                Level::TRACE,
                false,
            ),
            (
                PreError::InvalidState("test".into()),
                Code::Internal,
                Level::ERROR,
                true,
            ),
            (
                PreError::ProtocolError("test".into()),
                Code::Internal,
                Level::WARN,
                true,
            ),
            (
                PreError::ReshareInProgress,
                Code::Unavailable,
                Level::TRACE,
                true,
            ),
            (
                PreError::Generic("test".into()),
                Code::Internal,
                Level::ERROR,
                true,
            ),
            (
                PreError::SystemTime("test".into()),
                Code::Internal,
                Level::ERROR,
                false,
            ),
            (
                PreError::RingState("test".into()),
                Code::Internal,
                Level::ERROR,
                false,
            ),
            (
                PreError::AuthZ("test".into()),
                Code::Unauthenticated,
                Level::TRACE,
                false,
            ),
        ];

        for (error, code, level, record_failure) in cases {
            let classification = error.classification();
            assert_eq!(classification.code, code, "{error}");
            assert_eq!(classification.level, level, "{error}");
            assert_eq!(classification.record_failure, record_failure, "{error}");
        }
    }

    #[test]
    fn conversion_preserves_pre_error_message() {
        let error = PreError::RingState("Failed to load ring polynomial state: missing".into());
        let expected = error.to_string();
        let status = tonic::Status::from(error);

        assert_eq!(status.code(), Code::Internal);
        assert_eq!(status.message(), expected);
    }
}
