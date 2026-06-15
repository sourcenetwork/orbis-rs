//! Sign (Threshold BLS Signing) related errors

use crate::error::{GrpcErrorClassification, GrpcServiceError};
use crate::metrics;
use thiserror::Error;

/// Sign (Threshold BLS Signing) related errors
#[derive(Error, Debug)]
pub enum SignError {
    /// Authentication/authorization error (e.g., sender identity mismatch)
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

    /// Ring/DKG session not found
    #[error("Ring not found: {0}")]
    RingNotFound(String),

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

    /// Nonce state error (FROST nonce management)
    #[error("Nonce state error: {0}")]
    NonceState(String),

    /// Protocol error (violations of protocol rules)
    #[error("Protocol error: {0}")]
    ProtocolError(String),

    /// Ring reshare is in progress or just completed; shares from different
    /// generations were mixed.  The client should retry shortly.
    #[error("Ring reshare in progress, try again shortly")]
    ReshareInProgress,

    /// Generic Sign error
    #[error("Sign error: {0}")]
    Generic(String),

    /// System time error
    #[error("System time error: {0}")]
    SystemTime(String),

    /// Failed to read the current timestamp for an incoming request
    #[error("{0}")]
    RequestTimestamp(String),

    /// Failed to load local ring state for the request
    #[error("{0}")]
    RingState(String),

    /// AuthZ error
    #[error("Authz error: {0}")]
    AuthZ(String),
}

/// Result type for Sign operations
pub type Result<T> = std::result::Result<T, SignError>;

impl From<std::time::SystemTimeError> for SignError {
    fn from(error: std::time::SystemTimeError) -> Self {
        Self::SystemTime(error.to_string())
    }
}

impl GrpcServiceError for SignError {
    const SERVICE: &'static str = "sign";

    fn classification(&self) -> GrpcErrorClassification {
        use tonic::Code;
        use tracing::Level;

        match self {
            SignError::Unauthorized(_) | SignError::AuthZ(_) => {
                GrpcErrorClassification::new(Code::Unauthenticated, Level::TRACE, false)
            }
            SignError::InvalidInput(_) => {
                GrpcErrorClassification::new(Code::InvalidArgument, Level::TRACE, false)
            }
            SignError::RingNotFound(_) => {
                GrpcErrorClassification::new(Code::NotFound, Level::TRACE, false)
            }
            SignError::ReshareInProgress => {
                GrpcErrorClassification::new(Code::Unavailable, Level::TRACE, true)
            }
            SignError::InsufficientShares { .. } => {
                GrpcErrorClassification::new(Code::FailedPrecondition, Level::WARN, true)
            }
            SignError::Timeout(_) => {
                GrpcErrorClassification::new(Code::DeadlineExceeded, Level::WARN, true)
            }
            SignError::NetworkConnection(_) => {
                GrpcErrorClassification::new(Code::Unavailable, Level::WARN, true)
            }
            SignError::VerificationFailed(_) => {
                GrpcErrorClassification::new(Code::InvalidArgument, Level::WARN, true)
            }
            SignError::ProtocolError(_) => {
                GrpcErrorClassification::new(Code::FailedPrecondition, Level::WARN, true)
            }
            SignError::NetworkCommunication(_) => {
                GrpcErrorClassification::new(Code::Internal, Level::WARN, true)
            }
            SignError::RequestTimestamp(_) | SignError::RingState(_) => {
                GrpcErrorClassification::new(Code::Internal, Level::ERROR, false)
            }
            SignError::Serialization(_)
            | SignError::Deserialization(_)
            | SignError::Crypto(_)
            | SignError::RecoveryFailed(_)
            | SignError::Storage(_)
            | SignError::InvalidState(_)
            | SignError::NonceState(_)
            | SignError::Generic(_)
            | SignError::SystemTime(_) => {
                GrpcErrorClassification::new(Code::Internal, Level::ERROR, true)
            }
        }
    }

    fn record_failure_metric(&self) {
        metrics::record_sign_request_failed();
    }
}

/// Convert SignError to tonic::Status for gRPC responses
impl From<SignError> for tonic::Status {
    fn from(error: SignError) -> Self {
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
    fn classifies_every_sign_error_variant() {
        let cases = vec![
            (
                SignError::Unauthorized("test".into()),
                Code::Unauthenticated,
                Level::TRACE,
                false,
            ),
            (
                SignError::Serialization("test".into()),
                Code::Internal,
                Level::ERROR,
                true,
            ),
            (
                SignError::Deserialization("test".into()),
                Code::Internal,
                Level::ERROR,
                true,
            ),
            (
                SignError::NetworkConnection("test".into()),
                Code::Unavailable,
                Level::WARN,
                true,
            ),
            (
                SignError::NetworkCommunication("test".into()),
                Code::Internal,
                Level::WARN,
                true,
            ),
            (
                SignError::Crypto("test".into()),
                Code::Internal,
                Level::ERROR,
                true,
            ),
            (
                SignError::VerificationFailed("test".into()),
                Code::InvalidArgument,
                Level::WARN,
                true,
            ),
            (
                SignError::RecoveryFailed("test".into()),
                Code::Internal,
                Level::ERROR,
                true,
            ),
            (
                SignError::Storage("test".into()),
                Code::Internal,
                Level::ERROR,
                true,
            ),
            (
                SignError::RingNotFound("test".into()),
                Code::NotFound,
                Level::TRACE,
                false,
            ),
            (
                SignError::InsufficientShares { got: 1, need: 2 },
                Code::FailedPrecondition,
                Level::WARN,
                true,
            ),
            (
                SignError::Timeout("test".into()),
                Code::DeadlineExceeded,
                Level::WARN,
                true,
            ),
            (
                SignError::InvalidInput("test".into()),
                Code::InvalidArgument,
                Level::TRACE,
                false,
            ),
            (
                SignError::InvalidState("test".into()),
                Code::Internal,
                Level::ERROR,
                true,
            ),
            (
                SignError::NonceState("test".into()),
                Code::Internal,
                Level::ERROR,
                true,
            ),
            (
                SignError::ProtocolError("test".into()),
                Code::FailedPrecondition,
                Level::WARN,
                true,
            ),
            (
                SignError::ReshareInProgress,
                Code::Unavailable,
                Level::TRACE,
                true,
            ),
            (
                SignError::Generic("test".into()),
                Code::Internal,
                Level::ERROR,
                true,
            ),
            (
                SignError::SystemTime("test".into()),
                Code::Internal,
                Level::ERROR,
                true,
            ),
            (
                SignError::RequestTimestamp("test".into()),
                Code::Internal,
                Level::ERROR,
                false,
            ),
            (
                SignError::RingState("test".into()),
                Code::Internal,
                Level::ERROR,
                false,
            ),
            (
                SignError::AuthZ("test".into()),
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
    fn conversion_preserves_sign_error_message() {
        let error = SignError::RequestTimestamp("Failed to get timestamp: clock error".into());
        let expected = error.to_string();
        let status = tonic::Status::from(error);

        assert_eq!(status.code(), Code::Internal);
        assert_eq!(status.message(), expected);
    }
}
