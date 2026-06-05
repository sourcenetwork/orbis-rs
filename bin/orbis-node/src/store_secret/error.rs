use crate::error::{GrpcErrorClassification, GrpcServiceError};
use crate::metrics;
use thiserror::Error;

/// StoreSecret related errors
#[derive(Error, Debug)]
pub enum StoreSecretError {
    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Storage error: {0}")]
    Storage(String),

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Deserialization error: {0}")]
    Deserialization(String),

    #[error("Ring not found: {0}")]
    RingNotFound(String),

    #[error("Signing error: {0}")]
    Signing(String),

    #[error("{0}")]
    SystemTime(String),
}

/// Result type for StoreSecret operations
pub type Result<T> = std::result::Result<T, StoreSecretError>;

impl GrpcServiceError for StoreSecretError {
    const SERVICE: &'static str = "store_secret";

    fn classification(&self) -> GrpcErrorClassification {
        use tonic::Code;
        use tracing::Level;

        match self {
            StoreSecretError::Unauthorized(_) => {
                GrpcErrorClassification::new(Code::Unauthenticated, Level::TRACE, false)
            }
            StoreSecretError::InvalidInput(_) | StoreSecretError::Validation(_) => {
                GrpcErrorClassification::new(Code::InvalidArgument, Level::TRACE, false)
            }
            StoreSecretError::RingNotFound(_) => {
                GrpcErrorClassification::new(Code::NotFound, Level::TRACE, false)
            }
            StoreSecretError::SystemTime(_) => {
                GrpcErrorClassification::new(Code::Internal, Level::ERROR, false)
            }
            StoreSecretError::Storage(_)
            | StoreSecretError::Serialization(_)
            | StoreSecretError::Deserialization(_)
            | StoreSecretError::Signing(_) => {
                GrpcErrorClassification::new(Code::Internal, Level::ERROR, true)
            }
        }
    }

    fn record_failure_metric(&self) {
        metrics::record_store_secret_failed();
    }
}

/// Convert StoreSecretError to tonic::Status for gRPC responses
impl From<StoreSecretError> for tonic::Status {
    fn from(error: StoreSecretError) -> Self {
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
    fn classifies_every_store_secret_error_variant() {
        let cases = vec![
            (
                StoreSecretError::Unauthorized("test".into()),
                Code::Unauthenticated,
                Level::TRACE,
                false,
            ),
            (
                StoreSecretError::InvalidInput("test".into()),
                Code::InvalidArgument,
                Level::TRACE,
                false,
            ),
            (
                StoreSecretError::Storage("test".into()),
                Code::Internal,
                Level::ERROR,
                true,
            ),
            (
                StoreSecretError::Validation("test".into()),
                Code::InvalidArgument,
                Level::TRACE,
                false,
            ),
            (
                StoreSecretError::Serialization("test".into()),
                Code::Internal,
                Level::ERROR,
                true,
            ),
            (
                StoreSecretError::Deserialization("test".into()),
                Code::Internal,
                Level::ERROR,
                true,
            ),
            (
                StoreSecretError::RingNotFound("test".into()),
                Code::NotFound,
                Level::TRACE,
                false,
            ),
            (
                StoreSecretError::Signing("test".into()),
                Code::Internal,
                Level::ERROR,
                true,
            ),
            (
                StoreSecretError::SystemTime("test".into()),
                Code::Internal,
                Level::ERROR,
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
    fn conversion_preserves_store_secret_error_message() {
        let error = StoreSecretError::SystemTime("Failed to get timestamp: clock error".into());
        let expected = error.to_string();
        let status = tonic::Status::from(error);

        assert_eq!(status.code(), Code::Internal);
        assert_eq!(status.message(), expected);
    }
}
