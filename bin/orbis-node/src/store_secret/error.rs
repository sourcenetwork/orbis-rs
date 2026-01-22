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
}

/// Result type for StoreSecret operations
pub type Result<T> = std::result::Result<T, StoreSecretError>;

/// Convert StoreSecretError to tonic::Status for gRPC responses
impl From<StoreSecretError> for tonic::Status {
    fn from(error: StoreSecretError) -> Self {
        match &error {
            StoreSecretError::Unauthorized(_) => tonic::Status::unauthenticated(error.to_string()),
            StoreSecretError::InvalidInput(_) | StoreSecretError::Validation(_) => {
                tonic::Status::invalid_argument(error.to_string())
            }
            StoreSecretError::RingNotFound(_) => tonic::Status::not_found(error.to_string()),
            StoreSecretError::Storage(_)
            | StoreSecretError::Serialization(_)
            | StoreSecretError::Deserialization(_) => {
                metrics::record_store_secret_failed();
                tonic::Status::internal(error.to_string())
            }
        }
    }
}
