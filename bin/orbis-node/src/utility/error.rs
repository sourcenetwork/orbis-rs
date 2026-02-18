use thiserror::Error;

/// Utility service related errors
#[derive(Error, Debug)]
pub enum UtilityError {
    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Ring not found: {0}")]
    RingNotFound(String),

    #[error("Deserialization error: {0}")]
    Deserialization(String),

    #[error("Crypto error: {0}")]
    Crypto(String),

    #[error("Signing error: {0}")]
    Signing(String),

    #[error("Unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

/// Convert UtilityError to tonic::Status for gRPC responses
impl From<UtilityError> for tonic::Status {
    fn from(error: UtilityError) -> Self {
        match &error {
            UtilityError::Unauthorized(_) => tonic::Status::unauthenticated(error.to_string()),
            UtilityError::RingNotFound(_) => tonic::Status::not_found(error.to_string()),
            UtilityError::Deserialization(_) => tonic::Status::invalid_argument(error.to_string()),
            UtilityError::UnsupportedAlgorithm(_) => {
                tonic::Status::invalid_argument(error.to_string())
            }
            UtilityError::Crypto(_) | UtilityError::Signing(_) | UtilityError::Internal(_) => {
                tonic::Status::internal(error.to_string())
            }
        }
    }
}
