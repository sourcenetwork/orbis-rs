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

    /// Generic PRE error
    #[error("PRE error: {0}")]
    Generic(String),
}

/// Result type for PRE operations
pub type Result<T> = std::result::Result<T, PreError>;

/// Convert PreError to tonic::Status for gRPC responses
impl From<PreError> for tonic::Status {
    fn from(error: PreError) -> Self {
        use tonic::Code;
        match error {
            PreError::Unauthorized(_) => {
                tonic::Status::new(Code::Unauthenticated, error.to_string())
            }
            PreError::InvalidInput(_) => {
                tonic::Status::new(Code::InvalidArgument, error.to_string())
            }
            PreError::SessionNotFound(_) => tonic::Status::new(Code::NotFound, error.to_string()),
            PreError::InsufficientShares { .. } => {
                tonic::Status::new(Code::FailedPrecondition, error.to_string())
            }
            PreError::Timeout(_) => tonic::Status::new(Code::DeadlineExceeded, error.to_string()),
            PreError::NetworkConnection(_) => {
                tonic::Status::new(Code::Unavailable, error.to_string())
            }
            PreError::VerificationFailed(_) => {
                tonic::Status::new(Code::InvalidArgument, error.to_string())
            }
            _ => tonic::Status::new(Code::Internal, error.to_string()),
        }
    }
}
