//! Sign (Threshold BLS Signing) related errors

use crate::metrics;
use thiserror::Error;

/// Sign (Threshold BLS Signing) related errors
#[derive(Error, Debug)]
pub enum SignError {
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

    /// Protocol error (violations of protocol rules)
    #[error("Protocol error: {0}")]
    ProtocolError(String),

    /// Generic Sign error
    #[error("Sign error: {0}")]
    Generic(String),
}

/// Result type for Sign operations
pub type Result<T> = std::result::Result<T, SignError>;

/// Convert SignError to tonic::Status for gRPC responses
impl From<SignError> for tonic::Status {
    fn from(error: SignError) -> Self {
        use tonic::Code;
        match error {
            SignError::InvalidInput(_) => {
                tonic::Status::new(Code::InvalidArgument, error.to_string())
            }
            SignError::RingNotFound(_) => tonic::Status::new(Code::NotFound, error.to_string()),
            SignError::InsufficientShares { .. } => {
                metrics::record_sign_request_failed();
                tonic::Status::new(Code::FailedPrecondition, error.to_string())
            }
            SignError::Timeout(_) => {
                metrics::record_sign_request_failed();
                tonic::Status::new(Code::DeadlineExceeded, error.to_string())
            }
            SignError::NetworkConnection(_) => {
                metrics::record_sign_request_failed();
                tonic::Status::new(Code::Unavailable, error.to_string())
            }
            SignError::VerificationFailed(_) => {
                metrics::record_sign_request_failed();
                tonic::Status::new(Code::InvalidArgument, error.to_string())
            }
            _ => {
                metrics::record_sign_request_failed();
                tonic::Status::new(Code::Internal, error.to_string())
            }
        }
    }
}
