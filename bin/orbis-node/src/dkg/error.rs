use crate::metrics;
use thiserror::Error;

/// DKG (Distributed Key Generation) related errors
#[derive(Error, Debug)]
pub enum DkgError {
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

    /// Local storage error
    #[error("Local storage error: {0}")]
    Storage(String),

    /// Bulletin error
    #[error("Bulletin error: {0}")]
    Bulletin(String),

    /// DKG session not found
    #[error("DKG session not found: {0}")]
    SessionNotFound(String),

    /// DKG protocol error (violations of protocol rules)
    #[error("DKG protocol error: {0}")]
    ProtocolError(String),

    /// Attempted to create a session that already exists
    #[error("DKG session already exists")]
    SessionAlreadyExists,

    /// Node has reached the maximum number of concurrent DKG sessions
    #[error("DKG session limit reached: cannot accept new sessions")]
    MaxSessionsReached,

    /// Invalid input
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    /// Invalid state
    #[error("Invalid state: {0}")]
    InvalidState(String),

    /// Commitment verification failed
    #[error("Commitment verification failed: {0}")]
    CommitmentVerificationFailed(String),

    /// Share verification failed
    #[error("Share verification failed: {0}")]
    ShareVerificationFailed(String),

    /// Share arrived before the sender's Phase 1 commitment
    #[error("Commitment not yet received from node {0}")]
    CommitmentNotYetReceived(u32),

    /// Generic DKG error
    #[error("DKG error: {0}")]
    Generic(String),

    /// Hash conversion error
    #[error("Hash conversion error: {0}")]
    HashConversion(#[from] std::array::TryFromSliceError),

    /// Insufficient peers to reach threshold
    #[error(
        "Insufficient peers: sent to {successful} of {total} peers, need {threshold} for threshold"
    )]
    InsufficientPeers {
        successful: usize,
        total: usize,
        threshold: usize,
    },
}

/// Result type for DKG operations
pub type Result<T> = std::result::Result<T, DkgError>;

/// Convert DkgError to tonic::Status for gRPC responses
impl From<DkgError> for tonic::Status {
    fn from(error: DkgError) -> Self {
        use tonic::Code;
        match error {
            DkgError::Unauthorized(_) => {
                tonic::Status::new(Code::Unauthenticated, error.to_string())
            }
            DkgError::InvalidInput(_) => {
                tonic::Status::new(Code::InvalidArgument, error.to_string())
            }
            DkgError::SessionNotFound(_) => tonic::Status::new(Code::NotFound, error.to_string()),
            DkgError::MaxSessionsReached => {
                tonic::Status::new(Code::ResourceExhausted, error.to_string())
            }
            DkgError::ProtocolError(_) => {
                metrics::record_dkg_session_failed();
                tonic::Status::new(Code::FailedPrecondition, error.to_string())
            }
            DkgError::NetworkConnection(_) => {
                metrics::record_dkg_session_failed();
                tonic::Status::new(Code::Unavailable, error.to_string())
            }
            DkgError::CommitmentVerificationFailed(_) => {
                metrics::record_dkg_session_failed();
                tonic::Status::new(Code::InvalidArgument, error.to_string())
            }
            DkgError::ShareVerificationFailed(_) => {
                metrics::record_dkg_session_failed();
                tonic::Status::new(Code::InvalidArgument, error.to_string())
            }
            _ => {
                metrics::record_dkg_session_failed();
                tonic::Status::new(Code::Internal, error.to_string())
            }
        }
    }
}
