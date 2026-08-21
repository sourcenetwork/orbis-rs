use crate::error::{GrpcErrorClassification, GrpcServiceError};
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

    /// Work belongs to an attempt that no longer owns the ceremony ID.
    #[error("stale DKG attempt: ceremony {ceremony_id}")]
    StaleAttempt { ceremony_id: u128 },

    /// DKG protocol error (violations of protocol rules)
    #[error("DKG protocol error: {0}")]
    ProtocolError(String),

    /// Attempted to create a session that already exists
    #[error("DKG session already exists")]
    SessionAlreadyExists,

    /// Node has reached the maximum number of concurrent DKG sessions
    #[error("DKG session limit reached: cannot accept new sessions")]
    MaxSessionsReached,

    /// A DKG ceremony cannot be created without participants.
    #[error("Invalid DKG participant count: {0}")]
    InvalidParticipantCount(usize),

    /// Node has reached the maximum number of persisted local rings
    #[error("local ring limit reached: node already manages {current} rings (max {max})")]
    MaxLocalRingsReached { current: usize, max: usize },

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

    /// Generic DKG error
    #[error("DKG error: {0}")]
    Generic(String),

    /// System time error
    #[error("{0}")]
    SystemTime(String),

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

    /// Multiple committee members failed the same preparation barrier
    /// (prepare/activate/begin). Carries every failure, not just the first,
    /// unlike a plain retry error from a single peer.
    #[error(
        "{barrier} barrier failed for {} of the committee: {}",
        failed_peers.len(),
        failed_peers
            .iter()
            .map(|(peer, reason)| format!("{peer}: {reason}"))
            .collect::<Vec<_>>()
            .join("; ")
    )]
    BarrierFailure {
        barrier: &'static str,
        failed_peers: Vec<(String, String)>,
    },
}

/// Result type for DKG operations
pub type Result<T> = std::result::Result<T, DkgError>;

impl GrpcServiceError for DkgError {
    const SERVICE: &'static str = "dkg";

    fn classification(&self) -> GrpcErrorClassification {
        use tonic::Code;
        use tracing::Level;

        match self {
            DkgError::Unauthorized(_) => {
                GrpcErrorClassification::new(Code::Unauthenticated, Level::TRACE, false)
            }
            DkgError::InvalidInput(_) | DkgError::InvalidParticipantCount(_) => {
                GrpcErrorClassification::new(Code::InvalidArgument, Level::TRACE, false)
            }
            DkgError::SessionNotFound(_) => {
                GrpcErrorClassification::new(Code::NotFound, Level::TRACE, false)
            }
            DkgError::StaleAttempt { .. } => {
                GrpcErrorClassification::new(Code::FailedPrecondition, Level::TRACE, false)
            }
            DkgError::SessionAlreadyExists => {
                GrpcErrorClassification::new(Code::AlreadyExists, Level::TRACE, false)
            }
            DkgError::MaxSessionsReached | DkgError::MaxLocalRingsReached { .. } => {
                GrpcErrorClassification::new(Code::ResourceExhausted, Level::WARN, false)
            }
            DkgError::ProtocolError(_) => {
                GrpcErrorClassification::new(Code::FailedPrecondition, Level::WARN, true)
            }
            DkgError::NetworkConnection(_) => {
                GrpcErrorClassification::new(Code::Unavailable, Level::WARN, true)
            }
            DkgError::CommitmentVerificationFailed(_) | DkgError::ShareVerificationFailed(_) => {
                GrpcErrorClassification::new(Code::InvalidArgument, Level::WARN, true)
            }
            DkgError::NetworkCommunication(_) | DkgError::InsufficientPeers { .. } => {
                GrpcErrorClassification::new(Code::Internal, Level::WARN, true)
            }
            DkgError::BarrierFailure { .. } => {
                GrpcErrorClassification::new(Code::Unavailable, Level::WARN, true)
            }
            DkgError::SystemTime(_) => {
                GrpcErrorClassification::new(Code::Internal, Level::ERROR, false)
            }
            DkgError::Serialization(_)
            | DkgError::Deserialization(_)
            | DkgError::Crypto(_)
            | DkgError::Storage(_)
            | DkgError::Bulletin(_)
            | DkgError::InvalidState(_)
            | DkgError::Generic(_)
            | DkgError::HashConversion(_) => {
                GrpcErrorClassification::new(Code::Internal, Level::ERROR, true)
            }
        }
    }
}

/// Convert DkgError to tonic::Status for gRPC responses
impl From<DkgError> for tonic::Status {
    fn from(error: DkgError) -> Self {
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
    fn classifies_every_dkg_error_variant() {
        let hash_error = <[u8; 2]>::try_from(&[1_u8][..]).unwrap_err();
        let cases = vec![
            (
                DkgError::Unauthorized("test".into()),
                Code::Unauthenticated,
                Level::TRACE,
                false,
            ),
            (
                DkgError::Serialization("test".into()),
                Code::Internal,
                Level::ERROR,
                true,
            ),
            (
                DkgError::Deserialization("test".into()),
                Code::Internal,
                Level::ERROR,
                true,
            ),
            (
                DkgError::NetworkConnection("test".into()),
                Code::Unavailable,
                Level::WARN,
                true,
            ),
            (
                DkgError::NetworkCommunication("test".into()),
                Code::Internal,
                Level::WARN,
                true,
            ),
            (
                DkgError::Crypto("test".into()),
                Code::Internal,
                Level::ERROR,
                true,
            ),
            (
                DkgError::Storage("test".into()),
                Code::Internal,
                Level::ERROR,
                true,
            ),
            (
                DkgError::Bulletin("test".into()),
                Code::Internal,
                Level::ERROR,
                true,
            ),
            (
                DkgError::SessionNotFound("test".into()),
                Code::NotFound,
                Level::TRACE,
                false,
            ),
            (
                DkgError::StaleAttempt { ceremony_id: 7 },
                Code::FailedPrecondition,
                Level::TRACE,
                false,
            ),
            (
                DkgError::ProtocolError("test".into()),
                Code::FailedPrecondition,
                Level::WARN,
                true,
            ),
            (
                DkgError::SessionAlreadyExists,
                Code::AlreadyExists,
                Level::TRACE,
                false,
            ),
            (
                DkgError::MaxSessionsReached,
                Code::ResourceExhausted,
                Level::WARN,
                false,
            ),
            (
                DkgError::InvalidParticipantCount(0),
                Code::InvalidArgument,
                Level::TRACE,
                false,
            ),
            (
                DkgError::MaxLocalRingsReached { current: 4, max: 4 },
                Code::ResourceExhausted,
                Level::WARN,
                false,
            ),
            (
                DkgError::InvalidInput("test".into()),
                Code::InvalidArgument,
                Level::TRACE,
                false,
            ),
            (
                DkgError::InvalidState("test".into()),
                Code::Internal,
                Level::ERROR,
                true,
            ),
            (
                DkgError::CommitmentVerificationFailed("test".into()),
                Code::InvalidArgument,
                Level::WARN,
                true,
            ),
            (
                DkgError::ShareVerificationFailed("test".into()),
                Code::InvalidArgument,
                Level::WARN,
                true,
            ),
            (
                DkgError::Generic("test".into()),
                Code::Internal,
                Level::ERROR,
                true,
            ),
            (
                DkgError::SystemTime("test".into()),
                Code::Internal,
                Level::ERROR,
                false,
            ),
            (
                DkgError::HashConversion(hash_error),
                Code::Internal,
                Level::ERROR,
                true,
            ),
            (
                DkgError::InsufficientPeers {
                    successful: 1,
                    total: 3,
                    threshold: 2,
                },
                Code::Internal,
                Level::WARN,
                true,
            ),
            (
                DkgError::BarrierFailure {
                    barrier: "prepare",
                    failed_peers: vec![("peer-a".into(), "timeout".into())],
                },
                Code::Unavailable,
                Level::WARN,
                true,
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
    fn conversion_preserves_dkg_error_message() {
        let error = DkgError::SystemTime("Failed to get timestamp: clock error".into());
        let expected = error.to_string();
        let status = tonic::Status::from(error);

        assert_eq!(status.code(), Code::Internal);
        assert_eq!(status.message(), expected);
    }
}
