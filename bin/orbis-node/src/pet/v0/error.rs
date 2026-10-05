use crate::pre::v0::error::PreError;
use thiserror::Error;

/// PET (ownership-tag check) related errors.
///
/// Unlike `PreError`/`SignError`, this has no `GrpcServiceError`/`tonic::Status`
/// conversion: PET has no public-facing service (see `pet/README.md`). It
/// surfaces to callers only via `From<PetError> for PreError`, since the only
/// caller today is PRE's own pipeline.
#[derive(Error, Debug)]
pub enum PetError {
    /// ACP error resolving the audit target's owner relationship.
    #[error("ACP error: {0}")]
    Acp(String),

    /// The tag does not match the resolved audit target — a genuine PET
    /// check failure, not a protocol/transport error.
    #[error("PET check failed: tag does not match the audit target")]
    Mismatch,

    /// Serialization error.
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Deserialization error.
    #[error("Deserialization error: {0}")]
    Deserialization(String),

    /// Network connection error.
    #[error("Network connection error: {0}")]
    NetworkConnection(String),

    /// Network communication error.
    #[error("Network communication error: {0}")]
    NetworkCommunication(String),

    /// Cryptographic operation error.
    #[error("Cryptographic operation error: {0}")]
    Crypto(String),

    /// Insufficient threshold-check shares.
    #[error("Insufficient PET check shares: got {got}, need {need}")]
    InsufficientShares { got: usize, need: usize },

    /// Timeout waiting for responses.
    #[error("Timeout waiting for responses: {0}")]
    Timeout(String),

    /// Invalid input.
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    /// Invalid state.
    #[error("Invalid state: {0}")]
    InvalidState(String),

    /// Protocol error (violations of protocol rules).
    #[error("Protocol error: {0}")]
    ProtocolError(String),

    /// Local storage error.
    #[error("Local storage error: {0}")]
    Storage(String),
}

pub type Result<T> = std::result::Result<T, PetError>;

/// A PET-check failure surfaces as a PRE authorization/protocol failure —
/// PET has no client-facing identity of its own, so its errors are folded
/// into whichever protocol invoked it.
impl From<PetError> for PreError {
    fn from(error: PetError) -> Self {
        match error {
            PetError::Acp(msg) => PreError::AuthZ(msg),
            PetError::Mismatch => PreError::Unauthorized(
                "PET check failed: tag does not match the audit target".to_string(),
            ),
            PetError::Serialization(msg) => PreError::Serialization(msg),
            PetError::Deserialization(msg) => PreError::Deserialization(msg),
            PetError::NetworkConnection(msg) => PreError::NetworkConnection(msg),
            PetError::NetworkCommunication(msg) => PreError::NetworkCommunication(msg),
            PetError::Crypto(msg) => PreError::Crypto(msg),
            PetError::InsufficientShares { got, need } => {
                PreError::InsufficientShares { got, need }
            }
            PetError::Timeout(msg) => PreError::Timeout(msg),
            PetError::InvalidInput(msg) => PreError::InvalidInput(msg),
            PetError::InvalidState(msg) => PreError::InvalidState(msg),
            PetError::ProtocolError(msg) => PreError::ProtocolError(msg),
            PetError::Storage(msg) => PreError::Storage(msg),
        }
    }
}
