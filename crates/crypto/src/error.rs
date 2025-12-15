use thiserror::Error;

/// Crypto-related errors
#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Dkg error: {0}")]
    DKGError(String),
    #[error("Dkg error: {0}")]
    ElGamalError(String),
    #[error("Serilization error: {0}")]
    SerializationError(#[from] ark_serialize::SerializationError),
}

/// Result type for network operations
pub type Result<T> = std::result::Result<T, CryptoError>;
