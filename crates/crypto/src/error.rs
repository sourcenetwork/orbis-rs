use thiserror::Error;

/// Crypto-related errors
#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Dkg error: {0}")]
    DKGError(String),
    #[error("ElGamal error: {0}")]
    ElGamalError(String),
    #[error("Serilization error: {0}")]
    SerializationError(#[from] ark_serialize::SerializationError),
    #[error("Invalid Signature Share")]
    InvalidSignatureShare,
    #[error("Invalid Signature")]
    InvalidSignature,
    #[error("Signing error: {0}")]
    SigningError(String),
    #[error("Parsing Error: {0}")]
    ParseError(String),
}

/// Result type for network operations
pub type Result<T> = std::result::Result<T, CryptoError>;
