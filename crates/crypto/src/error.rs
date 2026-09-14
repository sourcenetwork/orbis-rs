use thiserror::Error;

/// Crypto-related errors
#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Dkg error: {0}")]
    DKGError(String),
    #[error("ElGamal error: {0}")]
    ElGamalError(String),
    #[error("Serialization error: {0}")]
    SerializationError(#[from] ark_serialize::SerializationError),
    // decaf377's constant-time fix pulled in arkworks 0.5 (see crates/crypto/Cargo.toml);
    // the bls12-381 path stays on 0.4, so decaf377 call sites need their own `From` arm.
    #[cfg(feature = "decaf377")]
    #[error("Serialization error: {0}")]
    SerializationError05(#[from] ark_serialize_05::SerializationError),
    #[error("Invalid Signature Share")]
    InvalidSignatureShare,
    #[error("Invalid Signature")]
    InvalidSignature,
    #[error("Signing error: {0}")]
    SigningError(String),
    #[error("Parsing Error: {0}")]
    ParseError(String),
    #[error("Commitment missing for node {0}")]
    CommitmentMissing(u32),
}

/// Result type for network operations
pub type Result<T> = std::result::Result<T, CryptoError>;
