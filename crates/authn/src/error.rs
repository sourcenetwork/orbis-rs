use thiserror::Error;

/// Crypto-related errors
#[derive(Error, Debug)]
pub enum AuthNError {
    #[error("DID Error: {0}")]
    DidError(String),
    #[error("JWT Error: {0}")]
    JwtError(String),
}

/// Result type for network operations
pub type Result<T> = std::result::Result<T, AuthNError>;
