use thiserror::Error;

/// Authentication and authorization errors
#[derive(Error, Debug)]
pub enum AuthNError {
    #[error("DID Error: {0}")]
    DidError(String),
    #[error("JWT Error: {0}")]
    JwtError(String),
    #[error("Unauthorized: {0}")]
    Unauthorized(String),
}

/// Result type for network operations
pub type Result<T> = std::result::Result<T, AuthNError>;
