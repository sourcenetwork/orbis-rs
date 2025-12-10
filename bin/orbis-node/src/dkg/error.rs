use thiserror::Error;

/// Crypto-related errors
#[derive(Error, Debug)]
pub enum ServerError {
    #[error("Dkg error: {0}")]
    DKGError(String),
}

/// Result type for network operations
pub type Result<T> = std::result::Result<T, ServerError>;
