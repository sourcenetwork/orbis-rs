use thiserror::Error;

/// Authorization related errors
#[derive(Error, Debug)]
pub enum AuthZError {
    #[error("Authentication failure")]
    Authentication,

    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    #[error("Chain error: {0}")]
    ChainError(String),

    #[error("Not found: {0}")]
    NotFound(String),
}

/// Result type for authorization operations
pub type Result<T> = std::result::Result<T, AuthZError>;
