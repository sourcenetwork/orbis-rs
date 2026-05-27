use thiserror::Error;

/// Bulletin related errors
#[derive(Error, Debug)]
pub enum BulletinError {
    #[error("Chain error: {0}")]
    ChainError(String),
    #[error("Parsing Error: {0}")]
    ParseError(String),
    #[error("Post not found: id={id}")]
    NotFound { id: String },
}

/// Result type for local storage operations
pub type Result<T> = std::result::Result<T, BulletinError>;
