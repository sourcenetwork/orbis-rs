use thiserror::Error;

/// Bulletin related errors
#[derive(Error, Debug)]
pub enum BulletinError {
    #[error("Chain error: {0}")]
    ChainError(String),
}

/// Result type for local storage operations
pub type Result<T> = std::result::Result<T, BulletinError>;
