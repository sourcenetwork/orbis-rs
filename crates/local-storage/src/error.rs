use thiserror::Error;

/// LocalStorage related errors
#[derive(Error, Debug)]
pub enum LocalStorageError {
    #[error("Posion Mutex error: {0}")]
    PosionError(String),
}

/// Result type for local storage operations
pub type Result<T> = std::result::Result<T, LocalStorageError>;
