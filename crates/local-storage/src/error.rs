use thiserror::Error;

/// LocalStorage related errors
#[derive(Error, Debug)]
pub enum LocalStorageError {
    #[error("Posion Mutex error: {0}")]
    PosionError(String),
    #[error("Encryption Error")]
    EncryptionError,
    #[error("Decryption Error")]
    DecryptionError,
    #[error("Item not found")]
    NotFound,
    #[error("Courrupted Data")]
    CorruptData,
}

/// Result type for local storage operations
pub type Result<T> = std::result::Result<T, LocalStorageError>;
