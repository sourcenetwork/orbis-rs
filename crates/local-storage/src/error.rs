use thiserror::Error;

/// LocalStorage related errors
#[derive(Error, Debug)]
pub enum LocalStorageError {
    #[error("Posion Mutex error: {0}")]
    PoisonError(String),
    #[error("Encryption Error")]
    EncryptionError,
    #[error("Decryption Error")]
    DecryptionError,
    #[error("Item not found")]
    NotFound,
    #[error("Courrupted Data")]
    CorruptData,
    #[error("Unique DB Error: {0}")]
    UniqueDBError(String),
    #[error("Invalid password")]
    InvalidPassword,
    #[error("Key derivation failed: {0}")]
    KeyDerivationError(String),
}

/// Result type for local storage operations
pub type Result<T> = std::result::Result<T, LocalStorageError>;
