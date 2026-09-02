use thiserror::Error;

/// LocalStorage related errors
#[derive(Error, Debug)]
pub enum LocalStorageError {
    #[error("Poison Mutex error: {0}")]
    PoisonError(String),
    #[error("Encryption Error")]
    EncryptionError,
    #[error("Decryption Error")]
    DecryptionError,
    #[error("Item not found")]
    NotFound,
    #[error("Corrupted Data")]
    CorruptData,
    #[error("Unique DB Error: {0}")]
    UniqueDBError(String),
    #[error("Invalid password")]
    InvalidPassword,
    #[error("Key derivation failed: {0}")]
    KeyDerivationError(String),
    /// The derived key does not match the commitment stored at database creation.
    /// Either the password is wrong or the salt / commitment slot was tampered.
    #[error("Key commitment mismatch (wrong password or tampered keying material)")]
    KeyCommitmentMismatch,
    /// A stored value could not be authenticated for the slot it was read from.
    /// Indicates a value was moved between slots or copied in from another
    /// database (e.g. under a shared password).
    #[error("Stored value failed slot authentication (moved or substituted)")]
    IntegrityCheckFailed,
}

/// Result type for local storage operations
pub type Result<T> = std::result::Result<T, LocalStorageError>;
