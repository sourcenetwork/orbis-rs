use thiserror::Error;

/// LocalStorage related errors
#[derive(Error, Debug)]
pub enum AuthZError {
    #[error("Authentication failure")]
    Authentication,
}

/// Result type for local storage operations
pub type Result<T> = std::result::Result<T, AuthZError>;
