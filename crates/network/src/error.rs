use thiserror::Error;

/// Network-related errors
#[derive(Error, Debug)]
pub enum NetworkError {
    #[error("Connection error: {0}")]
    Connection(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Protocol error: {0}")]
    Protocol(String),

    #[error("Timeout: {0}")]
    Timeout(String),

    #[error("Peer not found: {0}")]
    PeerNotFound(String),

    #[error("Invalid address: {0}")]
    InvalidAddress(String),

    #[error("Invalid config: {0}")]
    InvalidConfig(String),
}

/// Result type for network operations
pub type Result<T> = std::result::Result<T, NetworkError>;
