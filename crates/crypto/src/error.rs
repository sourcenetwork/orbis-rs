use thiserror::Error;

/// Crypto-related errors
#[derive(Error, Debug)]
pub enum CryptoError {}

/// Result type for network operations
pub type Result<T> = std::result::Result<T, CryptoError>;
