//! Error types for blockchain operations.

use thiserror::Error;

/// Errors that can occur during blockchain operations.
#[derive(Error, Debug)]
pub enum BlockchainError {
    #[error("RPC error: {0}")]
    Rpc(String),

    #[error("REST API error: {0}")]
    Rest(String),

    #[error("Transaction error: {0}")]
    Transaction(String),

    #[error("Transaction failed with code {code}: {log}")]
    TxFailed { code: u32, log: String },

    #[error("Signing error: {0}")]
    Signing(String),

    #[error("Query error: {0}")]
    Query(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Account not found: {0}")]
    AccountNotFound(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Timeout: {0}")]
    Timeout(String),

    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
}

impl From<serde_json::Error> for BlockchainError {
    fn from(err: serde_json::Error) -> Self {
        BlockchainError::Serialization(err.to_string())
    }
}

impl From<tendermint_rpc::Error> for BlockchainError {
    fn from(err: tendermint_rpc::Error) -> Self {
        BlockchainError::Rpc(err.to_string())
    }
}

impl From<cosmrs::ErrorReport> for BlockchainError {
    fn from(err: cosmrs::ErrorReport) -> Self {
        BlockchainError::Signing(err.to_string())
    }
}

/// Result type for blockchain operations.
pub type Result<T> = std::result::Result<T, BlockchainError>;
