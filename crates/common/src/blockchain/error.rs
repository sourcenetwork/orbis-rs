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

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Timeout: {0}")]
    Timeout(String),

    #[error("Chain not available: {0}")]
    ChainNotAvailable(String),

    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("Parse Int: {0}")]
    ParseInt(#[from] std::num::ParseIntError),
}

impl From<serde_json::Error> for BlockchainError {
    fn from(err: serde_json::Error) -> Self {
        BlockchainError::Serialization(err.to_string())
    }
}

impl From<tendermint_rpc::Error> for BlockchainError {
    fn from(err: tendermint_rpc::Error) -> Self {
        // `tendermint_rpc::Error`'s `Display` for several variants (notably
        // `Http`) is a fixed literal like "HTTP error" — the actual
        // underlying failure (timeout, connection refused, DNS, TLS, etc.)
        // is only reachable by walking the `source()` chain, not `to_string()`,
        // which otherwise leaves every such failure indistinguishable.
        let mut detail = err.to_string();
        let mut source = std::error::Error::source(&err);
        while let Some(cause) = source {
            detail.push_str(": ");
            detail.push_str(&cause.to_string());
            source = cause.source();
        }
        BlockchainError::Rpc(detail)
    }
}

impl From<cosmrs::ErrorReport> for BlockchainError {
    fn from(err: cosmrs::ErrorReport) -> Self {
        BlockchainError::Signing(err.to_string())
    }
}

/// Result type for blockchain operations.
pub type Result<T> = std::result::Result<T, BlockchainError>;
