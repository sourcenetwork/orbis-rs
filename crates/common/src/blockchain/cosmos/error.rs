//! Cosmos transport and signing error conversions.

use crate::blockchain::BlockchainError;

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
