//! Chain configuration for SourceHub.

use serde::{Deserialize, Serialize};

/// Gas price configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GasPrice {
    /// Amount per gas unit (e.g., 0.025)
    pub amount: f64,
    /// Denomination (e.g., "usource")
    pub denom: String,
}

impl Default for GasPrice {
    fn default() -> Self {
        Self {
            amount: 0.025,
            denom: "uopen".to_string(),
        }
    }
}

/// Configuration for connecting to a SourceHub chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainConfig {
    /// Chain ID (e.g., "sourcehub-testnet")
    pub chain_id: String,

    /// Tendermint RPC URL (e.g., "http://localhost:26657")
    pub rpc_url: String,

    /// Cosmos REST API URL (e.g., "http://localhost:1317")
    pub rest_url: String,

    /// gRPC URL (e.g., "http://localhost:9090")
    pub grpc_url: String,

    /// Account address prefix (e.g., "source")
    pub account_prefix: String,

    /// Default gas limit for transactions
    pub default_gas_limit: u64,

    /// Gas price configuration
    pub gas_price: GasPrice,
}

impl ChainConfig {
    /// Create a new ChainConfig builder.
    pub fn builder() -> ChainConfigBuilder {
        ChainConfigBuilder::default()
    }

    /// Configuration for local development (default Docker setup).
    pub fn local() -> Self {
        Self {
            chain_id: "sourcehub-localnet".to_string(),
            rpc_url: "http://localhost:26657".to_string(),
            rest_url: "http://localhost:1317".to_string(),
            grpc_url: "http://localhost:9090".to_string(),
            account_prefix: "source".to_string(),
            default_gas_limit: 200_000,
            gas_price: GasPrice::default(),
        }
    }

    /// Calculate fee from gas limit.
    pub fn calculate_fee(&self, gas_limit: u64) -> u64 {
        ((gas_limit as f64) * self.gas_price.amount).ceil() as u64
    }
}

/// Builder for ChainConfig.
#[derive(Debug, Default)]
pub struct ChainConfigBuilder {
    chain_id: Option<String>,
    rpc_url: Option<String>,
    rest_url: Option<String>,
    grpc_url: Option<String>,
    account_prefix: Option<String>,
    default_gas_limit: Option<u64>,
    gas_price: Option<GasPrice>,
}

impl ChainConfigBuilder {
    pub fn chain_id(mut self, chain_id: impl Into<String>) -> Self {
        self.chain_id = Some(chain_id.into());
        self
    }

    pub fn rpc_url(mut self, rpc_url: impl Into<String>) -> Self {
        self.rpc_url = Some(rpc_url.into());
        self
    }

    pub fn rest_url(mut self, rest_url: impl Into<String>) -> Self {
        self.rest_url = Some(rest_url.into());
        self
    }

    pub fn grpc_url(mut self, grpc_url: impl Into<String>) -> Self {
        self.grpc_url = Some(grpc_url.into());
        self
    }

    pub fn account_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.account_prefix = Some(prefix.into());
        self
    }

    pub fn default_gas_limit(mut self, gas_limit: u64) -> Self {
        self.default_gas_limit = Some(gas_limit);
        self
    }

    pub fn gas_price(mut self, gas_price: GasPrice) -> Self {
        self.gas_price = Some(gas_price);
        self
    }

    /// Build the ChainConfig. Uses local defaults for any unset values.
    pub fn build(self) -> ChainConfig {
        let local = ChainConfig::local();
        ChainConfig {
            chain_id: self.chain_id.unwrap_or(local.chain_id),
            rpc_url: self.rpc_url.unwrap_or(local.rpc_url),
            rest_url: self.rest_url.unwrap_or(local.rest_url),
            grpc_url: self.grpc_url.unwrap_or(local.grpc_url),
            account_prefix: self.account_prefix.unwrap_or(local.account_prefix),
            default_gas_limit: self.default_gas_limit.unwrap_or(local.default_gas_limit),
            gas_price: self.gas_price.unwrap_or(local.gas_price),
        }
    }
}
