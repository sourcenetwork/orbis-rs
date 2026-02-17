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

    /// Safety buffer multiplier (e.g., 1.2 for 20% extra)
    pub gas_multiplier: f64,
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
            default_gas_limit: 300_000,
            gas_price: GasPrice::default(),
            gas_multiplier: 1.2,
        }
    }

    /// Convert this config into a builder with all fields pre-populated.
    pub fn to_builder(&self) -> ChainConfigBuilder {
        ChainConfigBuilder {
            chain_id: Some(self.chain_id.clone()),
            rpc_url: Some(self.rpc_url.clone()),
            rest_url: Some(self.rest_url.clone()),
            grpc_url: Some(self.grpc_url.clone()),
            account_prefix: Some(self.account_prefix.clone()),
            default_gas_limit: Some(self.default_gas_limit),
            gas_price: Some(self.gas_price.clone()),
            gas_multiplier: Some(self.gas_multiplier),
        }
    }

    /// Calculate fee from gas limit.
    pub fn calculate_fee(&self, gas_limit: u64) -> u64 {
        ((gas_limit as f64) * self.gas_price.amount).ceil() as u64
    }
}

/// Builder for ChainConfig.
#[derive(Debug, Default, Clone)]
pub struct ChainConfigBuilder {
    pub chain_id: Option<String>,
    pub rpc_url: Option<String>,
    pub rest_url: Option<String>,
    pub grpc_url: Option<String>,
    pub account_prefix: Option<String>,
    pub default_gas_limit: Option<u64>,
    pub gas_price: Option<GasPrice>,
    pub gas_multiplier: Option<f64>,
}

impl ChainConfigBuilder {
    pub fn chain_id(mut self, chain_id: Option<String>) -> Self {
        self.chain_id = chain_id;
        self
    }

    pub fn rpc_url(mut self, rpc_url: Option<String>) -> Self {
        self.rpc_url = rpc_url;
        self
    }

    pub fn rest_url(mut self, rest_url: Option<String>) -> Self {
        self.rest_url = rest_url;
        self
    }

    pub fn grpc_url(mut self, grpc_url: Option<String>) -> Self {
        self.grpc_url = grpc_url;
        self
    }

    pub fn account_prefix(mut self, prefix: Option<String>) -> Self {
        self.account_prefix = prefix;
        self
    }

    pub fn default_gas_limit(mut self, gas_limit: Option<u64>) -> Self {
        self.default_gas_limit = gas_limit;
        self
    }

    pub fn gas_price(mut self, gas_price: Option<GasPrice>) -> Self {
        self.gas_price = gas_price;
        self
    }

    pub fn denom(mut self, denom: Option<String>) -> Self {
        if let Some(denom) = denom {
            self.gas_price.get_or_insert_with(GasPrice::default).denom = denom;
        }
        self
    }

    pub fn gas_multiplier(mut self, gas_multiplier: Option<f64>) -> Self {
        self.gas_multiplier = gas_multiplier;
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
            gas_multiplier: self.gas_multiplier.unwrap_or(local.gas_multiplier),
        }
    }
}
