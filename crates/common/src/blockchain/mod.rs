//! Blockchain client module for interacting with SourceHub (Cosmos SDK / Tendermint chain).
//!
//! This module provides:
//! - `ChainConfig` - Configuration for connecting to the chain
//! - `SourceHubClient` - Client for queries and transaction broadcasting
//! - `TxSigner` - Transaction signing using secp256k1
//! - `acp` - Access Control Policy module types and operations
//! - `bulletin` - Bulletin board module types and operations

pub mod acp;
pub mod bank;
pub mod bulletin;
mod client;
mod config;
mod error;
mod signer;

pub use client::{AccountInfo, BroadcastResult, SourceHubClient};
pub use config::{ChainConfig, ChainConfigBuilder, GasPrice};
pub use error::{BlockchainError, Result};
pub use signer::TxSigner;

#[cfg(test)]
pub mod tests;

// Known test key for the "test" account created in docker-compose-sourcehub-test.yml
/// This corresponds to the mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
/// with Cosmos HD path m/44'/118'/0'/0/0
pub const TEST_ACCOUNT_HEX_KEY: &str =
    "c4a48e2fce1481cd3294b4490f6678090ea98d3d0e5cd984558ab0968741b104";
