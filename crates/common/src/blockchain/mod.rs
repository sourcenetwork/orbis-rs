//! Blockchain client module for interacting with Vera (Cosmos SDK / Tendermint chain).
//!
//! This module provides:
//! - `ChainConfig` - Configuration for connecting to the chain
//! - `VeraClient` - Client for queries and transaction broadcasting
//! - `TxSigner` - Transaction signing using secp256k1
//! - `acp` - Access Control Policy module types and operations
//! - `bulletin` - Bulletin board module types and operations

pub mod acp;
pub mod bank;
pub mod bulletin;
mod client;
mod config;
mod error;
pub mod events;
pub mod orbis;
mod signer;

pub use client::{AccountInfo, BroadcastResult, VeraClient};
pub use config::{ChainConfig, ChainConfigBuilder, GasPrice};
pub use error::{BlockchainError, Result};
pub use signer::{sign_node_message_with_hex_key, verify_node_message, TxSigner};

#[cfg(test)]
pub mod tests;

// Known test key for the "test" account created in docker-compose-vera-test.yml
/// This corresponds to the mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
/// with Cosmos HD path m/44'/118'/0'/0/0
pub const TEST_ACCOUNT_HEX_KEY: &str =
    "c4a48e2fce1481cd3294b4490f6678090ea98d3d0e5cd984558ab0968741b104";

/// Compressed secp256k1 public key of `TEST_ACCOUNT_HEX_KEY`.
/// Used as `--node-controller-key` in Docker integration-test compose files so that
/// the test account can call `UpdateNodeInfo` on behalf of the nodes.
pub const TEST_ACCOUNT_PUBKEY_HEX: &str =
    "024f4e2ad99c34d60b9ba6283c9431a8418af8673212961f97a77b6377fcd05b62";
