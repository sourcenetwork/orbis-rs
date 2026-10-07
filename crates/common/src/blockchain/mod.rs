//! Shared Orbis wire types, object IDs, and node message signatures.
//!
//! The default `cosmos` feature also provides `ChainConfig`, `VeraClient`,
//! `TxSigner`, and Cosmos SDK / CometBFT queries, transactions, and subscriptions.
//! Disable default features to use the shared encodings without chain transport.

pub mod acp;
pub mod bank;
pub mod bulletin;
#[cfg(feature = "cosmos")]
pub mod cosmos;
mod error;
mod node_signing;
pub mod orbis;

#[cfg(feature = "cosmos")]
pub use cosmos::*;
pub use error::{BlockchainError, Result};
pub use node_signing::{sign_node_message_with_hex_key, verify_node_message};

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
