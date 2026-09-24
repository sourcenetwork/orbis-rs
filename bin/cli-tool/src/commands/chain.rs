//! Shared chain-client construction and transaction-result helpers.
//!
//! Every chain-administration command (`admin`) and several bulletin commands
//! (`bulletin`) need a configured chain client, and most administration commands
//! need to turn a broadcast result into an error when the transaction itself failed
//! on-chain (a non-zero `code` — a distinct failure mode from the RPC call itself
//! erroring). Centralized here so each command only states what it wants to do.

use anyhow::{anyhow, Result};
use common::blockchain::{BroadcastResult, ChainConfig, ChainConfigBuilder, TxSigner, VeraClient};

/// Builds a `ChainConfigBuilder` from a resolved `ChainConfig`, for the bulletin
/// client constructors (`VeraBulletin::new`/`with_signer`), which take a builder
/// rather than a `ChainConfig` directly.
pub(crate) fn chain_config_builder(config: &ChainConfig) -> ChainConfigBuilder {
    ChainConfigBuilder::default()
        .chain_id(Some(config.chain_id.clone()))
        .rpc_url(Some(config.rpc_url.clone()))
        .rest_url(Some(config.rest_url.clone()))
        .grpc_url(Some(config.grpc_url.clone()))
        .account_prefix(Some(config.account_prefix.clone()))
        .default_gas_limit(Some(config.default_gas_limit))
        .gas_price(Some(config.gas_price.clone()))
        .gas_multiplier(Some(config.gas_multiplier))
        .allow_insecure_rpc(Some(config.allow_insecure_rpc))
}

/// A read-only chain client, for commands that only query on-chain state.
pub(crate) async fn vera_client(config: ChainConfig) -> Result<VeraClient> {
    VeraClient::new(config)
        .await
        .map_err(|e| anyhow!("Failed to create client: {}", e))
}

/// Builds a `TxSigner` from a hex-encoded signing key, for commands that need
/// a signer standalone rather than wrapped in a `VeraClient` (e.g. to pass to
/// `VeraBulletin::with_signer`, or to derive a signer's public key/DID).
pub(crate) fn tx_signer(signing_key_hex: &str, config: ChainConfig) -> Result<TxSigner> {
    TxSigner::from_hex_key(signing_key_hex, config)
        .map_err(|e| anyhow!("Failed to create signer: {}", e))
}

/// A chain client signed with `signing_key_hex`, for commands that submit a
/// transaction.
pub(crate) async fn signed_vera_client(
    config: ChainConfig,
    signing_key_hex: &str,
) -> Result<VeraClient> {
    let signer = tx_signer(signing_key_hex, config.clone())?;
    VeraClient::with_signer(config, signer)
        .await
        .map_err(|e| anyhow!("Failed to create Vera client: {}", e))
}

/// Turns a broadcast result into an error carrying its code and log when the
/// transaction failed on-chain (`code != 0`) — the RPC call itself having
/// succeeded says nothing about whether the chain accepted the transaction.
pub(crate) fn ensure_tx_success(action: &str, result: &BroadcastResult) -> Result<()> {
    if result.code != 0 {
        return Err(anyhow!("{action}: code {} {}", result.code, result.log));
    }
    Ok(())
}
