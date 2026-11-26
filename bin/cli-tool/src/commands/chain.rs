//! Shared chain-client construction and transaction-result helpers.
//!
//! Chain-administration commands (`admin`) need a configured chain client,
//! and most of them need to turn a broadcast result into an error when the
//! transaction itself failed on-chain (a non-zero `code` — a distinct
//! failure mode from the RPC call itself erroring). Centralized here so
//! each command only states what it wants to do. (`bulletin`'s own
//! chain-client needs are met by `orbis-sdk` directly now, not this
//! module.)

use anyhow::{anyhow, Result};
use common::blockchain::{BroadcastResult, ChainConfig, TxSigner, VeraGoClient};

/// A read-only chain client, for commands that only query on-chain state.
pub(crate) async fn vera_client(config: ChainConfig) -> Result<VeraGoClient> {
    VeraGoClient::new(config)
        .await
        .map_err(|e| anyhow!("Failed to create client: {}", e))
}

/// Builds a `TxSigner` from a hex-encoded signing key, for commands that need
/// a signer standalone rather than wrapped in a `VeraGoClient` (e.g. to pass to
/// `VeraGoBulletin::with_signer`, or to derive a signer's public key/DID).
pub(crate) fn tx_signer(signing_key_hex: &str, config: ChainConfig) -> Result<TxSigner> {
    TxSigner::from_hex_key(signing_key_hex, config)
        .map_err(|e| anyhow!("Failed to create signer: {}", e))
}

/// A chain client signed with `signing_key_hex`, for commands that submit a
/// transaction.
pub(crate) async fn signed_vera_client(
    config: ChainConfig,
    signing_key_hex: &str,
) -> Result<VeraGoClient> {
    let signer = tx_signer(signing_key_hex, config.clone())?;
    VeraGoClient::with_signer(config, signer)
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
