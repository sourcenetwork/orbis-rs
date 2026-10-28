//! Integration-test-only account funding against a local Vera/Cosmos devnet.
//!
//! Not part of the production bulletin path: `ensure_funded` tops up an
//! address from the devnet's well-known funded test account so a freshly
//! started node has gas to pay its own fees. Moved here (from `cli-tool`) so
//! both `cli-tool` and `bulletin`'s Vera backend can call it without `bulletin`
//! depending on `cli-tool`.

use super::{ChainConfig, TxSigner, VeraClient};
use crate::blockchain::{Result, TEST_ACCOUNT_HEX_KEY};

pub async fn fund_with_signer(
    address: String,
    config: ChainConfig,
    signing_key_hex: &str,
) -> Result<()> {
    fund_impl(address, config, signing_key_hex).await
}

pub async fn fund(address: String, config: ChainConfig) -> Result<()> {
    fund_impl(address, config, TEST_ACCOUNT_HEX_KEY).await
}

/// Ensure an integration account has at least `minimum` tokens without
/// submitting another transfer when the fixture funded it in genesis.
pub async fn ensure_funded(address: String, config: ChainConfig, minimum: u64) -> Result<()> {
    let client = VeraClient::new(config.clone()).await?;
    const BALANCE_MAX_ATTEMPTS: u32 = 30;
    const BALANCE_RETRY_DELAY: tokio::time::Duration = tokio::time::Duration::from_secs(1);

    for attempt in 1..=BALANCE_MAX_ATTEMPTS {
        match client.get_balance(&address, "uopen").await {
            Ok(balance) if balance >= minimum => return Ok(()),
            Ok(_) => return fund_impl(address, config, TEST_ACCOUNT_HEX_KEY).await,
            Err(error) if attempt < BALANCE_MAX_ATTEMPTS => {
                eprintln!(
                    "Balance query failed while waiting for the integration chain \
                     (attempt {attempt}/{BALANCE_MAX_ATTEMPTS}), retrying: {error}"
                );
                tokio::time::sleep(BALANCE_RETRY_DELAY).await;
            }
            Err(error) => return Err(error),
        }
    }

    unreachable!("the bounded balance-query loop always returns")
}

async fn fund_impl(address: String, config: ChainConfig, signing_key_hex: &str) -> Result<()> {
    println!("Funding address: {}", address);

    // Transfer a reasonable amount (e.g., 1000000 uopen = 1 OPEN)
    // This should be enough for multiple transactions
    let amount = 1_000_000u64;
    let denom = "uopen";

    println!("Transferring {} {} to {}", amount, denom, address);

    // Retry logic for timing issues (REST API might not be ready immediately)
    // and sequence mismatch issues (multiple nodes starting simultaneously)
    // This is dumb but fine for testing
    let max_retries = 15;
    let mut last_error = None;

    // Create the client (with signer) once
    let signer = TxSigner::from_hex_key(signing_key_hex, config.clone())?;
    let client = VeraClient::with_signer(config, signer).await?;

    for attempt in 1..=max_retries {
        match client.transfer(&address, amount, denom).await {
            Ok(result) => {
                println!(
                    "Transfer successful! Tx hash: {}, Height: {:?}",
                    result.tx_hash, result.height
                );
                return Ok(());
            }
            Err(e) => {
                let err_str = e.to_string();
                println!(
                    "Transfer attempt {}/{} failed: {}",
                    attempt, max_retries, err_str
                );
                last_error = Some(e);
                if attempt < max_retries {
                    // Use pseudo-random delay (1-4 seconds) to desynchronize competing nodes
                    // Based on current time nanos to add jitter between nodes
                    let nanos = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_nanos() as u64)
                        .unwrap_or(0);
                    let delay_ms = 1000 + (nanos % 3000);
                    println!("Retrying in {}ms...", delay_ms);
                    tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;
                }
            }
        }
    }

    Err(last_error.expect("each failed funding attempt records its error"))
}
