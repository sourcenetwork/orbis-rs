//! Vera blockchain client.

use crate::blockchain::{bank, BlockchainError, ChainConfig, Result, TxSigner};
use base64::Engine;
use cosmrs::Any;
use prost::Message;
use reqwest::Client as HttpClient;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::time::Duration;
use tendermint_rpc::{Client, HttpClient as TendermintClient, HttpClientUrl};
use tokio::sync::Mutex;
use tokio::time::sleep;

const RPC_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const RPC_POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(5);

// ============================================================================
// Transaction Polling Constants
// ============================================================================

/// Maximum number of attempts when polling for transaction confirmation.
/// Block time is typically 1-5 seconds, so 30 attempts gives 30 seconds of polling.
const TX_POLL_MAX_ATTEMPTS: u32 = 30;

/// Interval between transaction polling attempts.
const TX_POLL_INTERVAL: Duration = Duration::from_secs(1);

// ============================================================================
// ABCI Query Retry Constants
// ============================================================================

/// Maximum attempts for an ABCI query before giving up. Only transport-level
/// failures (e.g. a brief Docker/DNS blip between containers) are retried -
/// a response the chain actually returned (including "not found") is
/// authoritative and returned immediately.
const ABCI_QUERY_MAX_ATTEMPTS: u32 = 4;

/// Base delay between ABCI query retries, scaled linearly by attempt number.
const ABCI_QUERY_RETRY_BASE_DELAY: Duration = Duration::from_millis(250);

// ============================================================================
// REST Transport Retry Constants
// ============================================================================

/// Maximum attempts for a REST call's `send()` before giving up. Mirrors
/// `abci_query`'s retry treatment of the analogous RPC failure class: only
/// transport-level failures (connection refused/reset, brief Docker/DNS
/// blip between containers) are retried here — a response the server
/// actually returned, including a non-2xx status, is authoritative and
/// handled by the caller, not retried. Slightly more attempts and a longer
/// base delay than ABCI's since REST calls (gas simulation, account/balance
/// queries) have been the observed source of transient Docker-integration
/// flakiness.
const REST_TRANSPORT_MAX_ATTEMPTS: u32 = 5;

/// Base delay between REST transport retries, scaled linearly by attempt number.
const REST_TRANSPORT_RETRY_BASE_DELAY: Duration = Duration::from_millis(500);

// ============================================================================
// Gas Simulation Constants
// ============================================================================

/// Gas limit used for transaction simulation.
/// Set high to ensure simulation succeeds; actual tx uses simulated gas.
const SIMULATION_GAS_LIMIT: u64 = 10_000_000;

/// Account information from the chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountInfo {
    /// Bech32 address
    pub address: String,
    /// Account number (for signing)
    pub account_number: u64,
    /// Sequence number (for signing)
    pub sequence: u64,
}

/// Result of broadcasting a transaction.
#[derive(Debug, Clone)]
pub struct BroadcastResult {
    /// Transaction hash
    pub tx_hash: String,
    /// Block height (if committed)
    pub height: Option<u64>,
    /// Result code (0 = success)
    pub code: u32,
    /// Log message
    pub log: String,
    /// Raw data (if any)
    pub data: Option<Vec<u8>>,
}

/// Decode ABCI response data bytes.
///
/// tendermint-rpc 0.40 with newer CometBFT versions hands back the raw base64
/// string bytes rather than the decoded binary. Try base64 decoding first; if
/// the bytes are not valid base64 (i.e. they already are binary proto), return
/// them unchanged.
fn decode_abci_data(raw: Vec<u8>) -> Vec<u8> {
    if raw.iter().all(|b| b.is_ascii()) {
        if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(&raw) {
            return decoded;
        }
    }
    raw
}

/// Client for interacting with Vera.
pub struct VeraClient {
    config: ChainConfig,
    rpc_client: TendermintClient,
    http_client: HttpClient,
    signer: Option<TxSigner>,
    /// Lock to serialize transaction submission.
    /// Cosmos SDK requires txs to reach the mempool in nonce order.
    tx_lock: Mutex<()>,
}

impl VeraClient {
    /// Create a new client for queries only.
    pub async fn new(config: ChainConfig) -> Result<Self> {
        // Refuse a plaintext chain endpoint on an untrusted host: RPC/REST
        // responses (ACP verdicts, bulletin records) are trusted as-is, so a
        // tamperable channel to a host outside the operator's control is an
        // authorization risk. Override with `allow_insecure_rpc`.
        config.validate_endpoints()?;

        let rpc_url: HttpClientUrl = config
            .rpc_url
            .as_str()
            .try_into()
            .map_err(|e| BlockchainError::Config(format!("Invalid RPC URL: {}", e)))?;
        let rpc_http_client = tendermint_reqwest::Client::builder()
            .timeout(RPC_REQUEST_TIMEOUT)
            .pool_idle_timeout(RPC_POOL_IDLE_TIMEOUT)
            .build()
            .map_err(|e| {
                BlockchainError::Config(format!("Failed to create RPC HTTP client: {}", e))
            })?;
        let rpc_client = TendermintClient::builder(rpc_url)
            .client(rpc_http_client)
            .build()
            .map_err(|e| BlockchainError::Config(format!("Failed to create RPC client: {}", e)))?;

        let http_client = HttpClient::builder()
            .timeout(std::time::Duration::from_secs(30))
            .connect_timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|e| BlockchainError::Config(format!("Failed to create HTTP client: {}", e)))?;

        Ok(Self {
            config,
            rpc_client,
            http_client,
            signer: None,
            tx_lock: Mutex::new(()),
        })
    }

    /// Create a new client with signing capability.
    ///
    /// This fetches the current account info from the chain and initializes
    /// the signer's account number and nonce for in-memory transaction sequencing.
    ///
    /// Retries with exponential backoff if the chain is not yet available,
    /// waiting up to 15 minutes for the chain to become ready.
    pub async fn with_signer(config: ChainConfig, signer: TxSigner) -> Result<Self> {
        let client = Self::new(config).await?;
        let address = signer.address();

        // Retry config: wait up to 15 minutes for chain to be available
        let backoff_config = || backoff::ExponentialBackoff {
            max_elapsed_time: Some(std::time::Duration::from_secs(15 * 60)),
            initial_interval: std::time::Duration::from_secs(2),
            max_interval: std::time::Duration::from_secs(30),
            ..Default::default()
        };

        // Fetch account info with retry (waits for chain to be available)
        let fetch_account_info = || async {
            client.get_account(&address).await.map_err(|e| {
                let error_msg = e.to_string();
                eprintln!("Signer init: Failed to connect to chain: {}", error_msg);
                eprintln!("Signer init: Retrying connection...");
                backoff::Error::Transient {
                    err: BlockchainError::ChainNotAvailable(format!(
                        "Chain not available yet: {}",
                        error_msg
                    )),
                    retry_after: None,
                }
            })
        };

        let account_info = backoff::future::retry(backoff_config(), fetch_account_info)
            .await
            .map_err(|e| {
                BlockchainError::ChainNotAvailable(format!(
                    "Failed to connect to chain after retries: {}",
                    e
                ))
            })?;

        eprintln!(
            "Signer init: Connected to chain. Account number: {}, sequence: {}",
            account_info.account_number, account_info.sequence
        );

        // Initialize the signer with account info
        signer.set_account_number(account_info.account_number);
        signer.set_nonce(account_info.sequence);

        Ok(Self {
            config: client.config,
            rpc_client: client.rpc_client,
            http_client: client.http_client,
            signer: Some(signer),
            tx_lock: Mutex::new(()),
        })
    }

    /// Get the signer (if configured).
    pub fn signer(&self) -> Option<&TxSigner> {
        self.signer.as_ref()
    }

    /// Get the chain configuration.
    pub fn config(&self) -> &ChainConfig {
        &self.config
    }

    /// Resync the signer's nonce from the chain.
    ///
    /// Call this after a transaction fails due to a sequence mismatch to
    /// recover and continue sending transactions. This fetches the current
    /// sequence number from the chain and updates the signer's in-memory nonce.
    ///
    /// Returns the new nonce value, or an error if no signer is configured
    /// or the chain query fails.
    pub async fn resync_nonce(&self) -> Result<u64> {
        let signer = self
            .signer()
            .ok_or_else(|| BlockchainError::Signing("No signer configured".to_string()))?;
        // Match `resync_account`'s locking order: without it, this could race
        // an in-progress broadcast (which holds `tx_lock` across its own
        // read-sign-send-bump sequence) and overwrite the nonce with a stale
        // value read before that broadcast's own update lands, or have its
        // own update immediately clobbered by that broadcast's bump.
        let _guard = self.tx_lock.lock().await;
        self.resync_nonce_inner(signer).await
    }

    /// Resync both the signer's account number and nonce from the chain.
    ///
    /// `with_signer` fetches account info once at construction time. If the
    /// account did not exist yet at that point (a brand-new address with no
    /// prior transactions), the chain returns account_number 0 as a
    /// placeholder — but once something else (e.g. a funding transfer) creates
    /// the account, it gets a real, non-zero account_number. Unlike a sequence
    /// drift, `resync_nonce` alone can't recover from this: it only re-fetches
    /// sequence, so a signer constructed before the account existed keeps
    /// signing with the wrong account_number forever. Call this once after
    /// confirming the account now exists (e.g. after a balance-check retry
    /// loop succeeds) and before this signer's first outgoing transaction.
    ///
    /// Returns `(account_number, sequence)`, or an error if no signer is
    /// configured or the chain query fails.
    pub async fn resync_account(&self) -> Result<(u64, u64)> {
        let signer = self
            .signer()
            .ok_or_else(|| BlockchainError::Signing("No signer configured".to_string()))?;
        let _guard = self.tx_lock.lock().await;
        let account_info = self.get_account(&signer.address()).await?;
        signer.set_account_number(account_info.account_number);
        signer.set_nonce(account_info.sequence);
        Ok((account_info.account_number, account_info.sequence))
    }

    /// Resync nonce given an already-resolved signer reference. Used internally
    /// when the signer is already in scope to avoid a second borrow.
    async fn resync_nonce_inner(&self, signer: &TxSigner) -> Result<u64> {
        let account_info = self.get_account(&signer.address()).await?;
        signer.set_nonce(account_info.sequence);
        Ok(account_info.sequence)
    }

    /// Get account information for an address.
    /// Returns default values (account_number: 0, sequence: 0) if the account doesn't exist yet.
    pub async fn get_account(&self, address: &str) -> Result<AccountInfo> {
        let url = format!(
            "{}/cosmos/auth/v1beta1/accounts/{}",
            self.config.rest_url, address
        );

        match self.rest_get_optional::<AccountResponse>(&url).await? {
            Some(response) => {
                // Parse the account info from the response
                // Cosmos SDK returns different account types, we need to handle the base account
                let account = response.account;

                Ok(AccountInfo {
                    address: account.address,
                    account_number: account.account_number.parse()?,
                    sequence: account.sequence.parse()?,
                })
            }
            None => {
                // Account doesn't exist yet - return default values
                // In Cosmos SDK, new accounts start with account_number 0 and sequence 0
                Ok(AccountInfo {
                    address: address.to_string(),
                    account_number: 0,
                    sequence: 0,
                })
            }
        }
    }

    /// Get the balance for a specific address and denomination.
    ///
    /// # Arguments
    /// * `address` - The bech32 address to query
    /// * `denom` - The denomination to query (e.g., "uopen")
    ///
    /// # Returns
    /// The balance amount as u64, or 0 if the address has no balance for that denomination
    pub async fn get_balance(&self, address: &str, denom: &str) -> Result<u64> {
        let url = format!(
            "{}/cosmos/bank/v1beta1/balances/{}",
            self.config.rest_url, address
        );

        let response: BalanceResponse = self.rest_get(&url).await?;

        // Find the balance for the specified denomination
        let balance = response
            .balances
            .iter()
            .find(|coin| coin.denom == denom)
            .and_then(|coin| coin.amount.parse::<u64>().ok())
            .unwrap_or(0);

        Ok(balance)
    }

    /// Broadcast a protobuf-encoded message as a transaction.
    ///
    /// Uses the signer's in-memory nonce and increments it for the next transaction.
    /// Transactions are serialized to ensure they reach the mempool in nonce order.
    pub async fn broadcast_proto_msg<T: Message>(
        &self,
        type_url: &str,
        msg: &T,
    ) -> Result<BroadcastResult> {
        let signer = self
            .signer()
            .ok_or_else(|| BlockchainError::Signing("No signer configured".to_string()))?;

        // Encode message as protobuf (can do outside lock)
        let msg_bytes = msg.encode_to_vec();

        let any_msg = Any {
            type_url: type_url.to_string(),
            value: msg_bytes,
        };

        // Acquire lock to ensure txs reach mempool in nonce order
        let _guard = self.tx_lock.lock().await;

        // Get account number and atomically fetch-and-increment the nonce
        let account_number = signer.account_number();
        let sequence = signer.fetch_and_increment_nonce();

        // Sign the transaction
        let tx_bytes = signer.sign_tx(
            vec![any_msg],
            account_number,
            sequence,
            None, // Use default gas
            None, // No memo
        )?;

        // Submit to mempool (CheckTx) - releases lock after this
        let sync_result = match self.broadcast_tx_sync(tx_bytes).await {
            Ok(result) => result,
            Err(error @ BlockchainError::TxFailed { .. }) => {
                // CheckTx rejected the transaction, so the chain did not consume
                // this sequence. Restore the signer's view before a caller
                // retries with a smaller batch.
                self.resync_nonce_inner(signer).await.map_err(|resync_err| {
                    BlockchainError::Signing(format!(
                        "Transaction was rejected before broadcast: {error}; additionally failed to resync nonce: {resync_err}"
                    ))
                })?;
                return Err(error);
            }
            Err(error) => return Err(error),
        };

        // Lock is released here, allowing next tx to submit
        drop(_guard);

        // Wait for confirmation by polling
        self.wait_for_tx(&sync_result.tx_hash).await
    }

    /// Broadcast a JSON-encoded message as a transaction (for messages not yet migrated to prost).
    ///
    /// Uses the signer's in-memory nonce and increments it for the next transaction.
    /// Transactions are serialized to ensure they reach the mempool in nonce order.
    pub async fn broadcast_json_msg<T: Serialize>(
        &self,
        type_url: &str,
        msg: &T,
    ) -> Result<BroadcastResult> {
        let signer = self
            .signer()
            .ok_or_else(|| BlockchainError::Signing("No signer configured".to_string()))?;

        // Encode message as JSON bytes (can do outside lock)
        let msg_bytes = serde_json::to_vec(msg)?;

        let any_msg = Any {
            type_url: type_url.to_string(),
            value: msg_bytes,
        };

        // Acquire lock to ensure txs reach mempool in nonce order
        let _guard = self.tx_lock.lock().await;

        // Get account number and atomically fetch-and-increment the nonce
        let account_number = signer.account_number();
        let sequence = signer.fetch_and_increment_nonce();

        // Sign the transaction
        let tx_bytes = signer.sign_tx(
            vec![any_msg],
            account_number,
            sequence,
            None, // Use default gas
            None, // No memo
        )?;

        // Submit to mempool (CheckTx) - releases lock after this
        let sync_result = self.broadcast_tx_sync(tx_bytes).await?;

        // Lock is released here, allowing next tx to submit
        drop(_guard);

        // Wait for confirmation by polling
        self.wait_for_tx(&sync_result.tx_hash).await
    }

    /// Broadcast a signed transaction and wait for it to be committed.
    pub async fn broadcast_tx_commit(&self, tx_bytes: Vec<u8>) -> Result<BroadcastResult> {
        let response = self.rpc_client.broadcast_tx_commit(tx_bytes).await?;

        let code = response.check_tx.code.value();
        if code != 0 {
            return Err(BlockchainError::TxFailed {
                code,
                log: response.check_tx.log.to_string(),
            });
        }

        let code = response.tx_result.code.value();
        if code != 0 {
            return Err(BlockchainError::TxFailed {
                code,
                log: response.tx_result.log.to_string(),
            });
        }

        Ok(BroadcastResult {
            tx_hash: response.hash.to_string(),
            height: Some(response.height.value()),
            code,
            log: response.tx_result.log.to_string(),
            data: Some(decode_abci_data(response.tx_result.data.to_vec())),
        })
    }

    /// Broadcast a signed transaction asynchronously (don't wait for commit).
    pub async fn broadcast_tx_async(&self, tx_bytes: Vec<u8>) -> Result<BroadcastResult> {
        let response = self.rpc_client.broadcast_tx_async(tx_bytes).await?;

        Ok(BroadcastResult {
            tx_hash: response.hash.to_string(),
            height: None,
            code: response.code.value(),
            log: response.log.to_string(),
            data: Some(decode_abci_data(response.data.to_vec())),
        })
    }

    /// Broadcast a signed transaction synchronously (wait for CheckTx only).
    pub async fn broadcast_tx_sync(&self, tx_bytes: Vec<u8>) -> Result<BroadcastResult> {
        let response = self.rpc_client.broadcast_tx_sync(tx_bytes).await?;

        let code = response.code.value();
        if code != 0 {
            return Err(BlockchainError::TxFailed {
                code,
                log: response.log.to_string(),
            });
        }

        Ok(BroadcastResult {
            tx_hash: response.hash.to_string(),
            height: None,
            code,
            log: response.log.to_string(),
            data: Some(decode_abci_data(response.data.to_vec())),
        })
    }

    /// Wait for a transaction to be committed to a block.
    ///
    /// Polls the chain until the transaction is found or timeout is reached.
    pub async fn wait_for_tx(&self, tx_hash: &str) -> Result<BroadcastResult> {
        let hash = tx_hash
            .parse()
            .map_err(|e| BlockchainError::Query(format!("Invalid tx hash: {}", e)))?;

        for _ in 0..TX_POLL_MAX_ATTEMPTS {
            match self.rpc_client.tx(hash, false).await {
                Ok(response) => {
                    let code = response.tx_result.code.value();
                    if code != 0 {
                        return Err(BlockchainError::TxFailed {
                            code,
                            log: response.tx_result.log.to_string(),
                        });
                    }

                    return Ok(BroadcastResult {
                        tx_hash: response.hash.to_string(),
                        height: Some(response.height.value()),
                        code,
                        log: response.tx_result.log.to_string(),
                        data: Some(decode_abci_data(response.tx_result.data.to_vec())),
                    });
                }
                Err(_) => {
                    // Tx not found yet, keep polling
                    sleep(TX_POLL_INTERVAL).await;
                }
            }
        }

        Err(BlockchainError::Timeout(format!(
            "Transaction {} not found after {} seconds",
            tx_hash, TX_POLL_MAX_ATTEMPTS
        )))
    }

    /// Execute an ABCI query.
    pub async fn abci_query(
        &self,
        path: &str,
        data: Vec<u8>,
        height: Option<u64>,
        prove: bool,
    ) -> Result<Vec<u8>> {
        let height = height
            .map(tendermint::block::Height::try_from)
            .transpose()
            .map_err(|e| BlockchainError::Query(format!("Invalid block height: {}", e)))?;

        let mut attempt = 0;
        let response = loop {
            attempt += 1;
            match self
                .rpc_client
                .abci_query(Some(path.to_string()), data.clone(), height, prove)
                .await
            {
                Ok(response) => break response,
                Err(_) if attempt < ABCI_QUERY_MAX_ATTEMPTS => {
                    sleep(ABCI_QUERY_RETRY_BASE_DELAY * attempt).await;
                }
                Err(error) => return Err(error.into()),
            }
        };

        if response.code.is_err() {
            let log = response.log.to_lowercase();
            if log.contains("not found") {
                return Err(BlockchainError::NotFound(response.log));
            }
            return Err(BlockchainError::Query(format!(
                "ABCI query failed: {} (code {})",
                response.log,
                response.code.value()
            )));
        }

        Ok(decode_abci_data(response.value))
    }

    pub(crate) async fn abci_query_optional(
        &self,
        path: &str,
        data: Vec<u8>,
        height: Option<u64>,
        prove: bool,
    ) -> Result<Option<Vec<u8>>> {
        match self.abci_query(path, data, height, prove).await {
            Ok(bytes) => Ok(Some(bytes)),
            Err(BlockchainError::NotFound(_)) => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// Get the latest block height.
    pub async fn get_latest_height(&self) -> Result<u64> {
        let status = self.rpc_client.status().await?;
        Ok(status.sync_info.latest_block_height.value())
    }

    /// Get the chain status.
    pub async fn get_status(&self) -> Result<tendermint_rpc::endpoint::status::Response> {
        Ok(self.rpc_client.status().await?)
    }

    /// Unix-seconds timestamp of the block committed at `height`.
    pub async fn get_block_time(&self, height: u64) -> Result<u64> {
        let block_height = tendermint::block::Height::try_from(height)
            .map_err(|e| BlockchainError::Query(format!("invalid block height {height}: {e}")))?;
        let response = self.rpc_client.block(block_height).await?;
        let secs = response
            .block
            .header
            .time
            .duration_since(tendermint::Time::unix_epoch())
            .map_err(|e| {
                BlockchainError::Query(format!("block {height} time before unix epoch: {e}"))
            })?
            .as_secs();
        Ok(secs)
    }

    /// Send a REST request, retrying past transport-level failures. See
    /// `REST_TRANSPORT_MAX_ATTEMPTS`'s docs for what is and isn't retried.
    /// Panics if `request`'s body can't be cloned (a streaming body) — none
    /// of this client's REST calls use one.
    async fn send_with_retry(
        request: reqwest::RequestBuilder,
    ) -> std::result::Result<reqwest::Response, reqwest::Error> {
        let mut attempt = 0;
        loop {
            attempt += 1;
            let this_attempt = request
                .try_clone()
                .expect("REST request body must be cloneable for retry");
            match this_attempt.send().await {
                Ok(response) => return Ok(response),
                Err(error) if attempt < REST_TRANSPORT_MAX_ATTEMPTS => {
                    eprintln!(
                        "REST request transport error (attempt {attempt}/{REST_TRANSPORT_MAX_ATTEMPTS}), retrying: {error}"
                    );
                    sleep(REST_TRANSPORT_RETRY_BASE_DELAY * attempt).await;
                }
                Err(error) => return Err(error),
            }
        }
    }

    /// Make a REST API GET request.
    pub async fn rest_get<T: DeserializeOwned>(&self, url: &str) -> Result<T> {
        let response = Self::send_with_retry(self.http_client.get(url))
            .await?
            .error_for_status()
            .map_err(|e| BlockchainError::Rest(e.to_string()))?;

        let body = response.text().await?;
        serde_json::from_str(&body).map_err(|e| {
            BlockchainError::Serialization(format!(
                "Failed to parse response: {} - body: {}",
                e, body
            ))
        })
    }

    /// Make a REST API GET request that returns None on 404.
    /// Useful for queries where 404 is a valid response (e.g., account doesn't exist).
    pub async fn rest_get_optional<T: DeserializeOwned>(&self, url: &str) -> Result<Option<T>> {
        let response = Self::send_with_retry(self.http_client.get(url)).await?;

        let status = response.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }

        let response = response
            .error_for_status()
            .map_err(|e| BlockchainError::Rest(e.to_string()))?;

        let body = response.text().await?;
        let parsed = serde_json::from_str(&body).map_err(|e| {
            BlockchainError::Serialization(format!(
                "Failed to parse response: {} - body: {}",
                e, body
            ))
        })?;
        Ok(Some(parsed))
    }

    /// Make a REST API POST request.
    pub async fn rest_post<T: DeserializeOwned, B: Serialize>(
        &self,
        url: &str,
        body: &B,
    ) -> Result<T> {
        let response = Self::send_with_retry(self.http_client.post(url).json(body))
            .await?
            .error_for_status()
            .map_err(|e| BlockchainError::Rest(e.to_string()))?;

        let body = response.text().await?;
        serde_json::from_str(&body).map_err(|e| {
            BlockchainError::Serialization(format!(
                "Failed to parse response: {} - body: {}",
                e, body
            ))
        })
    }

    /// Transfer coins from the signer's account to another address.
    ///
    /// # Arguments
    /// * `to_address` - The recipient's bech32 address
    /// * `amount` - The amount to transfer (in base units, e.g., uopen)
    /// * `denom` - The denomination (e.g., "uopen")
    pub async fn transfer(
        &self,
        to_address: &str,
        amount: u64,
        denom: &str,
    ) -> Result<BroadcastResult> {
        let signer = self
            .signer()
            .ok_or_else(|| BlockchainError::Signing("No signer configured".to_string()))?;

        // Create the bank transfer message using protobuf
        let coin = bank::Coin {
            denom: denom.to_string(),
            amount: amount.to_string(),
        };

        let msg = bank::MsgSend {
            from_address: signer.address(),
            to_address: to_address.to_string(),
            amount: vec![coin],
        };

        // Use protobuf encoding with gas simulation
        self.broadcast_proto_msg_with_gas(
            bank::MsgSend::TYPE_URL,
            &msg,
            self.config().gas_multiplier,
        )
        .await
    }

    /// Simulate a transaction to estimate gas usage.
    ///
    /// # Arguments
    /// * `tx_bytes` - The signed transaction bytes to simulate
    ///
    /// # Returns
    /// The estimated gas used by the transaction.
    pub async fn simulate_tx(&self, tx_bytes: &[u8]) -> Result<u64> {
        let url = format!("{}/cosmos/tx/v1beta1/simulate", self.config.rest_url);

        let request = SimulateRequest {
            tx_bytes: base64::engine::general_purpose::STANDARD.encode(tx_bytes),
        };

        // Make the request and get raw response for debugging
        let response = Self::send_with_retry(self.http_client.post(&url).json(&request)).await?;

        let status = response.status();
        let body = response.text().await?;

        if !status.is_success() {
            return Err(BlockchainError::Rest(format!(
                "Simulate failed with status {}: {}",
                status, body
            )));
        }

        let parsed: SimulateResponse = serde_json::from_str(&body).map_err(|e| {
            BlockchainError::Serialization(format!(
                "Failed to parse simulate response: {} - body: {}",
                e, body
            ))
        })?;

        parsed
            .gas_info
            .gas_used
            .parse()
            .map_err(|e| BlockchainError::Serialization(format!("Invalid gas_used: {}", e)))
    }

    /// Broadcast a protobuf-encoded message with automatic gas estimation.
    ///
    /// This simulates the transaction first to get accurate gas usage,
    /// then broadcasts with the estimated gas plus a safety buffer.
    ///
    /// # Arguments
    /// * `type_url` - The protobuf type URL for the message
    /// * `msg` - The message to broadcast
    /// * `gas_multiplier` - Safety buffer multiplier (e.g., 1.3 for 30% extra)
    pub async fn broadcast_proto_msg_with_gas<T: Message>(
        &self,
        type_url: &str,
        msg: &T,
        gas_multiplier: f64,
    ) -> Result<BroadcastResult> {
        let any_msg = Any {
            type_url: type_url.to_string(),
            value: msg.encode_to_vec(),
        };

        self.broadcast_proto_msgs_with_gas(vec![any_msg], gas_multiplier)
            .await
    }

    /// Broadcast several protobuf messages in one Cosmos transaction with
    /// automatic gas estimation.
    ///
    /// Cosmos executes messages in order and rolls the transaction back if any
    /// message fails. Callers should keep batches bounded by the chain's block
    /// gas and transaction-size limits. This method intentionally accepts
    /// [`Any`] values so a batch may contain different message types.
    pub async fn broadcast_proto_msgs_with_gas(
        &self,
        messages: Vec<Any>,
        gas_multiplier: f64,
    ) -> Result<BroadcastResult> {
        if messages.is_empty() {
            return Err(BlockchainError::Config(
                "Cannot broadcast an empty transaction".to_string(),
            ));
        }
        if !gas_multiplier.is_finite() || gas_multiplier < 1.0 {
            return Err(BlockchainError::Config(format!(
                "Gas multiplier must be finite and at least 1.0, got {gas_multiplier}"
            )));
        }

        let signer = self
            .signer()
            .ok_or_else(|| BlockchainError::Signing("No signer configured".to_string()))?;

        // Acquire lock to ensure txs reach mempool in nonce order
        let _guard = self.tx_lock.lock().await;

        // Get account info for simulation
        let account_number = signer.account_number();
        let sequence = signer.fetch_and_increment_nonce();

        // Build tx with high gas limit for simulation
        let sim_tx_bytes = signer.sign_tx(
            messages.clone(),
            account_number,
            sequence,
            Some(SIMULATION_GAS_LIMIT),
            None,
        )?;

        // Simulate to get actual gas usage
        let gas_used = match self.simulate_tx(&sim_tx_bytes).await {
            Ok(gas) => gas,
            Err(e) => {
                // Resync the nonce from the chain — simulation failed before any tx was
                // submitted, so the in-memory counter is ahead of reality. Resyncing
                // handles both "document already exists" (chain still at N) and
                // "sequence mismatch" (chain advanced to M while we held N).
                self.resync_nonce_inner(signer)
                    .await
                    .map_err(|resync_err| {
                        BlockchainError::Signing(format!(
                            "Gas simulation failed: {}; additionally failed to resync nonce: {}",
                            e, resync_err
                        ))
                    })?;
                return Err(BlockchainError::Signing(format!(
                    "Gas simulation failed: {}",
                    e
                )));
            }
        };

        // Calculate gas limit with buffer
        let gas_limit = ((gas_used as f64) * gas_multiplier).ceil() as u64;

        // Rebuild transaction with accurate gas limit
        // Note: We use the same sequence number - simulation doesn't change chain state
        let tx_bytes = signer.sign_tx(messages, account_number, sequence, Some(gas_limit), None)?;

        // Submit to mempool
        let sync_result = match self.broadcast_tx_sync(tx_bytes).await {
            Ok(result) => result,
            Err(error @ BlockchainError::TxFailed { .. }) => {
                // CheckTx rejected the transaction, so the chain did not consume
                // this sequence. Restore the signer's view before a caller
                // retries with a smaller batch, matching `broadcast_proto_msg`'s
                // handling of the same failure.
                self.resync_nonce_inner(signer).await.map_err(|resync_err| {
                    BlockchainError::Signing(format!(
                        "Transaction was rejected before broadcast: {error}; additionally failed to resync nonce: {resync_err}"
                    ))
                })?;
                return Err(error);
            }
            Err(error) => return Err(error),
        };

        // Lock is released here
        drop(_guard);

        // Wait for confirmation
        self.wait_for_tx(&sync_result.tx_hash).await
    }
}

// Internal response types for parsing Cosmos REST API responses

#[derive(Debug, Deserialize)]
struct AccountResponse {
    account: AccountData,
}

#[derive(Debug, Deserialize)]
struct AccountData {
    #[serde(rename = "@type", default)]
    #[allow(dead_code)]
    type_url: String,
    address: String,
    #[serde(default)]
    account_number: String,
    #[serde(default)]
    sequence: String,
}

// Internal response types for parsing Cosmos REST API balance responses
#[derive(Debug, Deserialize)]
struct BalanceResponse {
    balances: Vec<BalanceCoin>,
}

#[derive(Debug, Deserialize)]
struct BalanceCoin {
    denom: String,
    amount: String,
}

// Types for transaction simulation
#[derive(Debug, Serialize)]
struct SimulateRequest {
    tx_bytes: String, // base64 encoded
}

#[derive(Debug, Deserialize)]
struct SimulateResponse {
    gas_info: GasInfo,
}

#[derive(Debug, Deserialize)]
struct GasInfo {
    gas_used: String,
    #[allow(dead_code)]
    gas_wanted: String,
}

#[cfg(test)]
mod tests {
    use super::{VeraClient, RPC_POOL_IDLE_TIMEOUT};
    use crate::blockchain::{ChainConfig, TxSigner, TEST_ACCOUNT_HEX_KEY};
    use serde_json::Value;
    use std::io;
    use std::sync::Arc;
    use std::time::Duration;
    use tendermint_rpc::Client;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::{mpsc, Notify};

    async fn read_http_request(
        stream: &mut TcpStream,
        buffer: &mut Vec<u8>,
    ) -> io::Result<Option<Vec<u8>>> {
        loop {
            if let Some(header_end) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
                let body_start = header_end + 4;
                let headers = std::str::from_utf8(&buffer[..header_end]).map_err(|error| {
                    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
                })?;
                let content_length = headers
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().ok())
                            .flatten()
                    })
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidData, "missing Content-Length")
                    })?;
                let request_end = body_start + content_length;
                if buffer.len() >= request_end {
                    let body = buffer[body_start..request_end].to_vec();
                    buffer.drain(..request_end);
                    return Ok(Some(body));
                }
            }

            let mut chunk = [0u8; 1024];
            let bytes_read = stream.read(&mut chunk).await?;
            if bytes_read == 0 {
                return Ok(None);
            }
            buffer.extend_from_slice(&chunk[..bytes_read]);
        }
    }

    async fn serve_connection(
        connection_id: usize,
        mut stream: TcpStream,
        request_connections: mpsc::UnboundedSender<usize>,
    ) -> io::Result<()> {
        let mut buffer = Vec::new();
        while let Some(body) = read_http_request(&mut stream, &mut buffer).await? {
            let request: Value = serde_json::from_slice(&body)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
            let response = serde_json::json!({
                "jsonrpc": "2.0",
                "id": request["id"],
                "result": {}
            })
            .to_string();
            let http_response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                response.len(),
                response
            );
            stream.write_all(http_response.as_bytes()).await?;
            request_connections.send(connection_id).map_err(|_| {
                io::Error::new(io::ErrorKind::BrokenPipe, "request receiver dropped")
            })?;
        }
        Ok(())
    }

    #[tokio::test]
    async fn rpc_client_discards_idle_connections_before_server_timeout() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let rpc_url = format!("http://{}", listener.local_addr().unwrap());
        let (request_connections_tx, mut request_connections_rx) = mpsc::unbounded_channel();
        let shutdown = Arc::new(Notify::new());
        let server_shutdown = shutdown.clone();

        let server = tokio::spawn(async move {
            let mut connection_id = 0;
            loop {
                tokio::select! {
                    _ = server_shutdown.notified() => break,
                    accepted = listener.accept() => {
                        let (stream, _) = accepted.unwrap();
                        connection_id += 1;
                        let request_connections = request_connections_tx.clone();
                        tokio::spawn(async move {
                            serve_connection(connection_id, stream, request_connections)
                                .await
                                .unwrap();
                        });
                    }
                }
            }
        });

        let config = ChainConfig::builder().rpc_url(Some(rpc_url)).build();
        let client = VeraClient::new(config).await.unwrap();

        client.rpc_client.health().await.unwrap();
        let first_connection = request_connections_rx.recv().await.unwrap();

        tokio::time::sleep(RPC_POOL_IDLE_TIMEOUT + Duration::from_secs(1)).await;

        client.rpc_client.health().await.unwrap();
        let second_connection = request_connections_rx.recv().await.unwrap();

        assert_ne!(
            first_connection, second_connection,
            "RPC client reused a connection after its configured idle timeout"
        );

        shutdown.notify_one();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn resync_account_holds_the_transaction_lock_during_query_and_update() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let config = ChainConfig::builder()
            .rpc_url(Some(endpoint.clone()))
            .rest_url(Some(endpoint))
            .build();
        let mut client = VeraClient::new(config.clone()).await.unwrap();
        client.signer = Some(TxSigner::from_hex_key(TEST_ACCOUNT_HEX_KEY, config).unwrap());
        let client = Arc::new(client);
        let tx_guard = client.tx_lock.lock().await;
        let resync_client = client.clone();
        let resync = tokio::spawn(async move { resync_client.resync_account().await });

        assert!(
            tokio::time::timeout(Duration::from_millis(100), listener.accept())
                .await
                .is_err(),
            "account query must wait for an in-flight transaction"
        );
        drop(tx_guard);

        let (mut stream, _) = tokio::time::timeout(Duration::from_secs(1), listener.accept())
            .await
            .expect("account query should start after transaction unlock")
            .unwrap();
        let mut request = Vec::new();
        loop {
            let mut chunk = [0u8; 1024];
            let count = stream.read(&mut chunk).await.unwrap();
            request.extend_from_slice(&chunk[..count]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        let address = client.signer().unwrap().address();
        let body = serde_json::json!({
            "account": {
                "@type": "/cosmos.auth.v1beta1.BaseAccount",
                "address": address,
                "account_number": "42",
                "sequence": "7"
            }
        })
        .to_string();
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        stream.write_all(response.as_bytes()).await.unwrap();

        assert_eq!(resync.await.unwrap().unwrap(), (42, 7));
        let signer = client.signer().unwrap();
        assert_eq!(signer.account_number(), 42);
        assert_eq!(signer.nonce(), 7);
    }
}
