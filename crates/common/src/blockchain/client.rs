//! SourceHub blockchain client.

use crate::blockchain::{BlockchainError, ChainConfig, Result, TxSigner};
use cosmrs::Any;
use prost::Message;
use reqwest::Client as HttpClient;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tendermint_rpc::{Client, HttpClient as TendermintClient};

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

/// Client for interacting with SourceHub.
pub struct SourceHubClient {
    config: ChainConfig,
    rpc_client: TendermintClient,
    http_client: HttpClient,
    signer: Option<TxSigner>,
}

impl SourceHubClient {
    /// Create a new client for queries only.
    pub async fn new(config: ChainConfig) -> Result<Self> {
        let rpc_client = TendermintClient::new(config.rpc_url.as_str())
            .map_err(|e| BlockchainError::Config(format!("Failed to create RPC client: {}", e)))?;

        let http_client = HttpClient::new();

        Ok(Self {
            config,
            rpc_client,
            http_client,
            signer: None,
        })
    }

    /// Create a new client with signing capability.
    pub async fn with_signer(config: ChainConfig, signer: TxSigner) -> Result<Self> {
        let mut client = Self::new(config).await?;
        client.signer = Some(signer);
        Ok(client)
    }

    /// Get the signer (if configured).
    pub fn signer(&self) -> Option<&TxSigner> {
        self.signer.as_ref()
    }

    /// Get the chain configuration.
    pub fn config(&self) -> &ChainConfig {
        &self.config
    }

    /// Get account information for an address.
    pub async fn get_account(&self, address: &str) -> Result<AccountInfo> {
        let url = format!(
            "{}/cosmos/auth/v1beta1/accounts/{}",
            self.config.rest_url, address
        );

        let response: AccountResponse = self.rest_get(&url).await?;

        // Parse the account info from the response
        // Cosmos SDK returns different account types, we need to handle the base account
        let account = response.account;

        Ok(AccountInfo {
            address: account.address,
            account_number: account.account_number.parse().unwrap_or(0),
            sequence: account.sequence.parse().unwrap_or(0),
        })
    }

    /// Broadcast a protobuf-encoded message as a transaction.
    pub async fn broadcast_proto_msg<T: Message>(
        &self,
        type_url: &str,
        msg: &T,
    ) -> Result<BroadcastResult> {
        let signer = self
            .signer()
            .ok_or_else(|| BlockchainError::Signing("No signer configured".to_string()))?;

        // Get account info for sequence number
        let account_info = self.get_account(&signer.address()).await?;

        // Encode message as protobuf
        let msg_bytes = msg.encode_to_vec();

        let any_msg = Any {
            type_url: type_url.to_string(),
            value: msg_bytes,
        };

        // Sign the transaction
        let tx_bytes = signer.sign_tx(
            vec![any_msg],
            account_info.account_number,
            account_info.sequence,
            None, // Use default gas
            None, // No memo
        )?;

        // Broadcast
        self.broadcast_tx_commit(tx_bytes).await
    }

    /// Broadcast a JSON-encoded message as a transaction (for messages not yet migrated to prost).
    pub async fn broadcast_json_msg<T: Serialize>(
        &self,
        type_url: &str,
        msg: &T,
    ) -> Result<BroadcastResult> {
        let signer = self
            .signer()
            .ok_or_else(|| BlockchainError::Signing("No signer configured".to_string()))?;

        // Get account info for sequence number
        let account_info = self.get_account(&signer.address()).await?;

        // Encode message as JSON bytes
        let msg_bytes = serde_json::to_vec(msg)?;

        let any_msg = Any {
            type_url: type_url.to_string(),
            value: msg_bytes,
        };

        // Sign the transaction
        let tx_bytes = signer.sign_tx(
            vec![any_msg],
            account_info.account_number,
            account_info.sequence,
            None, // Use default gas
            None, // No memo
        )?;

        // Broadcast
        self.broadcast_tx_commit(tx_bytes).await
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
            data: Some(response.tx_result.data.to_vec()),
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
            data: Some(response.data.to_vec()),
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
            data: Some(response.data.to_vec()),
        })
    }

    /// Execute an ABCI query.
    pub async fn abci_query(
        &self,
        path: &str,
        data: Vec<u8>,
        height: Option<u64>,
        prove: bool,
    ) -> Result<Vec<u8>> {
        let height = height.map(|h| tendermint::block::Height::try_from(h).unwrap());

        let response = self
            .rpc_client
            .abci_query(Some(path.to_string()), data, height, prove)
            .await?;

        if response.code.is_err() {
            return Err(BlockchainError::Query(format!(
                "ABCI query failed: {} (code {})",
                response.log,
                response.code.value()
            )));
        }

        Ok(response.value)
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

    /// Make a REST API GET request.
    pub async fn rest_get<T: DeserializeOwned>(&self, url: &str) -> Result<T> {
        let response = self
            .http_client
            .get(url)
            .send()
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

    /// Make a REST API POST request.
    pub async fn rest_post<T: DeserializeOwned, B: Serialize>(
        &self,
        url: &str,
        body: &B,
    ) -> Result<T> {
        let response = self
            .http_client
            .post(url)
            .json(body)
            .send()
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
