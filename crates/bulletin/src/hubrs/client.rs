use alloy_primitives::Address;
use serde_json::{json, Value};

use crate::error::{BulletinError, Result};

use super::signer::EvmSigner;
use super::types::TransactionReceipt;

/// Lightweight EVM JSON-RPC client for hub.rs precompile interactions
pub struct EvmClient {
    http: reqwest::Client,
    rpc_url: String,
    signer: Option<EvmSigner>,
}

impl EvmClient {
    pub fn new(rpc_url: String, signer: Option<EvmSigner>) -> Self {
        Self {
            http: reqwest::Client::new(),
            rpc_url,
            signer,
        }
    }

    /// Perform a read-only eth_call
    pub async fn eth_call(&self, to: Address, calldata: Vec<u8>) -> Result<Vec<u8>> {
        let result = self
            .rpc_request(
                "eth_call",
                json!([
                    {
                        "to": format!("{:?}", to),
                        "data": format!("0x{}", hex::encode(&calldata)),
                    },
                    "latest"
                ]),
            )
            .await?;

        let hex_str = result
            .as_str()
            .ok_or_else(|| BulletinError::ChainError("eth_call returned non-string".into()))?;

        let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
        hex::decode(hex_str)
            .map_err(|e| BulletinError::ChainError(format!("Failed to decode eth_call result: {}", e)))
    }

    /// Get the transaction count (nonce) for an address
    pub async fn get_nonce(&self, address: Address) -> Result<u64> {
        let result = self
            .rpc_request(
                "eth_getTransactionCount",
                json!([format!("{:?}", address), "latest"]),
            )
            .await?;

        let hex_str = result
            .as_str()
            .ok_or_else(|| BulletinError::ChainError("nonce returned non-string".into()))?;

        let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
        u64::from_str_radix(hex_str, 16)
            .map_err(|e| BulletinError::ChainError(format!("Failed to parse nonce: {}", e)))
    }

    /// Send a raw signed transaction
    pub async fn send_raw_transaction(&self, raw_tx: &[u8]) -> Result<String> {
        let result = self
            .rpc_request(
                "eth_sendRawTransaction",
                json!([format!("0x{}", hex::encode(raw_tx))]),
            )
            .await?;

        result
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| BulletinError::ChainError("sendRawTransaction returned non-string".into()))
    }

    /// Get the transaction receipt
    pub async fn get_transaction_receipt(&self, tx_hash: &str) -> Result<Option<TransactionReceipt>> {
        let result = self
            .rpc_request("eth_getTransactionReceipt", json!([tx_hash]))
            .await?;

        if result.is_null() {
            return Ok(None);
        }

        serde_json::from_value(result)
            .map(Some)
            .map_err(|e| BulletinError::ChainError(format!("Failed to parse receipt: {}", e)))
    }

    /// Wait for a transaction receipt with polling
    pub async fn wait_for_receipt(&self, tx_hash: &str) -> Result<TransactionReceipt> {
        for _ in 0..30 {
            if let Some(receipt) = self.get_transaction_receipt(tx_hash).await? {
                return Ok(receipt);
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
        Err(BulletinError::ChainError(format!(
            "Timeout waiting for receipt of tx {}",
            tx_hash
        )))
    }

    /// Send a precompile transaction: fetch nonce, sign, send, wait for receipt
    pub async fn send_precompile_tx(&self, to: Address, calldata: Vec<u8>) -> Result<TransactionReceipt> {
        let signer = self
            .signer
            .as_ref()
            .ok_or_else(|| BulletinError::ChainError("No signer configured for write operation".into()))?;

        let nonce = self.get_nonce(signer.address()).await?;
        let raw_tx = signer.sign_tx(to, calldata, nonce)?;
        let tx_hash = self.send_raw_transaction(&raw_tx).await?;
        let receipt = self.wait_for_receipt(&tx_hash).await?;

        if !receipt.succeeded() {
            return Err(BulletinError::ChainError(format!(
                "Transaction {} reverted",
                tx_hash
            )));
        }

        Ok(receipt)
    }

    /// Make a JSON-RPC request and return the result field
    async fn rpc_request(&self, method: &str, params: Value) -> Result<Value> {
        let body = json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": 1,
        });

        let response = self
            .http
            .post(&self.rpc_url)
            .json(&body)
            .send()
            .await
            .map_err(|e| BulletinError::ChainError(format!("RPC request failed: {}", e)))?;

        let json: Value = response
            .json()
            .await
            .map_err(|e| BulletinError::ChainError(format!("Failed to parse RPC response: {}", e)))?;

        if let Some(error) = json.get("error") {
            return Err(BulletinError::ChainError(format!("RPC error: {}", error)));
        }

        json.get("result")
            .cloned()
            .ok_or_else(|| BulletinError::ChainError("RPC response missing 'result' field".into()))
    }
}
