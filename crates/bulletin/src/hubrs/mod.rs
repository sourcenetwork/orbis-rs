mod abi;
mod client;
pub mod signer;
mod types;

use alloy_primitives::Address;
use alloy_sol_types::SolCall;
use async_trait::async_trait;
use sha2::{Digest, Sha256};

use crate::error::{BulletinError, Result};
use crate::r#trait::{Bulletin, BulletinPost};

use abi::{IBulletin, BULLETIN_PRECOMPILE_ADDRESS};
use client::EvmClient;
use types::HubPost;

#[cfg(test)]
mod tests;

/// Configuration for connecting to a hub.rs node
pub struct HubRsConfig {
    pub rpc_url: String,
    pub chain_id: u64,
}

/// Hub.rs bulletin client using EVM precompiles
pub struct HubRsBulletin {
    client: EvmClient,
    precompile_addr: Address,
}

#[async_trait]
impl Bulletin for HubRsBulletin {
    async fn register(&self, namespace: String) -> Result<()> {
        let calldata = IBulletin::registerNamespaceCall {
            namespace,
        }
        .abi_encode();

        self.client
            .send_precompile_tx(self.precompile_addr, calldata)
            .await?;

        Ok(())
    }

    async fn post(
        &self,
        namespace: String,
        payload: Vec<u8>,
        proof: Vec<u8>,
        artifact: Option<String>,
    ) -> Result<()> {
        let calldata = IBulletin::createPostCall {
            namespace,
            payload: payload.into(),
            proof: proof.into(),
            artifact: artifact.unwrap_or_default(),
        }
        .abi_encode();

        self.client
            .send_precompile_tx(self.precompile_addr, calldata)
            .await?;

        Ok(())
    }

    async fn read(&self, namespace: String, id: String) -> Result<BulletinPost> {
        // Strip "bulletin/" prefix if present for robustness
        let ns = namespace
            .strip_prefix("bulletin/")
            .unwrap_or(&namespace)
            .to_string();

        let calldata = IBulletin::getPostCall {
            namespace: ns.clone(),
            id: id.clone(),
        }
        .abi_encode();

        let result_bytes = self
            .client
            .eth_call(self.precompile_addr, calldata)
            .await?;

        // ABI-decode the return value: getPost returns (bytes memory)
        let decoded = IBulletin::getPostCall::abi_decode_returns(&result_bytes)
            .map_err(|e| {
                BulletinError::ChainError(format!("Failed to ABI-decode getPost response: {}", e))
            })?;

        let json_bytes: &[u8] = &decoded.0;

        if json_bytes.is_empty() {
            return Err(BulletinError::NotFound {
                namespace: ns,
                id,
            });
        }

        let hub_post: HubPost = serde_json::from_slice(json_bytes).map_err(|e| {
            BulletinError::ParseError(format!(
                "Failed to parse hub.rs post JSON: {}",
                e
            ))
        })?;

        Ok(BulletinPost {
            id: hub_post.id,
            namespace: hub_post.namespace,
            payload: hub_post.payload,
            proof: hub_post.proof,
        })
    }

    fn get_post_id(&self, namespace: &str, payload: &[u8]) -> Result<String> {
        Ok(Self::compute_post_id(namespace, payload))
    }
}

impl HubRsBulletin {
    pub fn name() -> String {
        "bulletin/hubrs".to_string()
    }

    /// Create a read-only client (no signing capability)
    pub fn new(config: HubRsConfig) -> Result<Self> {
        let precompile_addr = Address::from(BULLETIN_PRECOMPILE_ADDRESS);
        let client = EvmClient::new(config.rpc_url, None);
        Ok(Self {
            client,
            precompile_addr,
        })
    }

    /// Create a client with signing capability for write operations
    pub fn with_signer(config: HubRsConfig, hex_key: &str) -> Result<Self> {
        let precompile_addr = Address::from(BULLETIN_PRECOMPILE_ADDRESS);
        let signer = signer::EvmSigner::from_hex(hex_key, config.chain_id)?;
        let client = EvmClient::new(config.rpc_url, Some(signer));
        Ok(Self {
            client,
            precompile_addr,
        })
    }

    /// Compute deterministic post ID from namespace and payload.
    /// Same as SourceHub: hex(SHA256(namespace_bytes || payload))
    pub fn compute_post_id(namespace: &str, payload: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(namespace.as_bytes());
        hasher.update(payload);
        hex::encode(hasher.finalize())
    }
}
