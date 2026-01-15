use crate::{
    error::{BulletinError, Result},
    r#trait::{Bulletin, BulletinPost},
};
use async_trait::async_trait;
use common::blockchain::{ChainConfigBuilder, SourceHubClient, TxSigner};
use sha2::{Digest, Sha256};

#[cfg(test)]
mod tests;

pub struct SourceHubBulletin {
    pub chain_client: SourceHubClient,
}

#[async_trait]
impl Bulletin for SourceHubBulletin {
    async fn register(&self, namespace: String) -> Result<()> {
        let result = self
            .chain_client
            .bulletin_register_namespace(&namespace)
            .await
            .map_err(|e| BulletinError::ChainError(e.to_string()))?;

        if result.code != 0 {
            return Err(BulletinError::ChainError(format!(
                "Failed to register namespace: code {}",
                result.code
            )));
        }

        Ok(())
    }

    async fn post(&self, namespace: String, payload: Vec<u8>, proof: Vec<u8>) -> Result<()> {
        let result = self
            .chain_client
            .bulletin_create_post_with_proof(&namespace, payload, proof)
            .await
            .map_err(|e| BulletinError::ChainError(e.to_string()))?;

        if result.code != 0 {
            return Err(BulletinError::ChainError(format!(
                "Failed to create post: code {}",
                result.code
            )));
        }

        Ok(())
    }
    async fn read(&self, namespace: String, id: String) -> Result<BulletinPost> {
        let post = self
            .chain_client
            .bulletin_read_post(&namespace, &id)
            .await
            .map_err(|e| BulletinError::ChainError(e.to_string()))?;

        Ok(BulletinPost {
            id: post.id,
            namespace: post.namespace,
            payload: post.payload,
            proof: post.proof,
        })
    }
}

impl SourceHubBulletin {
    pub async fn new(chain_config_builder: ChainConfigBuilder) -> Result<Self> {
        Ok(SourceHubBulletin {
            chain_client: SourceHubClient::new(chain_config_builder.build())
                .await
                .map_err(|e| BulletinError::ChainError(e.to_string()))?,
        })
    }

    pub async fn with_signer(
        chain_config_builder: ChainConfigBuilder,
        signer: TxSigner,
    ) -> Result<Self> {
        // Get the address before moving the signer
        let address = signer.address();

        let client = SourceHubBulletin {
            chain_client: SourceHubClient::with_signer(chain_config_builder.build(), signer)
                .await
                .map_err(|e| BulletinError::ChainError(e.to_string()))?,
        };

        // Transfer to self to register account on-chain (registers public key)
        let amount = 1u64;
        let denom = "uopen";

        let _result = client
            .chain_client
            .transfer(&address, amount, denom)
            .await
            .map_err(|e| BulletinError::ChainError(e.to_string()))?;

        Ok(client)
    }

    pub fn get_post_id(namespace: &str, payload: &[u8]) -> Result<String> {
        let mut hasher = Sha256::new();

        hasher.update(namespace.as_bytes());
        hasher.update(payload);

        let hash = hasher.finalize();
        Ok(hex::encode(hash))
    }
}
