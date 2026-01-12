use crate::{
    error::{BulletinError, Result},
    r#trait::{Bulletin, BulletinPost},
};
use async_trait::async_trait;
use common::blockchain::{bulletin::Post, ChainConfigBuilder, SourceHubClient};
use sha2::{Digest, Sha256};

#[cfg(test)]
mod tests;

pub struct SourceHubBulletin {
    pub chain_client: SourceHubClient,
}

#[async_trait]
impl Bulletin for SourceHubBulletin {
    async fn register(&self, namespace: String) -> Result<()> {
        todo!();
    }
    async fn post(&self, namespace: String, id: String, message: Vec<u8>) -> Result<()> {
        todo!();
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

    pub fn get_post_id(namespace: &str, payload: &[u8]) -> Result<String> {
        let mut hasher = Sha256::new();

        hasher.update(namespace.as_bytes());
        hasher.update(payload);

        let hash = hasher.finalize();
        Ok(hex::encode(hash))
    }
}
