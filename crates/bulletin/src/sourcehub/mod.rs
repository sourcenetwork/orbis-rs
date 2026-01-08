use crate::{
    error::{BulletinError, Result},
    r#trait::Bulletin,
};
use async_trait::async_trait;
use common::blockchain::{ChainConfigBuilder, SourceHubClient};

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
    async fn read(&self, namespace: String, id: String) -> Result<()> {
        todo!();
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
}
