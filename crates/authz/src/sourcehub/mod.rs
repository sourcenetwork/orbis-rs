use crate::{
    error::{AuthZError, Result},
    r#trait::Authz,
};
use async_trait::async_trait;
use common::blockchain::{acp::Policy, ChainConfig, SourceHubClient};

#[cfg(test)]
mod tests;

pub struct SourceHubAuth {
    chain_client: SourceHubClient,
}

#[async_trait]
impl Authz for SourceHubAuth {
    async fn check(&self, persmission: Vec<u8>, subject: String) -> Result<bool> {
        let policy = self.get_policy(subject).await.unwrap();
        dbg!(policy);
        Ok(true)
    }
}

impl SourceHubAuth {
    pub async fn new() -> Self {
        // TODO just for testing for now
        SourceHubAuth {
            chain_client: SourceHubClient::new(ChainConfig::local()).await.unwrap(),
        }
    }
    pub async fn get_policy(&self, policy_id: String) -> Result<Policy> {
        Ok(self
            .chain_client
            .acp_query_policy(&policy_id)
            .await
            .unwrap()
            .record
            .unwrap()
            .policy
            .unwrap())
    }
}
