use crate::error::Result;
use async_trait::async_trait;

#[async_trait]
pub trait Authz: Send + Sync {
    /// Evaluate the on-chain policy for `subject` at the latest height.
    async fn check(&self, permission: Vec<u8>, subject: &str) -> Result<bool>;

    /// Evaluate the on-chain policy for `subject` at a specific block `height` (`None` = latest).
    /// Report refutations anchor `height` to the relay block so every co-signer and the chain
    /// reach the same verdict regardless of when they re-check.
    async fn check_at_height(
        &self,
        permission: Vec<u8>,
        subject: &str,
        height: Option<u64>,
    ) -> Result<bool>;
}
