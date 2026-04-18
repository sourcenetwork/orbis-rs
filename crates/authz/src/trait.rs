use crate::error::Result;
use async_trait::async_trait;

#[async_trait]
pub trait Authz: Send + Sync {
    async fn check(&self, permission: Vec<u8>, subject: &str) -> Result<bool>;
}
