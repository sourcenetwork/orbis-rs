use crate::error::Result;
use async_trait::async_trait;

#[async_trait]
pub trait Authz {
    async fn check(&self, permission: Vec<u8>, subject: String) -> Result<bool>;
}
