use crate::error::Result;
use async_trait::async_trait;

#[async_trait]
pub trait Bulletin {
    async fn register(&self, namespace: String) -> Result<()>;
    async fn post(&self, namespace: String, id: String, message: Vec<u8>) -> Result<()>;
    async fn read(&self, namespace: String, id: String) -> Result<()>;
}
