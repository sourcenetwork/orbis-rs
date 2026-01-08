use crate::error::Result;
use async_trait::async_trait;

#[async_trait]
pub trait Bulletin {
    async fn post(&self) -> Result<()>;
    async fn read(&self) -> Result<()>;
}
