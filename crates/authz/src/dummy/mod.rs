use crate::{error::Result, r#trait::Authz};
use async_trait::async_trait;

pub struct DummyAuthZ;

#[async_trait]
impl Authz for DummyAuthZ {
    async fn check(&self, _permission: Vec<u8>, _subject: &str) -> Result<bool> {
        Ok(true)
    }

    async fn check_at(&self, _permission: Vec<u8>, _subject: &str, _anchor: &str) -> Result<bool> {
        Ok(true)
    }

    async fn current_anchor(&self) -> Result<String> {
        Ok("0".to_string())
    }

    async fn anchor_time(&self, _anchor: &str) -> Result<u64> {
        Ok(0)
    }
}

impl DummyAuthZ {
    pub fn name() -> String {
        "authz/dummy".to_string()
    }

    pub async fn new() -> Result<Self> {
        Ok(DummyAuthZ)
    }
}
