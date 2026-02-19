use crate::{error::Result, r#trait::Authz};
use async_trait::async_trait;

pub struct DummyAuthZ;

#[async_trait]
impl Authz for DummyAuthZ {
    async fn check(&self, _permission: Vec<u8>, _subject: &String) -> Result<bool> {
        Ok(true)
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
