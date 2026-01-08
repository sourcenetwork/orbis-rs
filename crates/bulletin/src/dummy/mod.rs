use crate::{
    error::Result,
    r#trait::{Bulletin, BulletinPost},
};
use async_trait::async_trait;

pub struct DummyBulletin;

#[async_trait]
impl Bulletin for DummyBulletin {
    async fn register(&self, namespace: String) -> Result<()> {
        Ok(())
    }
    async fn post(&self, namespace: String, id: String, message: Vec<u8>) -> Result<()> {
        Ok(())
    }
    async fn read(&self, namespace: String, id: String) -> Result<BulletinPost> {
        Ok(BulletinPost::default())
    }
}

impl DummyBulletin {
    pub async fn new() -> Result<Self> {
        Ok(DummyBulletin)
    }
}
