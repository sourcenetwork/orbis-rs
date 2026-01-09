use crate::{
    error::Result,
    r#trait::{Bulletin, BulletinPost},
};
use async_trait::async_trait;
use std::sync::Mutex;

pub struct DummyBulletin {
    post: Mutex<BulletinPost>,
}

#[async_trait]
impl Bulletin for DummyBulletin {
    async fn register(&self, _namespace: String) -> Result<()> {
        Ok(())
    }
    async fn post(&self, _namespace: String, _id: String, _message: Vec<u8>) -> Result<()> {
        Ok(())
    }
    async fn read(&self, _namespace: String, _id: String) -> Result<BulletinPost> {
        Ok(self.post.lock().unwrap().clone())
    }
}

impl DummyBulletin {
    pub fn new() -> Self {
        DummyBulletin {
            post: Mutex::new(BulletinPost::default()),
        }
    }

    pub fn set_post(&self, post: BulletinPost) {
        *self.post.lock().unwrap() = post;
    }
}
