use crate::{
    error::Result,
    r#trait::{Bulletin, BulletinPost},
};
use async_trait::async_trait;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Mutex;

#[derive(Debug)]
pub struct DummyBulletin {
    /// Storage for posts: (namespace, id) -> BulletinPost
    posts: Mutex<HashMap<(String, String), BulletinPost>>,
}

#[async_trait]
impl Bulletin for DummyBulletin {
    async fn register(&self, _namespace: String) -> Result<()> {
        Ok(())
    }

    async fn post(
        &self,
        namespace: String,
        payload: Vec<u8>,
        proof: Vec<u8>,
        _artifact: Option<String>,
    ) -> Result<()> {
        // Generate deterministic ID from full namespace + payload (same as SourceHubBulletin)
        let full_namespace = format!("bulletin/{}", namespace);
        let id = Self::compute_post_id(&full_namespace, &payload);

        let post = BulletinPost {
            id: id.clone(),
            namespace: namespace.clone(),
            payload,
            proof,
        };

        let mut posts = self.posts.lock().unwrap();
        posts.insert((namespace, id), post);
        Ok(())
    }

    async fn read(&self, namespace: String, id: String) -> Result<BulletinPost> {
        let posts = self.posts.lock().unwrap();
        Ok(posts.get(&(namespace, id)).cloned().unwrap_or_default())
    }

    fn get_post_id(&self, namespace: &str, payload: &[u8]) -> Result<String> {
        Ok(Self::compute_post_id(namespace, payload))
    }
}

impl DummyBulletin {
    pub async fn new() -> Result<Self> {
        Ok(DummyBulletin {
            posts: Mutex::new(HashMap::new()),
        })
    }

    /// Set a post directly (for test setup)
    pub fn set_post(&self, namespace: String, id: String, post: BulletinPost) {
        let mut posts = self.posts.lock().unwrap();
        posts.insert((namespace, id), post);
    }

    /// Compute deterministic post ID from namespace and payload
    /// This matches the SourceHubBulletin implementation
    fn compute_post_id(namespace: &str, payload: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(namespace.as_bytes());
        hasher.update(payload);
        hex::encode(hasher.finalize())
    }

    /// Get all posts in a given namespace (for testing)
    pub fn get_posts_by_namespace(&self, namespace: &str) -> Vec<BulletinPost> {
        let posts = self.posts.lock().unwrap();
        posts
            .iter()
            .filter(|((ns, _), _)| ns == namespace)
            .map(|(_, post)| post.clone())
            .collect()
    }
}
