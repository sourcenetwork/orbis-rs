use crate::{
    error::Result,
    r#trait::{Bulletin, BulletinPost},
};
use async_trait::async_trait;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Mutex;

pub struct DummyBulletin {
    /// Storage for posts: (namespace, id) -> BulletinPost
    posts: Mutex<HashMap<(String, String), BulletinPost>>,
}

#[async_trait]
impl Bulletin for DummyBulletin {
    async fn register(&self, _namespace: String) -> Result<()> {
        Ok(())
    }

    async fn post(&self, namespace: String, payload: Vec<u8>, proof: Vec<u8>) -> Result<()> {
        // Generate deterministic ID from namespace + payload (same as SourceHubBulletin)
        let id = Self::compute_post_id(&namespace, &payload);

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

    /// Get the ID that would be generated for a given namespace and payload
    /// Useful for tests that need to know the ID before reading
    pub fn get_post_id(namespace: &str, payload: &[u8]) -> String {
        Self::compute_post_id(namespace, payload)
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
