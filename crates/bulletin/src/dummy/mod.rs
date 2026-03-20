use crate::{
    error::{BulletinError, Result},
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
        // Generate deterministic ID from namespace + payload, matching SourceHubBulletin.
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
        posts
            .get(&(namespace.clone(), id.clone()))
            .cloned()
            .ok_or(BulletinError::NotFound { namespace, id })
    }

    fn get_post_id(&self, namespace: &str, payload: &[u8]) -> Result<String> {
        Ok(Self::compute_post_id(namespace, payload))
    }
}

impl DummyBulletin {
    pub fn name() -> String {
        "bulletin/dummy".to_string()
    }
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

    /// Compute deterministic post ID from namespace and payload.
    /// Mirrors SourceHub's on-chain behavior: the chain stores posts under
    /// "bulletin/{namespace}", so the hash is SHA256("bulletin/{namespace}" || payload).
    fn compute_post_id(namespace: &str, payload: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(format!("bulletin/{}", namespace).as_bytes());
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
