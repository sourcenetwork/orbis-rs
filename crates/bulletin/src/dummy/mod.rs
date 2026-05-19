use crate::{
    error::{BulletinError, Result},
    r#trait::{Bulletin, BulletinKind, BulletinPost, RingPayload},
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
        _kind: BulletinKind,
        payload: Vec<u8>,
        _artifact: Option<String>,
    ) -> Result<()> {
        // Generate deterministic ID from namespace + payload, matching SourceHubBulletin.
        let id = Self::compute_post_id(&namespace, &payload);

        let post = BulletinPost {
            id: id.clone(),
            namespace: namespace.clone(),
            payload,
        };

        let mut posts = self.posts.lock().unwrap();
        posts.insert((namespace, id), post);
        Ok(())
    }

    async fn update(&self, namespace: String, id: String, _artifact: Option<String>) -> Result<()> {
        let mut posts = self.posts.lock().unwrap();
        let post = posts
            .get_mut(&(namespace.clone(), id.clone()))
            .ok_or(BulletinError::NotFound { namespace, id })?;
        let mut payload: RingPayload = serde_json::from_slice(&post.payload)
            .map_err(|e| BulletinError::ParseError(e.to_string()))?;
        let new_peer_ids = payload.new_peer_ids.take().ok_or_else(|| {
            BulletinError::ParseError("ring payload is missing new_peer_ids for update".to_string())
        })?;
        let new_threshold = payload.new_threshold.take().ok_or_else(|| {
            BulletinError::ParseError(
                "ring payload is missing new_threshold for update".to_string(),
            )
        })?;
        payload.peer_ids = new_peer_ids;
        payload.threshold = new_threshold;
        payload.block_number_nonce = payload.block_number_nonce.saturating_add(1);
        post.payload =
            serde_json::to_vec(&payload).map_err(|e| BulletinError::ParseError(e.to_string()))?;
        Ok(())
    }

    async fn read(
        &self,
        namespace: String,
        id: String,
        _kind: BulletinKind,
    ) -> Result<BulletinPost> {
        let posts = self.posts.lock().unwrap();
        posts
            .get(&(namespace.clone(), id.clone()))
            .cloned()
            .ok_or(BulletinError::NotFound { namespace, id })
    }

    fn chain_id(&self) -> String {
        "sourcehub-localnet".to_string()
    }

    fn get_post_id(&self, namespace: &str, payload: &[u8]) -> Result<String> {
        Ok(Self::compute_post_id(namespace, payload))
    }

    fn get_ring_id(
        &self,
        namespace: &str,
        ring_pk: &str,
        peer_ids: &[String],
        threshold: u32,
        pss_interval: Option<u64>,
        policy_id: &str,
    ) -> Result<String> {
        Ok(common::blockchain::orbis::generate_ring_id(
            namespace,
            ring_pk,
            peer_ids,
            threshold,
            pss_interval,
            policy_id,
        ))
    }

    async fn ring_canonical_hash(&self, ring_id: &str) -> Result<[u8; 32]> {
        let posts = self.posts.lock().unwrap();
        let post =
            posts
                .values()
                .find(|p| p.id == ring_id)
                .ok_or_else(|| BulletinError::NotFound {
                    namespace: String::new(),
                    id: ring_id.to_string(),
                })?;
        Ok(Sha256::digest(&post.payload).into())
    }

    async fn ring_finalized_canonical_hash(&self, ring_id: &str) -> Result<[u8; 32]> {
        let posts = self.posts.lock().unwrap();
        let post =
            posts
                .values()
                .find(|p| p.id == ring_id)
                .ok_or_else(|| BulletinError::NotFound {
                    namespace: String::new(),
                    id: ring_id.to_string(),
                })?;
        let mut payload: RingPayload = serde_json::from_slice(&post.payload)
            .map_err(|e| BulletinError::ParseError(e.to_string()))?;
        let new_peer_ids = payload
            .new_peer_ids
            .take()
            .unwrap_or_else(|| payload.peer_ids.clone());
        let new_threshold = payload.new_threshold.take().unwrap_or(payload.threshold);
        payload.peer_ids = new_peer_ids;
        payload.threshold = new_threshold;
        payload.block_number_nonce = payload.block_number_nonce.saturating_add(1);
        let finalized_bytes =
            serde_json::to_vec(&payload).map_err(|e| BulletinError::ParseError(e.to_string()))?;
        Ok(Sha256::digest(&finalized_bytes).into())
    }
}

impl Default for DummyBulletin {
    fn default() -> Self {
        DummyBulletin {
            posts: Mutex::new(HashMap::new()),
        }
    }
}

impl DummyBulletin {
    pub fn name() -> String {
        "bulletin/dummy".to_string()
    }
    pub async fn new() -> Result<Self> {
        Ok(DummyBulletin::default())
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
