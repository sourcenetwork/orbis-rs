use crate::{
    error::{BulletinError, Result},
    r#trait::{
        Bulletin, BulletinKind, BulletinPost, DocumentPayload, KeyDerivation, NodeInfo, RingPayload,
    },
};
use async_trait::async_trait;
use common::blockchain::orbis::{
    generate_document_id, generate_key_derivation_id, generate_ring_id,
    ring_reshare_finalize_sign_bytes as orbis_ring_reshare_finalize_sign_bytes,
};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Mutex;

#[derive(Debug)]
pub struct DummyBulletin {
    /// Storage for typed Orbis objects by object ID.
    posts: Mutex<HashMap<String, BulletinPost>>,
}

#[async_trait]
impl Bulletin for DummyBulletin {
    async fn register(&self) -> Result<()> {
        Ok(())
    }

    async fn post(
        &self,
        kind: BulletinKind,
        payload: Vec<u8>,
        _artifact: Option<String>,
    ) -> Result<()> {
        let id = match kind {
            BulletinKind::NodeInfo => {
                return Err(BulletinError::ParseError(
                    "DummyBulletin cannot derive a NodeInfo id; use set_node_info for test setup"
                        .to_string(),
                ))
            }
            _ => Self::typed_post_id(&payload).unwrap_or_else(|| Self::compute_post_id(&payload)),
        };

        let post = BulletinPost {
            id: id.clone(),
            payload,
        };

        let mut posts = self.posts.lock().unwrap();
        posts.insert(id, post);
        Ok(())
    }

    async fn update(
        &self,
        id: String,
        _signature_scheme: String,
        _signature: Vec<u8>,
    ) -> Result<()> {
        let mut posts = self.posts.lock().unwrap();
        let post = posts.get_mut(&id).ok_or(BulletinError::NotFound { id })?;
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

    async fn read(&self, id: String, _kind: BulletinKind) -> Result<BulletinPost> {
        let posts = self.posts.lock().unwrap();
        posts
            .get(&id)
            .cloned()
            .ok_or(BulletinError::NotFound { id })
    }

    fn chain_id(&self) -> String {
        "sourcehub-localnet".to_string()
    }

    fn get_post_id(&self, payload: &[u8]) -> Result<String> {
        Ok(Self::typed_post_id(payload).unwrap_or_else(|| Self::compute_post_id(payload)))
    }

    fn get_ring_id(
        &self,
        peer_ids: &[String],
        threshold: u32,
        pss_interval: Option<u64>,
        policy_id: &str,
        nonce: Option<&str>,
    ) -> Result<String> {
        Ok(common::blockchain::orbis::generate_ring_id(
            peer_ids,
            threshold,
            pss_interval,
            policy_id,
            nonce,
        ))
    }

    async fn ring_canonical_hash(&self, ring_id: &str) -> Result<[u8; 32]> {
        let posts = self.posts.lock().unwrap();
        let post = posts.get(ring_id).ok_or_else(|| BulletinError::NotFound {
            id: ring_id.to_string(),
        })?;
        Ok(Sha256::digest(&post.payload).into())
    }

    fn ring_reshare_finalize_sign_bytes(
        &self,
        chain_id: &str,
        ring_id: &str,
        ring_pk: &str,
        current_ring_sha256: Vec<u8>,
        finalized_ring_sha256: Vec<u8>,
        block_number_nonce: u64,
    ) -> Result<Vec<u8>> {
        orbis_ring_reshare_finalize_sign_bytes(
            chain_id,
            ring_id,
            ring_pk,
            current_ring_sha256,
            finalized_ring_sha256,
            block_number_nonce,
        )
        .map_err(|e| BulletinError::ParseError(e.to_string()))
    }

    async fn ring_finalized_canonical_hash(&self, ring_id: &str) -> Result<[u8; 32]> {
        let posts = self.posts.lock().unwrap();
        let post = posts.get(ring_id).ok_or_else(|| BulletinError::NotFound {
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
    pub fn set_post(&self, id: String, post: BulletinPost) {
        let mut posts = self.posts.lock().unwrap();
        posts.insert(id, post);
    }

    /// Set a node info record directly for test setup.
    pub fn set_node_info(&self, node_key: String, node_info: NodeInfo) -> Result<()> {
        let payload: Vec<u8> = node_info.try_into()?;
        self.set_post(
            node_key.clone(),
            BulletinPost {
                id: node_key,
                payload,
            },
        );
        Ok(())
    }

    /// Compute deterministic post ID from raw payload bytes for non-typed test payloads.
    fn compute_post_id(payload: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(payload);
        hex::encode(hasher.finalize())
    }

    fn typed_post_id(payload: &[u8]) -> Option<String> {
        if let Ok(doc) = serde_json::from_slice::<DocumentPayload>(payload) {
            return Some(generate_document_id(
                &doc.ring_id,
                &doc.document,
                &doc.proof,
                &doc.policy_id,
                &doc.resource,
                &doc.permission,
                doc.tier.as_deref(),
                doc.timestamp,
            ));
        }
        if let Ok(kd) = serde_json::from_slice::<KeyDerivation>(payload) {
            return Some(generate_key_derivation_id(
                &kd.ring_id,
                &kd.derivation,
                &kd.policy_id,
                &kd.resource,
                &kd.permission,
            ));
        }
        if let Ok(ring) = serde_json::from_slice::<RingPayload>(payload) {
            return Some(generate_ring_id(
                &ring.peer_ids,
                ring.threshold,
                ring.pss_interval,
                ring.policy_id.as_deref().unwrap_or(""),
                None,
            ));
        }
        None
    }

    /// Get all posts (for testing).
    pub fn get_posts(&self) -> Vec<BulletinPost> {
        let posts = self.posts.lock().unwrap();
        posts.values().cloned().collect()
    }
}
