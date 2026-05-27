use crate::{
    error::{BulletinError, Result},
    r#trait::{
        Bulletin, BulletinKind, BulletinPost, DocumentPayload, KeyDerivation, NodeInfo,
        RingFinalizationPayload, RingPayload,
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
    /// Successful fresh-DKG finalization confirmations by ring ID.
    finalization_counts: Mutex<HashMap<String, usize>>,
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
            BulletinKind::Finalize => {
                let finalize: RingFinalizationPayload = serde_json::from_slice(&payload)
                    .map_err(|e| BulletinError::ParseError(e.to_string()))?;
                return self.post_finalized_ring(finalize);
            }
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
        let new_peer_node_keys = payload.new_peer_node_keys.take().ok_or_else(|| {
            BulletinError::ParseError(
                "ring payload is missing new_peer_node_keys for update".to_string(),
            )
        })?;
        let new_threshold = payload.new_threshold.take().ok_or_else(|| {
            BulletinError::ParseError(
                "ring payload is missing new_threshold for update".to_string(),
            )
        })?;
        payload.peer_node_keys = new_peer_node_keys;
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
        peer_node_keys: &[String],
        threshold: u32,
        pss_interval: Option<u64>,
        policy_id: &str,
        nonce: Option<&str>,
    ) -> Result<String> {
        Ok(common::blockchain::orbis::generate_ring_id(
            peer_node_keys,
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
        let new_peer_node_keys = payload
            .new_peer_node_keys
            .take()
            .unwrap_or_else(|| payload.peer_node_keys.clone());
        let new_threshold = payload.new_threshold.take().unwrap_or(payload.threshold);
        payload.peer_node_keys = new_peer_node_keys;
        payload.threshold = new_threshold;
        let finalized_bytes =
            serde_json::to_vec(&payload).map_err(|e| BulletinError::ParseError(e.to_string()))?;
        Ok(Sha256::digest(&finalized_bytes).into())
    }
}

impl DummyBulletin {
    fn post_finalized_ring(&self, finalize: RingFinalizationPayload) -> Result<()> {
        let mut posts = self.posts.lock().unwrap();
        let post = posts
            .get_mut(&finalize.ring_id)
            .ok_or_else(|| BulletinError::NotFound {
                id: finalize.ring_id.clone(),
            })?;
        let mut payload: RingPayload = serde_json::from_slice(&post.payload)
            .map_err(|e| BulletinError::ParseError(e.to_string()))?;

        if payload.ring_pk.is_empty() {
            payload.ring_pk = finalize.ring_pk;
            post.payload = serde_json::to_vec(&payload)
                .map_err(|e| BulletinError::ParseError(e.to_string()))?;
            *self
                .finalization_counts
                .lock()
                .unwrap()
                .entry(finalize.ring_id)
                .or_default() += 1;
            return Ok(());
        }

        if payload.ring_pk == finalize.ring_pk {
            *self
                .finalization_counts
                .lock()
                .unwrap()
                .entry(finalize.ring_id)
                .or_default() += 1;
            return Ok(());
        }

        Err(BulletinError::ParseError(format!(
            "ring_pk conflict for ring {}",
            finalize.ring_id
        )))
    }
}

impl Default for DummyBulletin {
    fn default() -> Self {
        DummyBulletin {
            posts: Mutex::new(HashMap::new()),
            finalization_counts: Mutex::new(HashMap::new()),
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
                &ring.peer_node_keys,
                ring.threshold,
                ring.pss_interval,
                ring.policy_id.as_deref().unwrap_or(""),
                None,
            ));
        }
        if let Ok(finalize) = serde_json::from_slice::<RingFinalizationPayload>(payload) {
            return Some(finalize.ring_id);
        }
        None
    }

    /// Get all posts (for testing).
    pub fn get_posts(&self) -> Vec<BulletinPost> {
        let posts = self.posts.lock().unwrap();
        posts.values().cloned().collect()
    }

    pub fn finalization_count(&self, ring_id: &str) -> usize {
        self.finalization_counts
            .lock()
            .unwrap()
            .get(ring_id)
            .copied()
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pending_ring_fixture() -> (DummyBulletin, String) {
        let bulletin = DummyBulletin::default();
        let payload = RingPayload {
            ring_pk: String::new(),
            peer_node_keys: vec!["node-a".to_string(), "node-b".to_string()],
            threshold: 2,
            policy_id: Some("policy-a".to_string()),
            ..Default::default()
        };
        let ring_id = bulletin
            .get_ring_id(
                &payload.peer_node_keys,
                payload.threshold,
                payload.pss_interval,
                payload.policy_id.as_deref().unwrap_or(""),
                None,
            )
            .expect("ring id");
        let payload_bytes: Vec<u8> = payload.try_into().expect("serialize ring");
        bulletin.set_post(
            ring_id.clone(),
            BulletinPost {
                id: ring_id.clone(),
                payload: payload_bytes,
            },
        );
        (bulletin, ring_id)
    }

    async fn post_finalized_ring(
        bulletin: &DummyBulletin,
        ring_id: &str,
        ring_pk: &str,
    ) -> Result<()> {
        let payload = RingFinalizationPayload {
            ring_id: ring_id.to_string(),
            ring_pk: ring_pk.to_string(),
        };
        let payload_bytes: Vec<u8> = payload.try_into()?;
        bulletin
            .post(BulletinKind::Finalize, payload_bytes, None)
            .await
    }

    #[tokio::test]
    async fn finalize_ring_sets_ring_pk() {
        let (bulletin, ring_id) = pending_ring_fixture();

        post_finalized_ring(&bulletin, &ring_id, "ring-pk")
            .await
            .expect("finalize ring through post");

        let post = bulletin
            .read(ring_id.clone(), BulletinKind::Ring)
            .await
            .expect("read ring");
        let payload = RingPayload::try_from(post).expect("parse ring");
        assert_eq!(payload.ring_pk, "ring-pk");
        assert_eq!(bulletin.finalization_count(&ring_id), 1);
    }

    #[tokio::test]
    async fn finalize_ring_accepts_matching_repeat() {
        let (bulletin, ring_id) = pending_ring_fixture();

        post_finalized_ring(&bulletin, &ring_id, "ring-pk")
            .await
            .expect("first finalize");
        post_finalized_ring(&bulletin, &ring_id, "ring-pk")
            .await
            .expect("matching repeat finalize");

        assert_eq!(bulletin.finalization_count(&ring_id), 2);
    }

    #[tokio::test]
    async fn finalize_ring_rejects_conflict_without_deleting() {
        let (bulletin, ring_id) = pending_ring_fixture();

        post_finalized_ring(&bulletin, &ring_id, "ring-pk")
            .await
            .expect("first finalize");
        let result = post_finalized_ring(&bulletin, &ring_id, "other-ring-pk").await;

        assert!(result.is_err());
        assert_eq!(bulletin.finalization_count(&ring_id), 1);
        let post = bulletin
            .read(ring_id, BulletinKind::Ring)
            .await
            .expect("ring remains present");
        let payload = RingPayload::try_from(post).expect("parse ring");
        assert_eq!(payload.ring_pk, "ring-pk");
    }
}
