use crate::{
    error::{BulletinError, Result},
    r#trait::{
        Bulletin, BulletinKind, BulletinPost, BulletinReportSubmission, BulletinWriteKind,
        DocumentPayload, KeyDerivation, NodeInfo, RingCancellationPayload, RingFinalizationPayload,
        RingPayload,
    },
};
use async_trait::async_trait;
use common::blockchain::orbis::{
    generate_document_id, generate_key_derivation_id,
    ring_reshare_finalize_sign_bytes as orbis_ring_reshare_finalize_sign_bytes,
};
use std::collections::HashMap;
use std::sync::Mutex;

#[derive(Debug)]
pub struct DummyBulletin {
    /// Storage for typed Orbis objects by object ID.
    posts: Mutex<HashMap<String, BulletinPost>>,
    /// Pending fresh-DKG aggregate public key candidates by ring ID.
    pending_finalization_ring_pks: Mutex<HashMap<String, String>>,
    /// Successful fresh-DKG finalization confirmations by ring ID.
    finalization_counts: Mutex<HashMap<String, usize>>,
    /// Test-only failure injection for pending-ring cancellation.
    fail_pending_ring_cancellations: Mutex<bool>,
    /// Accumulated fault reports submitted via submit_report() — useful for test assertions.
    submitted_reports: Mutex<Vec<BulletinReportSubmission>>,
    /// Node demerit points by (ring_id, node_key) — for test assertions.
    node_demerits: Mutex<HashMap<(String, String), u64>>,
}

#[async_trait]
impl Bulletin for DummyBulletin {
    async fn post(&self, kind: BulletinWriteKind, payload: Vec<u8>) -> Result<String> {
        let id =
            match kind {
                BulletinWriteKind::Finalize => {
                    let finalize: RingFinalizationPayload = serde_json::from_slice(&payload)
                        .map_err(|e| BulletinError::ParseError(e.to_string()))?;
                    return self.post_finalized_ring(finalize);
                }
                BulletinWriteKind::CancelPendingRing => {
                    let cancellation: RingCancellationPayload = serde_json::from_slice(&payload)
                        .map_err(|e| BulletinError::ParseError(e.to_string()))?;
                    return self.cancel_pending_ring(cancellation);
                }
                BulletinWriteKind::NodeInfo => return Err(BulletinError::ParseError(
                    "DummyBulletin cannot derive a NodeInfo id; use set_node_info for test setup"
                        .to_string(),
                )),
                BulletinWriteKind::Document => Self::document_id(&payload)?,
                BulletinWriteKind::KeyDerivation => Self::key_derivation_id(&payload)?,
            };

        let post = BulletinPost {
            id: id.clone(),
            payload,
        };

        let mut posts = self.posts.lock().unwrap();
        posts.insert(id.clone(), post);
        Ok(id)
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

    async fn submit_report(&self, submission: BulletinReportSubmission) -> Result<()> {
        self.submitted_reports.lock().unwrap().push(submission);
        Ok(())
    }

    fn chain_id(&self) -> String {
        "sourcehub-localnet".to_string()
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
}

impl DummyBulletin {
    fn cancel_pending_ring(&self, cancellation: RingCancellationPayload) -> Result<String> {
        if *self.fail_pending_ring_cancellations.lock().unwrap() {
            return Err(BulletinError::ChainError(
                "injected pending ring cancellation failure".to_string(),
            ));
        }

        let mut posts = self.posts.lock().unwrap();
        let post = posts
            .get(&cancellation.ring_id)
            .ok_or_else(|| BulletinError::NotFound {
                id: cancellation.ring_id.clone(),
            })?;
        let payload: RingPayload = serde_json::from_slice(&post.payload)
            .map_err(|e| BulletinError::ParseError(e.to_string()))?;
        if !payload.ring_pk.is_empty() {
            return Err(BulletinError::ParseError(format!(
                "ring {} is already finalized",
                cancellation.ring_id
            )));
        }

        posts.remove(&cancellation.ring_id);
        self.pending_finalization_ring_pks
            .lock()
            .unwrap()
            .remove(&cancellation.ring_id);
        self.finalization_counts
            .lock()
            .unwrap()
            .remove(&cancellation.ring_id);
        Ok(cancellation.ring_id)
    }

    fn post_finalized_ring(&self, finalize: RingFinalizationPayload) -> Result<String> {
        let mut posts = self.posts.lock().unwrap();
        let post = posts
            .get_mut(&finalize.ring_id)
            .ok_or_else(|| BulletinError::NotFound {
                id: finalize.ring_id.clone(),
            })?;
        let mut payload: RingPayload = serde_json::from_slice(&post.payload)
            .map_err(|e| BulletinError::ParseError(e.to_string()))?;
        let participant_count = payload.peer_node_keys.len();
        if participant_count == 0 {
            return Err(BulletinError::ParseError(format!(
                "ring {} has no peer_node_keys",
                finalize.ring_id
            )));
        }

        if payload.ring_pk.is_empty() {
            {
                let mut pending = self.pending_finalization_ring_pks.lock().unwrap();
                if let Some(pending_ring_pk) = pending.get(&finalize.ring_id) {
                    if pending_ring_pk != &finalize.ring_pk {
                        return Err(BulletinError::ParseError(format!(
                            "ring_pk conflict for ring {}",
                            finalize.ring_id
                        )));
                    }
                } else {
                    pending.insert(finalize.ring_id.clone(), finalize.ring_pk.clone());
                }
            }

            let finalization_count = {
                let mut counts = self.finalization_counts.lock().unwrap();
                let count = counts.entry(finalize.ring_id.clone()).or_default();
                *count += 1;
                *count
            };

            if finalization_count >= participant_count {
                payload.ring_pk = finalize.ring_pk;
                post.payload = serde_json::to_vec(&payload)
                    .map_err(|e| BulletinError::ParseError(e.to_string()))?;
                self.pending_finalization_ring_pks
                    .lock()
                    .unwrap()
                    .remove(&finalize.ring_id);
            }

            return Ok(finalize.ring_id);
        }

        if payload.ring_pk == finalize.ring_pk {
            *self
                .finalization_counts
                .lock()
                .unwrap()
                .entry(finalize.ring_id.clone())
                .or_default() += 1;
            return Ok(finalize.ring_id);
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
            pending_finalization_ring_pks: Mutex::new(HashMap::new()),
            finalization_counts: Mutex::new(HashMap::new()),
            fail_pending_ring_cancellations: Mutex::new(false),
            submitted_reports: Mutex::new(Vec::new()),
            node_demerits: Mutex::new(HashMap::new()),
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

    /// Drain and return all fault reports submitted via submit_report().
    pub fn take_submitted_reports(&self) -> Vec<BulletinReportSubmission> {
        std::mem::take(&mut *self.submitted_reports.lock().unwrap())
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

    /// Set a ring record directly for test setup.
    pub fn set_ring(&self, ring_id: String, ring_payload: RingPayload) -> Result<()> {
        let payload: Vec<u8> = ring_payload.try_into()?;
        self.set_post(
            ring_id.clone(),
            BulletinPost {
                id: ring_id,
                payload,
            },
        );
        Ok(())
    }

    fn document_id(payload: &[u8]) -> Result<String> {
        let doc: DocumentPayload = serde_json::from_slice(payload)
            .map_err(|e| BulletinError::ParseError(e.to_string()))?;
        Ok(generate_document_id(
            &doc.ring_id,
            &doc.document,
            &doc.proof,
            &doc.policy_id,
            &doc.resource,
            &doc.permission,
            doc.tier.as_deref(),
            doc.timestamp,
        ))
    }

    fn key_derivation_id(payload: &[u8]) -> Result<String> {
        let kd: KeyDerivation = serde_json::from_slice(payload)
            .map_err(|e| BulletinError::ParseError(e.to_string()))?;
        Ok(generate_key_derivation_id(
            &kd.ring_id,
            &kd.derivation,
            &kd.policy_id,
            &kd.resource,
            &kd.permission,
        ))
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

    pub fn set_fail_pending_ring_cancellations(&self, fail: bool) {
        *self.fail_pending_ring_cancellations.lock().unwrap() = fail;
    }

    /// Set node demerit points directly for test setup.
    pub fn set_node_demerits(&self, ring_id: &str, node_key: &str, points: u64) {
        self.node_demerits
            .lock()
            .unwrap()
            .insert((ring_id.to_string(), node_key.to_string()), points);
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
            upgrade_info: crate::r#trait::UpgradeInfo {
                current_version: 1,
                next_version: Some(2),
                activation_time: Some(500),
            },
            ..Default::default()
        };
        let ring_id = "test-pending-ring".to_string();
        bulletin
            .set_ring(ring_id.clone(), payload)
            .expect("seed pending ring");
        (bulletin, ring_id)
    }

    async fn post_finalized_ring(
        bulletin: &DummyBulletin,
        ring_id: &str,
        ring_pk: &str,
    ) -> Result<String> {
        let payload = RingFinalizationPayload {
            ring_id: ring_id.to_string(),
            ring_pk: ring_pk.to_string(),
        };
        let payload_bytes: Vec<u8> = payload.try_into()?;
        bulletin
            .post(BulletinWriteKind::Finalize, payload_bytes)
            .await
    }

    async fn read_ring_payload(bulletin: &DummyBulletin, ring_id: &str) -> RingPayload {
        let post = bulletin
            .read(ring_id.to_string(), BulletinKind::Ring)
            .await
            .expect("read ring");
        RingPayload::try_from(post).expect("parse ring")
    }

    #[tokio::test]
    async fn finalize_ring_sets_ring_pk_after_all_participants_confirm() {
        let (bulletin, ring_id) = pending_ring_fixture();

        post_finalized_ring(&bulletin, &ring_id, "ring-pk")
            .await
            .expect("finalize ring through post");

        let payload = read_ring_payload(&bulletin, &ring_id).await;
        assert_eq!(payload.ring_pk, "");
        assert_eq!(bulletin.finalization_count(&ring_id), 1);

        post_finalized_ring(&bulletin, &ring_id, "ring-pk")
            .await
            .expect("second finalize ring through post");

        let payload = read_ring_payload(&bulletin, &ring_id).await;
        assert_eq!(payload.ring_pk, "ring-pk");
        assert_eq!(payload.upgrade_info.current_version, 1);
        assert_eq!(payload.upgrade_info.next_version, Some(2));
        assert_eq!(payload.upgrade_info.activation_time, Some(500));
        assert_eq!(bulletin.finalization_count(&ring_id), 2);
    }

    #[tokio::test]
    async fn finalize_ring_accepts_matching_confirmations() {
        let (bulletin, ring_id) = pending_ring_fixture();

        post_finalized_ring(&bulletin, &ring_id, "ring-pk")
            .await
            .expect("first finalize");
        post_finalized_ring(&bulletin, &ring_id, "ring-pk")
            .await
            .expect("matching repeat finalize");

        let payload = read_ring_payload(&bulletin, &ring_id).await;
        assert_eq!(payload.ring_pk, "ring-pk");
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
        let payload = read_ring_payload(&bulletin, &ring_id).await;
        assert_eq!(payload.ring_pk, "");
    }

    #[tokio::test]
    async fn cancel_pending_ring_deletes_ring_and_finalization_state() {
        let (bulletin, ring_id) = pending_ring_fixture();

        post_finalized_ring(&bulletin, &ring_id, "ring-pk")
            .await
            .expect("record first finalization");
        assert_eq!(bulletin.finalization_count(&ring_id), 1);

        let cancellation = RingCancellationPayload {
            ring_id: ring_id.clone(),
        };
        let payload_bytes: Vec<u8> = cancellation.try_into().expect("serialize cancellation");
        let cancelled_id = bulletin
            .post(BulletinWriteKind::CancelPendingRing, payload_bytes)
            .await
            .expect("cancel pending ring");
        assert_eq!(cancelled_id, ring_id);
        assert!(matches!(
            bulletin.read(ring_id.clone(), BulletinKind::Ring).await,
            Err(BulletinError::NotFound { .. })
        ));
        assert_eq!(bulletin.finalization_count(&ring_id), 0);

        let replacement = RingPayload {
            ring_pk: String::new(),
            peer_node_keys: vec!["node-a".to_string(), "node-b".to_string()],
            threshold: 2,
            ..Default::default()
        };
        bulletin
            .set_ring(ring_id.clone(), replacement)
            .expect("seed replacement ring");
        post_finalized_ring(&bulletin, &ring_id, "replacement-pk")
            .await
            .expect("old pending ring_pk state should be cleared");
        assert_eq!(bulletin.finalization_count(&ring_id), 1);
    }
}
