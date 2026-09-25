//! PET Response State Management
//!
//! Tracks the collection of threshold PET-check responses from ring nodes,
//! mirroring `pre::v0::response_state::PreResponseManager` (both are thin
//! wrappers over the shared `helpers::response_manager::ResponseManager`).

use crate::constants::MAX_PET_RESPONSES;
use crate::helpers::response_manager::{
    ResponseInitOutcome, ResponseManager, ResponseStoreOutcome,
};
use crate::pet::v0::messages::PetMessage;

/// PET Response State Manager.
pub struct PetResponseManager {
    inner: ResponseManager<PetMessage>,
}

impl PetResponseManager {
    fn key(protocol_version: u64, request_id: &str) -> String {
        format!("v{protocol_version}:{request_id}")
    }

    pub fn new() -> Self {
        Self {
            inner: ResponseManager::new(MAX_PET_RESPONSES, "PET"),
        }
    }

    pub(crate) async fn init_response_for_version(
        &self,
        protocol_version: u64,
        request_id: String,
        expected_peer_ids: &[String],
    ) -> ResponseInitOutcome {
        self.inner
            .init_response(Self::key(protocol_version, &request_id), expected_peer_ids)
            .await
    }

    pub(crate) async fn store_response_for_version(
        &self,
        protocol_version: u64,
        request_id: &str,
        message: PetMessage,
        sender_peer_bytes: &[u8],
    ) -> ResponseStoreOutcome {
        let key = Self::key(protocol_version, request_id);
        self.inner
            .store_response(&key, message, sender_peer_bytes)
            .await
    }

    pub(crate) async fn remove_response_for_version(
        &self,
        protocol_version: u64,
        request_id: &str,
    ) {
        let key = Self::key(protocol_version, request_id);
        self.inner.remove_response(&key).await
    }
}

impl Default for PetResponseManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
impl PetResponseManager {
    pub(crate) async fn pending_count(&self) -> usize {
        self.inner.pending_count().await
    }

    pub(crate) async fn get_responses(&self, request_id: &str) -> Option<Vec<PetMessage>> {
        self.get_responses_for_version(network::V0.version, request_id)
            .await
    }

    pub(crate) async fn get_responses_for_version(
        &self,
        protocol_version: u64,
        request_id: &str,
    ) -> Option<Vec<PetMessage>> {
        let key = Self::key(protocol_version, request_id);
        self.inner.get_responses(&key).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_response(request_id: &str, from_node_id: u32) -> PetMessage {
        PetMessage::CheckResponse {
            request_id: request_id.to_string(),
            from_node_id,
            partial: vec![1, 2, 3],
            signature: vec![4, 5, 6],
        }
    }

    fn peer_bytes(hex_id: &str) -> Vec<u8> {
        hex::decode(hex_id).unwrap()
    }

    const PEER_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const PEER_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const UNKNOWN: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

    #[tokio::test]
    async fn accepts_expected_peers() {
        let mgr = PetResponseManager::new();
        let expected = vec![PEER_A.to_string(), PEER_B.to_string()];

        assert_eq!(
            mgr.init_response_for_version(0, "req-1".into(), &expected)
                .await,
            ResponseInitOutcome::Created
        );

        mgr.store_response_for_version(0, "req-1", dummy_response("req-1", 1), &peer_bytes(PEER_A))
            .await;
        mgr.store_response_for_version(0, "req-1", dummy_response("req-1", 2), &peer_bytes(PEER_B))
            .await;

        let responses = mgr.get_responses("req-1").await.unwrap();
        assert_eq!(responses.len(), 2);
    }

    #[tokio::test]
    async fn rejects_unexpected_peer() {
        let mgr = PetResponseManager::new();
        let expected = vec![PEER_A.to_string()];

        assert_eq!(
            mgr.init_response_for_version(0, "req-1".into(), &expected)
                .await,
            ResponseInitOutcome::Created
        );

        mgr.store_response_for_version(
            0,
            "req-1",
            dummy_response("req-1", 99),
            &peer_bytes(UNKNOWN),
        )
        .await;

        let responses = mgr.get_responses("req-1").await.unwrap();
        assert_eq!(responses.len(), 0, "unexpected peer should be rejected");
    }

    #[tokio::test]
    async fn rejects_duplicate_from_same_peer() {
        let mgr = PetResponseManager::new();
        let expected = vec![PEER_A.to_string()];

        assert_eq!(
            mgr.init_response_for_version(0, "req-1".into(), &expected)
                .await,
            ResponseInitOutcome::Created
        );

        mgr.store_response_for_version(0, "req-1", dummy_response("req-1", 1), &peer_bytes(PEER_A))
            .await;
        mgr.store_response_for_version(0, "req-1", dummy_response("req-1", 1), &peer_bytes(PEER_A))
            .await;

        let responses = mgr.get_responses("req-1").await.unwrap();
        assert_eq!(
            responses.len(),
            1,
            "duplicate from same peer should be rejected"
        );
    }

    #[tokio::test]
    async fn protocol_versions_are_isolated() {
        let mgr = PetResponseManager::new();
        let expected = [PEER_A.to_string()];
        assert_eq!(
            mgr.init_response_for_version(0, "same-id".into(), &expected)
                .await,
            ResponseInitOutcome::Created
        );
        assert_eq!(
            mgr.init_response_for_version(1, "same-id".into(), &expected)
                .await,
            ResponseInitOutcome::Created
        );
        assert_eq!(
            mgr.store_response_for_version(
                1,
                "same-id",
                dummy_response("same-id", 1),
                &peer_bytes(PEER_A),
            )
            .await,
            ResponseStoreOutcome::Stored
        );

        // v0 and v1 use the same request_id string but are isolated entries:
        // only v1 has a stored response.
        assert_eq!(
            mgr.get_responses_for_version(0, "same-id")
                .await
                .unwrap()
                .len(),
            0,
            "v0 entry"
        );
        assert_eq!(
            mgr.get_responses_for_version(1, "same-id")
                .await
                .unwrap()
                .len(),
            1,
            "v1 entry"
        );
    }

    #[tokio::test]
    async fn cleanup_removes_state() {
        let mgr = PetResponseManager::new();
        let expected = vec![PEER_A.to_string()];

        assert_eq!(
            mgr.init_response_for_version(0, "req-1".into(), &expected)
                .await,
            ResponseInitOutcome::Created
        );
        mgr.store_response_for_version(0, "req-1", dummy_response("req-1", 1), &peer_bytes(PEER_A))
            .await;

        mgr.remove_response_for_version(0, "req-1").await;

        assert!(
            mgr.get_responses("req-1").await.is_none(),
            "state should be gone after cleanup"
        );
    }

    #[tokio::test]
    async fn response_limit_enforcement() {
        let mgr = PetResponseManager::new();

        for i in 0..MAX_PET_RESPONSES {
            let ok = mgr
                .init_response_for_version(0, format!("req-{}", i), &[])
                .await;
            assert_eq!(
                ok,
                ResponseInitOutcome::Created,
                "init should succeed for slot {}",
                i
            );
        }

        let rejected = mgr
            .init_response_for_version(0, "req-over-limit".into(), &[])
            .await;
        assert_ne!(
            rejected,
            ResponseInitOutcome::Created,
            "init should fail when limit is reached"
        );
        assert_eq!(mgr.pending_count().await, MAX_PET_RESPONSES);
    }
}
