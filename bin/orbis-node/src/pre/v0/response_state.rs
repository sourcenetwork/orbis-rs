//! PRE Response State Management
//!
//! This module tracks the state of PRE (Proxy Re-Encryption) response collection.
//! When a PRE request is initiated, responses are collected from multiple nodes
//! and stored here until the threshold is met.

use crate::constants::MAX_PRE_RESPONSES;
use crate::helpers::response_manager::{
    AuthenticatedResponse, ResponseInitOutcome, ResponseManager, ResponseStoreOutcome,
};
use crate::pre::v0::messages::PreMessage;

/// PRE Response State Manager
///
/// Manages the collection of PRE responses from multiple nodes.
/// Each PRE request gets a unique request_id and collects responses
/// until the threshold is met.
pub struct PreResponseManager {
    inner: ResponseManager<PreMessage>,
}

impl PreResponseManager {
    fn key(protocol_version: u64, request_id: &str) -> String {
        format!("v{protocol_version}:{request_id}")
    }

    pub fn new() -> Self {
        Self {
            inner: ResponseManager::new(MAX_PRE_RESPONSES, "PRE"),
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
        message: PreMessage,
        sender_peer_bytes: &[u8],
    ) -> ResponseStoreOutcome {
        let key = Self::key(protocol_version, request_id);
        self.inner
            .store_response(&key, message, sender_peer_bytes)
            .await
    }

    pub(crate) async fn take_authenticated_responses_for_version(
        &self,
        protocol_version: u64,
        request_id: &str,
    ) -> Option<Vec<AuthenticatedResponse<PreMessage>>> {
        let key = Self::key(protocol_version, request_id);
        self.inner.take_authenticated_responses(&key).await
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

impl Default for PreResponseManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
impl PreResponseManager {
    pub(crate) async fn pending_count(&self) -> usize {
        self.inner.pending_count().await
    }

    pub(crate) async fn get_responses(&self, request_id: &str) -> Option<Vec<PreMessage>> {
        let key = Self::key(network::V0.version, request_id);
        self.inner.get_responses(&key).await
    }

    pub(crate) async fn take_responses(&self, request_id: &str) -> Option<Vec<PreMessage>> {
        let key = Self::key(network::V0.version, request_id);
        self.inner.take_responses(&key).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pre::v0::messages::PreMessage;
    use std::sync::Arc;

    /// Helper: create a dummy ReencryptResponse with a given node_id
    fn dummy_response(request_id: &str, from_node_id: u32) -> PreMessage {
        PreMessage::ReencryptResponse {
            request_id: request_id.to_string(),
            from_node_id,
            share: vec![1, 2, 3],
            challenge: vec![4, 5, 6],
            proof: vec![7, 8, 9],
            signed_at: 1_700_000_000,
            response_signature: vec![10, 11, 12],
        }
    }

    /// Helper: convert a hex node ID to raw bytes (simulates PeerId::as_bytes())
    fn peer_bytes(hex_id: &str) -> Vec<u8> {
        hex::decode(hex_id).unwrap()
    }

    const PEER_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const PEER_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const UNKNOWN: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

    #[tokio::test]
    async fn test_accepts_expected_peers() {
        let mgr = PreResponseManager::new();
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
    async fn test_rejects_unexpected_peer() {
        let mgr = PreResponseManager::new();
        let expected = vec![PEER_A.to_string(), PEER_B.to_string()];

        assert_eq!(
            mgr.init_response_for_version(0, "req-1".into(), &expected)
                .await,
            ResponseInitOutcome::Created
        );

        // Unknown peer tries to respond
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
    async fn test_rejects_duplicate_from_same_peer() {
        let mgr = PreResponseManager::new();
        let expected = vec![PEER_A.to_string(), PEER_B.to_string()];

        assert_eq!(
            mgr.init_response_for_version(0, "req-1".into(), &expected)
                .await,
            ResponseInitOutcome::Created
        );

        mgr.store_response_for_version(0, "req-1", dummy_response("req-1", 1), &peer_bytes(PEER_A))
            .await;
        // Same peer tries again
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
    async fn test_take_responses_consumes_entry() {
        let mgr = PreResponseManager::new();
        let expected = vec![PEER_A.to_string()];

        assert_eq!(
            mgr.init_response_for_version(0, "req-take".into(), &expected)
                .await,
            ResponseInitOutcome::Created
        );
        mgr.store_response_for_version(
            0,
            "req-take",
            dummy_response("req-take", 1),
            &peer_bytes(PEER_A),
        )
        .await;

        // take_responses should return the responses…
        let taken = mgr.take_responses("req-take").await;
        assert!(taken.is_some());
        assert_eq!(taken.unwrap().len(), 1);

        // …and the entry should be gone afterwards
        assert!(
            mgr.get_responses("req-take").await.is_none(),
            "entry must be removed after take_responses"
        );
    }

    #[tokio::test]
    async fn test_rejects_peer_impersonating_another_node_id() {
        let mgr = PreResponseManager::new();
        let expected = vec![PEER_A.to_string(), PEER_B.to_string()];

        assert_eq!(
            mgr.init_response_for_version(0, "req-1".into(), &expected)
                .await,
            ResponseInitOutcome::Created
        );

        // PEER_A responds legitimately
        mgr.store_response_for_version(0, "req-1", dummy_response("req-1", 1), &peer_bytes(PEER_A))
            .await;
        // PEER_A tries again but claims to be node 2 — still rejected (same peer bytes)
        mgr.store_response_for_version(0, "req-1", dummy_response("req-1", 2), &peer_bytes(PEER_A))
            .await;

        let responses = mgr.get_responses("req-1").await.unwrap();
        assert_eq!(
            responses.len(),
            1,
            "same peer with different node_id should still be rejected"
        );
    }

    #[tokio::test]
    async fn test_expected_peers_with_address_suffix() {
        let mgr = PreResponseManager::new();
        // Peer IDs with @address suffixes (as they come from the ring)
        let expected = vec![
            format!("{}@192.168.1.1:4000", PEER_A),
            format!("{}@192.168.1.2:4000", PEER_B),
        ];

        assert_eq!(
            mgr.init_response_for_version(0, "req-1".into(), &expected)
                .await,
            ResponseInitOutcome::Created
        );

        // Raw peer bytes match the hex node part (before @)
        mgr.store_response_for_version(0, "req-1", dummy_response("req-1", 1), &peer_bytes(PEER_A))
            .await;
        mgr.store_response_for_version(0, "req-1", dummy_response("req-1", 2), &peer_bytes(PEER_B))
            .await;

        let responses = mgr.get_responses("req-1").await.unwrap();
        assert_eq!(
            responses.len(),
            2,
            "peers with @address suffix should still match"
        );
    }

    #[tokio::test]
    async fn test_cleanup_removes_state() {
        let mgr = PreResponseManager::new();
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
    async fn test_init_rejects_duplicate_request_id() {
        let mgr = PreResponseManager::new();
        let expected = vec![PEER_A.to_string()];

        assert_eq!(
            mgr.init_response_for_version(0, "req-1".into(), &expected)
                .await,
            ResponseInitOutcome::Created
        );
        assert_ne!(
            mgr.init_response_for_version(0, "req-1".into(), &expected)
                .await,
            ResponseInitOutcome::Created,
            "duplicate request_id should be rejected"
        );
    }

    // =========================================================================
    // Concurrent access
    // =========================================================================

    #[tokio::test]
    async fn test_concurrent_init_same_request_id() {
        let mgr = Arc::new(PreResponseManager::new());
        let m1 = mgr.clone();
        let m2 = mgr.clone();
        let e1 = vec![PEER_A.to_string()];
        let e2 = vec![PEER_A.to_string()];

        let (r1, r2) = tokio::join!(
            async move {
                m1.init_response_for_version(0, "req-race".into(), &e1)
                    .await
            },
            async move {
                m2.init_response_for_version(0, "req-race".into(), &e2)
                    .await
            },
        );

        // The write lock serialises both inits; exactly one must win
        assert_ne!(r1, r2, "exactly one concurrent init should succeed");
        assert_eq!(mgr.pending_count().await, 1);
    }

    #[tokio::test]
    async fn test_concurrent_take_responses() {
        let mgr = Arc::new(PreResponseManager::new());
        mgr.init_response_for_version(0, "req-take-race".into(), &[PEER_A.to_string()])
            .await;
        mgr.store_response_for_version(
            0,
            "req-take-race",
            dummy_response("req-take-race", 1),
            &peer_bytes(PEER_A),
        )
        .await;

        let m1 = mgr.clone();
        let m2 = mgr.clone();

        let (r1, r2) = tokio::join!(
            async move { m1.take_responses("req-take-race").await },
            async move { m2.take_responses("req-take-race").await },
        );

        // Exactly one task removes the entry; the other gets None
        assert_ne!(
            r1.is_some(),
            r2.is_some(),
            "exactly one concurrent take should return data"
        );
        let responses = r1.or(r2).unwrap();
        assert_eq!(responses.len(), 1);
    }

    // =========================================================================
    // Resource limits
    // =========================================================================

    #[tokio::test]
    async fn test_response_limit_enforcement() {
        let mgr = PreResponseManager::new();

        for i in 0..MAX_PRE_RESPONSES {
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

        // The next one must be rejected
        let rejected = mgr
            .init_response_for_version(0, "req-over-limit".into(), &[])
            .await;
        assert_ne!(
            rejected,
            ResponseInitOutcome::Created,
            "init should fail when limit is reached"
        );
        assert_eq!(mgr.pending_count().await, MAX_PRE_RESPONSES);
    }

    #[tokio::test]
    async fn test_separate_requests_are_isolated() {
        let mgr = PreResponseManager::new();

        assert_eq!(
            mgr.init_response_for_version(0, "req-1".into(), &[PEER_A.to_string()])
                .await,
            ResponseInitOutcome::Created
        );
        assert_eq!(
            mgr.init_response_for_version(0, "req-2".into(), &[PEER_B.to_string()])
                .await,
            ResponseInitOutcome::Created
        );

        // PEER_A responds to req-1 (expected)
        mgr.store_response_for_version(0, "req-1", dummy_response("req-1", 1), &peer_bytes(PEER_A))
            .await;
        // PEER_A tries to respond to req-2 (not expected there)
        mgr.store_response_for_version(0, "req-2", dummy_response("req-2", 1), &peer_bytes(PEER_A))
            .await;

        assert_eq!(mgr.get_responses("req-1").await.unwrap().len(), 1);
        assert_eq!(
            mgr.get_responses("req-2").await.unwrap().len(),
            0,
            "PEER_A not expected in req-2"
        );
    }

    #[tokio::test]
    async fn protocol_versions_are_isolated() {
        let mgr = PreResponseManager::new();
        let expected = [PEER_A.to_string()];
        assert!(
            mgr.init_response_for_version(0, "same-id".into(), &expected)
                .await
                == ResponseInitOutcome::Created
        );
        assert!(
            mgr.init_response_for_version(1, "same-id".into(), &expected)
                .await
                == ResponseInitOutcome::Created
        );
        assert!(
            mgr.store_response_for_version(
                1,
                "same-id",
                dummy_response("same-id", 1),
                &peer_bytes(PEER_A),
            )
            .await
                == ResponseStoreOutcome::Stored
        );

        assert!(mgr
            .take_authenticated_responses_for_version(0, "same-id")
            .await
            .expect("v0 entry")
            .is_empty());
        assert_eq!(
            mgr.take_authenticated_responses_for_version(1, "same-id")
                .await
                .expect("v1 entry")
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn crafted_request_ids_do_not_collide_across_versions() {
        let mgr = PreResponseManager::new();
        let expected = [PEER_A.to_string()];

        assert!(
            mgr.init_response_for_version(0, "1:same-id".into(), &expected)
                .await
                == ResponseInitOutcome::Created
        );
        assert!(
            mgr.init_response_for_version(1, "same-id".into(), &expected)
                .await
                == ResponseInitOutcome::Created
        );
        assert!(
            mgr.store_response_for_version(
                0,
                "1:same-id",
                dummy_response("1:same-id", 1),
                &peer_bytes(PEER_A),
            )
            .await
                == ResponseStoreOutcome::Stored
        );
        assert!(
            mgr.store_response_for_version(
                1,
                "same-id",
                dummy_response("same-id", 1),
                &peer_bytes(PEER_A),
            )
            .await
                == ResponseStoreOutcome::Stored
        );

        assert_eq!(
            mgr.take_authenticated_responses_for_version(0, "1:same-id")
                .await
                .expect("v0 entry")
                .len(),
            1
        );
        assert_eq!(
            mgr.take_authenticated_responses_for_version(1, "same-id")
                .await
                .expect("v1 entry")
                .len(),
            1
        );
    }
}
