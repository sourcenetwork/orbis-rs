//! PRE Response State Management
//!
//! This module tracks the state of PRE (Proxy Re-Encryption) response collection.
//! When a PRE request is initiated, responses are collected from multiple nodes
//! and stored here until the threshold is met.

use crate::constants::MAX_PRE_RESPONSES;
use crate::helpers::helpers::extract_node_part;
use crate::pre::messages::PreMessage;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;

/// PRE response entry for collecting responses from nodes
pub struct PreResponseEntry {
    pub responses: Vec<PreMessage>,
    /// Set of expected responder peer hex node IDs (the node part before '@').
    /// Built at init time from the ring's peer list (excluding self).
    /// When a response is accepted, the peer is removed from this set.
    /// This serves as both an allowlist (reject unknown peers) and dedup
    /// (a peer already removed cannot respond again).
    pub expected_peers: HashSet<String>,
}

/// PRE Response State Manager
///
/// Manages the collection of PRE responses from multiple nodes.
/// Each PRE request gets a unique request_id and collects responses
/// until the threshold is met.
pub struct PreResponseManager {
    /// request_id -> response entry
    states: Arc<RwLock<HashMap<String, PreResponseEntry>>>,
}

impl PreResponseManager {
    pub fn new() -> Self {
        Self {
            states: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Initialize PRE response collection with the set of expected responders.
    ///
    /// `expected_peer_ids` should be the ring's peer_id strings for every node
    /// that will be contacted (i.e. excluding self). The node part (hex before '@')
    /// is extracted and stored as the allowlist.
    ///
    /// Returns false if the limit is exceeded or if the request_id already exists.
    pub async fn init_response(&self, request_id: String, expected_peer_ids: &[String]) -> bool {
        let mut responses = self.states.write().await;

        // Check if request_id already exists to avoid overwriting existing state
        if responses.contains_key(&request_id) {
            tracing::warn!(
                request_id = %request_id,
                "PRE response entry already exists for request_id"
            );
            return false;
        }

        // Check limit
        if responses.len() >= MAX_PRE_RESPONSES {
            tracing::error!(
                pending = responses.len(),
                max = MAX_PRE_RESPONSES,
                "PRE response limit exceeded"
            );
            return false;
        }

        let expected_peers: HashSet<String> = expected_peer_ids
            .iter()
            .map(|pid| extract_node_part(pid))
            .collect();

        responses.insert(
            request_id,
            PreResponseEntry {
                responses: Vec::new(),
                expected_peers,
            },
        );
        true
    }

    /// Store a PRE response, validating the sender against the expected responder set.
    ///
    /// The sender is identified by their authenticated network peer_id bytes (not the
    /// self-reported `from_node_id`). The hex node part is checked against the
    /// `expected_peers` set — if the sender is not expected (either unknown or already
    /// responded), the response is rejected.
    pub async fn store_response(
        &self,
        request_id: &str,
        message: PreMessage,
        sender_peer_bytes: &[u8],
    ) {
        let sender_hex = hex::encode(sender_peer_bytes);
        let mut responses = self.states.write().await;
        if let Some(entry) = responses.get_mut(request_id) {
            if !entry.expected_peers.remove(&sender_hex) {
                tracing::warn!(
                    sender_peer = %sender_hex,
                    request_id = request_id,
                    "PRE: Rejecting response from unexpected or duplicate peer"
                );
                return;
            }
            entry.responses.push(message);
        }
    }

    /// Get collected PRE responses
    pub async fn get_responses(&self, request_id: &str) -> Option<Vec<PreMessage>> {
        let responses = self.states.read().await;
        responses
            .get(request_id)
            .map(|entry| entry.responses.clone())
    }

    /// Remove PRE response entry (cleanup after completion)
    pub async fn remove_response(&self, request_id: &str) {
        let mut responses = self.states.write().await;
        responses.remove(request_id);
    }

    /// Get the number of pending PRE requests
    pub async fn pending_count(&self) -> usize {
        let responses = self.states.read().await;
        responses.len()
    }
}

impl Default for PreResponseManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pre::messages::PreMessage;

    /// Helper: create a dummy ReencryptResponse with a given node_id
    fn dummy_response(request_id: &str, from_node_id: u32) -> PreMessage {
        PreMessage::ReencryptResponse {
            request_id: request_id.to_string(),
            from_node_id,
            share: vec![1, 2, 3],
            challenge: vec![4, 5, 6],
            proof: vec![7, 8, 9],
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

        assert!(mgr.init_response("req-1".into(), &expected).await);

        mgr.store_response("req-1", dummy_response("req-1", 1), &peer_bytes(PEER_A))
            .await;
        mgr.store_response("req-1", dummy_response("req-1", 2), &peer_bytes(PEER_B))
            .await;

        let responses = mgr.get_responses("req-1").await.unwrap();
        assert_eq!(responses.len(), 2);
    }

    #[tokio::test]
    async fn test_rejects_unexpected_peer() {
        let mgr = PreResponseManager::new();
        let expected = vec![PEER_A.to_string(), PEER_B.to_string()];

        assert!(mgr.init_response("req-1".into(), &expected).await);

        // Unknown peer tries to respond
        mgr.store_response("req-1", dummy_response("req-1", 99), &peer_bytes(UNKNOWN))
            .await;

        let responses = mgr.get_responses("req-1").await.unwrap();
        assert_eq!(responses.len(), 0, "unexpected peer should be rejected");
    }

    #[tokio::test]
    async fn test_rejects_duplicate_from_same_peer() {
        let mgr = PreResponseManager::new();
        let expected = vec![PEER_A.to_string(), PEER_B.to_string()];

        assert!(mgr.init_response("req-1".into(), &expected).await);

        mgr.store_response("req-1", dummy_response("req-1", 1), &peer_bytes(PEER_A))
            .await;
        // Same peer tries again
        mgr.store_response("req-1", dummy_response("req-1", 1), &peer_bytes(PEER_A))
            .await;

        let responses = mgr.get_responses("req-1").await.unwrap();
        assert_eq!(
            responses.len(),
            1,
            "duplicate from same peer should be rejected"
        );
    }

    #[tokio::test]
    async fn test_rejects_peer_impersonating_another_node_id() {
        let mgr = PreResponseManager::new();
        let expected = vec![PEER_A.to_string(), PEER_B.to_string()];

        assert!(mgr.init_response("req-1".into(), &expected).await);

        // PEER_A responds legitimately
        mgr.store_response("req-1", dummy_response("req-1", 1), &peer_bytes(PEER_A))
            .await;
        // PEER_A tries again but claims to be node 2 — still rejected (same peer bytes)
        mgr.store_response("req-1", dummy_response("req-1", 2), &peer_bytes(PEER_A))
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

        assert!(mgr.init_response("req-1".into(), &expected).await);

        // Raw peer bytes match the hex node part (before @)
        mgr.store_response("req-1", dummy_response("req-1", 1), &peer_bytes(PEER_A))
            .await;
        mgr.store_response("req-1", dummy_response("req-1", 2), &peer_bytes(PEER_B))
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

        assert!(mgr.init_response("req-1".into(), &expected).await);
        mgr.store_response("req-1", dummy_response("req-1", 1), &peer_bytes(PEER_A))
            .await;

        mgr.remove_response("req-1").await;

        assert!(
            mgr.get_responses("req-1").await.is_none(),
            "state should be gone after cleanup"
        );
    }

    #[tokio::test]
    async fn test_init_rejects_duplicate_request_id() {
        let mgr = PreResponseManager::new();
        let expected = vec![PEER_A.to_string()];

        assert!(mgr.init_response("req-1".into(), &expected).await);
        assert!(
            !mgr.init_response("req-1".into(), &expected).await,
            "duplicate request_id should be rejected"
        );
    }

    #[tokio::test]
    async fn test_separate_requests_are_isolated() {
        let mgr = PreResponseManager::new();

        assert!(
            mgr.init_response("req-1".into(), &[PEER_A.to_string()])
                .await
        );
        assert!(
            mgr.init_response("req-2".into(), &[PEER_B.to_string()])
                .await
        );

        // PEER_A responds to req-1 (expected)
        mgr.store_response("req-1", dummy_response("req-1", 1), &peer_bytes(PEER_A))
            .await;
        // PEER_A tries to respond to req-2 (not expected there)
        mgr.store_response("req-2", dummy_response("req-2", 1), &peer_bytes(PEER_A))
            .await;

        assert_eq!(mgr.get_responses("req-1").await.unwrap().len(), 1);
        assert_eq!(
            mgr.get_responses("req-2").await.unwrap().len(),
            0,
            "PEER_A not expected in req-2"
        );
    }
}
