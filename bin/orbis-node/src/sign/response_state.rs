//! Sign Response State Management
//!
//! This module tracks the state of Sign (threshold BLS signing) response collection.
//! When a sign request is initiated, responses are collected from multiple nodes
//! and stored here until the threshold is met.
//!
//! Both the response entries and FROST nonce states have TTL-based expiration to
//! prevent memory leaks from abandoned signing processes.

use crate::constants::{
    MAX_NONCE_STATES, MAX_SIGN_RESPONSES, SIGN_EXPIRATION_CHECK_INTERVAL, SIGN_NONCE_TTL,
    SIGN_RESPONSE_TTL,
};
use crate::helpers::helpers::extract_node_part;
use crate::metrics;
use crate::sign::messages::SignMessage;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;

/// Sign response entry for collecting responses from nodes
pub struct SignResponseEntry {
    pub responses: Vec<SignMessage>,
    /// Set of expected responder peer hex node IDs (the node part before '@').
    /// Built at init time from the ring's peer list (excluding self).
    /// When a response is accepted, the peer is removed from this set.
    /// This serves as both an allowlist (reject unknown peers) and dedup
    /// (a peer already removed cannot respond again).
    pub expected_peers: HashSet<String>,
    /// When this entry was created (for TTL-based expiration)
    pub created_at: Instant,
}

/// FROST nonce state entry with timestamp for TTL-based expiration
struct NonceEntry {
    bytes: Vec<u8>,
    created_at: Instant,
}

/// Sign Response State Manager
///
/// Manages the collection of signature share responses from multiple nodes.
/// Each sign request gets a unique request_id and collects responses
/// until the threshold is met.
///
/// Also holds FROST nonce signing state on the responder side between
/// Round 1 (nonce generation) and Round 2 (signing). Nonce state entries
/// are consumed on read to prevent nonce reuse.
///
/// A background expiration worker periodically sweeps both maps to remove
/// entries older than their respective TTLs, preventing memory leaks from
/// abandoned signing processes.
pub struct SignResponseManager {
    /// request_id -> response entry
    states: Arc<RwLock<HashMap<String, SignResponseEntry>>>,
    /// request_id -> nonce entry with timestamp (FROST only, responder side)
    nonce_states: Arc<RwLock<HashMap<String, NonceEntry>>>,
}

impl SignResponseManager {
    pub fn new() -> Self {
        let states = Arc::new(RwLock::new(HashMap::new()));
        let nonce_states = Arc::new(RwLock::new(HashMap::new()));

        // Spawn background expiration worker
        let states_clone = states.clone();
        let nonce_states_clone = nonce_states.clone();
        tokio::spawn(async move {
            Self::expiration_worker(states_clone, nonce_states_clone).await;
        });

        Self {
            states,
            nonce_states,
        }
    }

    /// Background task that periodically removes expired sign states
    ///
    /// Sweeps both the response entries and nonce states, removing any that
    /// have exceeded their TTL. This catches abandoned signing processes where
    /// the initiator crashed or a network partition prevented completion.
    async fn expiration_worker(
        states: Arc<RwLock<HashMap<String, SignResponseEntry>>>,
        nonce_states: Arc<RwLock<HashMap<String, NonceEntry>>>,
    ) {
        let mut interval = tokio::time::interval(SIGN_EXPIRATION_CHECK_INTERVAL);

        loop {
            interval.tick().await;

            let now = Instant::now();

            // Sweep nonce states
            {
                let mut nonces = nonce_states.write().await;
                let initial_count = nonces.len();

                nonces.retain(|request_id, entry| {
                    let age = now.duration_since(entry.created_at);
                    if age > SIGN_NONCE_TTL {
                        metrics::record_sign_state_abandoned();
                        tracing::warn!(
                            request_id = %request_id,
                            age_secs = age.as_secs(),
                            "SignResponseManager: Removing expired nonce state"
                        );
                        return false;
                    }
                    true
                });

                let removed = initial_count - nonces.len();
                if removed > 0 {
                    tracing::info!(
                        removed = removed,
                        remaining = nonces.len(),
                        "SignResponseManager: Expired nonce state cleanup complete"
                    );
                }
            }

            // Sweep response entries
            {
                let mut responses = states.write().await;
                let initial_count = responses.len();

                responses.retain(|request_id, entry| {
                    let age = now.duration_since(entry.created_at);
                    if age > SIGN_RESPONSE_TTL {
                        metrics::record_sign_state_abandoned();
                        tracing::warn!(
                            request_id = %request_id,
                            age_secs = age.as_secs(),
                            "SignResponseManager: Removing expired response entry"
                        );
                        return false;
                    }
                    true
                });

                let removed = initial_count - responses.len();
                if removed > 0 {
                    tracing::info!(
                        removed = removed,
                        remaining = responses.len(),
                        "SignResponseManager: Expired response entry cleanup complete"
                    );
                }
            }
        }
    }

    /// Initialize sign response collection with the set of expected responders.
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
                "Sign response entry already exists for request_id"
            );
            return false;
        }

        // Check limit
        if responses.len() >= MAX_SIGN_RESPONSES {
            tracing::error!(
                pending = responses.len(),
                max = MAX_SIGN_RESPONSES,
                "Sign response limit exceeded"
            );
            return false;
        }

        let expected_peers: HashSet<String> = expected_peer_ids
            .iter()
            .map(|pid| extract_node_part(pid))
            .collect();

        responses.insert(
            request_id,
            SignResponseEntry {
                responses: Vec::new(),
                expected_peers,
                created_at: Instant::now(),
            },
        );
        true
    }

    /// Store a sign response, validating the sender against the expected responder set.
    ///
    /// The sender is identified by their authenticated network peer_id bytes (not the
    /// self-reported `from_node_id`). The hex node part is checked against the
    /// `expected_peers` set — if the sender is not expected (either unknown or already
    /// responded), the response is rejected.
    pub async fn store_response(
        &self,
        request_id: &str,
        message: SignMessage,
        sender_peer_bytes: &[u8],
    ) {
        let sender_hex = hex::encode(sender_peer_bytes);
        let mut responses = self.states.write().await;
        if let Some(entry) = responses.get_mut(request_id) {
            if !entry.expected_peers.remove(&sender_hex) {
                tracing::warn!(
                    sender_peer = %sender_hex,
                    request_id = request_id,
                    "Sign: Rejecting response from unexpected or duplicate peer"
                );
                return;
            }
            entry.responses.push(message);
        }
    }

    /// Get collected sign responses without consuming the entry.
    /// Prefer `take_responses` when the entry is no longer needed after reading.
    pub async fn get_responses(&self, request_id: &str) -> Option<Vec<SignMessage>> {
        let responses = self.states.read().await;
        responses
            .get(request_id)
            .map(|entry| entry.responses.clone())
    }

    /// Take collected sign responses, removing the entry atomically.
    ///
    /// Prefer this over `get_responses` + `remove_response` — it acquires a single
    /// write lock and moves the `Vec` out without cloning.
    pub async fn take_responses(&self, request_id: &str) -> Option<Vec<SignMessage>> {
        let mut responses = self.states.write().await;
        responses.remove(request_id).map(|entry| entry.responses)
    }

    /// Remove sign response entry (cleanup after completion)
    pub async fn remove_response(&self, request_id: &str) {
        let mut responses = self.states.write().await;
        responses.remove(request_id);
    }

    /// Get the number of pending sign requests
    pub async fn pending_count(&self) -> usize {
        let responses = self.states.read().await;
        responses.len()
    }

    // ========================================================================
    // Nonce state methods (FROST responder side)
    // ========================================================================

    /// Store signing state bytes for a request.
    /// Returns false if the limit is exceeded or the key already exists.
    pub async fn store_nonce(&self, request_id: String, bytes: Vec<u8>) -> bool {
        let mut states = self.nonce_states.write().await;
        if states.len() >= MAX_NONCE_STATES {
            tracing::error!(
                pending = states.len(),
                max = MAX_NONCE_STATES,
                "Nonce state limit exceeded"
            );
            return false;
        }
        if states.contains_key(&request_id) {
            tracing::warn!(
                request_id = %request_id,
                "Nonce state already exists for request_id"
            );
            return false;
        }
        states.insert(
            request_id,
            NonceEntry {
                bytes,
                created_at: Instant::now(),
            },
        );
        true
    }

    /// Take (consume) signing state bytes for a request.
    /// Returns None if not found. Removes the entry to prevent nonce reuse.
    pub async fn take_nonce(&self, request_id: &str) -> Option<Vec<u8>> {
        let mut states = self.nonce_states.write().await;
        states.remove(request_id).map(|entry| entry.bytes)
    }
}

impl Default for SignResponseManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sign::messages::SignMessage;

    /// Helper: create a dummy SignResponse
    fn dummy_sign_response(request_id: &str, from_node_id: u32) -> SignMessage {
        SignMessage::SignResponse {
            request_id: request_id.to_string(),
            from_node_id,
            sig_share: vec![1, 2, 3],
        }
    }

    /// Helper: create a dummy NonceResponse
    fn dummy_nonce_response(request_id: &str, from_node_id: u32) -> SignMessage {
        SignMessage::NonceResponse {
            request_id: request_id.to_string(),
            from_node_id,
            nonce_commitment: vec![4, 5, 6],
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
        let mgr = SignResponseManager::new();
        let expected = vec![PEER_A.to_string(), PEER_B.to_string()];

        assert!(mgr.init_response("req-1".into(), &expected).await);

        mgr.store_response(
            "req-1",
            dummy_sign_response("req-1", 1),
            &peer_bytes(PEER_A),
        )
        .await;
        mgr.store_response(
            "req-1",
            dummy_sign_response("req-1", 2),
            &peer_bytes(PEER_B),
        )
        .await;

        let responses = mgr.get_responses("req-1").await.unwrap();
        assert_eq!(responses.len(), 2);
    }

    #[tokio::test]
    async fn test_rejects_unexpected_peer() {
        let mgr = SignResponseManager::new();
        let expected = vec![PEER_A.to_string(), PEER_B.to_string()];

        assert!(mgr.init_response("req-1".into(), &expected).await);

        mgr.store_response(
            "req-1",
            dummy_sign_response("req-1", 99),
            &peer_bytes(UNKNOWN),
        )
        .await;

        let responses = mgr.get_responses("req-1").await.unwrap();
        assert_eq!(responses.len(), 0, "unexpected peer should be rejected");
    }

    #[tokio::test]
    async fn test_rejects_duplicate_from_same_peer() {
        let mgr = SignResponseManager::new();
        let expected = vec![PEER_A.to_string(), PEER_B.to_string()];

        assert!(mgr.init_response("req-1".into(), &expected).await);

        mgr.store_response(
            "req-1",
            dummy_sign_response("req-1", 1),
            &peer_bytes(PEER_A),
        )
        .await;
        mgr.store_response(
            "req-1",
            dummy_sign_response("req-1", 1),
            &peer_bytes(PEER_A),
        )
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
        let mgr = SignResponseManager::new();
        let expected = vec![PEER_A.to_string(), PEER_B.to_string()];

        assert!(mgr.init_response("req-1".into(), &expected).await);

        mgr.store_response(
            "req-1",
            dummy_sign_response("req-1", 1),
            &peer_bytes(PEER_A),
        )
        .await;
        // Same peer, different claimed node_id — still rejected
        mgr.store_response(
            "req-1",
            dummy_sign_response("req-1", 2),
            &peer_bytes(PEER_A),
        )
        .await;

        let responses = mgr.get_responses("req-1").await.unwrap();
        assert_eq!(
            responses.len(),
            1,
            "same peer with different node_id should still be rejected"
        );
    }

    #[tokio::test]
    async fn test_nonce_and_sign_rounds_isolated() {
        let mgr = SignResponseManager::new();
        let expected = vec![PEER_A.to_string(), PEER_B.to_string()];

        // Round 1: nonce collection
        assert!(mgr.init_response("nonce-req-1".into(), &expected).await);
        mgr.store_response(
            "nonce-req-1",
            dummy_nonce_response("nonce-req-1", 1),
            &peer_bytes(PEER_A),
        )
        .await;
        mgr.store_response(
            "nonce-req-1",
            dummy_nonce_response("nonce-req-1", 2),
            &peer_bytes(PEER_B),
        )
        .await;

        let nonce_responses = mgr.get_responses("nonce-req-1").await.unwrap();
        assert_eq!(nonce_responses.len(), 2);

        // Cleanup nonce round
        mgr.remove_response("nonce-req-1").await;

        // Round 2: sign collection — same peers get fresh expected set
        assert!(mgr.init_response("req-1".into(), &expected).await);
        mgr.store_response(
            "req-1",
            dummy_sign_response("req-1", 1),
            &peer_bytes(PEER_A),
        )
        .await;
        mgr.store_response(
            "req-1",
            dummy_sign_response("req-1", 2),
            &peer_bytes(PEER_B),
        )
        .await;

        let sign_responses = mgr.get_responses("req-1").await.unwrap();
        assert_eq!(sign_responses.len(), 2);
    }

    #[tokio::test]
    async fn test_expected_peers_with_address_suffix() {
        let mgr = SignResponseManager::new();
        let expected = vec![
            format!("{}@192.168.1.1:4000", PEER_A),
            format!("{}@192.168.1.2:4000", PEER_B),
        ];

        assert!(mgr.init_response("req-1".into(), &expected).await);

        mgr.store_response(
            "req-1",
            dummy_sign_response("req-1", 1),
            &peer_bytes(PEER_A),
        )
        .await;
        mgr.store_response(
            "req-1",
            dummy_sign_response("req-1", 2),
            &peer_bytes(PEER_B),
        )
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
        let mgr = SignResponseManager::new();
        let expected = vec![PEER_A.to_string()];

        assert!(mgr.init_response("req-1".into(), &expected).await);
        mgr.store_response(
            "req-1",
            dummy_sign_response("req-1", 1),
            &peer_bytes(PEER_A),
        )
        .await;

        mgr.remove_response("req-1").await;
        assert!(
            mgr.get_responses("req-1").await.is_none(),
            "state should be gone after cleanup"
        );
    }

    #[tokio::test]
    async fn test_init_rejects_duplicate_request_id() {
        let mgr = SignResponseManager::new();
        let expected = vec![PEER_A.to_string()];

        assert!(mgr.init_response("req-1".into(), &expected).await);
        assert!(
            !mgr.init_response("req-1".into(), &expected).await,
            "duplicate request_id should be rejected"
        );
    }

    #[tokio::test]
    async fn test_separate_requests_are_isolated() {
        let mgr = SignResponseManager::new();

        assert!(
            mgr.init_response("req-1".into(), &[PEER_A.to_string()])
                .await
        );
        assert!(
            mgr.init_response("req-2".into(), &[PEER_B.to_string()])
                .await
        );

        mgr.store_response(
            "req-1",
            dummy_sign_response("req-1", 1),
            &peer_bytes(PEER_A),
        )
        .await;
        // PEER_A not expected in req-2
        mgr.store_response(
            "req-2",
            dummy_sign_response("req-2", 1),
            &peer_bytes(PEER_A),
        )
        .await;

        assert_eq!(mgr.get_responses("req-1").await.unwrap().len(), 1);
        assert_eq!(
            mgr.get_responses("req-2").await.unwrap().len(),
            0,
            "PEER_A not expected in req-2"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_nonce_expiration() {
        // Test that expired nonces are cleaned up by the expiration worker.
        // Uses start_paused = true so tokio::time::advance drives the interval
        // timer without real wall-clock delays. We backdate created_at because
        // std::time::Instant uses real wall time, not tokio's mock clock.
        let mgr = SignResponseManager::new();

        // Store a nonce normally
        assert!(mgr.store_nonce("exp-1".into(), vec![1, 2, 3]).await);

        // Backdate the entry to make it look expired to the worker
        {
            let mut nonces = mgr.nonce_states.write().await;
            if let Some(entry) = nonces.get_mut("exp-1") {
                entry.created_at =
                    Instant::now() - (SIGN_NONCE_TTL + std::time::Duration::from_secs(10));
            }
        }

        // Advance tokio time past the check interval so the worker fires
        tokio::time::advance(SIGN_EXPIRATION_CHECK_INTERVAL + std::time::Duration::from_secs(1))
            .await;
        // Yield to let the expiration worker run
        tokio::task::yield_now().await;

        // The expired nonce should have been cleaned up
        assert!(
            mgr.take_nonce("exp-1").await.is_none(),
            "expired nonce should be cleaned up by expiration worker"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_response_expiration() {
        let mgr = SignResponseManager::new();
        let expected = vec![PEER_A.to_string()];

        assert!(mgr.init_response("exp-resp-1".into(), &expected).await);

        // Backdate the entry to make it look expired
        {
            let mut states = mgr.states.write().await;
            if let Some(entry) = states.get_mut("exp-resp-1") {
                entry.created_at =
                    Instant::now() - (SIGN_RESPONSE_TTL + std::time::Duration::from_secs(10));
            }
        }

        // Advance tokio time past the check interval so the worker fires
        tokio::time::advance(SIGN_EXPIRATION_CHECK_INTERVAL + std::time::Duration::from_secs(1))
            .await;
        // Yield to let the expiration worker run
        tokio::task::yield_now().await;

        assert!(
            mgr.get_responses("exp-resp-1").await.is_none(),
            "expired response entry should be cleaned up by expiration worker"
        );
    }
}
