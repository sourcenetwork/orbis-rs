//! Sign Response State Management
//!
//! This module tracks the state of Sign (threshold BLS signing) response collection.
//! When a sign request is initiated, responses are collected from multiple nodes
//! and stored here until the threshold is met.

use crate::constants::{MAX_NONCE_STATES, MAX_SIGN_RESPONSES};
use crate::sign::messages::SignMessage;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Sign response entry for collecting responses from nodes
pub struct SignResponseEntry {
    pub responses: Vec<SignMessage>,
    /// Tracks node IDs we've already received responses from (for deduplication)
    pub seen_node_ids: HashSet<u32>,
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
pub struct SignResponseManager {
    /// request_id -> response entry
    states: Arc<RwLock<HashMap<String, SignResponseEntry>>>,
    /// request_id -> serialized signing state bytes (FROST only, responder side)
    nonce_states: Arc<RwLock<HashMap<String, Vec<u8>>>>,
}

impl SignResponseManager {
    pub fn new() -> Self {
        Self {
            states: Arc::new(RwLock::new(HashMap::new())),
            nonce_states: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Initialize sign response collection with limit checking
    ///
    /// Returns false if the limit is exceeded or if the request_id already exists.
    pub async fn init_response(&self, request_id: String) -> bool {
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

        responses.insert(
            request_id,
            SignResponseEntry {
                responses: Vec::new(),
                seen_node_ids: HashSet::new(),
            },
        );
        true
    }

    /// Store a sign response (with early deduplication)
    pub async fn store_response(&self, request_id: &str, message: SignMessage) {
        let mut responses = self.states.write().await;
        if let Some(entry) = responses.get_mut(request_id) {
            if let Some(from_node_id) = message.from_node_id() {
                if entry.seen_node_ids.contains(&from_node_id) {
                    tracing::warn!(
                        from_node_id = from_node_id,
                        request_id = request_id,
                        "Sign: Skipping duplicate response from node"
                    );
                    return;
                }
                entry.seen_node_ids.insert(from_node_id);
            }
            entry.responses.push(message);
        }
    }

    /// Get collected sign responses
    pub async fn get_responses(&self, request_id: &str) -> Option<Vec<SignMessage>> {
        let responses = self.states.read().await;
        responses
            .get(request_id)
            .map(|entry| entry.responses.clone())
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
        states.insert(request_id, bytes);
        true
    }

    /// Take (consume) signing state bytes for a request.
    /// Returns None if not found. Removes the entry to prevent nonce reuse.
    pub async fn take_nonce(&self, request_id: &str) -> Option<Vec<u8>> {
        let mut states = self.nonce_states.write().await;
        states.remove(request_id)
    }
}

impl Default for SignResponseManager {
    fn default() -> Self {
        Self::new()
    }
}
