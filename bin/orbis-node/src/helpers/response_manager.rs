//! Generic response collection manager for MPC protocols.
//!
//! Both the PRE and Sign protocols collect responses from a set of expected
//! peer nodes and deduplicate them before the coordinator processes them.
//! This module provides a single generic implementation so the two protocols
//! share the same logic.

use crate::helpers::helpers::extract_node_part;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Configuration for the background expiration worker.
///
/// When provided to [`ResponseManager::with_expiration`], a background task
/// is spawned that periodically removes entries older than `ttl`.
pub struct ExpirationConfig {
    pub ttl: Duration,
    pub check_interval: Duration,
}

#[derive(Clone)]
pub struct AuthenticatedResponse<M> {
    pub message: M,
    pub sender_peer_hex: String,
}

struct ResponseEntry<M> {
    responses: Vec<AuthenticatedResponse<M>>,
    /// Allowlist + dedup set: populated at init, each peer is removed on first
    /// accepted response. A peer that is absent (unknown or already responded)
    /// is rejected.
    expected_peers: HashSet<String>,
    created_at: Instant,
}

/// Generic response collection manager.
///
/// Each in-flight request is identified by a `String` key (`request_id`).
/// Responses from peers are accepted only from the set of peers declared at
/// init time; duplicate responses from the same peer are silently dropped.
///
/// `M` is the protocol message type (e.g. `PreMessage`, `SignMessage`).
pub struct ResponseManager<M> {
    states: Arc<RwLock<HashMap<String, ResponseEntry<M>>>>,
    max_entries: usize,
    /// Short protocol name used in tracing output (e.g. `"PRE"`, `"Sign"`).
    label: &'static str,
}

impl<M: Clone + Send + Sync + 'static> ResponseManager<M> {
    /// Create a manager without an expiration worker.
    pub fn new(max_entries: usize, label: &'static str) -> Self {
        Self {
            states: Arc::new(RwLock::new(HashMap::new())),
            max_entries,
            label,
        }
    }

    /// Create a manager with a background expiration worker.
    ///
    /// The worker periodically sweeps the map and removes entries older than
    /// `config.ttl`. This catches abandoned protocol runs where the initiator
    /// crashed before cleanup.
    pub fn with_expiration(
        max_entries: usize,
        label: &'static str,
        config: ExpirationConfig,
    ) -> Self {
        let states = Arc::new(RwLock::new(HashMap::new()));
        let states_clone = states.clone();
        tokio::spawn(async move {
            Self::expiration_worker(states_clone, config.ttl, config.check_interval, label).await;
        });
        Self {
            states,
            max_entries,
            label,
        }
    }

    async fn expiration_worker(
        states: Arc<RwLock<HashMap<String, ResponseEntry<M>>>>,
        ttl: Duration,
        check_interval: Duration,
        label: &'static str,
    ) {
        let mut interval = tokio::time::interval(check_interval);
        loop {
            interval.tick().await;
            let now = Instant::now();
            let mut map = states.write().await;
            let before = map.len();
            map.retain(|request_id, entry| {
                let age = now.duration_since(entry.created_at);
                if age > ttl {
                    tracing::warn!(
                        request_id = %request_id,
                        age_secs = age.as_secs(),
                        "{}: removing expired response entry",
                        label,
                    );
                    return false;
                }
                true
            });
            let removed = before - map.len();
            if removed > 0 {
                tracing::info!(
                    removed,
                    remaining = map.len(),
                    "{}: expired response entry cleanup complete",
                    label,
                );
            }
        }
    }

    /// Register a new in-flight request and declare its expected responders.
    ///
    /// `expected_peer_ids` are the full peer-ID strings (optionally with
    /// `@address` suffix) for every node that will be contacted. The hex node
    /// part (before `@`) is stored as the allowlist.
    ///
    /// Returns `false` if the entry limit is reached or `request_id` already
    /// exists (duplicate detection).
    pub async fn init_response(&self, request_id: String, expected_peer_ids: &[String]) -> bool {
        let mut map = self.states.write().await;

        if map.contains_key(&request_id) {
            tracing::warn!(
                request_id = %request_id,
                "{}: response entry already exists for request_id",
                self.label,
            );
            return false;
        }

        if map.len() >= self.max_entries {
            tracing::error!(
                pending = map.len(),
                max = self.max_entries,
                "{}: response limit exceeded",
                self.label,
            );
            return false;
        }

        let expected_peers: HashSet<String> = expected_peer_ids
            .iter()
            .map(|pid| extract_node_part(pid))
            .collect();

        map.insert(
            request_id,
            ResponseEntry {
                responses: Vec::new(),
                expected_peers,
                created_at: Instant::now(),
            },
        );
        true
    }

    /// Accept a response from `sender_peer_bytes`, rejecting unknown or
    /// duplicate senders.
    pub async fn store_response(
        &self,
        request_id: &str,
        message: M,
        sender_peer_bytes: &[u8],
    ) -> bool {
        let sender_hex = hex::encode(sender_peer_bytes);
        let mut map = self.states.write().await;
        if let Some(entry) = map.get_mut(request_id) {
            if !entry.expected_peers.remove(&sender_hex) {
                tracing::warn!(
                    sender_peer = %sender_hex,
                    request_id,
                    "{}: rejecting response from unexpected or duplicate peer",
                    self.label,
                );
                return false;
            }
            entry.responses.push(AuthenticatedResponse {
                message,
                sender_peer_hex: sender_hex,
            });
            return true;
        }
        false
    }

    /// Clone the collected responses without consuming the entry.
    ///
    /// Prefer [`take_responses`] when the entry is no longer needed.
    pub async fn get_responses(&self, request_id: &str) -> Option<Vec<M>> {
        let map = self.states.read().await;
        map.get(request_id).map(|entry| {
            entry
                .responses
                .iter()
                .map(|response| response.message.clone())
                .collect()
        })
    }

    /// Remove the entry and return its responses in a single write lock.
    pub async fn take_responses(&self, request_id: &str) -> Option<Vec<M>> {
        let mut map = self.states.write().await;
        map.remove(request_id).map(|entry| {
            entry
                .responses
                .into_iter()
                .map(|response| response.message)
                .collect()
        })
    }

    /// Remove the entry and return responses with their authenticated sender.
    pub async fn take_authenticated_responses(
        &self,
        request_id: &str,
    ) -> Option<Vec<AuthenticatedResponse<M>>> {
        let mut map = self.states.write().await;
        map.remove(request_id).map(|entry| entry.responses)
    }

    /// Discard the entry (explicit cleanup after completion or error).
    pub async fn remove_response(&self, request_id: &str) {
        let mut map = self.states.write().await;
        map.remove(request_id);
    }

    /// Number of in-flight requests currently tracked.
    pub async fn pending_count(&self) -> usize {
        self.states.read().await.len()
    }
}
