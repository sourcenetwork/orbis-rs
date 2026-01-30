//! PRE Response State Management
//!
//! This module tracks the state of PRE (Proxy Re-Encryption) response collection.
//! When a PRE request is initiated, responses are collected from multiple nodes
//! and stored here until the threshold is met.

use crate::constants::MAX_PRE_RESPONSES;
use crate::pre::messages::PreMessage;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// PRE response entry for collecting responses from nodes
pub struct PreResponseEntry {
    pub responses: Vec<PreMessage>,
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

    /// Initialize PRE response collection with limit checking
    ///
    /// Returns false if the limit is exceeded or if the request_id already exists.
    pub async fn init_response(&self, request_id: String) -> bool {
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

        responses.insert(
            request_id,
            PreResponseEntry {
                responses: Vec::new(),
            },
        );
        true
    }

    /// Store a PRE response
    pub async fn store_response(&self, request_id: &str, message: PreMessage) {
        let mut responses = self.states.write().await;
        if let Some(entry) = responses.get_mut(request_id) {
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
