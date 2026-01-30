//! Sign Response State Management
//!
//! This module tracks the state of Sign (threshold BLS signing) response collection.
//! When a sign request is initiated, responses are collected from multiple nodes
//! and stored here until the threshold is met.

use crate::constants::MAX_SIGN_RESPONSES;
use crate::sign::messages::SignMessage;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Sign response entry for collecting responses from nodes
pub struct SignResponseEntry {
    pub responses: Vec<SignMessage>,
}

/// Sign Response State Manager
///
/// Manages the collection of signature share responses from multiple nodes.
/// Each sign request gets a unique request_id and collects responses
/// until the threshold is met.
pub struct SignResponseManager {
    /// request_id -> response entry
    states: Arc<RwLock<HashMap<String, SignResponseEntry>>>,
}

impl SignResponseManager {
    pub fn new() -> Self {
        Self {
            states: Arc::new(RwLock::new(HashMap::new())),
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
            },
        );
        true
    }

    /// Store a sign response
    pub async fn store_response(&self, request_id: &str, message: SignMessage) {
        let mut responses = self.states.write().await;
        if let Some(entry) = responses.get_mut(request_id) {
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
}

impl Default for SignResponseManager {
    fn default() -> Self {
        Self::new()
    }
}
