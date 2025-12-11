//! Test helpers for orbis-node
//!
//! This module provides utility functions for setting up test environments.

use crate::app_state::AppState;
use std::sync::Arc;

/// Create a test AppState with an initialized iroh network
///
/// This function initializes a new iroh network and creates an AppState
/// instance suitable for testing. The network is fully initialized and ready
/// to use for node-to-node communication in tests.
///
/// # Arguments
/// * `node_id` - Optional node identifier. If None, uses "test-node"
/// * `bind_address` - Optional bind address. If None, uses "127.0.0.1:0"
///
/// # Returns
/// An `AppState` instance with an initialized iroh network
///
/// # Example
/// ```rust
/// #[tokio::test]
/// async fn test_my_feature() {
///     let app_state = create_test_app_state(None, None).await;
///     // Use app_state in your test...
/// }
/// ```
pub async fn create_test_app_state(
    node_id: Option<String>,
    bind_address: Option<String>,
) -> AppState {
    let node_id = node_id.unwrap_or_else(|| "test-node".to_string());
    let bind_address = bind_address.unwrap_or_else(|| "127.0.0.1:0".to_string());

    // Initialize iroh network for testing
    let network = network::IrohNetwork::new()
        .await
        .expect("Failed to initialize iroh network for testing");

    let network_arc = Arc::new(network);

    // Create AppState with the network
    AppState::new(node_id, bind_address, network_arc)
}

/// Create a test AppState with default values
///
/// Convenience function that creates a test AppState with default
/// node_id ("test-node") and bind_address ("127.0.0.1:0").
///
/// # Example
/// ```rust
/// #[tokio::test]
/// async fn test_my_feature() {
///     let app_state = create_test_app_state_default().await;
///     // Use app_state in your test...
/// }
/// ```
pub async fn create_test_app_state_default() -> AppState {
    create_test_app_state(None, None).await
}
