//! Test helpers for orbis-node
//!
//! This module provides utility functions for setting up test environments.

use crate::app_state::AppState;
use hex;
use network::IrohRouter;
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

/// Information about a node in a test network
pub struct TestNode {
    /// The node's AppState
    pub app_state: AppState,
    /// The node's peer ID (iroh PublicKey bytes)
    pub peer_id: network::PeerId,
    /// The node's address (iroh PublicKey string)
    pub address: String,
    /// The node's router (if started)
    pub router: Option<IrohRouter>,
}

impl std::fmt::Debug for TestNode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TestNode")
            .field("app_state", &"<AppState>")
            .field("peer_id", &hex::encode(self.peer_id.as_bytes()))
            .field("address", &self.address)
            .field(
                "router",
                &if self.router.is_some() {
                    "Some(<IrohRouter>)"
                } else {
                    "None"
                },
            )
            .finish()
    }
}

/// A three-node test network setup
///
/// This struct holds all the information needed for a three-node test network
/// with Alice, Bob, and Charlie.
#[derive(Debug)]
pub struct ThreeNodeNetwork {
    /// Alice node (typically the initiator)
    pub alice: TestNode,
    /// Bob node (peer)
    pub bob: TestNode,
    /// Charlie node (peer)
    pub charlie: TestNode,
}

impl ThreeNodeNetwork {
    /// Get Bob and Charlie's peer IDs formatted for connection
    ///
    /// Returns a vector of peer ID strings that can be used in StartDkgRequest
    pub fn get_peer_ids_for_connection(&self) -> Vec<String> {
        vec![self.bob.address.clone(), self.charlie.address.clone()]
    }

    /// Shutdown all routers in the network
    pub async fn shutdown_routers(&mut self) -> Result<(), network::error::NetworkError> {
        if let Some(router) = self.bob.router.take() {
            router.shutdown().await?;
        }
        if let Some(router) = self.charlie.router.take() {
            router.shutdown().await?;
        }
        Ok(())
    }
}

/// Set up a three-node test network
///
/// This function creates three nodes (Alice, Bob, Charlie), initializes their networks,
/// gets their peer IDs and addresses, and optionally starts routers for Bob and Charlie
/// to accept incoming connections.
///
/// # Arguments
/// * `start_routers` - If true, starts routers for Bob and Charlie to accept connections
///
/// # Returns
/// A `ThreeNodeNetwork` containing all three nodes with their information
///
/// # Example
/// ```rust
/// #[tokio::test]
/// async fn test_three_nodes() {
///     let mut network = setup_three_node_network(true).await;
///
///     // Get peer IDs for connection
///     let peer_ids = network.get_peer_ids_for_connection();
///
///     // Use network in your test...
///
///     // Clean up
///     network.shutdown_routers().await.unwrap();
/// }
/// ```
pub async fn setup_three_node_network(start_routers: bool) -> ThreeNodeNetwork {
    use network::Network;

    println!("Setting up three-node test network...");

    // Create three nodes: Alice, Bob, and Charlie
    let alice_state =
        create_test_app_state(Some("alice".to_string()), Some("127.0.0.1:0".to_string())).await;
    let bob_state =
        create_test_app_state(Some("bob".to_string()), Some("127.0.0.1:0".to_string())).await;
    let charlie_state =
        create_test_app_state(Some("charlie".to_string()), Some("127.0.0.1:0".to_string())).await;

    // Get peer IDs and addresses for each node
    let alice_peer_id = alice_state.network.local_peer_id();
    let alice_address = alice_state
        .network
        .local_address()
        .expect("Failed to get Alice's address");

    let bob_peer_id = bob_state.network.local_peer_id();
    let bob_address = bob_state
        .network
        .local_address()
        .expect("Failed to get Bob's address");

    let charlie_peer_id = charlie_state.network.local_peer_id();
    let charlie_address = charlie_state
        .network
        .local_address()
        .expect("Failed to get Charlie's address");

    println!(
        "Alice - Peer ID: {}, Address: {}",
        hex::encode(alice_peer_id.as_bytes()),
        alice_address
    );
    println!(
        "Bob - Peer ID: {}, Address: {}",
        hex::encode(bob_peer_id.as_bytes()),
        bob_address
    );
    println!(
        "Charlie - Peer ID: {}, Address: {}",
        hex::encode(charlie_peer_id.as_bytes()),
        charlie_address
    );

    // Optionally start routers for Bob and Charlie
    let bob_router = if start_routers {
        println!("Starting router for Bob...");
        Some(network::IrohRouter::builder(bob_state.network.endpoint().clone()).spawn())
    } else {
        None
    };

    let charlie_router = if start_routers {
        println!("Starting router for Charlie...");
        Some(network::IrohRouter::builder(charlie_state.network.endpoint().clone()).spawn())
    } else {
        None
    };

    ThreeNodeNetwork {
        alice: TestNode {
            app_state: alice_state,
            peer_id: alice_peer_id,
            address: alice_address,
            router: None,
        },
        bob: TestNode {
            app_state: bob_state,
            peer_id: bob_peer_id,
            address: bob_address,
            router: bob_router,
        },
        charlie: TestNode {
            app_state: charlie_state,
            peer_id: charlie_peer_id,
            address: charlie_address,
            router: charlie_router,
        },
    }
}
