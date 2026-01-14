//! Test helpers for orbis-node
//!
//! This module provides utility functions for setting up test environments.

use crate::app_state::AppState;
use crate::constants::BULLETIN_RING_NAMESPACE;
use crate::dkg::protocol_handler;
use crate::dkg::protocol_handler::create_router_with_handlers;
use authz::dummy::DummyAuthZ;
use authz::r#trait::Authz;
use authz::sourcehub::SourceHubAuth;
use bulletin::{
    dummy::DummyBulletin,
    r#trait::{Bulletin, BulletinPost},
    BulletinImpl,
};
use common::blockchain::ChainConfigBuilder;
use hex;
use local_storage::{r#trait::LocalStorage, LocalStorageImpl};
use network::Router;
use std::{fs, sync::Arc};

// Concrete crypto implementations for tests
use crypto::bls12_381::dkg::DKGNode;
use crypto::bls12_381::pre::ThresholdDealerNode;

// Type aliases matching main.rs
type DkgImpl = DKGNode;
type PreImpl = ThresholdDealerNode;

// Re-export JWT utilities from authn for test convenience
pub use authn::{add_auth_header, create_authenticated_request, JwtSigner};

/// Type alias for backward compatibility - use JwtSigner instead
pub type TestKeyPair = JwtSigner;

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
///     let app_state = create_test_app_state(None).await;
///     // Use app_state in your test...
/// }
/// ```
pub async fn create_test_app_state(
    bind_address: Option<String>,
    dummy_authz: bool,
    dummy_bulletin: bool,
    db_name: &str,
) -> AppState<DkgImpl> {
    let bulletin: Arc<dyn Bulletin + Send + Sync> = if dummy_bulletin {
        Arc::new(
            DummyBulletin::new()
                .await
                .expect("Failed to initialize dummy bulletin"),
        )
    } else {
        Arc::new(
            BulletinImpl::new(ChainConfigBuilder::default())
                .await
                .expect("Failed to initialize bulletin"),
        )
    };
    create_test_app_state_with_bulletin(bind_address, dummy_authz, bulletin, db_name).await
}

/// Create a test AppState with a shared bulletin instance
///
/// Use this when you need multiple nodes to share the same bulletin (e.g., in multi-node tests).
pub async fn create_test_app_state_with_bulletin(
    bind_address: Option<String>,
    dummy_authz: bool,
    bulletin: Arc<dyn Bulletin + Send + Sync>,
    db_name: &str,
) -> AppState<DkgImpl> {
    let bind_address = bind_address.unwrap_or_else(|| "127.0.0.1:0".to_string());

    // Initialize network for testing
    let network: Arc<dyn network::Network> = Arc::new(
        network::IrohNetwork::new()
            .await
            .expect("Failed to initialize network for testing"),
    );
    let local_storage =
        LocalStorageImpl::new(None, test_db_path(db_name)).expect("Failed to create local storage");
    let mut authz: Arc<dyn Authz> = Arc::new(
        SourceHubAuth::new(ChainConfigBuilder::default())
            .await
            .expect("Failed to initialize Authz"),
    );

    if dummy_authz {
        authz = Arc::new(
            DummyAuthZ::new()
                .await
                .expect("Failed to initialize dummy Authz"),
        )
    }

    // Create AppState with the network (node_id is no longer needed - it's session-specific)
    AppState::<DkgImpl>::new(bind_address, network, local_storage, authz, bulletin)
}

/// Create a test AppState with default values
///
/// Convenience function that creates a test AppState with default
/// node_id (1) and bind_address ("127.0.0.1:0").
///
/// # Example
/// ```rust
/// #[tokio::test]
/// async fn test_my_feature() {
///     let app_state = create_test_app_state_default().await;
///     // Use app_state in your test...
/// }
/// ```
pub async fn create_test_app_state_default(db_name: &str) -> AppState<DkgImpl> {
    create_test_app_state(None, true, true, db_name).await
}

/// Information about a node in a test network
pub struct TestNode {
    /// The node's AppState
    pub app_state: AppState<DkgImpl>,
    /// The node's peer ID (iroh PublicKey bytes)
    pub peer_id: network::PeerId,
    /// The node's address (iroh PublicKey string)
    pub address: String,
    /// The node's router (if started)
    pub router: Option<Box<dyn Router>>,
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
                    "Some(<Router>)"
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
    /// Get peer IDs for connection (excluding self)
    ///
    /// Returns a vector of peer ID strings that can be used in StartDkgRequest.
    /// The peer IDs are formatted as "node_id@ip:port" for proper addressing.
    /// This excludes Alice's own peer ID to avoid self-connection errors.
    pub fn get_peer_ids_for_connection(&self) -> Vec<String> {
        // The address field contains the formatted "node_id@ip:port" string
        // Exclude Alice's own peer ID to avoid self-connection
        vec![self.bob.address.clone(), self.charlie.address.clone()]
    }

    /// Get all peer IDs including Alice (for SessionInit)
    ///
    /// Returns a vector of all peer ID strings including Alice.
    /// This should be used in SessionInit messages so all nodes know about all participants.
    pub fn get_all_peer_ids(&self) -> Vec<String> {
        vec![
            self.alice.address.clone(),
            self.bob.address.clone(),
            self.charlie.address.clone(),
        ]
    }

    /// Shutdown all routers in the network
    pub async fn shutdown_routers(&mut self) -> Result<(), network::error::NetworkError> {
        if let Some(router) = self.alice.router.take() {
            router.shutdown().await?;
        }
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
pub async fn setup_three_node_network(start_routers: bool, db_name: &str) -> ThreeNodeNetwork {
    println!("Setting up three-node test network...");

    // Create a shared bulletin for all nodes
    let shared_bulletin: Arc<dyn Bulletin + Send + Sync> = Arc::new(
        DummyBulletin::new()
            .await
            .expect("Failed to initialize shared dummy bulletin"),
    );

    // Create three nodes: Alice, Bob, and Charlie (all sharing the same bulletin)
    let alice_state = create_test_app_state_with_bulletin(
        Some("127.0.0.1:0".to_string()),
        true,
        shared_bulletin.clone(),
        &format!("{}_1", db_name),
    )
    .await;
    let bob_state = create_test_app_state_with_bulletin(
        Some("127.0.0.1:0".to_string()),
        true,
        shared_bulletin.clone(),
        &format!("{}_2", db_name),
    )
    .await;
    let charlie_state = create_test_app_state_with_bulletin(
        Some("127.0.0.1:0".to_string()),
        true,
        shared_bulletin,
        &format!("{}_3", db_name),
    )
    .await;

    // Get peer IDs and addresses for each node
    let alice_peer_id = alice_state.network.local_peer_id();
    let alice_address = alice_state
        .network
        .local_address()
        .expect("Failed to get Alice's address");
    // Get socket address for peer ID formatting
    let alice_socket_addr = alice_state
        .network
        .bound_addresses()
        .first()
        .copied()
        .map(|addr| format!("{}", addr))
        .unwrap_or_else(|| "127.0.0.1:0".to_string());
    let alice_peer_id_with_addr = format!("{}@{}", alice_address, alice_socket_addr);

    let bob_peer_id = bob_state.network.local_peer_id();
    let bob_address = bob_state
        .network
        .local_address()
        .expect("Failed to get Bob's address");
    let bob_socket_addr = bob_state
        .network
        .bound_addresses()
        .first()
        .copied()
        .map(|addr| format!("{}", addr))
        .unwrap_or_else(|| "127.0.0.1:0".to_string());
    let bob_peer_id_with_addr = format!("{}@{}", bob_address, bob_socket_addr);

    let charlie_peer_id = charlie_state.network.local_peer_id();
    let charlie_address = charlie_state
        .network
        .local_address()
        .expect("Failed to get Charlie's address");
    let charlie_socket_addr = charlie_state
        .network
        .bound_addresses()
        .first()
        .copied()
        .map(|addr| format!("{}", addr))
        .unwrap_or_else(|| "127.0.0.1:0".to_string());
    let charlie_peer_id_with_addr = format!("{}@{}", charlie_address, charlie_socket_addr);

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

    // Optionally start routers for all nodes with DKG protocol handler
    // Use the same production setup as main.rs
    // Alice also needs a router to accept incoming connections from Bob and Charlie
    let alice_router = if start_routers {
        println!("Starting router for Alice...");
        let alice_app_state = Arc::new(alice_state.clone());
        Some(
            protocol_handler::create_router_with_dkg_handler::<DkgImpl>(
                &alice_state.network,
                alice_app_state,
            )
            .expect("Failed to create router for Alice"),
        )
    } else {
        None
    };

    let bob_router = if start_routers {
        println!("Starting router for Bob...");
        let bob_app_state = Arc::new(bob_state.clone());
        Some(
            protocol_handler::create_router_with_dkg_handler::<DkgImpl>(
                &bob_state.network,
                bob_app_state,
            )
            .expect("Failed to create router for Bob"),
        )
    } else {
        None
    };

    let charlie_router = if start_routers {
        println!("Starting router for Charlie...");
        let charlie_app_state = Arc::new(charlie_state.clone());
        Some(
            protocol_handler::create_router_with_dkg_handler::<DkgImpl>(
                &charlie_state.network,
                charlie_app_state,
            )
            .expect("Failed to create router for Charlie"),
        )
    } else {
        None
    };

    ThreeNodeNetwork {
        alice: TestNode {
            app_state: alice_state,
            peer_id: alice_peer_id,
            address: alice_peer_id_with_addr,
            router: alice_router,
        },
        bob: TestNode {
            app_state: bob_state,
            peer_id: bob_peer_id,
            address: bob_peer_id_with_addr,
            router: bob_router,
        },
        charlie: TestNode {
            app_state: charlie_state,
            peer_id: charlie_peer_id,
            address: charlie_peer_id_with_addr,
            router: charlie_router,
        },
    }
}

/// Set up a three-node test network with both DKG and PRE protocol handlers
///
/// This function creates three nodes (Alice, Bob, Charlie), initializes their networks,
/// gets their peer IDs and addresses, and optionally starts routers for all nodes
/// to accept incoming connections for both DKG and PRE protocols.
///
/// # Arguments
/// * `start_routers` - If true, starts routers for all nodes to accept connections
///
/// # Returns
/// A `ThreeNodeNetwork` containing all three nodes with their information
pub async fn setup_three_node_network_with_pre(
    start_routers: bool,
    dummy_authz: bool,
    dummy_bulletin: bool,
    db_name: &str,
) -> ThreeNodeNetwork {
    println!("Setting up three-node test network with DKG and PRE handlers...");

    // Create a shared bulletin for all nodes
    let shared_bulletin: Arc<dyn Bulletin + Send + Sync> = if dummy_bulletin {
        Arc::new(
            DummyBulletin::new()
                .await
                .expect("Failed to initialize shared dummy bulletin"),
        )
    } else {
        Arc::new(
            BulletinImpl::new(ChainConfigBuilder::default())
                .await
                .expect("Failed to initialize shared bulletin"),
        )
    };

    // Create three nodes: Alice, Bob, and Charlie (all sharing the same bulletin)
    let alice_state = create_test_app_state_with_bulletin(
        Some("127.0.0.1:0".to_string()),
        dummy_authz,
        shared_bulletin.clone(),
        &format!("{}_1", db_name),
    )
    .await;
    let bob_state = create_test_app_state_with_bulletin(
        Some("127.0.0.1:0".to_string()),
        dummy_authz,
        shared_bulletin.clone(),
        &format!("{}_2", db_name),
    )
    .await;
    let charlie_state = create_test_app_state_with_bulletin(
        Some("127.0.0.1:0".to_string()),
        dummy_authz,
        shared_bulletin,
        &format!("{}_3", db_name),
    )
    .await;

    // Get peer IDs and addresses for each node
    let alice_peer_id = alice_state.network.local_peer_id();
    let alice_address = alice_state
        .network
        .local_address()
        .expect("Failed to get Alice's address");
    // Get socket address for peer ID formatting
    let alice_socket_addr = alice_state
        .network
        .bound_addresses()
        .first()
        .copied()
        .map(|addr| format!("{}", addr))
        .unwrap_or_else(|| "127.0.0.1:0".to_string());
    let alice_peer_id_with_addr = format!("{}@{}", alice_address, alice_socket_addr);

    let bob_peer_id = bob_state.network.local_peer_id();
    let bob_address = bob_state
        .network
        .local_address()
        .expect("Failed to get Bob's address");
    let bob_socket_addr = bob_state
        .network
        .bound_addresses()
        .first()
        .copied()
        .map(|addr| format!("{}", addr))
        .unwrap_or_else(|| "127.0.0.1:0".to_string());
    let bob_peer_id_with_addr = format!("{}@{}", bob_address, bob_socket_addr);

    let charlie_peer_id = charlie_state.network.local_peer_id();
    let charlie_address = charlie_state
        .network
        .local_address()
        .expect("Failed to get Charlie's address");
    let charlie_socket_addr = charlie_state
        .network
        .bound_addresses()
        .first()
        .copied()
        .map(|addr| format!("{}", addr))
        .unwrap_or_else(|| "127.0.0.1:0".to_string());
    let charlie_peer_id_with_addr = format!("{}@{}", charlie_address, charlie_socket_addr);

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

    // Start routers for all nodes with both DKG and PRE protocol handlers
    let alice_router = if start_routers {
        println!("Starting router for Alice with DKG and PRE handlers...");
        let alice_app_state = Arc::new(alice_state.clone());
        Some(
            create_router_with_handlers::<DkgImpl, PreImpl>(&alice_state.network, alice_app_state)
                .expect("Failed to create router for Alice"),
        )
    } else {
        None
    };

    let bob_router = if start_routers {
        println!("Starting router for Bob with DKG and PRE handlers...");
        let bob_app_state = Arc::new(bob_state.clone());
        Some(
            create_router_with_handlers::<DkgImpl, PreImpl>(&bob_state.network, bob_app_state)
                .expect("Failed to create router for Bob"),
        )
    } else {
        None
    };

    let charlie_router = if start_routers {
        println!("Starting router for Charlie with DKG and PRE handlers...");
        let charlie_app_state = Arc::new(charlie_state.clone());
        Some(
            create_router_with_handlers::<DkgImpl, PreImpl>(
                &charlie_state.network,
                charlie_app_state,
            )
            .expect("Failed to create router for Charlie"),
        )
    } else {
        None
    };

    ThreeNodeNetwork {
        alice: TestNode {
            app_state: alice_state,
            peer_id: alice_peer_id,
            address: alice_peer_id_with_addr,
            router: alice_router,
        },
        bob: TestNode {
            app_state: bob_state,
            peer_id: bob_peer_id,
            address: bob_peer_id_with_addr,
            router: bob_router,
        },
        charlie: TestNode {
            app_state: charlie_state,
            peer_id: charlie_peer_id,
            address: charlie_peer_id_with_addr,
            router: charlie_router,
        },
    }
}

pub fn test_db_path(name: &str) -> String {
    let project_root = project_root::get_project_root().unwrap();
    format!("{}/test_dbs/{}.redb", project_root.display(), name)
}

/// Clean up a test database file
///
/// Call this at the end of each test to remove the database file.
/// Silently ignores errors (e.g., if file doesn't exist).
pub fn cleanup_db(path: &str) {
    let _ = fs::remove_file(path);
}

/// Get bulletin ring info for tests
pub async fn get_test_bulletin(bulletin: &Arc<dyn Bulletin + Send + Sync>) -> BulletinPost {
    bulletin
        .read(BULLETIN_RING_NAMESPACE.to_string(), "test".to_string())
        .await
        .unwrap()
}
