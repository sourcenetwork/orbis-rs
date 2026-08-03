//! Test helpers for orbis-node
//!
//! This module provides utility functions for setting up test environments.

use crate::app_state::AppState;

pub const TEST_FRESH_DKG_RING_ID: &str = "test-fresh-dkg-ring";

pub const ORBIS_RING_POLICY_YAML: &str = r#"
name: orbis ring policy
resources:
- name: ring_policy
  permissions:
  - name: create_ring
    expr: ring_creator
  relations:
  - name: ring_creator
    types:
    - actor
- name: ring
  permissions:
  - name: update_ring
    expr: operator
  relations:
  - name: operator
    types:
    - actor
"#;

use crate::helpers::create_routers::{
    create_router_with_all_handlers, create_router_with_handlers,
};
use crate::ring_state::RingIndexEntry;
use authz::dummy::DummyAuthZ;
use authz::r#trait::Authz;
use authz::AuthzImpl;
use bulletin::{
    dummy::DummyBulletin,
    r#trait::{Bulletin, BulletinPost, BulletinWriteKind, NodeInfo, RingPayload},
    BulletinImpl,
};
use cli_tool;
#[cfg(feature = "integration-test")]
use common::blockchain::TEST_ACCOUNT_HEX_KEY;
use common::blockchain::{
    acp::{Actor, Object, Relationship, Subject, SubjectKind},
    ChainConfig, ChainConfigBuilder, SourceHubClient, TxSigner,
};
use hex;
use local_storage::{
    r#trait::{LocalStorage, LocalStorageKeys},
    LocalStorageImpl,
};
use network::{NetworkImpl, Router};
use proto::info_service::NodeStatus;
use std::{fs, sync::Arc};
use tokio::time::Duration;
use zeroize::Zeroizing;

// Concrete crypto implementations for tests (selected via crypto crate features)
use crypto::{DkgImpl, PreImpl, SignImpl};

// Re-export JWT utilities from authn for test convenience
pub use authn::{create_authenticated_request, JwtSigner};

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
///     let app_state = create_test_app_state(true, true, "my_test").await;
///     // Use app_state in your test...
/// }
/// ```
pub async fn create_test_app_state(
    dummy_authz: bool,
    dummy_bulletin: bool,
    db_name: &str,
) -> AppState<DkgImpl> {
    if dummy_bulletin {
        let bulletin = Arc::new(
            DummyBulletin::new()
                .await
                .expect("Failed to initialize dummy bulletin"),
        );
        create_test_app_state_with_bulletin(dummy_authz, bulletin, db_name).await
    } else {
        let bulletin: Arc<dyn Bulletin + Send + Sync> = Arc::new(
            BulletinImpl::new(ChainConfigBuilder::default())
                .await
                .expect("Failed to initialize bulletin"),
        );
        create_test_app_state_with_bulletin_inner(dummy_authz, bulletin, None, db_name).await
    }
}

/// Create a test AppState with a shared bulletin instance
///
/// Use this when you need multiple nodes to share the same bulletin (e.g., in multi-node tests).
pub async fn create_test_app_state_with_bulletin(
    dummy_authz: bool,
    bulletin: Arc<DummyBulletin>,
    db_name: &str,
) -> AppState<DkgImpl> {
    let bulletin_trait: Arc<dyn Bulletin + Send + Sync> = bulletin.clone();
    create_test_app_state_with_bulletin_inner(dummy_authz, bulletin_trait, Some(bulletin), db_name)
        .await
}

async fn create_test_app_state_with_bulletin_inner(
    dummy_authz: bool,
    bulletin: Arc<dyn Bulletin + Send + Sync>,
    dummy_bulletin: Option<Arc<DummyBulletin>>,
    db_name: &str,
) -> AppState<DkgImpl> {
    // Initialize network for testing — bind to loopback so iroh advertises
    // 127.0.0.1 and same-machine peers can connect without a relay.
    let network: Arc<dyn network::Network> = Arc::new(
        NetworkImpl::builder()
            .bind_addr_v4("127.0.0.1:0".parse().unwrap())
            .private_routes_only()
            .idle_timeout_ms(crate::constants::NETWORK_IDLE_TIMEOUT_MS)
            .build()
            .await
            .expect("Failed to initialize network for testing"),
    );
    let local_storage = LocalStorageImpl::new("test-password".to_string(), test_db_path(db_name))
        .expect("Failed to create local storage");
    let local_peer_id_hex = hex::encode(network.local_peer_id().as_bytes());
    let mut node_signing_key = [0u8; 32];
    loop {
        getrandom::getrandom(&mut node_signing_key).expect("generate test node signing key");
        if TxSigner::new(&node_signing_key, ChainConfig::local()).is_ok() {
            break;
        }
    }
    let node_signing_key_hex = hex::encode(node_signing_key);
    local_storage
        .set_encrypted(
            LocalStorageKeys::NodeSigningKey,
            Zeroizing::new(node_signing_key_hex.as_bytes().to_vec()),
        )
        .expect("store test node signing key");
    let test_node_key = TxSigner::from_hex_key(&node_signing_key_hex, ChainConfig::local())
        .expect("test node signer")
        .public_key_hex();
    let node_info = NodeInfo {
        peer_id: local_peer_id_hex,
        controller_key: "test-controller-key".to_string(),
        whitelisted_policy_ids: vec!["test-policy".to_string()],
        whitelisted_ring_ids: vec![TEST_FRESH_DKG_RING_ID.to_string()],
    };
    let node_key = if let Some(dummy_bulletin) = dummy_bulletin {
        dummy_bulletin
            .set_node_info(test_node_key.clone(), node_info)
            .expect("Failed to seed test NodeInfo");
        test_node_key
    } else {
        let node_info_payload: Vec<u8> = node_info
            .try_into()
            .expect("Failed to serialize test NodeInfo");
        bulletin
            .post(BulletinWriteKind::NodeInfo, node_info_payload)
            .await
            .expect("Failed to seed test NodeInfo")
    };
    let mut authz: Arc<dyn Authz> = Arc::new(
        AuthzImpl::new(ChainConfigBuilder::default())
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

    AppState::<DkgImpl>::new(node_key, network, local_storage, authz, bulletin)
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
    create_test_app_state(true, true, db_name).await
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
    /// Shared DummyBulletin for direct test access (when using dummy bulletin)
    pub dummy_bulletin: Option<Arc<DummyBulletin>>,
}

impl ThreeNodeNetwork {
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

fn seed_three_node_dummy_bulletin(
    dummy_bulletin: &Arc<DummyBulletin>,
    nodes: [(&AppState<DkgImpl>, &str); 3],
) {
    let peer_node_keys: Vec<String> = nodes
        .iter()
        .map(|(state, _)| state.node_key.clone())
        .collect();

    for (state, peer_id) in nodes {
        dummy_bulletin
            .set_node_info(
                state.node_key.clone(),
                NodeInfo {
                    peer_id: peer_id.to_string(),
                    controller_key: "test-controller-key".to_string(),
                    whitelisted_policy_ids: vec!["test-policy".to_string()],
                    whitelisted_ring_ids: vec![TEST_FRESH_DKG_RING_ID.to_string()],
                },
            )
            .expect("seed routed NodeInfo");
    }

    let payload = RingPayload {
        upgrade_info: Default::default(),
        ring_pk: String::new(),
        peer_node_keys,
        new_peer_node_keys: None,
        new_threshold: None,
        threshold: 2,
        pss_interval: 86400,
        block_number_nonce: 0,
        policy_id: Some("test-policy".to_string()),
        reporting: Default::default(),
    };
    dummy_bulletin
        .set_ring(TEST_FRESH_DKG_RING_ID.to_string(), payload)
        .expect("seed fresh DKG ring fixture");
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
    // DKG reshare Phase 4 collects a threshold signature over the bulletin
    // update, so even DKG-focused network tests need the Sign handler available.
    setup_three_node_network_impl(start_routers, true, true, db_name, TestRouterHandlers::All).await
}

/// Which protocol handlers the test routers install.
#[derive(Clone, Copy)]
enum TestRouterHandlers {
    /// DKG + PRE only.
    DkgPre,
    /// DKG + PRE + Sign.
    All,
}

impl TestRouterHandlers {
    fn label(self) -> &'static str {
        match self {
            TestRouterHandlers::DkgPre => "DKG and PRE",
            TestRouterHandlers::All => "DKG, PRE, and Sign",
        }
    }
}

/// Create one test node on the shared bulletin and resolve its peer identity.
///
/// Returns the node's state, peer ID, and `address@socket` route string.
async fn setup_test_node(
    name: &str,
    dummy_authz: bool,
    shared_bulletin: Arc<dyn Bulletin + Send + Sync>,
    dummy_bulletin: Option<Arc<DummyBulletin>>,
    db_name: &str,
) -> (AppState<DkgImpl>, network::PeerId, String) {
    let state = create_test_app_state_with_bulletin_inner(
        dummy_authz,
        shared_bulletin,
        dummy_bulletin,
        db_name,
    )
    .await;
    let peer_id = state.network.local_peer_id();
    let address = state
        .network
        .local_address()
        .unwrap_or_else(|e| panic!("Failed to get {name}'s address: {e:?}"));
    // Get socket address for peer ID formatting
    let socket_addr = state
        .network
        .bound_addresses()
        .first()
        .copied()
        .map(|addr| format!("{}", addr))
        .unwrap_or_else(|| "127.0.0.1:0".to_string());
    let peer_id_with_addr = format!("{}@{}", address, socket_addr);

    println!(
        "{} - Peer ID: {}, Address: {}",
        name,
        hex::encode(peer_id.as_bytes()),
        address
    );

    (state, peer_id, peer_id_with_addr)
}

/// Start a router for one test node with the selected protocol handlers.
fn start_test_router(
    name: &str,
    state: &AppState<DkgImpl>,
    handlers: TestRouterHandlers,
) -> Box<dyn Router> {
    println!(
        "Starting router for {} with {} handlers...",
        name,
        handlers.label()
    );
    let app_state = Arc::new(state.clone());
    let router = match handlers {
        TestRouterHandlers::DkgPre => {
            create_router_with_handlers::<DkgImpl, PreImpl>(&state.network, app_state)
        }
        TestRouterHandlers::All => {
            create_router_with_all_handlers::<DkgImpl, PreImpl, SignImpl>(&state.network, app_state)
        }
    };
    router.unwrap_or_else(|e| panic!("Failed to create router for {name}: {e:?}"))
}

/// Shared implementation behind the `setup_three_node_network*` variants.
///
/// Creates three nodes (Alice, Bob, Charlie) on one shared bulletin, seeds the
/// dummy bulletin with their NodeInfo routes and the fresh-DKG ring fixture
/// (when using a dummy bulletin), and optionally starts a router per node with
/// the selected protocol handlers.
async fn setup_three_node_network_impl(
    start_routers: bool,
    dummy_authz: bool,
    dummy_bulletin: bool,
    db_name: &str,
    handlers: TestRouterHandlers,
) -> ThreeNodeNetwork {
    println!(
        "Setting up three-node test network with {} handlers...",
        handlers.label()
    );

    // Create a shared bulletin for all nodes (keep concrete DummyBulletin for test access)
    let (shared_bulletin, dummy_bulletin_arc): (
        Arc<dyn Bulletin + Send + Sync>,
        Option<Arc<DummyBulletin>>,
    ) = if dummy_bulletin {
        let db = Arc::new(
            DummyBulletin::new()
                .await
                .expect("Failed to initialize shared dummy bulletin"),
        );
        (db.clone(), Some(db))
    } else {
        (
            Arc::new(
                BulletinImpl::new(ChainConfigBuilder::default())
                    .await
                    .expect("Failed to initialize shared bulletin"),
            ),
            None,
        )
    };

    // Create three nodes: Alice, Bob, and Charlie (all sharing the same bulletin)
    let (alice_state, alice_peer_id, alice_peer_id_with_addr) = setup_test_node(
        "Alice",
        dummy_authz,
        shared_bulletin.clone(),
        dummy_bulletin_arc.clone(),
        &format!("{}_1", db_name),
    )
    .await;
    let (bob_state, bob_peer_id, bob_peer_id_with_addr) = setup_test_node(
        "Bob",
        dummy_authz,
        shared_bulletin.clone(),
        dummy_bulletin_arc.clone(),
        &format!("{}_2", db_name),
    )
    .await;
    let (charlie_state, charlie_peer_id, charlie_peer_id_with_addr) = setup_test_node(
        "Charlie",
        dummy_authz,
        shared_bulletin,
        dummy_bulletin_arc.clone(),
        &format!("{}_3", db_name),
    )
    .await;

    if let Some(dummy_bulletin) = &dummy_bulletin_arc {
        seed_three_node_dummy_bulletin(
            dummy_bulletin,
            [
                (&alice_state, &alice_peer_id_with_addr),
                (&bob_state, &bob_peer_id_with_addr),
                (&charlie_state, &charlie_peer_id_with_addr),
            ],
        );
    }

    let (alice_router, bob_router, charlie_router) = if start_routers {
        (
            Some(start_test_router("Alice", &alice_state, handlers)),
            Some(start_test_router("Bob", &bob_state, handlers)),
            Some(start_test_router("Charlie", &charlie_state, handlers)),
        )
    } else {
        (None, None, None)
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
        dummy_bulletin: dummy_bulletin_arc,
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
    setup_three_node_network_impl(
        start_routers,
        dummy_authz,
        dummy_bulletin,
        db_name,
        TestRouterHandlers::DkgPre,
    )
    .await
}

/// Set up a three-node test network with DKG, PRE, and Sign protocol handlers
///
/// This function creates three nodes (Alice, Bob, Charlie), initializes their networks,
/// gets their peer IDs and addresses, and optionally starts routers for all nodes
/// to accept incoming connections for DKG, PRE, and Sign protocols.
///
/// # Arguments
/// * `start_routers` - If true, starts routers for all nodes to accept connections
/// * `dummy_authz` - If true, uses dummy authorization
/// * `dummy_bulletin` - If true, uses dummy bulletin
/// * `db_name` - Base name for the test database
///
/// # Returns
/// A `ThreeNodeNetwork` containing all three nodes with their information
pub async fn setup_three_node_network_with_sign(
    start_routers: bool,
    dummy_authz: bool,
    dummy_bulletin: bool,
    db_name: &str,
) -> ThreeNodeNetwork {
    setup_three_node_network_impl(
        start_routers,
        dummy_authz,
        dummy_bulletin,
        db_name,
        TestRouterHandlers::All,
    )
    .await
}

/// Post a `RingPayload` to the bulletin and write a `RingIndexEntry` into local storage.
///
/// Shared by all test modules that need to set up a ring for PSS / refresh validation tests.
pub async fn write_ring_to_bulletin(
    storage: &impl LocalStorage,
    bulletin: &DummyBulletin,
    ring_pk: &str,
    peer_node_keys: Vec<String>,
    pss_interval: u64,
) {
    let payload = RingPayload {
        upgrade_info: Default::default(),
        ring_pk: ring_pk.to_string(),
        peer_node_keys,
        new_peer_node_keys: None,
        new_threshold: None,
        threshold: 1,
        pss_interval,
        block_number_nonce: 0,
        policy_id: None,
        reporting: Default::default(),
    };
    let post_id = format!("test-ring-{ring_pk}");
    bulletin
        .set_ring(post_id.clone(), payload)
        .expect("seed ring fixture");
    let mut ring_index: Vec<RingIndexEntry> = storage
        .get(LocalStorageKeys::RingIndex)
        .ok()
        .flatten()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();
    if !ring_index.iter().any(|e| e.ring_pk_str == ring_pk) {
        ring_index.push(RingIndexEntry {
            ring_pk_str: ring_pk.to_string(),
            bulletin_post_id: post_id,
            indexed_at_secs: 0,
        });
        storage
            .set(
                LocalStorageKeys::RingIndex,
                serde_json::to_vec(&ring_index).unwrap(),
            )
            .unwrap();
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

/// Get bulletin ring info for tests using the DummyBulletin directly
/// Returns the first dummy bulletin post, or a default empty post if none found.
pub fn get_test_ring_post(dummy_bulletin: &DummyBulletin) -> BulletinPost {
    let posts = dummy_bulletin.get_posts();
    posts
        .iter()
        .find(|post| {
            serde_json::from_slice::<RingPayload>(&post.payload)
                .map(|ring| !ring.ring_pk.is_empty())
                .unwrap_or(false)
        })
        .cloned()
        .unwrap_or_default()
}

async fn check_full_grpc_ready(endpoint: &str) -> Result<(), String> {
    let node_info = cli_tool::query_node_info(endpoint.to_string())
        .await
        .map_err(|e| e.to_string())?;

    if node_info.status == NodeStatus::Ready {
        Ok(())
    } else {
        Err(format!(
            "node reported status {}",
            node_info.status.as_str_name()
        ))
    }
}

/// Wait for multiple gRPC endpoints to become fully ready
///
/// Polls each endpoint until it responds to `query_node_info` with `READY`.
/// This is useful for waiting for Docker-based integration test nodes to initialize.
///
/// # Arguments
/// * `endpoints` - Slice of gRPC endpoint URLs to poll (e.g., "http://localhost:50051")
/// * `max_attempts` - Maximum number of attempts per endpoint before failing
/// * `poll_interval` - Duration to wait between poll attempts
///
/// # Panics
/// Panics if any endpoint fails to become ready within the maximum attempts.
///
/// # Example
/// ```rust
/// use std::time::Duration;
///
/// #[tokio::test]
/// async fn test_with_docker_nodes() {
///     let endpoints = &["http://localhost:50051", "http://localhost:50052"];
///     wait_for_nodes_ready(endpoints, 90, Duration::from_secs(1)).await;
///     // Nodes are now ready...
/// }
/// ```
pub async fn wait_for_nodes_ready(
    endpoints: &[&str],
    max_attempts: u32,
    poll_interval: std::time::Duration,
) {
    use tokio::time::sleep;

    for (i, endpoint) in endpoints.iter().enumerate() {
        let node_num = i + 1;
        for attempt in 1..=max_attempts {
            match check_full_grpc_ready(endpoint).await {
                Ok(_) => {
                    println!(
                        "Node {} ({}) is ready after {} attempts",
                        node_num, endpoint, attempt
                    );
                    break;
                }
                Err(_) if attempt < max_attempts => {
                    if attempt % 10 == 1 {
                        println!(
                            "Waiting for node {} ({}) to be ready (attempt {}/{})",
                            node_num, endpoint, attempt, max_attempts
                        );
                    }
                    sleep(poll_interval).await;
                }
                Err(e) => {
                    panic!(
                        "Node {} ({}) failed to become ready after {} attempts: {}",
                        node_num, endpoint, max_attempts, e
                    );
                }
            }
        }
    }
}

// ============================================================================
// Integration-test chain helpers (new DKG flow)
// ============================================================================

/// Create an orbis ring governance policy and register both the policy itself
/// and the given ring as ACP objects, all using the provided `client`.
///
/// Using an existing client avoids account-sequence conflicts when the caller
/// also uses that client for subsequent transactions.
/// Compute the did:key DID for a secp256k1 compressed public key (hex-encoded).
/// Format: `did:key:z{base58btc([0xe7, 0x01] + pubkey_bytes)}`
/// Matches SourceHub `x/acp/did/types.go` `DIDFromPubKey` for secp256k1 keys.
fn secp256k1_pubkey_to_did(compressed_pubkey_hex: &str) -> String {
    let pubkey_bytes = hex::decode(compressed_pubkey_hex).expect("invalid compressed pubkey hex");
    let mut prefixed = vec![0xe7u8, 0x01u8]; // varint(231) = secp256k1-pub multicodec
    prefixed.extend_from_slice(&pubkey_bytes);
    format!("did:key:z{}", bs58::encode(&prefixed).into_string())
}

pub async fn create_ring_governance_with_ring(
    client: &SourceHubClient,
    ring_id: &str,
    operator_pubkeys: &[&str],
) -> String {
    let ids_before: std::collections::HashSet<String> = client
        .acp_list_policy_ids()
        .await
        .expect("list policy ids")
        .ids
        .into_iter()
        .collect();

    client
        .acp_create_policy(ORBIS_RING_POLICY_YAML, 1)
        .await
        .expect("create orbis ring policy");

    // Poll until the new policy appears on-chain (confirms it is committed).
    let policy_id = client
        .acp_list_policy_ids()
        .await
        .expect("list policy ids after create")
        .ids
        .into_iter()
        .find(|id| !ids_before.contains(id))
        .expect("new policy ID not found");

    client
        .acp_register_object(
            &policy_id,
            Object {
                resource: "ring_policy".to_string(),
                id: policy_id.clone(),
            },
        )
        .await
        .expect("register ring_policy object");

    client
        .acp_register_object(
            &policy_id,
            Object {
                resource: "ring".to_string(),
                id: ring_id.to_string(),
            },
        )
        .await
        .expect("register ring object");

    // Grant each node's DID the `operator` relation so MsgFinalizeRing passes the
    // SourceHub ACP update_ring permission check (nodes sign with secp256k1 keys,
    // and SourceHub derives did:key from the on-chain pubkey for the permission lookup).
    for pubkey_hex in operator_pubkeys {
        let node_did = secp256k1_pubkey_to_did(pubkey_hex);
        client
            .acp_set_relationship(
                &policy_id,
                Relationship {
                    object: Some(Object {
                        resource: "ring".to_string(),
                        id: ring_id.to_string(),
                    }),
                    relation: "operator".to_string(),
                    subject: Some(Subject {
                        kind: Some(SubjectKind::Actor(Actor { id: node_did })),
                    }),
                },
            )
            .await
            .expect("grant node operator on ring");
    }

    policy_id
}

/// Create an orbis ring governance policy as TEST_ACCOUNT_HEX_KEY, register its
/// own policy ID as a `ring_policy` ACP object, and return the policy ID.
#[cfg(feature = "integration-test")]
pub async fn create_orbis_ring_policy(chain_config: &ChainConfig) -> String {
    let client = SourceHubClient::with_signer(
        chain_config.clone(),
        TxSigner::from_hex_key(TEST_ACCOUNT_HEX_KEY, chain_config.clone())
            .expect("test account signer"),
    )
    .await
    .expect("chain client for policy creation");

    let ids_before: std::collections::HashSet<String> = client
        .acp_list_policy_ids()
        .await
        .expect("list policy ids")
        .ids
        .into_iter()
        .collect();

    client
        .acp_create_policy(ORBIS_RING_POLICY_YAML, 1)
        .await
        .expect("create orbis ring policy");

    let policy_id = client
        .acp_list_policy_ids()
        .await
        .expect("list policy ids after create")
        .ids
        .into_iter()
        .find(|id| !ids_before.contains(id))
        .expect("new policy ID not found in list");

    client
        .acp_register_object(
            &policy_id,
            Object {
                resource: "ring_policy".to_string(),
                id: policy_id.clone(),
            },
        )
        .await
        .expect("register ring_policy object");

    policy_id
}

/// Create a ring on-chain as TEST_ACCOUNT_HEX_KEY and return its ring_id.
#[cfg(feature = "integration-test")]
pub async fn create_ring_on_chain(
    chain_config: &ChainConfig,
    node_keys: &[String],
    threshold: u32,
    policy_id: &str,
    nonce: Option<&str>,
) -> String {
    let client = SourceHubClient::with_signer(
        chain_config.clone(),
        TxSigner::from_hex_key(TEST_ACCOUNT_HEX_KEY, chain_config.clone())
            .expect("test account signer"),
    )
    .await
    .expect("chain client for ring creation");

    let (_, ring_id) = client
        .orbis_create_ring_get_id(
            node_keys.to_vec(),
            threshold,
            86400,
            policy_id,
            nonce.map(String::from),
            network::V0.version,
            None,
        )
        .await
        .expect("create ring on-chain");

    ring_id
}

/// Poll the chain until the ring is finalized (ring_pk != "") or the timeout expires.
/// Panics on timeout.
pub async fn wait_for_ring_finalized(
    chain_config: &ChainConfig,
    ring_id: &str,
    timeout: Duration,
) -> String {
    let client = SourceHubClient::new(chain_config.clone())
        .await
        .expect("chain client for ring polling");

    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if let Ok(Some(ring)) = client.orbis_read_ring(ring_id).await {
            if !ring.ring_pk.is_empty() {
                return ring.ring_pk;
            }
        }
        if tokio::time::Instant::now() >= deadline {
            panic!("Timed out waiting for ring {} to be finalized", ring_id);
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}
