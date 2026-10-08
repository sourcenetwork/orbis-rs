//! Test helpers for orbis-node
//!
//! This module provides utility functions for setting up test environments.

use crate::app_state::AppState;

pub const TEST_FRESH_DKG_RING_ID: &str = "test-fresh-dkg-ring";

// `ORBIS_RING_POLICY_YAML`, `create_orbis_ring_policy`, `create_ring_governance_with_ring`,
// and `wait_for_ring_finalized` moved to `test_support::admin::cosmos` (the
// shared E2E harness crate, reachable from both `src/tests/*` and
// `tests/*.rs`). The three functions are re-exported here so existing call
// sites keep compiling unchanged; the YAML constant had no external callers
// (grep confirmed) so it isn't re-exported — reach it via
// `test_support::admin::cosmos::ORBIS_RING_POLICY_YAML` if ever needed.
// `create_ring_on_chain`/`create_ring_on_chain_with_trusted_relays` stayed
// here; see their doc comments below.
#[cfg(feature = "integration-test-cosmos")]
pub use test_support::admin::cosmos::{
    create_orbis_ring_policy, create_ring_governance_with_ring, wait_for_ring_finalized,
};

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
#[cfg(feature = "integration-test-cosmos")]
use cli_tool;
#[cfg(feature = "integration-test-cosmos")]
use common::blockchain::TEST_ACCOUNT_HEX_KEY;
use common::blockchain::{ChainConfig, ChainConfigBuilder, TxSigner};
use hex;
use local_storage::{
    r#trait::{LocalStorage, LocalStorageKeys},
    LocalStorageImpl,
};
use network::{NetworkImpl, Router};
#[cfg(feature = "integration-test-cosmos")]
use proto::info_service::NodeStatus;
use std::{fs, sync::Arc};
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
    trusted_auth_relay_dids: Vec<String>,
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
        trusted_auth_relay_dids: if trusted_auth_relay_dids.is_empty() {
            None
        } else {
            Some(trusted_auth_relay_dids)
        },
        reporting: Default::default(),
        requires_pet: false,
        pet_pk: None,
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
    setup_three_node_network_impl(
        start_routers,
        true,
        true,
        db_name,
        TestRouterHandlers::All,
        vec![],
    )
    .await
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
    trusted_auth_relay_dids: Vec<String>,
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
            trusted_auth_relay_dids,
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
        vec![],
    )
    .await
}

pub async fn setup_three_node_network_with_pre_and_trusted_relays(
    db_name: &str,
    trusted_auth_relay_dids: Vec<String>,
) -> ThreeNodeNetwork {
    setup_three_node_network_impl(
        true,
        true,
        true,
        db_name,
        TestRouterHandlers::DkgPre,
        trusted_auth_relay_dids,
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
        vec![],
    )
    .await
}

pub async fn setup_three_node_network_with_sign_and_trusted_relays(
    db_name: &str,
    trusted_auth_relay_dids: Vec<String>,
) -> ThreeNodeNetwork {
    setup_three_node_network_impl(
        true,
        true,
        true,
        db_name,
        TestRouterHandlers::All,
        trusted_auth_relay_dids,
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
        trusted_auth_relay_dids: None,
        reporting: Default::default(),
        requires_pet: false,
        pet_pk: None,
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

/// A no-op `network::Topic` for test fixtures that need to construct a DKG
/// `ConfiguredTransport` but don't exercise real broadcast/receive behavior.
pub struct NoopTestTopic {
    id: network::TopicId,
}

impl NoopTestTopic {
    pub fn new(id: [u8; 32]) -> Self {
        Self {
            id: network::TopicId::new(id),
        }
    }
}

#[async_trait::async_trait]
impl network::Topic for NoopTestTopic {
    fn id(&self) -> network::TopicId {
        self.id
    }

    async fn broadcast(&self, _data: bytes::Bytes) -> network::Result<()> {
        Ok(())
    }

    async fn recv(&self) -> network::Result<network::PubSubEvent> {
        std::future::pending().await
    }
}

/// A minimal single-member `CeremonyConfig` for test fixtures that need a DKG
/// `ConfiguredTransport` but don't exercise committee contents.
pub fn minimal_test_ceremony_config() -> crate::dkg::v0::transport::CeremonyConfig {
    crate::dkg::v0::transport::CeremonyConfig {
        current: crate::dkg::v0::transport::CommitteeConfig {
            node_keys: vec!["test-node".to_string()],
            peer_routes: vec!["test-node@127.0.0.1:9000".to_string()],
            node_id_assignments: std::collections::HashMap::from([("test-node".to_string(), 1)]),
            threshold: 1,
        },
        next: None,
    }
}

pub fn test_db_path(name: &str) -> String {
    use_fast_test_kdf();
    let project_root = project_root::get_project_root().unwrap();
    format!("{}/test_dbs/{}.redb", project_root.display(), name)
}

/// Drop the Argon2 KDF cost for local storage to a trivial value for the test
/// suite (many `LocalStorageImpl::new` calls). Idempotent; a value the caller set
/// in the environment is left alone. Reached via `test_db_path`, which nearly
/// every storage-using test calls right before opening a database.
pub fn use_fast_test_kdf() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        if std::env::var_os("ORBIS_LOCAL_STORAGE_KDF_M_COST_KIB").is_none() {
            std::env::set_var("ORBIS_LOCAL_STORAGE_KDF_M_COST_KIB", "8");
        }
        if std::env::var_os("ORBIS_LOCAL_STORAGE_KDF_T_COST").is_none() {
            std::env::set_var("ORBIS_LOCAL_STORAGE_KDF_T_COST", "1");
        }
    });
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

// No current native caller (every caller today is a Cosmos/Docker test),
// hence gated the same as the Cosmos-only helpers above rather than left at
// the backend-neutral `integration-test` base — move back to the weaker gate
// if/when a native scenario needs this too.
#[cfg(feature = "integration-test-cosmos")]
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
// Same rationale as `check_full_grpc_ready` above: no native caller exists
// yet, so this stays Cosmos-gated rather than at the shared base.
#[cfg(feature = "integration-test-cosmos")]
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

/// Create a ring on-chain as TEST_ACCOUNT_HEX_KEY and return its ring_id.
///
/// Stayed here rather than moving to `test_support::admin::cosmos` alongside
/// its sibling helpers: it calls `cli_tool::create_ring`, and `cli-tool`
/// hardcodes a default crypto feature (`bls12-381`) that would conflict with a
/// jubjub build's feature unification if pulled into `test-support` as a
/// dependency. See `test_support::admin::cosmos`'s doc comment.
#[cfg(feature = "integration-test-cosmos")]
pub async fn create_ring_on_chain(
    chain_config: &ChainConfig,
    node_keys: &[String],
    threshold: u32,
    policy_id: &str,
    nonce: Option<&str>,
) -> String {
    create_ring_on_chain_with_trusted_relays(
        chain_config,
        node_keys,
        threshold,
        policy_id,
        nonce,
        vec![],
        false,
    )
    .await
}

#[cfg(feature = "integration-test-cosmos")]
pub async fn create_ring_on_chain_with_trusted_relays(
    chain_config: &ChainConfig,
    node_keys: &[String],
    threshold: u32,
    policy_id: &str,
    nonce: Option<&str>,
    trusted_auth_relay_dids: Vec<String>,
    requires_pet: bool,
) -> String {
    cli_tool::create_ring(
        node_keys.to_vec(),
        threshold,
        86400,
        policy_id.to_string(),
        nonce.map(String::from),
        network::V0.version,
        trusted_auth_relay_dids,
        requires_pet,
        chain_config.clone(),
        TEST_ACCOUNT_HEX_KEY,
    )
    .await
    .expect("create ring on-chain")
}
