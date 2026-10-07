//! Backend-dispatching integration-test network: a chain plus orbis-node
//! instances. [`IntegrationTestNetwork::builder`] defaults to
//! [`IntegrationBackend::Cosmos`], preserving every existing call site's
//! behavior unchanged; pass `.with_backend(IntegrationBackend::NativeVera)`
//! to provision the native Vera chain instead.
//!
//! The two backends' concrete types (`.cosmos()` / `.native()`) keep their
//! full original APIs for callers that need backend-specific detail; the
//! methods directly on `IntegrationTestNetwork` are the backend-neutral
//! surface shared scenario code is meant to use.

#[cfg(feature = "cosmos")]
mod cosmos;
#[cfg(feature = "cosmos")]
pub use cosmos::CosmosNetwork;

#[cfg(all(unix, feature = "native"))]
mod native;
#[cfg(all(unix, feature = "native"))]
pub use native::NativeNetworkAdapter;

use crate::admin::BackendAdmin;
use crate::backend::IntegrationBackend;

/// Node info returned from the info endpoint
#[derive(Debug, Clone)]
pub struct NodeInfo {
    pub grpc_endpoint: String,
    pub peer_id: String,
    pub p2p_address: String,
    pub public_address: String,
}

enum NetworkInner {
    // Boxed: `CosmosNetwork` is far larger than `NativeNetworkAdapter`, and
    // both features can be active in the same build (e.g. `orbis-node`'s
    // `native` feature doesn't disable `test-support`'s default `cosmos`
    // feature — that split is Phase D of the harness-unification plan).
    #[cfg(feature = "cosmos")]
    Cosmos(Box<CosmosNetwork>),
    #[cfg(all(unix, feature = "native"))]
    Native(Box<NativeNetworkAdapter>),
}

pub struct IntegrationTestNetwork {
    backend: IntegrationBackend,
    inner: NetworkInner,
}

pub struct IntegrationTestNetworkBuilder {
    backend: IntegrationBackend,
    node_count: usize,
    production_node_build: bool,
    unsafe_testing_runtime_enabled: bool,
    #[cfg(feature = "cosmos")]
    genesis_patches: serde_json::Map<String, serde_json::Value>,
    #[cfg(all(unix, feature = "native"))]
    native_deployment_seed: u64,
}

impl IntegrationTestNetwork {
    pub fn builder() -> IntegrationTestNetworkBuilder {
        IntegrationTestNetworkBuilder {
            backend: IntegrationBackend::default(),
            node_count: 3,
            production_node_build: false,
            unsafe_testing_runtime_enabled: true,
            #[cfg(feature = "cosmos")]
            genesis_patches: serde_json::Map::new(),
            #[cfg(all(unix, feature = "native"))]
            native_deployment_seed: 9000,
        }
    }

    pub fn new() -> Self {
        Self::builder().build()
    }

    pub fn backend(&self) -> IntegrationBackend {
        self.backend
    }

    #[cfg(feature = "cosmos")]
    pub fn cosmos(&self) -> &CosmosNetwork {
        match &self.inner {
            NetworkInner::Cosmos(network) => network,
            #[allow(unreachable_patterns)]
            _ => panic!(
                "IntegrationTestNetwork::cosmos() called on a {:?} backend",
                self.backend
            ),
        }
    }

    #[cfg(all(unix, feature = "native"))]
    pub fn native(&self) -> &NativeNetworkAdapter {
        match &self.inner {
            NetworkInner::Native(network) => network,
            #[allow(unreachable_patterns)]
            _ => panic!(
                "IntegrationTestNetwork::native() called on a {:?} backend",
                self.backend
            ),
        }
    }

    pub fn admin(&self) -> &dyn BackendAdmin {
        match &self.inner {
            #[cfg(feature = "cosmos")]
            NetworkInner::Cosmos(network) => network.admin(),
            #[cfg(all(unix, feature = "native"))]
            NetworkInner::Native(network) => network.admin(),
            // Reachable only when neither backend feature is enabled, in
            // which case `NetworkInner` has no variants and this crate's
            // builder can't have produced an `IntegrationTestNetwork` to
            // call this on in the first place — but the match still needs
            // an arm for that configuration to typecheck (same rationale as
            // `.cosmos()`/`.native()`'s fallback arm above).
            #[allow(unreachable_patterns)]
            _ => panic!(
                "test-support built with neither the \"cosmos\" nor \"native\" feature enabled"
            ),
        }
    }

    // `NODE1_SERVICE`..`NODE4_SERVICE` and `transform_p2p_address` are
    // associated items (not instance methods), so `Deref` below doesn't reach
    // them — every existing `IntegrationTestNetwork::NODE1_SERVICE` /
    // `IntegrationTestNetwork::transform_p2p_address(..)` call site (there are
    // many, across `src/tests/*`) resolves these directly instead.
    #[cfg(feature = "cosmos")]
    pub const NODE1_SERVICE: &'static str = CosmosNetwork::NODE1_SERVICE;
    #[cfg(feature = "cosmos")]
    pub const NODE2_SERVICE: &'static str = CosmosNetwork::NODE2_SERVICE;
    #[cfg(feature = "cosmos")]
    pub const NODE3_SERVICE: &'static str = CosmosNetwork::NODE3_SERVICE;
    #[cfg(feature = "cosmos")]
    pub const NODE4_SERVICE: &'static str = CosmosNetwork::NODE4_SERVICE;

    #[cfg(feature = "cosmos")]
    pub fn transform_p2p_address(p2p_address: &str, container_name: &str) -> String {
        CosmosNetwork::transform_p2p_address(p2p_address, container_name)
    }
}

impl Default for IntegrationTestNetwork {
    fn default() -> Self {
        Self::new()
    }
}

/// Transparent access to every original `CosmosNetwork` instance method
/// (`node1_endpoint`, `all_endpoints`, `vera_rpc_url`, `chain_config`,
/// `restart_nodes`, `stop_service`, `start_service`, …) for the many existing
/// call sites that reach them directly on `IntegrationTestNetwork`, predating
/// this dispatch wrapper. Panics via `.cosmos()` if the backend isn't Cosmos —
/// same behavior as calling `.cosmos()` explicitly.
#[cfg(feature = "cosmos")]
impl std::ops::Deref for IntegrationTestNetwork {
    type Target = CosmosNetwork;

    fn deref(&self) -> &CosmosNetwork {
        self.cosmos()
    }
}

impl IntegrationTestNetworkBuilder {
    pub fn with_backend(mut self, backend: IntegrationBackend) -> Self {
        self.backend = backend;
        self
    }

    pub fn with_node_count(mut self, node_count: usize) -> Self {
        self.node_count = node_count;
        self
    }

    pub fn with_production_node_build(mut self) -> Self {
        self.production_node_build = true;
        self.unsafe_testing_runtime_enabled = false;
        self
    }

    pub fn with_unsafe_testing_runtime_disabled(mut self) -> Self {
        self.unsafe_testing_runtime_enabled = false;
        self
    }

    /// Cosmos-only escape hatch: inject arbitrary genesis module state into the
    /// Vera chain before it starts, bypassing keeper validation via `InitGenesis`.
    #[cfg(feature = "cosmos")]
    pub fn with_module_genesis(mut self, module: &str, state: serde_json::Value) -> Self {
        self.genesis_patches.insert(module.to_string(), state);
        self
    }

    /// Native-only escape hatch: seed the native Vera devnet's keys/genesis
    /// deterministically. Defaults to a fixed seed shared by every builder
    /// that doesn't call this.
    #[cfg(all(unix, feature = "native"))]
    pub fn with_native_deployment_seed(mut self, seed: u64) -> Self {
        self.native_deployment_seed = seed;
        self
    }

    pub fn build(self) -> IntegrationTestNetwork {
        match self.backend {
            #[cfg(feature = "cosmos")]
            IntegrationBackend::Cosmos => {
                let mut builder = CosmosNetwork::builder().with_node_count(self.node_count);
                if self.production_node_build {
                    builder = builder.with_production_node_build();
                }
                if !self.unsafe_testing_runtime_enabled {
                    builder = builder.with_unsafe_testing_runtime_disabled();
                }
                for (module, state) in self.genesis_patches {
                    builder = builder.with_module_genesis(&module, state);
                }
                IntegrationTestNetwork {
                    backend: IntegrationBackend::Cosmos,
                    inner: NetworkInner::Cosmos(Box::new(builder.build())),
                }
            }
            #[cfg(not(feature = "cosmos"))]
            IntegrationBackend::Cosmos => {
                panic!("IntegrationBackend::Cosmos requires the \"cosmos\" feature")
            }
            #[allow(unreachable_patterns)]
            IntegrationBackend::NativeVera => panic!(
                "IntegrationTestNetworkBuilder::build() is synchronous; native network \
                 bootstrap is async. Use .build_async().await instead (requires the \
                 \"native\" feature on unix)."
            ),
        }
    }

    /// Async counterpart of [`Self::build`], required for
    /// [`IntegrationBackend::NativeVera`] — native's chain bootstrap polls the
    /// chain over RPC (`NativeTestNetwork::start_with_genesis`) and can't be
    /// driven from a synchronous `build()` without an executor-flavor-fragile
    /// `block_in_place` bridge. Phase B's Compose-driven native bring-up may
    /// make this synchronous like Cosmos's; until then, native callers await
    /// this instead of calling `.build()`.
    #[cfg(all(unix, feature = "native"))]
    pub async fn build_async(self) -> IntegrationTestNetwork {
        match self.backend {
            IntegrationBackend::NativeVera => {
                let cluster = NativeNetworkAdapter::start(self.native_deployment_seed).await;
                IntegrationTestNetwork {
                    backend: IntegrationBackend::NativeVera,
                    inner: NetworkInner::Native(Box::new(cluster)),
                }
            }
            #[allow(unreachable_patterns)]
            _ => panic!(
                "IntegrationTestNetworkBuilder::build_async() is for \
                 IntegrationBackend::NativeVera only; call .build() for Cosmos"
            ),
        }
    }
}
