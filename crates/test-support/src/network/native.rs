//! Native arm of the dispatch wrapper: a validator cluster
//! ([`crate::NativeTestNetwork`]) plus Orbis node containers, both on the
//! *same* Docker Compose project (`docker/docker-compose-native-integration-test.yml`),
//! brought up in two stages because each Orbis node's `vera.json` fixture
//! needs the chain's deployment root — only known once the validators have
//! produced a block.
//!
//! Scoped the same way `CosmosNetwork` is: this brings nodes up and connects
//! them to the chain, nothing more. Policy/ring/node-authorization setup
//! (this crate's `BackendAdmin`, wired to native in a later phase) happens
//! after the network exists, exactly like Cosmos's `test_helpers.rs`
//! functions run after `CosmosNetwork::builder().build()` returns.

use crate::admin::{BackendAdmin, DocumentId, PolicyId, RingId, RingKeys, RingSpec, RingView};
use crate::compose::{
    compose_command, localhost_url, published_port, report_compose_failure, stop_compose,
};
use crate::native_network::{self, NativeTestNetwork};
use std::{fs, time::Duration};

const ORBIS_GRPC_PORT: u16 = 50051;
const ORBIS_NODE_COUNT: usize = 3;

fn orbis_service(index: usize) -> &'static str {
    match index {
        0 => "node1",
        1 => "node2",
        2 => "node3",
        3 => "node4",
        _ => panic!("native devnet default topology only supports 4 orbis nodes"),
    }
}

struct NativeOrbisNode {
    grpc_endpoint: String,
}

pub struct NativeNetworkAdapter {
    cluster: NativeTestNetwork,
    orbis_nodes: Vec<NativeOrbisNode>,
    admin: NativeAdminStub,
    _node_fixtures: tempfile::TempDir,
}

impl NativeNetworkAdapter {
    pub async fn start(deployment: u64) -> Self {
        let cluster = NativeTestNetwork::start(deployment).await;
        let node_fixtures = tempfile::Builder::new()
            .prefix("orbis-native-nodes-")
            .tempdir()
            .expect("native orbis node fixture dir");
        let orbis_nodes =
            bring_up_orbis_nodes(&cluster, node_fixtures.path(), ORBIS_NODE_COUNT).await;
        Self {
            cluster,
            orbis_nodes,
            admin: NativeAdminStub,
            _node_fixtures: node_fixtures,
        }
    }

    pub fn cluster(&self) -> &NativeTestNetwork {
        &self.cluster
    }

    pub fn node_endpoints(&self) -> Vec<String> {
        self.orbis_nodes
            .iter()
            .map(|node| node.grpc_endpoint.clone())
            .collect()
    }

    pub fn node1_endpoint(&self) -> String {
        self.orbis_nodes[0].grpc_endpoint.clone()
    }

    /// Orbis nodes are already health-checked (TCP-reachable) by the time
    /// [`Self::start`] returns — see [`wait_for_grpc_ready`].
    pub fn wait_for_healthy(&self) {}

    pub fn restart_nodes(&self) -> Vec<String> {
        let services: Vec<&str> = (0..self.orbis_nodes.len()).map(orbis_service).collect();
        let status = compose_command(self.cluster.compose_file(), self.cluster.project_name())
            .arg("restart")
            .args(&services)
            .status()
            .expect("failed to restart native orbis containers");
        if !status.success() {
            report_compose_failure(self.cluster.compose_file(), self.cluster.project_name());
            panic!("failed to restart native orbis containers");
        }
        services
            .iter()
            .map(|service| {
                localhost_url(
                    published_port(
                        self.cluster.compose_file(),
                        self.cluster.project_name(),
                        service,
                        ORBIS_GRPC_PORT,
                    )
                    .unwrap_or_else(|error| {
                        panic!("discover restarted {service} endpoint: {error}")
                    }),
                )
            })
            .collect()
    }

    pub fn stop_node(&self, index: usize) {
        let service = orbis_service(index);
        let status = compose_command(self.cluster.compose_file(), self.cluster.project_name())
            .args(["stop", service])
            .status()
            .expect("docker compose stop failed");
        if !status.success() {
            report_compose_failure(self.cluster.compose_file(), self.cluster.project_name());
            panic!("Failed to stop native orbis service {service}");
        }
    }

    pub fn start_node(&self, index: usize) -> String {
        let service = orbis_service(index);
        let status = compose_command(self.cluster.compose_file(), self.cluster.project_name())
            .args(["start", service])
            .status()
            .expect("docker compose start failed");
        if !status.success() {
            report_compose_failure(self.cluster.compose_file(), self.cluster.project_name());
            panic!("Failed to start native orbis service {service}");
        }
        localhost_url(
            published_port(
                self.cluster.compose_file(),
                self.cluster.project_name(),
                service,
                ORBIS_GRPC_PORT,
            )
            .unwrap_or_else(|error| {
                panic!("failed to discover {service} endpoint after starting service: {error}")
            }),
        )
    }

    pub fn admin(&self) -> &dyn BackendAdmin {
        &self.admin
    }
}

impl Drop for NativeNetworkAdapter {
    fn drop(&mut self) {
        // The underlying `NativeTestNetwork`'s own `Drop` tears the whole
        // Compose project down (`stop_compose`, which removes every service
        // including node1-3) — nothing extra to do for the orbis-node half.
    }
}

async fn bring_up_orbis_nodes(
    cluster: &NativeTestNetwork,
    fixtures: &std::path::Path,
    count: usize,
) -> Vec<NativeOrbisNode> {
    // All three orbis nodes point at the same validator for chain RPC — this
    // mirrors `NativeWorkflow::start_with_network`'s existing convention
    // (`cluster.node(0).rpc_url()`), just via its Compose service name
    // instead of a host-published port, since this URL is dialed *inside*
    // the orbis-node containers.
    let endpoint = format!(
        "http://{}:{}",
        native_network::vera_service(0),
        native_network::VERA_RPC_PORT
    );

    let services: Vec<&str> = (0..count).map(orbis_service).collect();
    let reuse_prebuilt = std::env::var_os("ORBIS_NATIVE_IMAGE").is_some();

    // Same race as the validator build (see `native_network.rs`): every
    // `node{1..4}` service shares one identical `build:` block, so build the
    // shared image once, by name, before bringing any of them up.
    // Every invocation below must replay the *validators'* full env var set
    // (deployment, network name, per-validator dirs/IPs) even though it only
    // targets node services: `docker compose build`/`up` re-evaluate the
    // whole file's desired state regardless of which services they target,
    // and a missing var reads as blank — which Compose treats as drift on
    // the (unrelated, already-running) validator services, recreating them
    // mid-test. See `NativeTestNetwork::compose_env`'s doc comment.
    if !reuse_prebuilt {
        let mut build = compose_command(cluster.compose_file(), cluster.project_name());
        build.args(["build", services[0]]);
        for (key, value) in cluster.compose_env() {
            build.env(key, value);
        }
        let status = build
            .status()
            .expect("Failed to build native orbis node image");
        if !status.success() {
            report_compose_failure(cluster.compose_file(), cluster.project_name());
            stop_compose(cluster.compose_file(), cluster.project_name());
            panic!("docker compose build failed for native orbis nodes");
        }
    }

    let mut command = compose_command(cluster.compose_file(), cluster.project_name());
    command.arg("up").arg("-d");
    for (key, value) in cluster.compose_env() {
        command.env(key, value);
    }
    command.args(&services);

    for (index, _) in services.iter().enumerate() {
        let dir = fixtures.join(format!("node-{index}"));
        fs::create_dir_all(&dir).expect("create native orbis node fixture dir");
        fs::write(dir.join("password"), "native-dkg-test").expect("write node password fixture");
        fs::write(
            dir.join("vera.json"),
            serde_json::to_vec(&serde_json::json!({
                "endpoint": endpoint,
                "deployment_id": cluster.deployment(),
                "deployment_root": cluster.deployment_root_hex(),
                "consensus_key": cluster.consensus_key_hex(),
            }))
            .unwrap(),
        )
        .expect("write node vera.json fixture");
        command.env(
            format!("ORBIS_NATIVE_NODE{}_DIR", index + 1),
            dir.display().to_string(),
        );
    }

    let status = command
        .status()
        .expect("Failed to start native orbis containers");
    if !status.success() {
        report_compose_failure(cluster.compose_file(), cluster.project_name());
        stop_compose(cluster.compose_file(), cluster.project_name());
        panic!("docker compose up failed for native orbis nodes");
    }

    let nodes: Vec<NativeOrbisNode> = services
        .iter()
        .map(|service| {
            let port = published_port(
                cluster.compose_file(),
                cluster.project_name(),
                service,
                ORBIS_GRPC_PORT,
            )
            .unwrap_or_else(|error| {
                report_compose_failure(cluster.compose_file(), cluster.project_name());
                stop_compose(cluster.compose_file(), cluster.project_name());
                panic!("discover {service} endpoint: {error}");
            });
            NativeOrbisNode {
                grpc_endpoint: localhost_url(port),
            }
        })
        .collect();

    wait_for_grpc_ready(cluster, &nodes).await;
    nodes
}

/// Poll every node's gRPC port until reachable, matching
/// `CosmosNetwork::all_services_healthy`'s plain TCP-connect approach rather
/// than parsing Compose's own healthcheck status.
async fn wait_for_grpc_ready(cluster: &NativeTestNetwork, nodes: &[NativeOrbisNode]) {
    tokio::time::timeout(Duration::from_secs(120), async {
        loop {
            let mut ready = true;
            for node in nodes {
                let address = node
                    .grpc_endpoint
                    .strip_prefix("http://")
                    .expect("node endpoint uses http://");
                ready &= tokio::net::TcpStream::connect(address).await.is_ok();
            }
            if ready {
                break;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        report_compose_failure(cluster.compose_file(), cluster.project_name());
        panic!("native orbis nodes failed to become reachable");
    });
}

/// Placeholder `BackendAdmin` for the native dispatch arm. The real
/// implementation (`bin/orbis-node/tests/support/admin.rs`) lives outside
/// this crate — see `crate::admin`'s doc comment — and isn't wired into the
/// dispatch wrapper until Phase C gives the shared scenario layer a reason to
/// call through it. Every method here is reachable but not yet meaningful;
/// each panics with a specific message rather than a generic one.
struct NativeAdminStub;

#[async_trait::async_trait]
impl BackendAdmin for NativeAdminStub {
    async fn create_policy(&self, _definition: &str) -> PolicyId {
        unimplemented!(
            "IntegrationTestNetwork (native): BackendAdmin not yet wired through the dispatch \
             wrapper — see bin/orbis-node/tests/support/admin.rs::NativeAdmin (Phase C)"
        )
    }

    async fn grant(
        &self,
        _policy: &PolicyId,
        _resource: &str,
        _object_id: &str,
        _relation: &str,
        _subject_did: &str,
    ) {
        unimplemented!("see NativeAdminStub::create_policy")
    }

    async fn revoke(
        &self,
        _policy: &PolicyId,
        _resource: &str,
        _object_id: &str,
        _relation: &str,
        _subject_did: &str,
    ) {
        unimplemented!("see NativeAdminStub::create_policy")
    }

    async fn register_ring(&self, _spec: RingSpec) -> RingId {
        unimplemented!("see NativeAdminStub::create_policy")
    }

    async fn read_ring(&self, _ring: &RingId) -> Option<RingView> {
        unimplemented!("see NativeAdminStub::create_policy")
    }

    async fn wait_for_finalized(&self, _ring: &RingId, _timeout: Duration) -> RingKeys {
        unimplemented!("see NativeAdminStub::create_policy")
    }

    async fn update_membership(
        &self,
        _ring: &RingId,
        _new_members: Vec<String>,
        _new_threshold: u32,
    ) {
        unimplemented!("see NativeAdminStub::create_policy")
    }

    async fn store_document(
        &self,
        _ring: &RingId,
        _payload: &[u8],
        _reader_dids: &[String],
    ) -> DocumentId {
        unimplemented!("see NativeAdminStub::create_policy")
    }

    async fn read_document(&self, _id: &DocumentId) -> Vec<u8> {
        unimplemented!("see NativeAdminStub::create_policy")
    }
}
