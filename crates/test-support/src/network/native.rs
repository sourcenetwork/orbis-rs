//! Native arm of the dispatch wrapper: a validator cluster
//! ([`crate::NativeTestNetwork`]) plus Orbis node containers, both on the
//! *same* Docker Compose project (`docker/docker-compose-native-integration-test.yml`),
//! brought up in two stages because each Orbis node's `services.json` fixture
//! needs the chain's deployment root — only known once the validators have
//! produced a block.
//!
//! Scoped the same way `CosmosNetwork` is: this brings nodes up and connects
//! them to the chain, nothing more. Policy/ring/node-authorization setup
//! Backend-specific policy/ring/node-authorization setup happens after the
//! network exists, exactly like Cosmos's `test_helpers.rs` functions run
//! after `CosmosNetwork::builder().build()` returns.

use crate::compose::{
    compose_command, localhost_url, published_port_with_env, report_compose_failure, stop_compose,
};
use crate::native_network::{self, NativeTestNetwork};
use std::{fs, time::Duration};

const ORBIS_GRPC_PORT: u16 = 50051;
const DEFAULT_ORBIS_NODE_COUNT: usize = 3;

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
    /// Complete Compose interpolation used when this project was created.
    /// Lifecycle commands must replay it so blank/default values are not
    /// interpreted as desired-state changes.
    compose_env: Vec<(String, String)>,
    _node_fixtures: tempfile::TempDir,
}

impl NativeNetworkAdapter {
    pub async fn start(deployment: u64) -> Self {
        Self::start_configured(deployment, DEFAULT_ORBIS_NODE_COUNT, false, false).await
    }

    pub async fn start_configured(
        deployment: u64,
        node_count: usize,
        production_node_build: bool,
        unsafe_testing_runtime_enabled: bool,
    ) -> Self {
        assert!(
            (1..=4).contains(&node_count),
            "native devnet supports between 1 and 4 orbis nodes"
        );
        assert!(
            !production_node_build || !unsafe_testing_runtime_enabled,
            "a production native node build cannot expose the unsafe testing service"
        );
        let cluster = NativeTestNetwork::start(deployment).await;
        let node_fixtures = tempfile::Builder::new()
            .prefix("orbis-native-nodes-")
            .tempdir()
            .expect("native orbis node fixture dir");
        let (orbis_nodes, node_env) = bring_up_orbis_nodes(
            &cluster,
            node_fixtures.path(),
            node_count,
            production_node_build,
            unsafe_testing_runtime_enabled,
        )
        .await;
        let mut compose_env = cluster.compose_env().to_vec();
        compose_env.extend(node_env);
        Self {
            cluster,
            orbis_nodes,
            compose_env,
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

    /// Host directory bind-mounted as this node's `/data`. Valid while the
    /// adapter is alive, including while the container is stopped.
    pub fn node_directory(&self, index: usize) -> std::path::PathBuf {
        assert!(
            index < self.orbis_nodes.len(),
            "native node index {index} is outside the started set"
        );
        self._node_fixtures.path().join(format!("node-{index}"))
    }

    /// Orbis nodes are already health-checked (TCP-reachable) by the time
    /// [`Self::start`] returns — see [`wait_for_grpc_ready`].
    pub fn wait_for_healthy(&self) {}

    fn compose_command(&self) -> std::process::Command {
        let mut command = compose_command(self.cluster.compose_file(), self.cluster.project_name());
        for (key, value) in &self.compose_env {
            command.env(key, value);
        }
        command
    }

    fn published_port(&self, service: &str) -> u16 {
        published_port_with_env(
            self.cluster.compose_file(),
            self.cluster.project_name(),
            service,
            ORBIS_GRPC_PORT,
            &self.compose_env,
        )
        .unwrap_or_else(|error| panic!("discover {service} endpoint: {error}"))
    }

    pub fn restart_nodes(&self) -> Vec<String> {
        let services: Vec<&str> = (0..self.orbis_nodes.len()).map(orbis_service).collect();
        let status = self
            .compose_command()
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
            .map(|service| localhost_url(self.published_port(service)))
            .collect()
    }

    pub fn stop_node(&self, index: usize) {
        let service = orbis_service(index);
        let status = self
            .compose_command()
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
        let status = self
            .compose_command()
            .args(["start", service])
            .status()
            .expect("docker compose start failed");
        if !status.success() {
            report_compose_failure(self.cluster.compose_file(), self.cluster.project_name());
            panic!("Failed to start native orbis service {service}");
        }
        localhost_url(self.published_port(service))
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
    production_node_build: bool,
    unsafe_testing_runtime_enabled: bool,
) -> (Vec<NativeOrbisNode>, Vec<(String, String)>) {
    // All three orbis nodes point at the same validator for chain RPC — this
    // matches the Trust gateway startup (`cluster.node(0).rpc_url()`),
    // just via its Compose service name
    // instead of a host-published port, since this URL is dialed *inside*
    // the orbis-node containers.
    let endpoint = format!(
        "http://{}:{}",
        native_network::vera_service(0),
        native_network::VERA_RPC_PORT
    );

    let services: Vec<&str> = (0..count).map(orbis_service).collect();
    let normal_image = std::env::var_os("ORBIS_NATIVE_IMAGE");
    let diagnostic_image = std::env::var_os("ORBIS_NATIVE_DIAGNOSTIC_IMAGE");
    let reuse_prebuilt = if unsafe_testing_runtime_enabled {
        assert!(
            diagnostic_image.is_some() || normal_image.is_none(),
            "ORBIS_NATIVE_DIAGNOSTIC_IMAGE is required for a diagnostic scenario when \
             ORBIS_NATIVE_IMAGE selects a prebuilt production image"
        );
        diagnostic_image.is_some()
    } else {
        normal_image.is_some()
    };
    let mut node_env = vec![
        (
            "ORBIS_BUILD_INTEGRATION_TEST".to_string(),
            (!production_node_build).to_string(),
        ),
        (
            "ORBIS_NATIVE_ENABLE_UNSAFE_TESTING".to_string(),
            unsafe_testing_runtime_enabled.to_string(),
        ),
    ];
    if unsafe_testing_runtime_enabled {
        if let Some(image) = diagnostic_image {
            node_env.push((
                "ORBIS_NATIVE_IMAGE".to_string(),
                image.to_string_lossy().into_owned(),
            ));
        }
    }

    // Materialize all bind mounts before the first Compose invocation and
    // retain their interpolation variables. They are part of the project's
    // effective configuration, not one-shot inputs to `compose up`.
    for index in 0..count {
        let dir = fixtures.join(format!("node-{index}"));
        fs::create_dir_all(&dir).expect("create native orbis node fixture dir");
        fs::write(dir.join("password"), "native-dkg-test").expect("write node password fixture");
        fs::write(
            dir.join("services.json"),
            serde_json::to_vec(&serde_json::json!({
                "authz": {
                    "endpoint": endpoint,
                    "deployment_root": cluster.deployment_root_hex(),
                    "consensus_key": cluster.consensus_key_hex(),
                },
                "bulletin": {
                    "endpoint": endpoint,
                    "deployment_id": cluster.deployment(),
                    "deployment_root": cluster.deployment_root_hex(),
                    "consensus_key": cluster.consensus_key_hex(),
                },
            }))
            .unwrap(),
        )
        .expect("write node services.json fixture");
        node_env.push((
            format!("ORBIS_NATIVE_NODE{}_USER", index + 1),
            crate::bind_mount_user(&dir).expect("node fixture owner"),
        ));
        node_env.push((
            format!("ORBIS_NATIVE_NODE{}_DIR", index + 1),
            dir.display().to_string(),
        ));
    }

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
        for (key, value) in &node_env {
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
    for (key, value) in &node_env {
        command.env(key, value);
    }
    command.args(&services);

    let status = command
        .status()
        .expect("Failed to start native orbis containers");
    if !status.success() {
        report_compose_failure(cluster.compose_file(), cluster.project_name());
        stop_compose(cluster.compose_file(), cluster.project_name());
        panic!("docker compose up failed for native orbis nodes");
    }

    let mut full_compose_env = cluster.compose_env().to_vec();
    full_compose_env.extend(node_env.iter().cloned());
    let nodes: Vec<NativeOrbisNode> = services
        .iter()
        .map(|service| {
            let port = published_port_with_env(
                cluster.compose_file(),
                cluster.project_name(),
                service,
                ORBIS_GRPC_PORT,
                &full_compose_env,
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
    (nodes, node_env)
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
