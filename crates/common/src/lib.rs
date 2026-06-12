pub mod blockchain;

use std::env;
use std::fs::{File, OpenOptions};
use std::process::Command;
use std::time::Duration;

const DOCKER_COMPOSE_FILE: &str = "docker/docker-compose-sourcehub-test.yml";
const INTEGRATION_TEST_COMPOSE_FILE: &str = "docker/docker-compose-integration-test.yml";
const SOURCEHUB_TEST_PROJECT: &str = "orbis-sourcehub-test";
const INTEGRATION_TEST_PROJECT: &str = "orbis-integration-test";
const DOCKER_TEST_LOCK_FILE: &str = "orbis-rs-docker-tests.lock";
pub const SOURCEHUB_RPC_URL: &str = "http://localhost:26657";
const SOURCEHUB_API_URL: &str = "http://localhost:1317";

fn acquire_docker_test_lock() -> File {
    let path = env::temp_dir().join(DOCKER_TEST_LOCK_FILE);
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .unwrap_or_else(|error| {
            panic!(
                "Failed to open Docker test lock {}: {error}",
                path.display()
            )
        });

    println!("Waiting for exclusive Docker test access...");
    lock.lock()
        .unwrap_or_else(|error| panic!("Failed to lock {}: {error}", path.display()));
    println!("Acquired exclusive Docker test access");
    lock
}

fn compose_command(compose_file: &str, project_name: &str) -> Command {
    let mut command = Command::new("docker");
    command
        .args([
            "compose",
            "--project-name",
            project_name,
            "-f",
            compose_file,
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR").to_string() + "/../..");
    command
}

fn report_compose_failure(compose_file: &str, project_name: &str) {
    eprintln!("Docker Compose startup failed; recent container logs follow:");
    let _ = compose_command(compose_file, project_name)
        .args(["logs", "--no-color", "--tail", "200"])
        .status();
}

fn stop_compose(compose_file: &str, project_name: &str) {
    match compose_command(compose_file, project_name)
        .args(["down", "-v", "--remove-orphans"])
        .status()
    {
        Ok(status) if !status.success() => {
            eprintln!("docker compose down exited with non-zero status: {status}");
        }
        Ok(_) => {}
        Err(error) => eprintln!("Failed to stop docker compose: {error}"),
    }
}

pub struct SourceHubTestContainer {
    compose_file: String,
    project_name: &'static str,
    _docker_lock: File,
}

impl SourceHubTestContainer {
    pub fn new() -> Self {
        let docker_lock = acquire_docker_test_lock();
        let compose_file = DOCKER_COMPOSE_FILE.to_string();

        let status = compose_command(&compose_file, SOURCEHUB_TEST_PROJECT)
            .args(["up", "-d"])
            .status()
            .expect("Failed to start docker compose");

        if !status.success() {
            report_compose_failure(&compose_file, SOURCEHUB_TEST_PROJECT);
            stop_compose(&compose_file, SOURCEHUB_TEST_PROJECT);
            panic!("Failed to start sourcehub container");
        }

        let container = Self {
            compose_file,
            project_name: SOURCEHUB_TEST_PROJECT,
            _docker_lock: docker_lock,
        };

        // Wait for the container to be healthy
        container.wait_for_healthy();

        container
    }

    pub fn wait_for_healthy(&self) {
        let max_attempts = 60;
        let delay = Duration::from_secs(2);

        for attempt in 1..=max_attempts {
            if self.is_healthy() {
                println!("SourceHub is healthy after {} attempts", attempt);
                return;
            }
            println!(
                "Waiting for SourceHub to be healthy (attempt {}/{})",
                attempt, max_attempts
            );
            std::thread::sleep(delay);
        }

        panic!(
            "SourceHub failed to become healthy after {} attempts",
            max_attempts
        );
    }

    pub fn is_healthy(&self) -> bool {
        // Check if the RPC endpoint is responding
        let rpc_healthy = Command::new("curl")
            .args(["-sf", &format!("{}/health", SOURCEHUB_RPC_URL)])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);

        if !rpc_healthy {
            return false;
        }

        // Also check if the REST API is responding
        let rest_healthy = Command::new("curl")
            .args([
                "-sf",
                &format!(
                    "{}/cosmos/base/tendermint/v1beta1/node_info",
                    SOURCEHUB_API_URL
                ),
            ])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);

        rest_healthy
    }

    pub fn rpc_url(&self) -> &'static str {
        SOURCEHUB_RPC_URL
    }

    pub fn api_url(&self) -> &'static str {
        SOURCEHUB_API_URL
    }
}

impl Default for SourceHubTestContainer {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for SourceHubTestContainer {
    fn drop(&mut self) {
        println!("Stopping SourceHub test container...");
        stop_compose(&self.compose_file, self.project_name);
    }
}

/// Node info returned from the info endpoint
#[derive(Debug, Clone)]
pub struct NodeInfo {
    pub grpc_endpoint: String,
    pub peer_id: String,
    pub p2p_address: String,
    pub public_address: String,
}

/// Integration test network that spins up sourcehub + 3 orbis nodes via Docker Compose.
///
/// The node image is built with the crypto implementation selected by the
/// `ORBIS_INTEGRATION_CRYPTO` env var (e.g. `bls12-381` or `decaf377`). When that var is set,
/// `docker compose up` is run with `--build` so the image matches. When unset, default is
/// bls12-381. Run the test with the same feature so host and containers match, e.g.:
/// `ORBIS_INTEGRATION_CRYPTO=decaf377 cargo test test_cli_calls_dkg_and_pre_endpoint --no-default-features --features integration-test,decaf377`
pub struct IntegrationTestNetwork {
    compose_file: String,
    project_name: &'static str,
    _patch_file: Option<tempfile::NamedTempFile>,
    _docker_lock: File,
}

/// Builder for `IntegrationTestNetwork` that supports injecting arbitrary genesis module state
/// into the SourceHub chain before it starts, bypassing keeper validation via `InitGenesis`.
pub struct IntegrationTestNetworkBuilder {
    genesis_patches: serde_json::Map<String, serde_json::Value>,
    docker_lock: File,
}

impl IntegrationTestNetwork {
    /// Node gRPC endpoints (localhost mapped ports)
    pub const NODE1_GRPC: &'static str = "http://localhost:50051";
    pub const NODE2_GRPC: &'static str = "http://localhost:50052";
    pub const NODE3_GRPC: &'static str = "http://localhost:50053";

    /// Container names for inter-container communication
    pub const NODE1_CONTAINER: &'static str = "orbis-integration-node-1";
    pub const NODE2_CONTAINER: &'static str = "orbis-integration-node-2";
    pub const NODE3_CONTAINER: &'static str = "orbis-integration-node-3";

    pub fn builder() -> IntegrationTestNetworkBuilder {
        IntegrationTestNetworkBuilder {
            genesis_patches: serde_json::Map::new(),
            docker_lock: acquire_docker_test_lock(),
        }
    }

    pub fn new() -> Self {
        Self::builder().build()
    }

    pub fn wait_for_healthy(&self) {
        let max_attempts = 120; // 4 minutes total (nodes take longer to build)
        let delay = Duration::from_secs(2);

        for attempt in 1..=max_attempts {
            if self.all_services_healthy() {
                println!(
                    "All integration test services healthy after {} attempts",
                    attempt
                );
                return;
            }
            println!(
                "Waiting for integration test services to be healthy (attempt {}/{})",
                attempt, max_attempts
            );
            std::thread::sleep(delay);
        }

        panic!(
            "Integration test services failed to become healthy after {} attempts",
            max_attempts
        );
    }

    fn all_services_healthy(&self) -> bool {
        // Check sourcehub
        let sourcehub_healthy = Command::new("curl")
            .args(["-sf", &format!("{}/health", SOURCEHUB_RPC_URL)])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if !sourcehub_healthy {
            return false;
        }

        // Check all three nodes by attempting to connect to their gRPC ports
        for port in [50051, 50052, 50053] {
            let node_healthy = Command::new("nc")
                .args(["-z", "localhost", &port.to_string()])
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false);

            if !node_healthy {
                return false;
            }
        }

        true
    }

    /// Get the gRPC endpoint for node 1 (the primary node for client requests)
    pub fn node1_endpoint(&self) -> &'static str {
        Self::NODE1_GRPC
    }

    /// Get all node gRPC endpoints
    pub fn all_endpoints(&self) -> Vec<&'static str> {
        vec![Self::NODE1_GRPC, Self::NODE2_GRPC, Self::NODE3_GRPC]
    }

    pub fn sourcehub_rpc_url(&self) -> &'static str {
        SOURCEHUB_RPC_URL
    }

    pub fn sourcehub_api_url(&self) -> &'static str {
        SOURCEHUB_API_URL
    }

    /// Transform a p2p_address from local format to Docker inter-container format
    ///
    /// The p2p_address from a container will be like `peer_id@0.0.0.0:12345`
    /// For inter-container communication, we need `peer_id@container_name:12345`
    pub fn transform_p2p_address(p2p_address: &str, container_name: &str) -> String {
        // Parse peer_id@host:port
        if let Some(at_pos) = p2p_address.find('@') {
            let peer_id = &p2p_address[..at_pos];
            let host_port = &p2p_address[at_pos + 1..];

            // Extract just the port (after the last colon)
            if let Some(colon_pos) = host_port.rfind(':') {
                let port = &host_port[colon_pos + 1..];
                return format!("{}@{}:{}", peer_id, container_name, port);
            }
        }
        // Fallback: return as-is
        p2p_address.to_string()
    }

    /// Get container name for a given node index (1, 2, or 3)
    pub fn container_name_for_node(node_index: usize) -> &'static str {
        match node_index {
            1 => Self::NODE1_CONTAINER,
            2 => Self::NODE2_CONTAINER,
            3 => Self::NODE3_CONTAINER,
            _ => panic!("Invalid node index: {}", node_index),
        }
    }
}

impl Default for IntegrationTestNetwork {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for IntegrationTestNetwork {
    fn drop(&mut self) {
        println!("Stopping integration test containers...");
        stop_compose(&self.compose_file, self.project_name);
    }
}

impl IntegrationTestNetworkBuilder {
    pub fn with_module_genesis(mut self, module: &str, state: serde_json::Value) -> Self {
        self.genesis_patches.insert(module.to_string(), state);
        self
    }

    pub fn build(self) -> IntegrationTestNetwork {
        let IntegrationTestNetworkBuilder {
            genesis_patches,
            docker_lock,
        } = self;
        let compose_file = INTEGRATION_TEST_COMPOSE_FILE.to_string();

        let crypto_feature: Option<&'static str> = if env::var("ORBIS_INTEGRATION_CRYPTO").is_ok() {
            None
        } else {
            #[cfg(feature = "bls12-381")]
            {
                Some("bls12-381")
            }
            #[cfg(all(not(feature = "bls12-381"), feature = "decaf377"))]
            {
                Some("decaf377")
            }
            #[cfg(not(any(feature = "bls12-381", feature = "decaf377")))]
            {
                None
            }
        };

        let patch_file: Option<tempfile::NamedTempFile> = if genesis_patches.is_empty() {
            None
        } else {
            let mut f = tempfile::NamedTempFile::new().expect("genesis patch tempfile");
            serde_json::to_writer(&mut f, &serde_json::Value::Object(genesis_patches))
                .expect("write genesis patch");
            Some(f)
        };

        let mut command = compose_command(&compose_file, INTEGRATION_TEST_PROJECT);
        command.args(["up", "-d", "--build"]);

        if let Some(feat) = crypto_feature {
            command.env("ORBIS_INTEGRATION_CRYPTO", feat);
        }
        if let Some(ref patch_file) = patch_file {
            command.env("GENESIS_PATCH_FILE", patch_file.path());
        } else {
            command.env_remove("GENESIS_PATCH_FILE");
        }

        let status = command.status().expect("Failed to start docker compose");

        if !status.success() {
            report_compose_failure(&compose_file, INTEGRATION_TEST_PROJECT);
            stop_compose(&compose_file, INTEGRATION_TEST_PROJECT);
            panic!("Failed to start integration test containers");
        }

        let network = IntegrationTestNetwork {
            compose_file,
            project_name: INTEGRATION_TEST_PROJECT,
            _patch_file: patch_file,
            _docker_lock: docker_lock,
        };
        network.wait_for_healthy();
        network
    }
}
