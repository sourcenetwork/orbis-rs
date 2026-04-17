pub mod blockchain;

use std::env;
use std::process::Command;
use std::time::Duration;

const DOCKER_COMPOSE_FILE: &str = "docker/docker-compose-sourcehub-test.yml";
const INTEGRATION_TEST_COMPOSE_FILE: &str = "docker/docker-compose-integration-test.yml";
pub const SOURCEHUB_RPC_URL: &str = "http://localhost:26657";
const SOURCEHUB_API_URL: &str = "http://localhost:1317";

pub struct SourceHubTestContainer {
    compose_file: String,
}

impl SourceHubTestContainer {
    pub fn new() -> Self {
        let compose_file = DOCKER_COMPOSE_FILE.to_string();

        // Start the container
        let status = Command::new("docker")
            .args(["compose", "-f", &compose_file, "up", "-d"])
            .current_dir(env!("CARGO_MANIFEST_DIR").to_string() + "/../..")
            .status()
            .expect("Failed to start docker compose");

        assert!(status.success(), "Failed to start sourcehub container");

        let container = Self { compose_file };

        // Wait for the container to be healthy
        container.wait_for_healthy();

        container
    }
}

impl Default for SourceHubTestContainer {
    fn default() -> Self {
        Self::new()
    }
}

impl SourceHubTestContainer {
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

impl Drop for SourceHubTestContainer {
    fn drop(&mut self) {
        println!("Stopping SourceHub test container...");

        let status = Command::new("docker")
            .args(["compose", "-f", &self.compose_file, "down", "-v"])
            .current_dir(env!("CARGO_MANIFEST_DIR").to_string() + "/../..")
            .status();

        if let Err(e) = status {
            eprintln!("Failed to stop docker compose: {}", e);
        }
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

    pub fn new() -> Self {
        let compose_file = INTEGRATION_TEST_COMPOSE_FILE.to_string();

        // Derive the crypto feature from compile-time cfg so the docker image
        // always matches the test binary. An explicit ORBIS_INTEGRATION_CRYPTO
        // env var overrides the compile-time default.
        let crypto_feature: Option<&'static str> = if env::var("ORBIS_INTEGRATION_CRYPTO").is_ok() {
            // Honour explicit override (already in env for docker-compose)
            None
        } else {
            // Set env var from compile-time feature so docker-compose picks it up
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

        if let Some(feat) = crypto_feature {
            env::set_var("ORBIS_INTEGRATION_CRYPTO", feat);
        }

        // Always rebuild so the node image matches the selected crypto feature
        let args = vec!["compose", "-f", &compose_file, "up", "-d", "--build"];

        let status = Command::new("docker")
            .args(&args)
            .current_dir(env!("CARGO_MANIFEST_DIR").to_string() + "/../..")
            .status()
            .expect("Failed to start docker compose");

        assert!(
            status.success(),
            "Failed to start integration test containers"
        );

        let network = Self { compose_file };

        // Wait for all services to be healthy
        network.wait_for_healthy();

        network
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

        let status = Command::new("docker")
            .args(["compose", "-f", &self.compose_file, "down", "-v"])
            .current_dir(env!("CARGO_MANIFEST_DIR").to_string() + "/../..")
            .status();

        if let Err(e) = status {
            eprintln!("Failed to stop docker compose: {}", e);
        }
    }
}
