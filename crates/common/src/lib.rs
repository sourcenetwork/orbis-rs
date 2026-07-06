pub mod blockchain;

use blockchain::{ChainConfig, ChainConfigBuilder};
use std::env;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

const DOCKER_COMPOSE_FILE: &str = "docker/docker-compose-sourcehub-test.yml";
const INTEGRATION_TEST_COMPOSE_FILE: &str = "docker/docker-compose-integration-test.yml";
static NEXT_PROJECT_ID: AtomicU64 = AtomicU64::new(0);

fn unique_project_name(prefix: &str) -> String {
    let sequence = NEXT_PROJECT_ID.fetch_add(1, Ordering::Relaxed);
    format!("{prefix}-{}-{sequence}", std::process::id())
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

fn parse_published_port(output: &str) -> Option<u16> {
    output
        .lines()
        .find(|line| !line.trim().is_empty())
        .and_then(|line| line.trim().rsplit_once(':'))
        .and_then(|(_, port)| port.parse().ok())
}

fn published_port(
    compose_file: &str,
    project_name: &str,
    service: &str,
    container_port: u16,
) -> Result<u16, String> {
    let output = compose_command(compose_file, project_name)
        .args(["port", service, &container_port.to_string()])
        .output()
        .map_err(|error| {
            format!("Failed to query published port for {service}:{container_port}: {error}")
        })?;

    if !output.status.success() {
        return Err(format!(
            "Failed to query published port for {service}:{container_port}: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_published_port(&stdout).ok_or_else(|| {
        format!("Unexpected docker compose port output for {service}:{container_port}: {stdout:?}")
    })
}

fn localhost_url(port: u16) -> String {
    format!("http://127.0.0.1:{port}")
}

fn report_compose_failure(compose_file: &str, project_name: &str) {
    eprintln!("Docker Compose diagnostics for project {project_name}:");
    let _ = compose_command(compose_file, project_name)
        .args(["ps", "--all"])
        .status();

    if let Ok(output) = compose_command(compose_file, project_name)
        .args(["ps", "--all", "--quiet"])
        .output()
    {
        let container_ids: Vec<&str> = std::str::from_utf8(&output.stdout)
            .unwrap_or_default()
            .lines()
            .filter(|line| !line.is_empty())
            .collect();
        if !container_ids.is_empty() {
            let _ = Command::new("docker")
                .args([
                    "inspect",
                    "--format",
                    "{{.Name}} status={{.State.Status}} exit={{.State.ExitCode}} restart={{.RestartCount}} oom={{.State.OOMKilled}}",
                ])
                .args(container_ids)
                .status();
        }
    }

    eprintln!("Recent container logs:");
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
    project_name: String,
    chain_config: ChainConfig,
}

impl SourceHubTestContainer {
    pub fn new() -> Self {
        let compose_file = DOCKER_COMPOSE_FILE.to_string();
        let project_name = unique_project_name("orbis-sourcehub");

        let status = compose_command(&compose_file, &project_name)
            .args(["up", "-d", "--build"])
            .status()
            .expect("Failed to start docker compose");

        if !status.success() {
            report_compose_failure(&compose_file, &project_name);
            stop_compose(&compose_file, &project_name);
            panic!("Failed to start sourcehub container");
        }

        let chain_config = (|| -> Result<ChainConfig, String> {
            Ok(ChainConfig::builder()
                .rpc_url(Some(localhost_url(published_port(
                    &compose_file,
                    &project_name,
                    "sourcehub",
                    26657,
                )?)))
                .rest_url(Some(localhost_url(published_port(
                    &compose_file,
                    &project_name,
                    "sourcehub",
                    1317,
                )?)))
                .grpc_url(Some(localhost_url(published_port(
                    &compose_file,
                    &project_name,
                    "sourcehub",
                    9090,
                )?)))
                .build())
        })()
        .unwrap_or_else(|error| {
            report_compose_failure(&compose_file, &project_name);
            stop_compose(&compose_file, &project_name);
            panic!("Failed to discover SourceHub endpoints: {error}");
        });

        let container = Self {
            compose_file,
            project_name,
            chain_config,
        };

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
        let rpc_healthy = Command::new("curl")
            .args(["-sf", &format!("{}/health", self.rpc_url())])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);

        if !rpc_healthy {
            return false;
        }

        let rest_healthy = Command::new("curl")
            .args([
                "-sf",
                &format!(
                    "{}/cosmos/base/tendermint/v1beta1/node_info",
                    self.api_url()
                ),
            ])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);

        rest_healthy
    }

    pub fn rpc_url(&self) -> &str {
        &self.chain_config.rpc_url
    }

    pub fn api_url(&self) -> &str {
        &self.chain_config.rest_url
    }

    pub fn grpc_url(&self) -> &str {
        &self.chain_config.grpc_url
    }

    pub fn chain_config(&self) -> ChainConfig {
        self.chain_config.clone()
    }

    pub fn chain_config_builder(&self) -> ChainConfigBuilder {
        ChainConfigBuilder::default()
            .rpc_url(Some(self.rpc_url().to_string()))
            .rest_url(Some(self.api_url().to_string()))
            .grpc_url(Some(self.grpc_url().to_string()))
    }
}

impl Default for SourceHubTestContainer {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for SourceHubTestContainer {
    fn drop(&mut self) {
        if std::thread::panicking() {
            report_compose_failure(&self.compose_file, &self.project_name);
        }
        println!("Stopping SourceHub test container...");
        stop_compose(&self.compose_file, &self.project_name);
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
    project_name: String,
    chain_config: ChainConfig,
    node_endpoints: [String; 3],
    _patch_file: Option<tempfile::NamedTempFile>,
}

/// Builder for `IntegrationTestNetwork` that supports injecting arbitrary genesis module state
/// into the SourceHub chain before it starts, bypassing keeper validation via `InitGenesis`.
pub struct IntegrationTestNetworkBuilder {
    genesis_patches: serde_json::Map<String, serde_json::Value>,
    production_node_build: bool,
    unsafe_testing_runtime_enabled: bool,
}

impl IntegrationTestNetwork {
    pub const NODE1_SERVICE: &'static str = "node1";
    pub const NODE2_SERVICE: &'static str = "node2";
    pub const NODE3_SERVICE: &'static str = "node3";

    pub fn builder() -> IntegrationTestNetworkBuilder {
        IntegrationTestNetworkBuilder {
            genesis_patches: serde_json::Map::new(),
            production_node_build: false,
            unsafe_testing_runtime_enabled: true,
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
        let sourcehub_healthy = Command::new("curl")
            .args(["-sf", &format!("{}/health", self.sourcehub_rpc_url())])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if !sourcehub_healthy {
            return false;
        }

        for endpoint in &self.node_endpoints {
            let address = endpoint
                .strip_prefix("http://")
                .expect("node endpoint should use http://");
            if std::net::TcpStream::connect_timeout(
                &address.parse().expect("valid node endpoint"),
                Duration::from_secs(1),
            )
            .is_err()
            {
                return false;
            }
        }

        true
    }

    /// Get the gRPC endpoint for node 1 (the primary node for client requests)
    pub fn node1_endpoint(&self) -> &str {
        &self.node_endpoints[0]
    }

    pub fn all_endpoints(&self) -> [&str; 3] {
        [
            &self.node_endpoints[0],
            &self.node_endpoints[1],
            &self.node_endpoints[2],
        ]
    }

    pub fn sourcehub_rpc_url(&self) -> &str {
        &self.chain_config.rpc_url
    }

    pub fn sourcehub_api_url(&self) -> &str {
        &self.chain_config.rest_url
    }

    pub fn sourcehub_grpc_url(&self) -> &str {
        &self.chain_config.grpc_url
    }

    pub fn chain_config(&self) -> ChainConfig {
        self.chain_config.clone()
    }

    pub fn chain_config_builder(&self) -> ChainConfigBuilder {
        ChainConfigBuilder::default()
            .rpc_url(Some(self.sourcehub_rpc_url().to_string()))
            .rest_url(Some(self.sourcehub_api_url().to_string()))
            .grpc_url(Some(self.sourcehub_grpc_url().to_string()))
    }

    /// Restart the Orbis node containers without rebuilding them or resetting
    /// their local storage. Docker may reassign ephemeral host ports during a
    /// restart, so the returned endpoints must replace any previously cached
    /// node endpoints.
    pub fn restart_nodes(&self) -> [String; 3] {
        let status = compose_command(&self.compose_file, &self.project_name)
            .args(["restart", "node1", "node2", "node3"])
            .status()
            .expect("Failed to restart integration test nodes");
        if !status.success() {
            report_compose_failure(&self.compose_file, &self.project_name);
            panic!("Failed to restart integration test nodes");
        }

        [
            localhost_url(
                published_port(&self.compose_file, &self.project_name, "node1", 50051)
                    .expect("discover restarted node1 endpoint"),
            ),
            localhost_url(
                published_port(&self.compose_file, &self.project_name, "node2", 50051)
                    .expect("discover restarted node2 endpoint"),
            ),
            localhost_url(
                published_port(&self.compose_file, &self.project_name, "node3", 50051)
                    .expect("discover restarted node3 endpoint"),
            ),
        ]
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

    pub fn service_name_for_node(node_index: usize) -> &'static str {
        match node_index {
            1 => Self::NODE1_SERVICE,
            2 => Self::NODE2_SERVICE,
            3 => Self::NODE3_SERVICE,
            _ => panic!("Invalid node index: {}", node_index),
        }
    }

    /// Stop a single Docker Compose service by name without removing it.
    pub fn stop_service(&self, service: &str) {
        let status = compose_command(&self.compose_file, &self.project_name)
            .args(["stop", service])
            .status()
            .expect("docker compose stop failed");
        if !status.success() {
            report_compose_failure(&self.compose_file, &self.project_name);
            panic!("Failed to stop service {service}");
        }
    }

    /// Start a previously stopped Docker Compose service without recreating it,
    /// preserving its local storage. Docker may reassign the ephemeral host port,
    /// so the returned gRPC endpoint must replace any previously cached one.
    pub fn start_service(&self, service: &str) -> String {
        let status = compose_command(&self.compose_file, &self.project_name)
            .args(["start", service])
            .status()
            .expect("docker compose start failed");
        if !status.success() {
            report_compose_failure(&self.compose_file, &self.project_name);
            panic!("Failed to start service {service}");
        }
        localhost_url(
            published_port(&self.compose_file, &self.project_name, service, 50051).unwrap_or_else(
                |error| {
                    panic!("failed to discover {service} endpoint after starting service: {error}")
                },
            ),
        )
    }
}

impl Default for IntegrationTestNetwork {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for IntegrationTestNetwork {
    fn drop(&mut self) {
        if std::thread::panicking() {
            report_compose_failure(&self.compose_file, &self.project_name);
        }
        println!("Stopping integration test containers...");
        stop_compose(&self.compose_file, &self.project_name);
    }
}

impl IntegrationTestNetworkBuilder {
    pub fn with_module_genesis(mut self, module: &str, state: serde_json::Value) -> Self {
        self.genesis_patches.insert(module.to_string(), state);
        self
    }

    /// Build Docker nodes with the default production feature set instead of
    /// the integration-test feature set.
    pub fn with_production_node_build(mut self) -> Self {
        self.production_node_build = true;
        self.unsafe_testing_runtime_enabled = false;
        self
    }

    /// Compile the integration-test feature set, but leave the unsafe testing
    /// gRPC service disabled at runtime.
    pub fn with_unsafe_testing_runtime_disabled(mut self) -> Self {
        self.unsafe_testing_runtime_enabled = false;
        self
    }

    pub fn build(self) -> IntegrationTestNetwork {
        let IntegrationTestNetworkBuilder {
            genesis_patches,
            production_node_build,
            unsafe_testing_runtime_enabled,
        } = self;
        let compose_file = INTEGRATION_TEST_COMPOSE_FILE.to_string();
        let project_name = unique_project_name("orbis-integration");

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
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;

                let mut permissions = f
                    .as_file()
                    .metadata()
                    .expect("read genesis patch tempfile metadata")
                    .permissions();
                permissions.set_mode(0o644);
                f.as_file()
                    .set_permissions(permissions)
                    .expect("make genesis patch tempfile readable by Docker container");
            }
            Some(f)
        };

        let mut command = compose_command(&compose_file, &project_name);
        command.args(["up", "-d", "--build"]);

        if let Some(feat) = crypto_feature {
            command.env("ORBIS_INTEGRATION_CRYPTO", feat);
        }
        command.env(
            "ORBIS_BUILD_INTEGRATION_TEST",
            if production_node_build {
                "false"
            } else {
                "true"
            },
        );
        command.env(
            "ORBIS_ENABLE_INTEGRATION_TEST",
            if unsafe_testing_runtime_enabled {
                "true"
            } else {
                "false"
            },
        );
        if let Some(ref patch_file) = patch_file {
            command.env("GENESIS_PATCH_FILE", patch_file.path());
        } else {
            command.env_remove("GENESIS_PATCH_FILE");
        }

        let status = command.status().expect("Failed to start docker compose");

        if !status.success() {
            report_compose_failure(&compose_file, &project_name);
            stop_compose(&compose_file, &project_name);
            panic!("Failed to start integration test containers");
        }

        let endpoints = (|| -> Result<(ChainConfig, [String; 3]), String> {
            let chain_config = ChainConfig::builder()
                .rpc_url(Some(localhost_url(published_port(
                    &compose_file,
                    &project_name,
                    "sourcehub",
                    26657,
                )?)))
                .rest_url(Some(localhost_url(published_port(
                    &compose_file,
                    &project_name,
                    "sourcehub",
                    1317,
                )?)))
                .grpc_url(Some(localhost_url(published_port(
                    &compose_file,
                    &project_name,
                    "sourcehub",
                    9090,
                )?)))
                .build();
            let node_endpoints = [
                localhost_url(published_port(
                    &compose_file,
                    &project_name,
                    "node1",
                    50051,
                )?),
                localhost_url(published_port(
                    &compose_file,
                    &project_name,
                    "node2",
                    50051,
                )?),
                localhost_url(published_port(
                    &compose_file,
                    &project_name,
                    "node3",
                    50051,
                )?),
            ];
            Ok((chain_config, node_endpoints))
        })()
        .unwrap_or_else(|error| {
            report_compose_failure(&compose_file, &project_name);
            stop_compose(&compose_file, &project_name);
            panic!("Failed to discover integration test endpoints: {error}");
        });
        let (chain_config, node_endpoints) = endpoints;

        let network = IntegrationTestNetwork {
            compose_file,
            project_name,
            chain_config,
            node_endpoints,
            _patch_file: patch_file,
        };
        network.wait_for_healthy();
        network
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_published_port, unique_project_name};

    #[test]
    fn parses_compose_port_output() {
        assert_eq!(parse_published_port("127.0.0.1:49152\n"), Some(49152));
    }

    #[test]
    fn project_names_are_unique() {
        assert_ne!(
            unique_project_name("orbis-test"),
            unique_project_name("orbis-test")
        );
    }
}
