//! A Vera (Cosmos/SourceHub) chain plus orbis-node instances, all via Docker Compose.

use crate::admin::cosmos::CosmosAdmin;
use crate::compose::{
    compose_command, localhost_url, published_port, report_compose_failure, stop_compose,
    unique_project_name,
};
use common::blockchain::{ChainConfig, ChainConfigBuilder};
use std::process::Command;
use std::time::Duration;

const INTEGRATION_TEST_COMPOSE_FILE: &str = "docker/docker-compose-integration-test.yml";

/// Integration test network that spins up vera + orbis nodes via Docker Compose.
///
/// The node image is built (`docker compose up --build`) with the crypto
/// implementation named by the `ORBIS_INTEGRATION_CRYPTO` env var, which the
/// compose subprocess inherits. **Unset ⇒ bls12-381.** A jubjub run must
/// export it so the built images match the host feature set — there is no
/// auto-detection:
/// `ORBIS_INTEGRATION_CRYPTO=jubjub cargo test --no-default-features --features integration-test,jubjub test_cli_calls_dkg_and_pre_endpoint`
pub struct CosmosNetwork {
    compose_file: String,
    project_name: String,
    chain_config: ChainConfig,
    node_endpoints: Vec<String>,
    admin: CosmosAdmin,
    defra_url: Option<String>,
    defra_container_url: Option<String>,
    _patch_file: Option<tempfile::NamedTempFile>,
}

/// Builder for `CosmosNetwork` that supports injecting arbitrary genesis module state
/// into the Vera chain before it starts, bypassing keeper validation via `InitGenesis`.
pub struct CosmosNetworkBuilder {
    genesis_patches: serde_json::Map<String, serde_json::Value>,
    production_node_build: bool,
    unsafe_testing_runtime_enabled: bool,
    node_count: usize,
    defra: bool,
}

impl CosmosNetwork {
    pub const NODE1_SERVICE: &'static str = "node1";
    pub const NODE2_SERVICE: &'static str = "node2";
    pub const NODE3_SERVICE: &'static str = "node3";
    pub const NODE4_SERVICE: &'static str = "node4";

    pub fn builder() -> CosmosNetworkBuilder {
        CosmosNetworkBuilder {
            genesis_patches: serde_json::Map::new(),
            production_node_build: false,
            unsafe_testing_runtime_enabled: true,
            node_count: 3,
            defra: false,
        }
    }

    pub fn new() -> Self {
        Self::builder().build()
    }

    pub fn admin(&self) -> &CosmosAdmin {
        &self.admin
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
        let vera_healthy = Command::new("curl")
            .args(["-sf", &format!("{}/health", self.vera_rpc_url())])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if !vera_healthy {
            return false;
        }

        if let Some(defra_url) = &self.defra_url {
            let defra_healthy = Command::new("curl")
                .args(["-sf", &format!("{defra_url}/health-check")])
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false);
            if !defra_healthy {
                return false;
            }
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

    pub fn all_endpoints(&self) -> Vec<&str> {
        self.node_endpoints.iter().map(String::as_str).collect()
    }

    /// Host-reachable URL for the Defra container, when
    /// `CosmosNetworkBuilder::with_defra` was used — `None` otherwise.
    /// For the test driver's own HTTP calls (provisioning the `PreShare`
    /// collection, polling health) only; nodes inside the Compose network
    /// always reach Defra via `http://defra:9181` (the container's own
    /// internal DNS name and fixed port), never this discovered host port.
    pub fn defra_url(&self) -> Option<&str> {
        self.defra_url.as_deref()
    }

    /// Address for Defra reachable from *inside* the Compose network's
    /// bridge — i.e. by orbis-node containers (ring `pre_share_endpoints`
    /// resolves this, not a Compose service name, so a reader running
    /// outside the Compose network, such as this test's own `cli_tool::do_pre`
    /// call, can resolve the same value too). The bridge's gateway IP is
    /// reachable both from sibling containers and, on a native Linux Docker
    /// host, from the host itself — the same host that commands `docker
    /// compose up` in the first place. `None` unless
    /// `CosmosNetworkBuilder::with_defra` was used. `Option<String>` (not
    /// `&str`): matches `NativeTestNetwork::defra_container_url`'s return
    /// type, which has no stored string to borrow from (it formats the
    /// address fresh from a static IP on every call) — same signature on
    /// both lets a shared test body call either without backend-specific
    /// handling.
    pub fn defra_container_url(&self) -> Option<String> {
        self.defra_container_url.clone()
    }

    pub fn vera_rpc_url(&self) -> &str {
        &self.chain_config.rpc_url
    }

    pub fn vera_api_url(&self) -> &str {
        &self.chain_config.rest_url
    }

    pub fn vera_grpc_url(&self) -> &str {
        &self.chain_config.grpc_url
    }

    pub fn chain_config(&self) -> ChainConfig {
        self.chain_config.clone()
    }

    pub fn chain_config_builder(&self) -> ChainConfigBuilder {
        ChainConfigBuilder::default()
            .rpc_url(Some(self.vera_rpc_url().to_string()))
            .rest_url(Some(self.vera_api_url().to_string()))
            .grpc_url(Some(self.vera_grpc_url().to_string()))
    }

    /// Restart the Orbis node containers without rebuilding them or resetting
    /// their local storage. Docker may reassign ephemeral host ports during a
    /// restart, so the returned endpoints must replace any previously cached
    /// node endpoints.
    pub fn restart_nodes(&self) -> Vec<String> {
        let services = self.node_services();
        let status = compose_command(&self.compose_file, &self.project_name)
            .arg("restart")
            .args(&services)
            .status()
            .expect("Failed to restart integration test nodes");
        if !status.success() {
            report_compose_failure(&self.compose_file, &self.project_name);
            panic!("Failed to restart integration test nodes");
        }

        services
            .iter()
            .map(|service| {
                localhost_url(
                    published_port(&self.compose_file, &self.project_name, service, 50051)
                        .unwrap_or_else(|error| {
                            panic!("discover restarted {service} endpoint: {error}")
                        }),
                )
            })
            .collect()
    }

    /// Unconnected UDP ports the node process is bound to inside the container.
    pub fn container_udp_listen_ports(&self, service: &str) -> Vec<u16> {
        let udp = compose_command(&self.compose_file, &self.project_name)
            .args(["exec", "-T", service, "cat", "/proc/net/udp"])
            .output();
        let fds = compose_command(&self.compose_file, &self.project_name)
            .args(["exec", "-T", service, "ls", "-l", "/proc/1/fd"])
            .output();
        let (Ok(udp), Ok(fds)) = (udp, fds) else {
            return Vec::new();
        };
        if !udp.status.success() || !fds.status.success() {
            return Vec::new();
        }
        parse_process_udp_listen_ports(
            &String::from_utf8_lossy(&udp.stdout),
            &String::from_utf8_lossy(&fds.stdout),
        )
    }

    /// Transform a p2p_address from local format to Docker inter-container format.
    ///
    /// The p2p_address from a container will be like `peer_id@0.0.0.0:12345`.
    /// For inter-container communication, we need `peer_id@container_name:12345`.
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
            4 => Self::NODE4_SERVICE,
            _ => panic!("Invalid node index: {}", node_index),
        }
    }

    fn node_services(&self) -> Vec<String> {
        (1..=self.node_endpoints.len())
            .map(|index| Self::service_name_for_node(index).to_string())
            .collect()
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

impl Default for CosmosNetwork {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for CosmosNetwork {
    fn drop(&mut self) {
        if std::thread::panicking() {
            report_compose_failure(&self.compose_file, &self.project_name);
        }
        println!("Stopping integration test containers...");
        stop_compose(&self.compose_file, &self.project_name);
    }
}

impl CosmosNetworkBuilder {
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

    pub fn with_node_count(mut self, node_count: usize) -> Self {
        assert!(
            matches!(node_count, 3 | 4),
            "integration test network supports 3 or 4 nodes"
        );
        self.node_count = node_count;
        self
    }

    /// Also bring up the Defra container (`defra` Compose profile), for a
    /// ring that uses `pre_share_endpoints`. Nodes reach it at
    /// `http://defra:9181`; the test driver itself uses
    /// [`CosmosNetwork::defra_url`].
    pub fn with_defra(mut self) -> Self {
        self.defra = true;
        self
    }

    pub fn build(self) -> CosmosNetwork {
        let CosmosNetworkBuilder {
            genesis_patches,
            production_node_build,
            unsafe_testing_runtime_enabled,
            node_count,
            defra,
        } = self;
        let compose_file = INTEGRATION_TEST_COMPOSE_FILE.to_string();
        let project_name = unique_project_name("orbis-integration");

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

        // CI (and anyone who wants to) can pre-build the node image and load it,
        // then set `ORBIS_INTEGRATION_IMAGE` so `docker compose up` reuses it
        // instead of running a cold `cargo build --release` per test. The
        // production-feature-set path (`with_production_node_build`) needs a
        // *different* image, so it always builds — into a throwaway per-project
        // tag so it never clobbers the shared pre-built one.
        let reuse_prebuilt =
            !production_node_build && std::env::var_os("ORBIS_INTEGRATION_IMAGE").is_some();
        let prod_check_image = format!("orbis-node-prod-check:{project_name}");

        let start_compose = || {
            let mut command = compose_command(&compose_file, &project_name);
            if node_count == 4 {
                command.args(["--profile", "node4"]);
            }
            if defra {
                command.args(["--profile", "defra"]);
            }
            if reuse_prebuilt {
                command.args(["up", "-d"]);
            } else {
                command.args(["up", "-d", "--build"]);
                if production_node_build {
                    command.env("ORBIS_INTEGRATION_IMAGE", &prod_check_image);
                }
            }

            // `ORBIS_INTEGRATION_CRYPTO` (if set) is inherited by the compose
            // subprocess; when unset the compose file defaults to bls12-381. A
            // Jubjub run must export it so the built node images match the host —
            // see this type's doc comment and the CI `jubjub` matrix leg.
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

            command.status()
        };

        let mut status = start_compose().expect("Failed to start docker compose");
        if !status.success() {
            eprintln!(
                "docker compose up failed for project {project_name} with status {status}; retrying once"
            );
            report_compose_failure(&compose_file, &project_name);
            stop_compose(&compose_file, &project_name);
            std::thread::sleep(Duration::from_secs(2));
            status = start_compose().expect("Failed to start docker compose on retry");
        }

        if !status.success() {
            report_compose_failure(&compose_file, &project_name);
            stop_compose(&compose_file, &project_name);
            panic!("Failed to start integration test containers");
        }

        let endpoints =
            (|| -> Result<(ChainConfig, Vec<String>, Option<String>, Option<String>), String> {
                let chain_config = ChainConfig::builder()
                    .rpc_url(Some(localhost_url(published_port(
                        &compose_file,
                        &project_name,
                        "vera",
                        26657,
                    )?)))
                    .rest_url(Some(localhost_url(published_port(
                        &compose_file,
                        &project_name,
                        "vera",
                        1317,
                    )?)))
                    .grpc_url(Some(localhost_url(published_port(
                        &compose_file,
                        &project_name,
                        "vera",
                        9090,
                    )?)))
                    .build();
                let mut node_endpoints = Vec::with_capacity(node_count);
                for index in 1..=node_count {
                    let service = CosmosNetwork::service_name_for_node(index);
                    node_endpoints.push(localhost_url(published_port(
                        &compose_file,
                        &project_name,
                        service,
                        50051,
                    )?));
                }
                let (defra_url, defra_container_url) = if defra {
                    let url =
                        localhost_url(published_port(&compose_file, &project_name, "defra", 9181)?);
                    let gateway = bridge_network_gateway(&project_name)?;
                    (Some(url), Some(format!("http://{gateway}:9181")))
                } else {
                    (None, None)
                };
                Ok((chain_config, node_endpoints, defra_url, defra_container_url))
            })()
            .unwrap_or_else(|error| {
                report_compose_failure(&compose_file, &project_name);
                stop_compose(&compose_file, &project_name);
                panic!("Failed to discover integration test endpoints: {error}");
            });
        let (chain_config, node_endpoints, defra_url, defra_container_url) = endpoints;

        let network = CosmosNetwork {
            compose_file,
            project_name,
            admin: CosmosAdmin::new(chain_config.clone()),
            chain_config,
            node_endpoints,
            defra_url,
            defra_container_url,
            _patch_file: patch_file,
        };
        network.wait_for_healthy();
        network
    }
}

/// Resolves the Compose-created bridge network's gateway IP for `project`.
/// Compose v2 names an unnamed network `{project}_{network_key}` by default
/// (confirmed via `docker compose config`, not guessed) — this repo's
/// compose file declares exactly one network, `orbis-integration-network`,
/// with no `name:` override.
fn bridge_network_gateway(project: &str) -> Result<String, String> {
    let network_name = format!("{project}_orbis-integration-network");
    let output = Command::new("docker")
        .args([
            "network",
            "inspect",
            &network_name,
            "--format",
            "{{(index .IPAM.Config 0).Gateway}}",
        ])
        .output()
        .map_err(|error| format!("Failed to run docker network inspect: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "docker network inspect {network_name} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let gateway = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if gateway.is_empty() {
        return Err(format!("{network_name} has no gateway IP"));
    }
    Ok(gateway)
}

/// Which listen port to publish for other containers.
///
/// When the advertised port is already bound, it is the socket iroh told
/// peers to dial (Linux CI: STUN reports that same port). Replacing it with
/// another of the process's UDP sockets dials a port that never answers.
/// A NAT mapping (Docker Desktop) advertises a port that is not bound, and
/// the process's listen port is the one containers can dial.
pub(crate) fn select_publish_port(advertised: u16, listen_ports: &[u16]) -> Option<u16> {
    if listen_ports.contains(&advertised) {
        return Some(advertised);
    }
    match listen_ports {
        [] => None,
        [port] => Some(*port),
        ports => {
            eprintln!(
                "advertised port {advertised} is not listening; UDP ports are {ports:?}, using {}",
                ports[0]
            );
            Some(ports[0])
        }
    }
}

/// Unconnected UDP ports held by the node process.
///
/// `/proc/net/udp` lists every socket in the netns. The `ls` of `/proc/1/fd`
/// (pid 1 is `orbis-node`) restricts that to sockets the node itself holds,
/// and `rem_address == 0` drops connected sockets.
fn parse_process_udp_listen_ports(udp: &str, fds: &str) -> Vec<u16> {
    let inodes: std::collections::HashSet<&str> = fds
        .lines()
        .filter_map(|line| {
            let start = line.find("socket:[")? + "socket:[".len();
            let rest = line.get(start..)?;
            let end = rest.find(']')?;
            Some(&rest[..end])
        })
        .collect();
    let mut unspecified = Vec::new();
    let mut other = Vec::new();
    for line in udp.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 10 || !inodes.contains(fields[9]) {
            continue;
        }
        let Some((local_ip, port_hex)) = fields[1].split_once(':') else {
            continue;
        };
        let Some((remote_ip, remote_port)) = fields[2].split_once(':') else {
            continue;
        };
        if remote_ip != "00000000" || remote_port != "0000" {
            continue;
        }
        let Ok(port) = u16::from_str_radix(port_hex, 16) else {
            continue;
        };
        if port == 0 {
            continue;
        }
        if local_ip == "00000000" {
            unspecified.push(port);
        } else {
            other.push(port);
        }
    }
    unspecified.sort_unstable();
    unspecified.dedup();
    other.sort_unstable();
    other.dedup();
    if unspecified.is_empty() {
        other
    } else {
        unspecified
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_process_udp_listen_ports, select_publish_port};

    #[test]
    fn keeps_the_advertised_port_when_it_is_listening() {
        // CI node2 advertised 41406 and also held an unrelated UDP socket
        // on 39132. Dialing 39132 never answered Prepare.
        assert_eq!(select_publish_port(41406, &[39132, 41406]), Some(41406));
    }

    #[test]
    fn replaces_a_nat_mapped_port_with_the_listen_port() {
        assert_eq!(select_publish_port(54153, &[60771]), Some(60771));
    }

    #[test]
    fn replaces_a_nat_mapped_port_when_several_sockets_are_listening() {
        assert_eq!(select_publish_port(50938, &[34059, 38059]), Some(34059));
    }

    #[test]
    fn parser_ignores_other_processes_and_connected_sockets() {
        let udp = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   1: 00000000:A1BE 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 111 2 0 0
   2: 00000000:98DC 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 222 2 0 0
   3: 0100007F:0050 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 333 2 0 0
   4: 00000000:A1BE 08080808:0043 07 00000000:00000000 00:00000000 00000000     0        0 111 2 0 0
   5: 00000000:1111 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 999 2 0 0
";
        let fds = "\
lrwx------ 1 root root 64 Nov 4 21:00 10 -> socket:[111]
lrwx------ 1 root root 64 Nov 4 21:00 11 -> socket:[222]
lrwx------ 1 root root 64 Nov 4 21:00 12 -> socket:[333]
";
        assert_eq!(parse_process_udp_listen_ports(udp, fds), vec![39132, 41406]);
    }
}
