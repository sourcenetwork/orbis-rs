//! Native Vera validator cluster, driven through Docker Compose
//! (`docker/docker-compose-native-integration-test.yml`).
//!
//! Unlike the old `ContainerNode`-per-validator approach (`network_mode:
//! host`, with an elaborate `TcpListener` reservation dance to avoid port
//! collisions across validators sharing one host port space), every
//! validator here runs as its own Compose service on a private bridge
//! network — each gets its own network namespace, so all four can use the
//! *same* fixed internal ports. Host-side access for this process's own RPC
//! polling still goes through Docker's ephemeral published-port mapping
//! (`compose::published_port`), exactly like `CosmosNetwork` already does for
//! the Cosmos chain.
//!
//! Validators are addressed by literal IP, not Compose service-name DNS:
//! `verad`'s peers.json parses bootstrapper addresses with Rust's strict
//! `SocketAddr::parse` (`crates/vera-node/src/config.rs`'s `load_peers`,
//! vendored, can't change) — no DNS resolution, so a hostname there is a hard
//! parse error at validator startup. Those IPs must be known *before* any
//! validator container starts (so `peers.json` can be mounted in ahead of
//! time), which rules out discovering them from already-running containers —
//! and empirically, Docker doesn't even assign a container's IP until it
//! actually starts (not at `create`), so a create-then-discover-then-start
//! sequence doesn't work either. Instead: pre-create a plain Docker network
//! (letting Docker pick a non-colliding subnet, the same way Compose's own
//! auto-created networks avoid collisions), read back that subnet, and
//! deterministically assign each validator a fixed IP within it — known
//! before any file is written or any container exists. Compose then joins
//! this network as `external: true` rather than managing it itself.

use crate::compose::{
    compose_command, localhost_url, published_port, report_compose_failure, stop_compose,
    unique_project_name,
};
use commonware_codec::Encode;
use std::{collections::BTreeMap, fs, net::Ipv4Addr, path::Path, process::Command, time::Duration};
use vera_client::VeraClient;
use vera_harness::cluster::{
    ConsensusPreset, GenesisBuilder, KeySet, NodeConfigBuilder, ValidatorConfig,
};

pub(crate) const NATIVE_COMPOSE_FILE: &str = "docker/docker-compose-native-integration-test.yml";
// Fixed container-internal ports — safe because each validator is its own
// Compose service (own network namespace), unlike the old host-network setup.
const VERA_P2P_PORT: u16 = 9000;
pub(crate) const VERA_RPC_PORT: u16 = 8645;

pub(crate) fn vera_service(index: usize) -> &'static str {
    match index {
        0 => "vera1",
        1 => "vera2",
        2 => "vera3",
        3 => "vera4",
        _ => panic!("native devnet only supports 4 validators"),
    }
}

/// One validator's chain RPC endpoint, host-reachable (for this process).
pub struct NativeTestNode {
    rpc_url: String,
}
impl NativeTestNode {
    pub fn rpc_url(&self) -> String {
        self.rpc_url.clone()
    }
}

/// A running 4-validator native Vera devnet, brought up via Docker Compose.
///
/// Scoped to the validator cluster only (matching this type's established
/// meaning throughout `bin/orbis-node/tests/support/*`) — Orbis node
/// bring-up on top of the same Compose project lives in
/// `crate::network::native::NativeNetworkAdapter`, which extends this same
/// Compose project (and joins this same Docker network) rather than
/// duplicating its lifecycle.
pub struct NativeTestNetwork {
    project_name: String,
    network_name: String,
    nodes: Vec<NativeTestNode>,
    deployment: u64,
    root_hex: String,
    consensus_key_hex: String,
    // Every `docker compose` invocation against this project must replay
    // this full set, not just the vars its own target services need:
    // `up`/`build` re-evaluate the *whole* file's desired state even when
    // scoped to specific services, and a missing var (e.g. a validator's
    // `ipv4_address`) reads as blank — which Compose treats as configuration
    // drift on that *other*, already-running service, recreating it.
    env_vars: Vec<(String, String)>,
    _root: tempfile::TempDir,
}

impl NativeTestNetwork {
    pub async fn start(deployment: u64) -> Self {
        Self::start_with_genesis(deployment, GenesisBuilder::devnet()).await
    }

    /// Customize only fresh fixture genesis; deployment, validators and normal timers stay shared.
    pub async fn start_with_genesis(deployment: u64, genesis: GenesisBuilder) -> Self {
        let mut directory = tempfile::Builder::new();
        directory.prefix("orbis-native-vera-");
        let mut root = if let Some(parent) = std::env::var_os("VERA_E2E_DIR") {
            fs::create_dir_all(&parent).unwrap();
            directory.tempdir_in(parent).unwrap()
        } else {
            directory.tempdir().unwrap()
        };
        if std::env::var("VERA_E2E_KEEP").is_ok_and(|value| value == "1") {
            root.disable_cleanup(true);
        }
        let root_path = root.path().canonicalize().unwrap();

        let keys = KeySet::builder().nodes(4).seed(deployment).build().unwrap();
        let dirs: Vec<_> = (0..4)
            .map(|i| root_path.join(format!("vera-{i}")))
            .collect();
        keys.write_to(&dirs).unwrap();

        let project_name = unique_project_name("orbis-native-integration");
        let network_name = format!("{project_name}-net");
        let subnet = create_external_network(&network_name);
        let validator_ips: Vec<String> = (0..4).map(|i| host_ip(&subnet, 11 + i as u32)).collect();

        let validators: Vec<ValidatorConfig> = keys
            .participants()
            .iter()
            .enumerate()
            .map(|(i, key)| ValidatorConfig {
                evm_address: format!("{:?}", vera_node::validator_address(key)),
                consensus_pubkey: hex::encode(key.encode()),
                p2p_address: format!("{}:{VERA_P2P_PORT}", validator_ips[i]),
            })
            .collect();
        let genesis_doc = genesis
            .chain_id(deployment)
            .blocks_per_epoch(192)
            .simplex(Default::default())
            .validators(validators)
            .epoch_info(keys.epoch_info_hex())
            .build();

        let config = NodeConfigBuilder::new()
            .chain_id(deployment)
            .preset(ConsensusPreset::Normal);
        let consensus = config.consensus();
        let _ = consensus; // baked into the Compose file's fixed --*-timeout-ms args (ConsensusPreset::Normal)

        // `KeySet::write_peers` (vendored, can't change) hardcodes
        // `127.0.0.1:{port}` bootstrapper addresses — build the same JSON
        // shape ourselves with each validator's pre-assigned IP instead (see
        // this module's doc comment for why hostnames can't be used here).
        let participants_hex: Vec<String> = keys
            .participants()
            .iter()
            .map(|pk| hex::encode(pk.encode()))
            .collect();
        let bootstrappers: BTreeMap<String, String> = keys
            .participants()
            .iter()
            .enumerate()
            .map(|(i, pk)| {
                (
                    hex::encode(pk.encode()),
                    format!("{}:{VERA_P2P_PORT}", validator_ips[i]),
                )
            })
            .collect();
        let peers_json = serde_json::json!({
            "validators": keys.node_count(),
            "threshold": keys.threshold(),
            "participants": participants_hex,
            "bootstrappers": bootstrappers,
        });

        for dir in &dirs {
            fs::write(
                dir.join("genesis.json"),
                serde_json::to_vec(&genesis_doc).unwrap(),
            )
            .unwrap();
            // Container-internal path (`/data`), not the host `dir` — each
            // validator's directory is bind-mounted to `/data` by Compose.
            fs::write(
                dir.join("config.toml"),
                config.build_config_toml(Path::new("/data"), VERA_P2P_PORT, VERA_RPC_PORT),
            )
            .unwrap();
            fs::write(
                dir.join("peers.json"),
                serde_json::to_vec(&peers_json).unwrap(),
            )
            .unwrap();
        }

        let reuse_prebuilt = std::env::var_os("ORBIS_NATIVE_VERA_IMAGE").is_some();
        let env_vars: Vec<(String, String)> = [
            (
                "ORBIS_NATIVE_DEPLOYMENT".to_string(),
                deployment.to_string(),
            ),
            (
                "ORBIS_NATIVE_NETWORK_NAME".to_string(),
                network_name.clone(),
            ),
            ("VERA_REF".to_string(), native_vera_ref()),
        ]
        .into_iter()
        .chain(dirs.iter().enumerate().map(|(i, dir)| {
            (
                format!("ORBIS_NATIVE_VERA{}_DIR", i + 1),
                dir.display().to_string(),
            )
        }))
        .chain(dirs.iter().enumerate().map(|(i, dir)| {
            (
                format!("ORBIS_NATIVE_VERA{}_USER", i + 1),
                crate::bind_mount_user(dir).expect("validator fixture owner"),
            )
        }))
        .chain(
            validator_ips
                .iter()
                .enumerate()
                .map(|(i, ip)| (format!("ORBIS_NATIVE_VERA{}_IP", i + 1), ip.clone())),
        )
        .collect();

        // All four `vera{1..4}` services share one identical `build:` block
        // (same image tag) — `up -d --build <4 services>` launches four
        // *parallel* builds of it, and even though BuildKit dedupes the
        // actual compile, the four parallel "export/tag `orbis-vera-native:local`"
        // steps race and three fail with "image ... already exists". Build
        // the shared image once, by name, before bringing any service up.
        if !reuse_prebuilt {
            let mut build = compose_command(NATIVE_COMPOSE_FILE, &project_name);
            build.args(["build", "vera1"]);
            for (key, value) in &env_vars {
                build.env(key, value);
            }
            let status = build
                .status()
                .expect("Failed to build native validator image");
            if !status.success() {
                report_compose_failure(NATIVE_COMPOSE_FILE, &project_name);
                stop_compose(NATIVE_COMPOSE_FILE, &project_name);
                remove_network(&network_name);
                panic!(
                    "docker compose build failed for native validators (project {project_name})"
                );
            }
        }

        let mut command = compose_command(NATIVE_COMPOSE_FILE, &project_name);
        command.args(["up", "-d", "vera1", "vera2", "vera3", "vera4"]);
        for (key, value) in &env_vars {
            command.env(key, value);
        }
        let status = command
            .status()
            .expect("Failed to start native validator containers");
        if !status.success() {
            report_compose_failure(NATIVE_COMPOSE_FILE, &project_name);
            stop_compose(NATIVE_COMPOSE_FILE, &project_name);
            remove_network(&network_name);
            panic!("docker compose up failed for native validators (project {project_name})");
        }

        let nodes: Vec<NativeTestNode> = (0..4)
            .map(|i| {
                let port = published_port(
                    NATIVE_COMPOSE_FILE,
                    &project_name,
                    vera_service(i),
                    VERA_RPC_PORT,
                )
                .unwrap_or_else(|error| {
                    report_compose_failure(NATIVE_COMPOSE_FILE, &project_name);
                    stop_compose(NATIVE_COMPOSE_FILE, &project_name);
                    remove_network(&network_name);
                    panic!("discover {} endpoint: {error}", vera_service(i));
                });
                NativeTestNode {
                    rpc_url: localhost_url(port),
                }
            })
            .collect();

        tokio::time::timeout(Duration::from_secs(60), async {
            loop {
                let mut ready = true;
                for (i, node) in nodes.iter().enumerate() {
                    if !service_running(&project_name, vera_service(i)) {
                        report_compose_failure(NATIVE_COMPOSE_FILE, &project_name);
                        panic!("native validator {} exited", vera_service(i));
                    }
                    ready &= VeraClient::new(node.rpc_url())
                        .chain_id()
                        .await
                        .is_ok_and(|id| id == deployment);
                }
                if ready {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .unwrap_or_else(|_| {
            report_compose_failure(NATIVE_COMPOSE_FILE, &project_name);
            stop_compose(NATIVE_COMPOSE_FILE, &project_name);
            remove_network(&network_name);
            panic!("native validators failed to become RPC-ready");
        });
        tokio::time::timeout(Duration::from_secs(60), async {
            loop {
                let mut ready = true;
                for (i, node) in nodes.iter().enumerate() {
                    if !service_running(&project_name, vera_service(i)) {
                        report_compose_failure(NATIVE_COMPOSE_FILE, &project_name);
                        panic!("native validator {} exited", vera_service(i));
                    }
                    ready &= VeraClient::new(node.rpc_url())
                        .block_number()
                        .await
                        .is_ok_and(|height| height >= 3);
                }
                if ready {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .unwrap_or_else(|_| {
            report_compose_failure(NATIVE_COMPOSE_FILE, &project_name);
            stop_compose(NATIVE_COMPOSE_FILE, &project_name);
            remove_network(&network_name);
            panic!("native validators failed to reach height 3");
        });

        // Derived purely from (seed, node count) — no network call needed.
        let trusted = *keys.epoch_info().output.public().public();
        let consensus_key_hex = hex::encode(trusted.encode());
        // Needs a live chain query: this is a property of the running chain
        // (the genesis block's hash), not something derivable from the
        // genesis spec alone.
        let first = VeraClient::new(nodes[0].rpc_url())
            .read_finalized_revision(1, &trusted)
            .await
            .unwrap_or_else(|error| {
                report_compose_failure(NATIVE_COMPOSE_FILE, &project_name);
                stop_compose(NATIVE_COMPOSE_FILE, &project_name);
                remove_network(&network_name);
                panic!("read finalized revision 1 from vera1: {error}");
            });
        let root_hex = first
            .parent_hash
            .strip_prefix("0x")
            .unwrap_or(&first.parent_hash)
            .to_string();

        Self {
            project_name,
            network_name,
            nodes,
            deployment,
            root_hex,
            consensus_key_hex,
            env_vars,
            _root: root,
        }
    }

    pub fn node(&self, index: usize) -> &NativeTestNode {
        &self.nodes[index]
    }

    /// The full env var set this project's validators were brought up with
    /// (deployment id, network name, per-validator dirs and IPs) — replay
    /// all of it on any later `docker compose` invocation against this same
    /// project, even one scoped to different services. See this struct's
    /// `env_vars` field doc comment for why. `pub` (not `pub(crate)`): callers
    /// outside this crate driving their own Orbis-node bring-up against this
    /// same Compose project (e.g. `bin/orbis-node/tests/support/native_workflow.rs`)
    /// need this too — see `build_service`/`bring_up_services` below.
    pub fn compose_env(&self) -> &[(String, String)] {
        &self.env_vars
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    pub fn compose_file(&self) -> &'static str {
        NATIVE_COMPOSE_FILE
    }

    pub fn project_name(&self) -> &str {
        &self.project_name
    }

    pub fn deployment(&self) -> u64 {
        self.deployment
    }

    /// Hex-encoded (no `0x` prefix) deployment root, ready to drop straight
    /// into a `vera.json` fixture's `deployment_root` field.
    pub fn deployment_root_hex(&self) -> &str {
        &self.root_hex
    }

    /// Hex-encoded consensus public key, ready to drop straight into a
    /// `vera.json` fixture's `consensus_key` field.
    pub fn consensus_key_hex(&self) -> &str {
        &self.consensus_key_hex
    }

    /// A validator's Compose service name (`vera1`..`vera4`), the endpoint an
    /// Orbis-node container reaches it at (e.g. a `vera.json` fixture's
    /// `"endpoint"` field should be `http://{name}:{VERA_RPC_PORT}` — these
    /// containers share this cluster's bridge network, so the service name
    /// resolves; a host-published port, by contrast, is only reachable from
    /// the test process itself, not from another container).
    pub fn validator_service(&self, index: usize) -> &'static str {
        vera_service(index)
    }

    pub fn validator_rpc_port(&self) -> u16 {
        VERA_RPC_PORT
    }

    /// Build one Compose service's image, replaying this project's full env
    /// var set plus `extra_env`. See [`compose_build`]'s doc comment for why
    /// this must happen once, by name, before `up`-ing a service that shares
    /// a `build:` block with others.
    pub fn build_service(&self, service: &str, extra_env: &[(String, String)]) {
        compose_build(
            NATIVE_COMPOSE_FILE,
            &self.project_name,
            service,
            &self.env_vars,
            extra_env,
        );
    }

    /// Bring up one or more already-built Compose services, replaying this
    /// project's full env var set plus `extra_env` (e.g. per-node fixture
    /// directories, a reshare-interval override).
    pub fn bring_up_services(&self, services: &[&str], extra_env: &[(String, String)]) {
        compose_up(
            NATIVE_COMPOSE_FILE,
            &self.project_name,
            services,
            &self.env_vars,
            extra_env,
        );
    }

    /// Discover a running service's host-published endpoint for the given
    /// container-internal port (e.g. `discover_endpoint("node1", 50051)`).
    pub fn discover_endpoint(&self, service: &str, container_port: u16) -> String {
        compose_discover_endpoint(
            NATIVE_COMPOSE_FILE,
            &self.project_name,
            service,
            container_port,
        )
    }

    pub fn stop_service(&self, service: &str) {
        compose_stop(NATIVE_COMPOSE_FILE, &self.project_name, service);
    }

    /// Start a previously stopped (not removed) service, preserving its
    /// container and bind-mounted state — unlike the legacy `ContainerNode`
    /// model, this reuses the same long-lived container rather than creating
    /// a fresh one, since `node1`..`node4` are pre-declared Compose services.
    pub fn start_service(&self, service: &str) {
        compose_start(NATIVE_COMPOSE_FILE, &self.project_name, service);
    }

    /// Send a signal to a running service's container (e.g. `"SIGKILL"` to
    /// simulate a crash, matching the legacy `ContainerNode::kill`/`pause`).
    pub fn kill_service(&self, service: &str, signal: &str) {
        compose_kill(NATIVE_COMPOSE_FILE, &self.project_name, service, signal);
    }

    /// `None` while the service's container is running; `Some(exit_code)`
    /// once it has exited — equivalent to the legacy `ContainerNode::try_wait`.
    pub fn service_exit_code(&self, service: &str) -> Option<i32> {
        compose_exit_code(NATIVE_COMPOSE_FILE, &self.project_name, service)
    }
}

/// Free-function counterparts of [`NativeTestNetwork`]'s Compose-driving
/// methods, taking `compose_file`/`project_name` explicitly — for callers
/// outside this crate that hold a long-lived handle to one named service
/// (e.g. `bin/orbis-node/tests/native_startup.rs`'s `Node`) without wanting to
/// borrow or clone the whole [`NativeTestNetwork`]. The methods above are
/// thin wrappers over these.
///
/// Building several services that share one `build:` block (e.g.
/// `node1`..`node4`, all `${ORBIS_NATIVE_IMAGE:-orbis-node-native:local}`)
/// must happen once, by name, before `up`-ing any of them: parallel
/// `up -d --build` across identical `build:` blocks has every service's
/// build try to tag the same final image simultaneously, and most of them
/// fail with "already exists".
pub fn compose_build(
    compose_file: &str,
    project_name: &str,
    service: &str,
    env: &[(String, String)],
    extra_env: &[(String, String)],
) {
    if std::env::var_os("ORBIS_NATIVE_IMAGE").is_some() {
        return; // Pre-built image supplied (e.g. by CI); nothing to build.
    }
    let mut build = compose_command(compose_file, project_name);
    if service == "node4" {
        build.args(["--profile", "node4"]);
    }
    build.args(["build", service]);
    for (key, value) in env.iter().chain(extra_env) {
        build.env(key, value);
    }
    let status = build.status().expect("Failed to build Compose service");
    if !status.success() {
        report_compose_failure(compose_file, project_name);
        panic!("docker compose build failed for service {service} (project {project_name})");
    }
}

pub fn compose_up(
    compose_file: &str,
    project_name: &str,
    services: &[&str],
    env: &[(String, String)],
    extra_env: &[(String, String)],
) {
    let mut command = compose_command(compose_file, project_name);
    if services.contains(&"node4") {
        command.args(["--profile", "node4"]);
    }
    command.arg("up").arg("-d").arg("--no-build");
    for (key, value) in env.iter().chain(extra_env) {
        command.env(key, value);
    }
    command.args(services);
    let status = command.status().expect("Failed to start Compose services");
    if !status.success() {
        report_compose_failure(compose_file, project_name);
        panic!("docker compose up failed for {services:?} (project {project_name})");
    }
}

pub fn compose_discover_endpoint(
    compose_file: &str,
    project_name: &str,
    service: &str,
    container_port: u16,
) -> String {
    let port = published_port(compose_file, project_name, service, container_port).unwrap_or_else(
        |error| {
            report_compose_failure(compose_file, project_name);
            panic!("discover {service} endpoint: {error}");
        },
    );
    localhost_url(port)
}

pub fn compose_stop(compose_file: &str, project_name: &str, service: &str) {
    let status = compose_command(compose_file, project_name)
        .args(["stop", service])
        .status()
        .expect("docker compose stop failed");
    if !status.success() {
        report_compose_failure(compose_file, project_name);
        panic!("Failed to stop service {service}");
    }
}

pub fn compose_start(compose_file: &str, project_name: &str, service: &str) {
    let status = compose_command(compose_file, project_name)
        .args(["start", service])
        .status()
        .expect("docker compose start failed");
    if !status.success() {
        report_compose_failure(compose_file, project_name);
        panic!("Failed to start service {service}");
    }
}

pub fn compose_kill(compose_file: &str, project_name: &str, service: &str, signal: &str) {
    let status = compose_command(compose_file, project_name)
        .args(["kill", "--signal", signal, service])
        .status()
        .expect("docker compose kill failed");
    if !status.success() {
        report_compose_failure(compose_file, project_name);
        panic!("Failed to signal service {service} with {signal}");
    }
}

/// `None` while the service's container is running; `Some(exit_code)` once
/// it has exited (crashed, been killed, or exited cleanly) — equivalent to
/// the legacy `ContainerNode::try_wait`'s "did it crash" check, reimplemented
/// against a named Compose service's container.
pub fn compose_exit_code(compose_file: &str, project_name: &str, service: &str) -> Option<i32> {
    let output = compose_command(compose_file, project_name)
        .args(["ps", "--all", "--quiet", service])
        .output()
        .expect("docker compose ps failed");
    let id = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if id.is_empty() {
        return None; // Container doesn't exist yet.
    }
    let inspect = std::process::Command::new("docker")
        .args([
            "inspect",
            "--format",
            "{{.State.Running}} {{.State.ExitCode}}",
            &id,
        ])
        .output()
        .expect("docker inspect failed");
    let text = String::from_utf8_lossy(&inspect.stdout);
    let mut parts = text.split_whitespace();
    let running: bool = parts.next().unwrap_or("true").parse().unwrap_or(true);
    let exit_code: i32 = parts.next().unwrap_or("0").parse().unwrap_or(0);
    (!running).then_some(exit_code)
}

/// Copy a service's full Compose logs to a local file, overwriting it —
/// equivalent to the legacy `ContainerNode::retain_logs`/`refresh_logs`.
pub fn compose_save_logs(
    compose_file: &str,
    project_name: &str,
    service: &str,
    destination: &Path,
) {
    let output = compose_command(compose_file, project_name)
        .args(["logs", "--no-color", "--no-log-prefix", service])
        .output()
        .expect("docker compose logs failed");
    fs::write(destination, &output.stdout).expect("write service logs");
}

impl Drop for NativeTestNetwork {
    fn drop(&mut self) {
        if std::thread::panicking() {
            report_compose_failure(NATIVE_COMPOSE_FILE, &self.project_name);
        }
        stop_compose(NATIVE_COMPOSE_FILE, &self.project_name);
        remove_network(&self.network_name);
    }
}

/// Compose-friendly replacement for `ContainerNode::try_wait_async`'s "did it
/// crash" check.
fn service_running(project_name: &str, service: &str) -> bool {
    compose_command(NATIVE_COMPOSE_FILE, project_name)
        .args(["ps", "--status", "running", "--format", "json", service])
        .output()
        .is_ok_and(|output| {
            output.status.success() && !String::from_utf8_lossy(&output.stdout).trim().is_empty()
        })
}

/// Create a plain (non-Compose-managed) bridge network and return its subnet
/// (e.g. `"172.30.0.0/16"`). Compose joins it later as `external: true`, so
/// Compose never tries to create or remove it itself.
///
/// Docker must see the subnet as user-configured before Compose may assign the
/// validators fixed `ipv4_address` values. To retain collision-free allocation,
/// first let Docker reserve a subnet on a short-lived probe network, then
/// recreate the real network with that subnet explicitly. A competing process
/// can claim it in the small remove/recreate window, so retry with a fresh
/// Docker allocation when explicit creation reports an overlap.
fn create_external_network(name: &str) -> String {
    let mut last_error = String::new();
    for attempt in 1..=16 {
        let probe = format!("{name}-subnet-probe-{attempt}");
        let created = Command::new("docker")
            .args(["network", "create", &probe])
            .output()
            .expect("Failed to create native integration subnet probe");
        if !created.status.success() {
            panic!(
                "docker network create failed for subnet probe {probe}: {}",
                String::from_utf8_lossy(&created.stderr)
            );
        }

        let inspected = Command::new("docker")
            .args([
                "network",
                "inspect",
                "--format",
                "{{(index .IPAM.Config 0).Subnet}}",
                &probe,
            ])
            .output()
            .expect("Failed to inspect native integration subnet probe");
        let subnet = String::from_utf8_lossy(&inspected.stdout)
            .trim()
            .to_string();
        remove_network(&probe);
        if !inspected.status.success() || subnet.is_empty() {
            panic!(
                "docker network inspect failed for {probe}: {}",
                String::from_utf8_lossy(&inspected.stderr)
            );
        }

        let explicit = Command::new("docker")
            .args(["network", "create", "--subnet", &subnet, name])
            .output()
            .expect("Failed to create native integration network");
        if explicit.status.success() {
            return subnet;
        }
        last_error = String::from_utf8_lossy(&explicit.stderr).trim().to_string();
    }
    panic!("docker network create failed for {name} after 16 allocations: {last_error}");
}

fn remove_network(name: &str) {
    let _ = Command::new("docker")
        .args(["network", "rm", name])
        .status();
}

/// Offset a subnet's network address by a small, fixed host count — e.g.
/// `host_ip("172.30.0.0/16", 11)` → `"172.30.0.11"`. Works for any prefix
/// length Docker might hand back (typically /16 or /20 for an
/// auto-allocated pool); only needs the subnet to be large enough to include
/// the low offsets this module uses (11..=14), which every default Docker
/// pool comfortably is.
fn host_ip(subnet_cidr: &str, offset: u32) -> String {
    let base = subnet_cidr
        .split_once('/')
        .map(|(ip, _prefix)| ip)
        .unwrap_or(subnet_cidr);
    let base: Ipv4Addr = base
        .parse()
        .expect("Docker-assigned subnet has a valid IPv4 network address");
    Ipv4Addr::from(u32::from(base) + offset).to_string()
}

/// The native Vera chain revision the validator image builds from, read from
/// `docker/NATIVE_VERA_REF` — a plain, manually-maintained pin (same
/// convention as `docker/VERA_REF`, which serves a different purpose: that
/// one is the upgrade-compatibility baseline `scripts/test-upgrade.sh` reads,
/// not the revision integration tests build against).
///
/// This file must agree with `scripts/native-vera-ref.py`'s output (the
/// `rev = "..."` pin shared by the `vera-client`/`vera-domain`/`vera-node`
/// git dependencies across this workspace's Cargo.toml files) — that script
/// is what CI's `native-vera-image` job actually builds from, so a stale
/// `docker/NATIVE_VERA_REF` means local integration-test runs build a
/// different chain revision than CI does. Bump both together when the SDK
/// pin moves; nothing enforces they match automatically (manually maintained
/// was the deliberate choice here, not an oversight).
fn native_vera_ref() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docker/NATIVE_VERA_REF");
    fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
        .trim()
        .to_string()
}
