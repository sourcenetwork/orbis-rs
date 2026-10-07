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
        ]
        .into_iter()
        .chain(dirs.iter().enumerate().map(|(i, dir)| {
            (
                format!("ORBIS_NATIVE_VERA{}_DIR", i + 1),
                dir.display().to_string(),
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
    /// `env_vars` field doc comment for why.
    pub(crate) fn compose_env(&self) -> &[(String, String)] {
        &self.env_vars
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    pub(crate) fn compose_file(&self) -> &'static str {
        NATIVE_COMPOSE_FILE
    }

    pub(crate) fn project_name(&self) -> &str {
        &self.project_name
    }

    pub(crate) fn deployment(&self) -> u64 {
        self.deployment
    }

    /// Hex-encoded (no `0x` prefix) deployment root, ready to drop straight
    /// into a `vera.json` fixture's `deployment_root` field.
    pub(crate) fn deployment_root_hex(&self) -> &str {
        &self.root_hex
    }

    /// Hex-encoded consensus public key, ready to drop straight into a
    /// `vera.json` fixture's `consensus_key` field.
    pub(crate) fn consensus_key_hex(&self) -> &str {
        &self.consensus_key_hex
    }
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

/// Create a plain (non-Compose-managed) bridge network and return its
/// Docker-assigned subnet (e.g. `"172.30.0.0/16"`). Compose joins it later as
/// `external: true`, so Compose never tries to create or remove it itself.
/// Letting Docker pick the subnet (rather than specifying one) is what avoids
/// collisions — both with other Docker networks already on the host and with
/// concurrently-running test shards, which each get their own uniquely-named
/// network here.
fn create_external_network(name: &str) -> String {
    let status = Command::new("docker")
        .args(["network", "create", name])
        .status()
        .expect("Failed to create native integration network");
    if !status.success() {
        panic!("docker network create failed for {name}");
    }
    let output = Command::new("docker")
        .args([
            "network",
            "inspect",
            "--format",
            "{{(index .IPAM.Config 0).Subnet}}",
            name,
        ])
        .output()
        .expect("Failed to inspect native integration network");
    if !output.status.success() {
        remove_network(name);
        panic!(
            "docker network inspect failed for {name}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    String::from_utf8_lossy(&output.stdout).trim().to_string()
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
