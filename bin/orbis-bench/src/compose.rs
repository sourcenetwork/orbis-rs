use crate::config::{CryptoFeature, NetworkProfileKind, ResourceLimits, StackPlan};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::fs;
use std::path::{Path, PathBuf};

pub const SOURCEHUB_SERVICE: &str = "sourcehub";
pub const CONTROLLER_PUBLIC_KEY: &str =
    "024f4e2ad99c34d60b9ba6283c9431a8418af8673212961f97a77b6377fcd05b62";
/// ACP policy IDs are `sha256(sha256(policy content) || counter)`, where
/// `counter` is a per-chain monotonic sequence number. This is always the
/// first policy created on a freshly booted SourceHub (see
/// `setup::create_ring_governance_policy`), so `counter` — and therefore this
/// ID — is fully deterministic. `create_ring_governance_policy` asserts the
/// chain actually returns this value, so a change on the SourceHub side
/// (e.g. a different policy-numbering scheme) fails loudly instead of
/// silently drifting.
pub const RING_GOVERNANCE_POLICY_ID: &str =
    "3199b84b4a6862c40fe2623879dfc36df281a2262898da36f7de65c376a93e05";

// SourceHub simulation can under-report the final write cost when a large
// FinalizeRing transaction changes chain state between simulation and delivery.
// Capacity runs need enough headroom that chain bookkeeping does not turn a
// completed 50-member ceremony into a false protocol timeout.
const BENCHMARK_CHAIN_GAS_MULTIPLIER: f64 = 3.0;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RingDefinition {
    pub id: String,
    pub peer_node_keys: Vec<String>,
    /// Nodes allowed to operate this ring. This is normally the current
    /// committee and is the old/new union for a planned reshare.
    #[serde(default)]
    pub operator_node_keys: Vec<String>,
    pub threshold: usize,
    pub pss_interval_secs: u64,
    pub policy_id: String,
}

#[derive(Clone, Debug)]
pub struct ComposeInput<'a> {
    pub repository_root: &'a Path,
    pub run_id: &'a str,
    pub stack_id: &'a str,
    pub stack: &'a StackPlan,
    pub crypto: CryptoFeature,
    pub sourcehub_ref: &'a str,
    pub sourcehub_replicas: usize,
    pub resources: &'a ResourceLimits,
    pub scheduler_poll_secs: u64,
}

#[derive(Clone, Debug)]
pub struct StackArtifacts {
    pub compose_file: PathBuf,
}

pub fn write_stack_files(stack_dir: &Path, input: &ComposeInput<'_>) -> Result<StackArtifacts> {
    fs::create_dir_all(stack_dir)
        .with_context(|| format!("create stack directory {}", stack_dir.display()))?;
    // Compose resolves bind-mount sources relative to the Compose file. Run
    // directories are often configured as repository-relative paths, so make
    // every generated host artifact absolute before embedding it in YAML.
    let stack_dir = stack_dir
        .canonicalize()
        .with_context(|| format!("resolve stack directory {}", stack_dir.display()))?;
    let compose_file = stack_dir.join("compose.yaml");

    let compose = compose_document(input)?;
    fs::write(&compose_file, serde_yaml::to_string(&compose)?)?;
    Ok(StackArtifacts { compose_file })
}

pub fn node_service(index: usize) -> String {
    format!("node-{index:03}")
}

/// Name of the SourceHub Compose service for a given replica index. Index 0
/// is always the sole validator, kept as the plain `"sourcehub"` name so
/// every existing single-replica reference (`SOURCEHUB_SERVICE`, the bench
/// controller's own chain client) needs no change when `sourcehub_replicas`
/// stays at its default of 1.
pub fn sourcehub_service_name(replica_index: usize) -> String {
    if replica_index == 0 {
        SOURCEHUB_SERVICE.to_string()
    } else {
        format!("sourcehub-{replica_index:03}")
    }
}

const SOURCEHUB_HANDOFF_VOLUME: &str = "sourcehub-handoff";

fn compose_document(input: &ComposeInput<'_>) -> Result<Value> {
    let mut services = Map::new();
    for replica_index in 0..input.sourcehub_replicas {
        let value = if replica_index == 0 {
            sourcehub_service(input)
        } else {
            sourcehub_replica_service(input)
        };
        services.insert(sourcehub_service_name(replica_index), value);
    }
    for index in 1..=input.stack.network_size {
        services.insert(node_service(index), node_service_value(input, index));
    }

    let mut volumes = Map::new();
    volumes.insert(SOURCEHUB_HANDOFF_VOLUME.to_string(), json!({}));
    for index in 1..=input.stack.network_size {
        volumes.insert(format!("node-{index:03}-data"), json!({}));
    }

    Ok(json!({
        "name": input.stack_id,
        "services": services,
        "networks": {"orbis-bench": {"driver": "bridge"}},
        "volumes": volumes,
    }))
}

/// The full `orbis-bench-sourcehub:<tag>` image reference for a given
/// `sourcehub_ref`, truncated to at most 12 characters (not bytes, so a
/// multi-byte character straddling that boundary doesn't panic on slicing).
/// Shared by the compose service definitions and the manifest image-digest
/// lookup so the tag can't drift between the two.
pub fn sourcehub_image_tag(sourcehub_ref: &str) -> String {
    let truncated: String = sourcehub_ref.chars().take(12).collect();
    format!("orbis-bench-sourcehub:{truncated}")
}

fn sourcehub_service(input: &ComposeInput<'_>) -> Value {
    let sourcehub_context = input.repository_root.join("docker");
    let command = r#"
set -eu
# SourceHub boots exactly once per stack and is never recreated (rings are
# created via live transaction after boot, not baked into genesis), so the
# handoff volume should always be empty here. Clear it defensively anyway —
# harmless if already empty, and it means a replica can never read leftover
# data from an earlier, unrelated stack if a volume were ever reused.
rm -f /handoff/ready
rm -rf /home/node/.sourcehub/*
sourcehubd init local-node --chain-id sourcehub-localnet --home /home/node/.sourcehub
sourcehubd keys add validator --keyring-backend test --home /home/node/.sourcehub
echo "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" | sourcehubd keys add test --recover --keyring-backend test --home /home/node/.sourcehub
sourcehubd genesis add-genesis-account validator 100000000000uopen --keyring-backend test --home /home/node/.sourcehub
sourcehubd genesis add-genesis-account test 100000000000uopen --keyring-backend test --home /home/node/.sourcehub
sourcehubd genesis gentx validator 10000000000uopen --keyring-backend test --chain-id sourcehub-localnet --home /home/node/.sourcehub
sourcehubd genesis collect-gentxs --home /home/node/.sourcehub
cp /home/node/.sourcehub/config/genesis.json /handoff/genesis.json
sourcehubd comet show-node-id --home /home/node/.sourcehub > /handoff/node-id.txt
# Replicas read these files as the image's default non-root `node` user.
# Root's default umask on this volume leaves them unreadable by anyone else,
# so make the handoff directory and its contents world-readable explicitly.
chmod -R a+rX /handoff
touch /handoff/ready
exec sourcehubd start --home /home/node/.sourcehub --rpc.laddr tcp://0.0.0.0:26657 --api.enable --api.address tcp://0.0.0.0:1317
"#;
    json!({
        "image": sourcehub_image_tag(input.sourcehub_ref),
        "build": {
            "context": sourcehub_context,
            "dockerfile": "Dockerfile.sourcehub-integration",
            "args": {"SOURCEHUB_REF": input.sourcehub_ref},
        },
        "entrypoint": ["/bin/sh", "-c"],
        "command": [command],
        // The image's default `node` user has no write access to a freshly
        // created named volume (owned root:root until something chowns it),
        // and the validator is the only service that writes into /handoff.
        "user": "root",
        "volumes": [format!("{SOURCEHUB_HANDOFF_VOLUME}:/handoff")],
        "ports": ["127.0.0.1::26657", "127.0.0.1::1317", "127.0.0.1::9090"],
        "networks": ["orbis-bench"],
        "labels": {
            "dev.orbis.bench.run": input.run_id,
            "dev.orbis.bench.stack": input.stack_id,
            "dev.orbis.bench.role": "sourcehub",
        },
        "healthcheck": {
            "test": ["CMD", "sourcehubd", "status", "--home", "/home/node/.sourcehub"],
            "interval": "5s",
            "timeout": "5s",
            "retries": 60,
            "start_period": "20s",
        },
    })
}

/// A non-validating SourceHub full node: syncs the validator's chain via P2P
/// and independently serves REST/RPC reads and tx relay, so 50 orbis nodes
/// hitting `FinalizeRing` around the same time aren't all queuing behind one
/// REST server. Needs no keyring — it never signs or broadcasts anything of
/// its own.
fn sourcehub_replica_service(input: &ComposeInput<'_>) -> Value {
    let sourcehub_context = input.repository_root.join("docker");
    let command = r#"
set -eu
# SourceHub boots exactly once per stack, so /handoff should never have
# leftover data when this container starts — but if a volume were ever
# reused, racing the validator to clear it first is not reliable (both sides
# start around the same time). Recording our own boot marker before checking
# lets us require a `ready` that is provably newer than this boot, not merely
# present, so we can never read a stale genesis/node-id.
touch /tmp/boot-marker
rm -rf /home/node/.sourcehub/*
sourcehubd init local-node --chain-id sourcehub-localnet --home /home/node/.sourcehub
handoff_timeout_seconds=300
handoff_waited_seconds=0
while :; do
  ready_is_current=
  if [ -f /handoff/ready ]; then
    ready_is_current="$$(find /handoff/ready -newer /tmp/boot-marker -print 2>/dev/null)"
  fi
  if [ -n "$$ready_is_current" ]; then
    break
  fi
  if [ "$$handoff_waited_seconds" -ge "$$handoff_timeout_seconds" ]; then
    echo "sourcehub replica timed out after $${handoff_timeout_seconds}s waiting for a current /handoff/ready marker" >&2
    exit 1
  fi
  sleep 1
  handoff_waited_seconds=$$((handoff_waited_seconds + 1))
done
cp /handoff/genesis.json /home/node/.sourcehub/config/genesis.json
exec sourcehubd start --home /home/node/.sourcehub --rpc.laddr tcp://0.0.0.0:26657 --api.enable --api.address tcp://0.0.0.0:1317 --p2p.persistent_peers "$$(cat /handoff/node-id.txt)@sourcehub:26656"
"#;
    json!({
        "image": sourcehub_image_tag(input.sourcehub_ref),
        "build": {
            "context": sourcehub_context,
            "dockerfile": "Dockerfile.sourcehub-integration",
            "args": {"SOURCEHUB_REF": input.sourcehub_ref},
        },
        "entrypoint": ["/bin/sh", "-c"],
        "command": [command],
        "volumes": [format!("{SOURCEHUB_HANDOFF_VOLUME}:/handoff:ro")],
        "ports": ["127.0.0.1::26657", "127.0.0.1::1317", "127.0.0.1::9090"],
        "networks": ["orbis-bench"],
        "labels": {
            "dev.orbis.bench.run": input.run_id,
            "dev.orbis.bench.stack": input.stack_id,
            "dev.orbis.bench.role": "sourcehub-replica",
        },
        "healthcheck": {
            "test": ["CMD", "sourcehubd", "status", "--home", "/home/node/.sourcehub"],
            "interval": "5s",
            "timeout": "5s",
            "retries": 60,
            "start_period": "20s",
        },
    })
}

fn node_service_value(input: &ComposeInput<'_>, index: usize) -> Value {
    let service = node_service(index);
    // Deliberately not passing `--network-private-routes-only` here: it disables
    // Iroh's relay-assisted hole punching and clears all discovery, leaving each
    // private DKG pair exchange with exactly one connection path and no fallback.
    // At 50-node scale that turns ordinary transient connection failures into a
    // sustained retry storm that never converges (confirmed by bisecting to the
    // commit that introduced the flag: private pair exchange completes cleanly
    // without it, and stalls indefinitely with it). Iroh's default relay/discovery
    // add real but acceptable overhead for a same-host Docker network.
    //
    // Bucket nodes across SourceHub replicas (index 0 is always the
    // validator) so REST/RPC load during ring finalization scales
    // horizontally instead of queuing behind one server.
    // `Experiment::validate()` rejects zero replicas, but `ComposeInput` can
    // also be reached directly (e.g. via `write_stack_files` from a test or
    // library caller) without going through that check first — normalize
    // rather than let an unvalidated zero panic here on the modulo.
    let sourcehub_target = sourcehub_service_name((index - 1) % input.sourcehub_replicas.max(1));
    let command = vec![
        "--addr".to_string(),
        "0.0.0.0:50051".to_string(),
        "--log-level".to_string(),
        "info".to_string(),
        "--authz-grpc".to_string(),
        format!("http://{sourcehub_target}:9090"),
        "--bulletin-grpc".to_string(),
        format!("http://{sourcehub_target}:9090"),
        "--chain-rpc".to_string(),
        format!("http://{sourcehub_target}:26657"),
        "--chain-rest".to_string(),
        format!("http://{sourcehub_target}:1317"),
        "--chain-gas-multiplier".to_string(),
        BENCHMARK_CHAIN_GAS_MULTIPLIER.to_string(),
        "--metrics-addr".to_string(),
        "0.0.0.0:9090".to_string(),
        "--runtime-base-path".to_string(),
        "/data".to_string(),
        "--reshare-interval-secs".to_string(),
        input.scheduler_poll_secs.to_string(),
        "--node-controller-key".to_string(),
        CONTROLLER_PUBLIC_KEY.to_string(),
        // Rings are created via live transaction after every node has already
        // booted (chain-assigned ring IDs aren't known in advance), so nodes
        // whitelist the fixed, deterministic governance policy ID instead of
        // specific ring IDs — a node accepts DKG participation for any ring
        // whose policy_id it whitelists (see `dkg/new_dkg_flow.md`).
        "--node-whitelisted-policy-id".to_string(),
        RING_GOVERNANCE_POLICY_ID.to_string(),
    ];

    let mut value = json!({
        "image": format!("orbis-bench-node:{}", input.crypto.feature_name()),
        "build": {
            "context": input.repository_root,
            "dockerfile": "bin/orbis-bench/Dockerfile.node",
            "args": {"CRYPTO_FEATURE": input.crypto.feature_name()},
        },
        "environment": {
            "ORBIS_PASSWORD": format!("orbis-bench-storage-{index:03}"),
            "ORBIS_SECRET_KEY": format!("orbis-bench-network-secret-{index:03}"),
            "RUST_LOG": "info",
        },
        "command": command,
        "volumes": [format!("{service}-data:/data")],
        "ports": ["127.0.0.1::50051", "127.0.0.1::9090"],
        "networks": ["orbis-bench"],
        "depends_on": {sourcehub_target.clone(): {"condition": "service_healthy"}},
        "labels": {
            "dev.orbis.bench.run": input.run_id,
            "dev.orbis.bench.stack": input.stack_id,
            "dev.orbis.bench.node-index": index.to_string(),
            "dev.orbis.bench.role": "node",
        },
        "healthcheck": {
            "test": ["CMD-SHELL", "nc -z 127.0.0.1 50051"],
            "interval": "5s",
            "timeout": "5s",
            "retries": 60,
            "start_period": "10s",
        },
    });
    let object = value.as_object_mut().expect("node service is an object");
    if input.stack.profile.kind == NetworkProfileKind::Wan {
        object.insert("cap_add".to_string(), json!(["NET_ADMIN"]));
    }
    if let Some(cpus) = input.resources.cpus_per_node {
        object.insert("cpus".to_string(), json!(cpus));
    }
    if let Some(memory) = &input.resources.memory_per_node {
        object.insert("mem_limit".to_string(), json!(memory));
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Experiment, NetworkProfile};

    fn render(network_size: usize, wan: bool) -> String {
        let mut experiment = Experiment::single(network_size, network_size, 2.min(network_size));
        experiment.profiles = vec![if wan {
            NetworkProfile::wan_50ms()
        } else {
            NetworkProfile::lan()
        }];
        let mut plan = experiment.resolve().unwrap();
        plan.assign_indices();
        let input = ComposeInput {
            repository_root: Path::new("/repo"),
            run_id: "run",
            stack_id: "orbis-bench-run-s000",
            stack: &plan.stacks[0],
            crypto: experiment.crypto,
            sourcehub_ref: &experiment.sourcehub_ref,
            sourcehub_replicas: experiment.sourcehub_replicas,
            resources: &experiment.resources,
            scheduler_poll_secs: 1,
        };
        serde_yaml::to_string(&compose_document(&input).unwrap()).unwrap()
    }

    #[test]
    fn generates_dynamic_ports_labels_and_requested_node_count() {
        let yaml = render(50, false);
        assert!(yaml.contains("node-050"));
        assert_eq!(yaml.matches("127.0.0.1::50051").count(), 50);
        assert_eq!(yaml.matches("--chain-gas-multiplier").count(), 50);
        let document: Value = serde_yaml::from_str(&yaml).unwrap();
        for service in document["services"].as_object().unwrap().values() {
            let Some(command) = service.get("command").and_then(Value::as_array) else {
                continue;
            };
            if let Some(position) = command
                .iter()
                .position(|argument| argument.as_str() == Some("--chain-gas-multiplier"))
            {
                assert_eq!(command[position + 1].as_str(), Some("3"));
            }
        }
        assert!(!yaml.contains("container_name"));
        assert!(!yaml.contains("NET_ADMIN"));
    }

    #[test]
    fn wan_is_the_only_profile_granted_net_admin() {
        let yaml = render(3, true);
        assert_eq!(yaml.matches("NET_ADMIN").count(), 3);
    }

    #[test]
    fn runtime_dockerfile_copies_only_the_node_executable() {
        let dockerfile = include_str!("../Dockerfile.node");
        assert!(
            dockerfile.contains("COPY --from=builder /orbis-node-bin /usr/local/bin/orbis-node")
        );
        assert!(!dockerfile.contains("/usr/local/bin/orbis-bench"));
        assert!(!dockerfile.contains("target/release/orbis-bench"));
    }

    #[test]
    fn generated_compose_file_uses_an_absolute_host_path() {
        let original_dir = std::env::current_dir().unwrap();
        let temp = tempfile::tempdir_in(&original_dir).unwrap();
        let relative_dir = temp.path().strip_prefix(&original_dir).unwrap();
        let experiment = Experiment::single(3, 3, 2);
        let mut plan = experiment.resolve().unwrap();
        plan.assign_indices();
        let input = ComposeInput {
            repository_root: Path::new("/repo"),
            run_id: "run",
            stack_id: "orbis-bench-run-s000",
            stack: &plan.stacks[0],
            crypto: experiment.crypto,
            sourcehub_ref: &experiment.sourcehub_ref,
            sourcehub_replicas: experiment.sourcehub_replicas,
            resources: &experiment.resources,
            scheduler_poll_secs: 1,
        };

        let artifacts = write_stack_files(relative_dir, &input).unwrap();

        assert!(artifacts.compose_file.is_absolute());
        assert!(artifacts.compose_file.starts_with(original_dir));
    }

    #[test]
    fn nodes_are_bucketed_across_sourcehub_replicas() {
        let mut experiment = Experiment::single(6, 6, 2);
        experiment.sourcehub_replicas = 3;
        experiment.profiles = vec![NetworkProfile::lan()];
        let mut plan = experiment.resolve().unwrap();
        plan.assign_indices();
        let input = ComposeInput {
            repository_root: Path::new("/repo"),
            run_id: "run",
            stack_id: "orbis-bench-run-s000",
            stack: &plan.stacks[0],
            crypto: experiment.crypto,
            sourcehub_ref: &experiment.sourcehub_ref,
            sourcehub_replicas: experiment.sourcehub_replicas,
            resources: &experiment.resources,
            scheduler_poll_secs: 1,
        };
        let document = compose_document(&input).unwrap();
        let services = document["services"].as_object().unwrap();

        assert!(services.contains_key("sourcehub"));
        assert!(services.contains_key("sourcehub-001"));
        assert!(services.contains_key("sourcehub-002"));
        assert!(!services.contains_key("sourcehub-003"));

        let target_of = |node: &str| -> String {
            let command = services[node]["command"].as_array().unwrap();
            let position = command
                .iter()
                .position(|argument| argument.as_str() == Some("--chain-rpc"))
                .unwrap();
            let url = command[position + 1].as_str().unwrap();
            url.trim_start_matches("http://")
                .split(':')
                .next()
                .unwrap()
                .to_string()
        };
        assert_eq!(target_of("node-001"), "sourcehub");
        assert_eq!(target_of("node-002"), "sourcehub-001");
        assert_eq!(target_of("node-003"), "sourcehub-002");
        assert_eq!(target_of("node-004"), "sourcehub");
        assert_eq!(target_of("node-005"), "sourcehub-001");
        assert_eq!(target_of("node-006"), "sourcehub-002");
    }

    #[test]
    fn replica_handoff_wait_is_posix_and_bounded() {
        let mut experiment = Experiment::single(3, 3, 2);
        experiment.sourcehub_replicas = 2;
        experiment.profiles = vec![NetworkProfile::lan()];
        let mut plan = experiment.resolve().unwrap();
        plan.assign_indices();
        let input = ComposeInput {
            repository_root: Path::new("/repo"),
            run_id: "run",
            stack_id: "orbis-bench-run-s000",
            stack: &plan.stacks[0],
            crypto: experiment.crypto,
            sourcehub_ref: &experiment.sourcehub_ref,
            sourcehub_replicas: experiment.sourcehub_replicas,
            resources: &experiment.resources,
            scheduler_poll_secs: 1,
        };
        let document = compose_document(&input).unwrap();
        let command = document["services"]["sourcehub-001"]["command"][0]
            .as_str()
            .expect("replica startup command");
        assert!(!command.contains(" -ot "));
        assert!(command.contains("find /handoff/ready -newer /tmp/boot-marker -print"));
        assert!(command.contains("handoff_timeout_seconds=300"));
        assert!(command.contains("sourcehub replica timed out after"));
        assert!(command.contains("exit 1"));
    }

    #[test]
    fn nodes_whitelist_the_ring_governance_policy_at_startup() {
        let yaml = render(50, false);
        assert_eq!(yaml.matches("--node-whitelisted-policy-id").count(), 50);
        assert!(!yaml.contains("--node-whitelisted-ring-id"));
        let document: Value = serde_yaml::from_str(&yaml).unwrap();
        for service in document["services"].as_object().unwrap().values() {
            let Some(command) = service.get("command").and_then(Value::as_array) else {
                continue;
            };
            if let Some(position) = command
                .iter()
                .position(|argument| argument.as_str() == Some("--node-whitelisted-policy-id"))
            {
                assert_eq!(
                    command[position + 1].as_str(),
                    Some(RING_GOVERNANCE_POLICY_ID)
                );
            }
        }
    }
}
