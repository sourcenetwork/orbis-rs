use crate::config::{CryptoFeature, NetworkProfileKind, ResourceLimits, StackPlan};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

pub const SOURCEHUB_SERVICE: &str = "sourcehub";
pub const CONTROLLER_PUBLIC_KEY: &str =
    "024f4e2ad99c34d60b9ba6283c9431a8418af8673212961f97a77b6377fcd05b62";
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
    pub rings: &'a [RingDefinition],
    pub node_ring_ids: &'a BTreeMap<usize, Vec<String>>,
    pub resources: &'a ResourceLimits,
    pub scheduler_poll_secs: u64,
}

#[derive(Clone, Debug)]
pub struct StackArtifacts {
    pub compose_file: PathBuf,
    pub genesis_patch_file: PathBuf,
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
    let genesis_patch_file = stack_dir.join("genesis-patch.json");
    let compose_file = stack_dir.join("compose.yaml");

    let genesis = genesis_patch(input.rings);
    fs::write(
        &genesis_patch_file,
        format!("{}\n", serde_json::to_string_pretty(&genesis)?),
    )?;

    let compose = compose_document(input, &genesis_patch_file)?;
    fs::write(&compose_file, serde_yaml::to_string(&compose)?)?;
    Ok(StackArtifacts {
        compose_file,
        genesis_patch_file,
    })
}

pub fn node_service(index: usize) -> String {
    format!("node-{index:03}")
}

fn compose_document(input: &ComposeInput<'_>, genesis_patch_file: &Path) -> Result<Value> {
    let mut services = Map::new();
    services.insert(
        SOURCEHUB_SERVICE.to_string(),
        sourcehub_service(input, genesis_patch_file),
    );
    for index in 1..=input.stack.network_size {
        services.insert(node_service(index), node_service_value(input, index));
    }

    let mut volumes = Map::new();
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

fn sourcehub_service(input: &ComposeInput<'_>, genesis_patch_file: &Path) -> Value {
    let sourcehub_context = input.repository_root.join("docker");
    let command = r#"
set -eu
rm -rf /home/node/.sourcehub/*
sourcehubd init local-node --chain-id sourcehub-localnet --home /home/node/.sourcehub
sourcehubd keys add validator --keyring-backend test --home /home/node/.sourcehub
echo "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" | sourcehubd keys add test --recover --keyring-backend test --home /home/node/.sourcehub
sourcehubd genesis add-genesis-account validator 100000000000uopen --keyring-backend test --home /home/node/.sourcehub
sourcehubd genesis add-genesis-account test 100000000000uopen --keyring-backend test --home /home/node/.sourcehub
sourcehubd genesis gentx validator 10000000000uopen --keyring-backend test --chain-id sourcehub-localnet --home /home/node/.sourcehub
sourcehubd genesis collect-gentxs --home /home/node/.sourcehub
if [ -s /tmp/genesis-patch.json ]; then
  jq --slurpfile patch /tmp/genesis-patch.json '.app_state *= $$patch[0]' /home/node/.sourcehub/config/genesis.json > /tmp/patched-genesis.json
  mv /tmp/patched-genesis.json /home/node/.sourcehub/config/genesis.json
fi
exec sourcehubd start --home /home/node/.sourcehub --rpc.laddr tcp://0.0.0.0:26657 --api.enable --api.address tcp://0.0.0.0:1317
"#;
    json!({
        "image": format!("orbis-bench-sourcehub:{}", &input.sourcehub_ref[..12.min(input.sourcehub_ref.len())]),
        "build": {
            "context": sourcehub_context,
            "dockerfile": "Dockerfile.sourcehub-integration",
            "args": {"SOURCEHUB_REF": input.sourcehub_ref},
        },
        "entrypoint": ["/bin/sh", "-c"],
        "command": [command],
        "volumes": [format!("{}:/tmp/genesis-patch.json:ro", genesis_patch_file.display())],
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
    let mut command = vec![
        "--addr".to_string(),
        "0.0.0.0:50051".to_string(),
        "--log-level".to_string(),
        "info".to_string(),
        "--authz-grpc".to_string(),
        "http://sourcehub:9090".to_string(),
        "--bulletin-grpc".to_string(),
        "http://sourcehub:9090".to_string(),
        "--chain-rpc".to_string(),
        "http://sourcehub:26657".to_string(),
        "--chain-rest".to_string(),
        "http://sourcehub:1317".to_string(),
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
    ];
    for ring_id in input.node_ring_ids.get(&index).into_iter().flatten() {
        command.push("--node-whitelisted-ring-id".to_string());
        command.push(ring_id.clone());
    }

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
        "depends_on": {"sourcehub": {"condition": "service_healthy"}},
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

fn genesis_patch(rings: &[RingDefinition]) -> Value {
    let rings: Vec<Value> = rings
        .iter()
        .map(|ring| {
            json!({
                "id": ring.id,
                "ring_pk": "",
                "peer_node_keys": ring.peer_node_keys,
                "threshold": ring.threshold,
                "pss_interval": ring.pss_interval_secs,
                "policy_id": ring.policy_id,
                "reporting": {
                    "demerit_config": {
                        "node_offline_demerits": 1,
                        "invalid_crypto_response_demerits": 1,
                        "unauthorized_request_demerits": 1,
                        "reset_interval_seconds": 86400,
                    },
                    "backup_node_keys": [],
                    "kick_threshold": ring.peer_node_keys.len().max(1),
                },
            })
        })
        .collect();
    json!({"orbis": {"rings": rings}})
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Experiment, NetworkProfile};
    use sha2::{Digest, Sha256};

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
            rings: &[],
            node_ring_ids: &BTreeMap::new(),
            resources: &experiment.resources,
            scheduler_poll_secs: 1,
        };
        serde_yaml::to_string(&compose_document(&input, Path::new("/tmp/genesis.json")).unwrap())
            .unwrap()
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
    fn generated_bind_mount_uses_an_absolute_host_path() {
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
            rings: &[],
            node_ring_ids: &BTreeMap::new(),
            resources: &experiment.resources,
            scheduler_poll_secs: 1,
        };

        let artifacts = write_stack_files(relative_dir, &input).unwrap();
        let yaml = std::fs::read_to_string(&artifacts.compose_file).unwrap();

        assert!(artifacts.compose_file.is_absolute());
        assert!(artifacts.genesis_patch_file.is_absolute());
        assert!(yaml.contains(&format!(
            "{}:/tmp/genesis-patch.json:ro",
            artifacts.genesis_patch_file.display()
        )));
    }

    #[test]
    fn genesis_patch_is_read_from_a_file_instead_of_process_arguments() {
        let yaml = render(3, false);
        assert!(yaml.contains("--slurpfile patch /tmp/genesis-patch.json"));
        assert!(!yaml.contains("--argjson patch"));
    }

    #[test]
    fn generated_compose_and_genesis_golden_digests() {
        let compose_3 = render(3, false);
        let compose_50 = render(50, true);
        let ring = RingDefinition {
            id: "golden-ring".into(),
            peer_node_keys: vec!["node-a".into(), "node-b".into(), "node-c".into()],
            operator_node_keys: Vec::new(),
            threshold: 2,
            pss_interval_secs: 5,
            policy_id: "policy".into(),
        };
        let genesis = serde_json::to_string_pretty(&genesis_patch(&[ring])).unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(compose_3)),
            "61cfdd6c1e9a341d9a9f94ecc9fb6a31c5a041276448667b60f6c23a1f7cb97e"
        );
        assert_eq!(
            hex::encode(Sha256::digest(compose_50)),
            "95d157dadd35be09d9bd9d70897a60a647e2fb60a2df55e6cd8334f0f5c17e48"
        );
        assert_eq!(
            hex::encode(Sha256::digest(genesis)),
            "7353509f9fc642b01a95111778b78bf9ce1c0a90c0aaf408b71a7c7a83f2e996"
        );
    }
}
