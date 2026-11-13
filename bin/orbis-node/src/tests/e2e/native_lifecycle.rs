//! Node startup helpers for the hosted Trust gateway qualification.
//!
//! `native_trust_gateway_ring_dkg` stays in this module because the external
//! gateway runner launches that ignored test by name.

pub(super) use test_support::NativeTestNetwork as TestCluster;

use proto::info_service::{
    info_service_client::InfoServiceClient, GetNodeInfoRequest, GetNodeInfoResponse, NodeStatus,
};
use std::{
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

/// Compose-backed Orbis node handle. Restarting a node reuses the same
/// container. The owning `TestCluster` tears the project down.
pub(super) struct ComposeNode {
    project_name: String,
    service: String,
    log: PathBuf,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct ComposeExit(i32);
impl ComposeExit {
    fn success(self) -> bool {
        self.0 == 0
    }
}
impl std::fmt::Display for ComposeExit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "container exit {}", self.0)
    }
}

const NATIVE_COMPOSE_FILE: &str = "docker/docker-compose-native-integration-test.yml";

impl ComposeNode {
    async fn try_wait_async(&self) -> Result<Option<ComposeExit>, ()> {
        let project_name = self.project_name.clone();
        let service = self.service.clone();
        Ok(tokio::task::spawn_blocking(move || {
            test_support::compose_exit_code(NATIVE_COMPOSE_FILE, &project_name, &service)
                .map(ComposeExit)
        })
        .await
        .unwrap())
    }

    async fn interrupt_async(&self) -> Result<(), ()> {
        test_support::compose_kill(
            NATIVE_COMPOSE_FILE,
            &self.project_name,
            &self.service,
            "SIGINT",
        );
        Ok(())
    }

    fn retain_logs(&self) -> Result<(), ()> {
        test_support::compose_save_logs(
            NATIVE_COMPOSE_FILE,
            &self.project_name,
            &self.service,
            &self.log,
        );
        Ok(())
    }
}

pub(super) struct Node(ComposeNode);
impl Node {
    /// `index` is the node's 0-based position (`node1`..`node4`).
    pub(super) fn attach(project_name: &str, index: usize, log: &Path) -> Self {
        Self(ComposeNode {
            project_name: project_name.to_string(),
            service: orbis_service(index),
            log: log.to_path_buf(),
        })
    }

    pub(super) async fn ready(&mut self, addr: &str, log: &Path) -> GetNodeInfoResponse {
        let mut connections = 0_u32;
        let mut responses = 0_u32;
        let mut last_status = None;
        tokio::time::timeout(Duration::from_secs(40), async {
            loop {
                assert!(
                    self.0.try_wait_async().await.unwrap().is_none(),
                    "node exited; logs retained privately"
                );
                if let Ok(mut client) = InfoServiceClient::connect(format!("http://{addr}")).await {
                    connections += 1;
                    if let Ok(response) = client.get_node_info(GetNodeInfoRequest {}).await {
                        responses += 1;
                        let info = response.into_inner();
                        last_status = Some(info.status);
                        assert!(!matches!(
                            info.status(),
                            NodeStatus::ConnectingToChain
                                | NodeStatus::WaitingForFunding
                                | NodeStatus::Funded
                        ));
                        if info.status() == NodeStatus::Ready {
                            return info;
                        }
                    }
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .unwrap_or_else(|_| {
            self.0.retain_logs().unwrap();
            use std::io::{Read, Seek, SeekFrom};
            let mut tail = Vec::new();
            let log_read = fs::File::open(&self.0.log).and_then(|mut file| {
                let length = file.metadata()?.len();
                file.seek(SeekFrom::Start(length.saturating_sub(65_536)))?;
                file.take(65_536).read_to_end(&mut tail)
            });
            let text = String::from_utf8_lossy(&tail);
            let endpoint = test_support::compose_discover_endpoint(
                NATIVE_COMPOSE_FILE,
                &self.0.project_name,
                &self.0.service,
                50051,
            );
            eprintln!(
                "native_readiness={}",
                serde_json::json!({
                    "restart": log.file_name().is_some_and(|name| name == "restart.log"),
                    "connections": connections,
                    "responses": responses,
                    "last_status": last_status,
                    "endpoint_changed": endpoint.trim_start_matches("http://") != addr,
                    "log_read": log_read.is_ok(),
                    "password_loaded": text.contains("Password loaded from file"),
                    "network_initializing": text.contains("Initializing network"),
                    "bootstrap_started": text.contains("Bootstrap info service started"),
                    "permission_denied": text.contains("Permission denied"),
                    "runtime_panicked": text.contains("panicked at"),
                })
            );
            panic!("startup timed out; logs retained privately")
        })
    }

    pub(super) async fn stop(&mut self) {
        tokio::time::timeout(Duration::from_secs(10), async {
            if let Some(status) = self.0.try_wait_async().await.unwrap() {
                assert!(status.success(), "{status}");
                return;
            }
            self.0.interrupt_async().await.unwrap();
            loop {
                if let Some(status) = self.0.try_wait_async().await.unwrap() {
                    assert!(status.success(), "{status}");
                    return;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .unwrap();
    }
}

/// `node1`..`node4`, matching `docker/docker-compose-native-integration-test.yml`.
pub(super) fn orbis_service(index: usize) -> String {
    match index {
        0 => "node1",
        1 => "node2",
        2 => "node3",
        3 => "node4",
        _ => panic!("native devnet default topology only supports 4 orbis nodes"),
    }
    .to_string()
}

/// Private node-fixture directory. `ORBIS_NATIVE_E2E_DIR` places it under a
/// caller-owned parent. `VERA_E2E_KEEP=1` retains it after the test returns.
pub(super) fn run_directory(
    deployment: u64,
    parent: Option<PathBuf>,
    keep: bool,
) -> tempfile::TempDir {
    let retained = keep || parent.is_some();
    let prefix = format!("orbis-native-{deployment}-");
    let mut builder = tempfile::Builder::new();
    builder.prefix(&prefix);
    builder.disable_cleanup(retained);
    let directory = match parent {
        Some(parent) => {
            assert!(
                !parent.as_os_str().is_empty(),
                "ORBIS_NATIVE_E2E_DIR must not be empty"
            );
            fs::create_dir_all(&parent).unwrap();
            builder.tempdir_in(parent).unwrap()
        }
        None => builder.tempdir().unwrap(),
    };
    if retained {
        eprintln!(
            "Retaining native Orbis logs and state: {}",
            directory.path().display()
        );
    }
    directory
}

/// Bring up `count` Orbis-node services against an already-running validator
/// cluster and return each node's `host:port` gRPC endpoint.
pub(super) fn bring_up_orbis_nodes(
    cluster: &TestCluster,
    fixtures: &Path,
    count: usize,
    reshare_interval_secs: u32,
    enable_unsafe_testing: bool,
) -> Vec<String> {
    let chain_endpoint = format!(
        "http://{}:{}",
        cluster.validator_service(0),
        cluster.validator_rpc_port()
    );
    let services: Vec<String> = (0..count).map(orbis_service).collect();
    let service_refs: Vec<&str> = services.iter().map(String::as_str).collect();

    let mut extra_env = vec![
        (
            "ORBIS_NATIVE_RESHARE_INTERVAL".to_string(),
            reshare_interval_secs.to_string(),
        ),
        (
            "ORBIS_NATIVE_ENABLE_UNSAFE_TESTING".to_string(),
            enable_unsafe_testing.to_string(),
        ),
    ];
    if enable_unsafe_testing {
        if let Some(image) = std::env::var_os("ORBIS_NATIVE_DIAGNOSTIC_IMAGE") {
            extra_env.push((
                "ORBIS_NATIVE_IMAGE".to_string(),
                image.to_string_lossy().into_owned(),
            ));
        }
    }
    for index in 0..count {
        let dir = fixtures.join(format!("node-{index}"));
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("password"), "native-dkg-test").unwrap();
        fs::write(
            dir.join("services.json"),
            serde_json::to_vec(&serde_json::json!({
                "authz": {
                    "endpoint": chain_endpoint,
                    "deployment_root": cluster.deployment_root_hex(),
                    "consensus_key": cluster.consensus_key_hex(),
                },
                "bulletin": {
                    "endpoint": chain_endpoint,
                    "deployment_id": cluster.deployment(),
                    "deployment_root": cluster.deployment_root_hex(),
                    "consensus_key": cluster.consensus_key_hex(),
                },
            }))
            .unwrap(),
        )
        .unwrap();
        extra_env.push((
            format!("ORBIS_NATIVE_NODE{}_USER", index + 1),
            test_support::bind_mount_user(&dir).expect("node fixture owner"),
        ));
        extra_env.push((
            format!("ORBIS_NATIVE_NODE{}_DIR", index + 1),
            dir.display().to_string(),
        ));
    }

    cluster.build_service(&services[0], &extra_env);
    cluster.bring_up_services(&service_refs, &extra_env);

    service_refs
        .iter()
        .map(|service| {
            cluster
                .discover_endpoint(service, 50051)
                .trim_start_matches("http://")
                .to_string()
        })
        .collect()
}

#[tokio::test]
#[ignore = "requires normal native Docker images and compiled Trust gateway contract artifacts"]
async fn native_trust_gateway_ring_dkg() {
    super::native_trust_gateway::run().await;
}

#[test]
fn native_directory_cleans_up_by_default() {
    let directory = run_directory(9075, None, false);
    let path = directory.path().to_path_buf();
    fs::write(path.join("node.log"), "fixture").unwrap();
    drop(directory);
    assert!(!path.exists());
}

#[test]
fn native_directory_retention_survives_unwind_without_reusing_runs() {
    let parent = tempfile::tempdir().unwrap();
    let first = run_directory(9075, Some(parent.path().to_path_buf()), false);
    let second = run_directory(9075, Some(parent.path().to_path_buf()), false);
    let paths = [first.path().to_path_buf(), second.path().to_path_buf()];
    assert_ne!(paths[0], paths[1]);
    let failed = std::panic::catch_unwind(|| {
        fs::write(first.path().join("node.log"), "failed fixture").unwrap();
        let _directory = first;
        panic!("fixture failure");
    });
    assert!(failed.is_err());
    drop(second);
    assert_eq!(
        fs::read_to_string(paths[0].join("node.log")).unwrap(),
        "failed fixture"
    );
    assert!(paths[1].is_dir());
    let kept = run_directory(9075, None, true);
    let kept_path = kept.path().to_path_buf();
    drop(kept);
    assert!(kept_path.is_dir());
    fs::remove_dir_all(kept_path).unwrap();
}
