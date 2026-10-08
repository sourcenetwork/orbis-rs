use test_support::NativeTestNetwork as TestCluster;

#[path = "support/native_confirmation.rs"]
mod native_confirmation;
use native_confirmation::{confirmed, submit};

#[cfg(any(feature = "bls12-381", feature = "jubjub"))]
#[path = "support/policy_generations.rs"]
mod policy_generations;

#[cfg(any(feature = "bls12-381", feature = "jubjub"))]
#[path = "support/admin.rs"]
mod admin;

#[cfg(any(feature = "bls12-381", feature = "jubjub"))]
#[path = "support/native_workflow.rs"]
mod native_workflow;

#[cfg(any(feature = "bls12-381", feature = "jubjub"))]
#[path = "support/native_pet.rs"]
mod native_pet;

#[cfg(any(feature = "bls12-381", feature = "jubjub"))]
#[path = "support/native_trust_gateway.rs"]
mod native_trust_gateway;

#[cfg(feature = "bls12-381")]
#[path = "support/defra_peers.rs"]
mod defra_peers;

#[cfg(feature = "bls12-381")]
#[path = "support/defra_documents.rs"]
mod defra_documents;

use proto::info_service::{
    info_service_client::InfoServiceClient, GetNodeInfoRequest, GetNodeInfoResponse, NodeStatus,
};
use std::{fs, path::Path, time::Duration};
use vera_client::VeraClient;
use vera_harness::cluster::KeySet;

/// Compose-backed Orbis node handle: `node{index+1}` (one of the 3-4
/// pre-declared services in `docker/docker-compose-native-integration-test.yml`),
/// driven through `test_support`'s free `compose_*` functions rather than a
/// legacy per-container `ContainerNode` (which refuses to run outside Linux —
/// see the harness-unification plan's Phase B/C reports for why this
/// replacement exists). Unlike `ContainerNode`, "restarting" a node reuses
/// the same long-lived container (`docker compose start`) instead of creating
/// a fresh one — these services are shared, named, and torn down as a whole
/// by the owning `TestCluster`'s `Drop`, not by any individual `Node`.
struct ComposeNode {
    project_name: String,
    service: String,
    log: std::path::PathBuf,
}

#[derive(Debug, Clone, Copy)]
struct ComposeExit(i32);
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

// Every method below returns a trivial `Result<T, ()>`/`Result<Option<T>, ()>`
// purely so the many existing `.0.<method>().unwrap()` call sites across
// `native_pet.rs`/`member_replacement.rs`/this file keep compiling unchanged
// — there's no real fallible-vs-panic distinction left to preserve (the
// underlying `compose_*` free functions already panic on a Docker-level
// failure), this is a call-site-compatibility shim, not meaningful error
// handling.
impl ComposeNode {
    fn try_wait(&self) -> Result<Option<ComposeExit>, ()> {
        Ok(
            test_support::compose_exit_code(NATIVE_COMPOSE_FILE, &self.project_name, &self.service)
                .map(ComposeExit),
        )
    }

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

    fn kill(&self) -> Result<(), ()> {
        test_support::compose_kill(
            NATIVE_COMPOSE_FILE,
            &self.project_name,
            &self.service,
            "SIGKILL",
        );
        Ok(())
    }

    fn pause(&self) -> Result<(), ()> {
        test_support::compose_kill(
            NATIVE_COMPOSE_FILE,
            &self.project_name,
            &self.service,
            "SIGSTOP",
        );
        Ok(())
    }

    fn wait(&self) -> Result<ComposeExit, ()> {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(exit) = self.try_wait().unwrap() {
                self.retain_logs().unwrap();
                return Ok(exit);
            }
            assert!(
                std::time::Instant::now() < deadline,
                "node did not exit in time"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
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

    async fn refresh_logs(&self) -> Result<(), ()> {
        self.retain_logs()
    }

    /// Start (or restart) this node's service — unlike `ContainerNode`, no
    /// per-node config is passed here: the compose file's `command:` already
    /// bakes everything in, and `node{index}`'s fixture directory (written
    /// once, before the service first starts) is reused across restarts.
    fn start_service(&self) {
        test_support::compose_start(NATIVE_COMPOSE_FILE, &self.project_name, &self.service);
    }
}

struct Node(ComposeNode);
impl Node {
    /// `index` is the node's 0-based position (`node1`..`node4`).
    fn attach(project_name: &str, index: usize, log: &Path) -> Self {
        Self(ComposeNode {
            project_name: project_name.to_string(),
            service: orbis_service(index),
            log: log.to_path_buf(),
        })
    }

    /// Restart a previously-brought-up node in place (same service, same
    /// fixture directory, same bind address — all already baked into the
    /// Compose service). Replaces the old `Node::start`/`start_bound` (which
    /// created a fresh `ContainerNode` each call); callers that used to pass
    /// `base`/`addr`/`controller`/`bind` now only need the node's index,
    /// since none of that varies between a node's launches anymore.
    fn restart(project_name: &str, index: usize, log: &Path) -> Self {
        let node = Self::attach(project_name, index, log);
        node.0.start_service();
        node
    }

    async fn ready(&mut self, addr: &str, _log: &Path) -> GetNodeInfoResponse {
        tokio::time::timeout(Duration::from_secs(40), async {
            loop {
                assert!(
                    self.0.try_wait_async().await.unwrap().is_none(),
                    "node exited; logs retained privately"
                );
                if let Ok(mut client) = InfoServiceClient::connect(format!("http://{addr}")).await {
                    if let Ok(response) = client.get_node_info(GetNodeInfoRequest {}).await {
                        let info = response.into_inner();
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
            panic!("startup timed out; logs retained privately")
        })
    }
    async fn stop(&mut self) {
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

/// `node1`..`node4`, matching `docker/docker-compose-native-integration-test.yml`
/// and `crates/test-support/src/network/native.rs`'s own `orbis_service` —
/// not shared with it directly (that one's private to `crates/test-support`)
/// since this crate can't reach a private fn in another crate's module.
fn orbis_service(index: usize) -> String {
    match index {
        0 => "node1",
        1 => "node2",
        2 => "node3",
        3 => "node4",
        _ => panic!("native devnet default topology only supports 4 orbis nodes"),
    }
    .to_string()
}

/// Bring up `count` Orbis-node services (`node1..node{count}`) against an
/// already-running validator cluster: write each node's `vera.json`/`password`
/// fixture, build the shared node image once (avoiding the build race
/// `crates/test-support/src/network/native.rs`'s `bring_up_orbis_nodes` doc
/// comment describes), bring all of them up together, and return each one's
/// discovered gRPC endpoint. `reshare_interval_secs`/`enable_unsafe_testing`
/// map to the Compose env vars `docker-compose-native-integration-test.yml`'s
/// node services read (`ORBIS_NATIVE_RESHARE_INTERVAL`/`ORBIS_NATIVE_ENABLE_UNSAFE_TESTING`).
fn bring_up_orbis_nodes(
    cluster: &TestCluster,
    fixtures: &Path,
    count: usize,
    reshare_interval_secs: u32,
    enable_unsafe_testing: bool,
) -> Vec<String> {
    assert!(!enable_unsafe_testing || cfg!(feature = "unsafe-testing"));
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
    // CI supplies a production native image and a separately compiled image
    // containing the unsafe testing service. Enabling the service at runtime
    // is not enough when the production binary was compiled without it, so
    // select the diagnostic image for the attributable-fault scenario.
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
            dir.join("vera.json"),
            serde_json::to_vec(&serde_json::json!({
                "endpoint": chain_endpoint,
                "deployment_id": cluster.deployment(),
                "deployment_root": cluster.deployment_root_hex(),
                "consensus_key": cluster.consensus_key_hex(),
            }))
            .unwrap(),
        )
        .unwrap();
        extra_env.push((
            format!("ORBIS_NATIVE_NODE{}_DIR", index + 1),
            dir.display().to_string(),
        ));
    }

    cluster.build_service(&services[0], &extra_env);
    cluster.bring_up_services(&service_refs, &extra_env);

    // Bare `host:port`, matching every existing `addresses: Vec<String>`
    // call site's convention (`format!("http://{addr}")`), not a full URL.
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

/// Compose service's fixed `--node-controller-key`
/// (`docker/docker-compose-native-integration-test.yml`), the compressed
/// secp256k1 public key for the fixed test private key `[34u8; 32]` — the
/// same convention `bin/orbis-node/tests/support/native_workflow.rs`/`admin.rs`
/// already use as `controller`/`controller_key`.
const COMPOSE_NODE_CONTROLLER_KEY: &str =
    "02466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27";

/// Bring up the dynamic 4th node (`node4`, `profiles: ["node4"]` in
/// `docker/docker-compose-native-integration-test.yml`) against an
/// already-running cluster/node1-3, reusing `node-0`'s `vera.json` (same
/// chain, same deployment). Returns the new node's handle and discovered
/// `host:port` gRPC endpoint. Replaces the old ad hoc
/// `TcpListener::bind("127.0.0.1:0")` + `Node::start` dance (that reserved an
/// arbitrary host port; `node4`'s port is fixed and published like every
/// other service's).
fn add_orbis_node4(cluster: &TestCluster, base: &Path) -> (Node, String) {
    let directory = base.join("node-3");
    fs::create_dir(&directory).unwrap();
    fs::write(directory.join("password"), "native-dkg-test").unwrap();
    fs::copy(base.join("node-0/vera.json"), directory.join("vera.json")).unwrap();
    let extra_env = [(
        "ORBIS_NATIVE_NODE4_DIR".to_string(),
        directory.display().to_string(),
    )];
    cluster.build_service("node4", &extra_env);
    cluster.bring_up_services(&["node4"], &extra_env);
    let endpoint = cluster
        .discover_endpoint("node4", 50051)
        .trim_start_matches("http://")
        .to_string();
    (
        Node::attach(cluster.project_name(), 3, &directory.join("node.log")),
        endpoint,
    )
}

#[tokio::test]
#[ignore = "temporarily disabled: Compose-backed Orbis stop/restart lifecycle is unreliable; re-enable after restart coverage is redesigned in the shared test harness"]
async fn native_startup_registers_and_preserves_identity_on_restart() {
    let deployment = 9073;
    let trusted = *KeySet::builder()
        .seed(deployment)
        .build()
        .unwrap()
        .epoch_info()
        .output
        .public()
        .public();
    let cluster = TestCluster::start(deployment).await;
    let url = cluster.node(0).rpc_url();
    let client = VeraClient::new(&url);
    let first = client.read_finalized_revision(1, &trusted).await.unwrap();
    let root = first.parent_hash.trim_start_matches("0x");
    let base = tempfile::tempdir().unwrap();
    // `COMPOSE_NODE_CONTROLLER_KEY`, not a fresh per-test key: `node1`'s
    // Compose service bakes one fixed `--node-controller-key` (see that
    // constant's doc comment) — unlike the legacy `ContainerNode` model,
    // this isn't a parameter a caller can vary per launch.
    let controller = COMPOSE_NODE_CONTROLLER_KEY;
    let endpoints = bring_up_orbis_nodes(&cluster, base.path(), 1, 1, false);
    let addr = &endpoints[0];
    let log = base.path().join("first.log");
    let mut node = Node::attach(cluster.project_name(), 0, &log);
    let first_info = node.ready(addr, &log).await;
    assert_eq!(first_info.node_key, first_info.public_address);
    assert_eq!(
        fs::read_to_string(base.path().join("node-0/public_key.txt")).unwrap(),
        first_info.node_key
    );
    let certified = client
        .read_threshold_node(&first_info.node_key, 1, &trusted)
        .await
        .unwrap()
        .record
        .unwrap();
    assert_eq!(certified.info.controller_key, controller);
    assert_eq!(certified.info.peer_id, first_info.peer_id);
    node.stop().await;
    let journal = base
        .path()
        .join("node-0")
        .join("native-vera")
        .join(root)
        .join("state.json");
    let before = fs::read(&journal).unwrap();
    let log = base.path().join("restart.log");
    let mut restarted = Node::restart(cluster.project_name(), 0, &log);
    let second_info = restarted.ready(addr, &log).await;
    assert_eq!(first_info.node_key, second_info.node_key);
    assert_eq!(first_info.peer_id, second_info.peer_id);
    restarted.stop().await;
    assert_eq!(before, fs::read(&journal).unwrap());
}

#[tokio::test]
#[ignore = "temporarily disabled: Compose-backed Orbis stop/restart lifecycle is unreliable; re-enable after restart coverage is redesigned in the shared test harness"]
#[cfg(any(feature = "bls12-381", feature = "jubjub"))]
#[serial_test::serial(defra_signing)]
async fn native_distributed_threshold_workflows() {
    distributed_threshold_workflows(false).await;
}

#[tokio::test]
#[ignore = "temporarily disabled: Compose-backed Orbis stop/restart lifecycle is unreliable; re-enable after restart coverage is redesigned in the shared test harness"]
#[cfg(feature = "bls12-381")]
#[serial_test::serial(defra_signing)]
async fn native_defra_signing() {
    distributed_threshold_workflows(true).await;
}

#[tokio::test]
#[ignore = "temporarily disabled: Compose-backed Orbis stop/restart lifecycle is unreliable; re-enable after restart coverage is redesigned in the shared test harness"]
#[cfg(any(feature = "bls12-381", feature = "jubjub"))]
async fn native_pet_threshold_workflows() {
    native_pet::run(native_pet::Scenario::Lifecycle).await;
}

/// Native half of the `cosmos_*`/`native_*` scenario pair the harness-unification
/// plan asks for (see `cosmos_dkg` in `bin/orbis-node/src/tests/integration.rs`).
/// Proves the shared provision-trigger-finalize-verify scenario on its
/// own, without any of `Scenario::Lifecycle`'s additional PET-document logic.
#[tokio::test]
#[cfg(any(feature = "bls12-381", feature = "jubjub"))]
async fn native_dkg() {
    let (_workflow, keys, _baseline) = native_pet::dkg_scenario(9079, false).await;
    assert!(
        !keys.public_key.is_empty(),
        "DKG must finalize the main key"
    );
    assert!(
        keys.pet_public_key.is_some_and(|pet| !pet.is_empty()),
        "DKG must finalize the PET key"
    );
}

/// Native adapter for the shared standard-DKG lifecycle: StoreSecret,
/// authorized PRE, derived-key signing, refresh, and committee reshare. The
/// scenario body is identical to `cosmos_dkg_and_pre`.
#[tokio::test]
#[cfg(all(
    feature = "unsafe-testing",
    any(feature = "bls12-381", feature = "jubjub")
))]
async fn native_dkg_and_pre() {
    let (object_id, derivation_id) = native_pet::dkg_pre_and_sign_scenario(9080).await;
    assert!(
        !object_id.is_empty(),
        "the shared PRE scenario must store a document"
    );
    assert!(
        !derivation_id.is_empty(),
        "the shared Sign scenario must store a key derivation"
    );
}

#[tokio::test]
#[ignore = "temporarily disabled: Compose-backed Orbis stop/restart lifecycle is unreliable; re-enable after restart coverage is redesigned in the shared test harness"]
#[cfg(any(feature = "bls12-381", feature = "jubjub"))]
async fn native_pet_member_replacement() {
    native_pet::run(native_pet::Scenario::MemberReplacement).await;
}

#[tokio::test]
#[ignore = "temporarily disabled: Compose-backed Orbis stop/restart lifecycle is unreliable; re-enable after restart coverage is redesigned in the shared test harness"]
#[cfg(any(feature = "bls12-381", feature = "jubjub"))]
async fn native_pet_scheduled_refresh_after_restart() {
    native_pet::run(native_pet::Scenario::ScheduledRefresh).await;
}

#[tokio::test]
#[ignore = "requires normal native Docker images and compiled Trust gateway contract artifacts"]
#[cfg(any(feature = "bls12-381", feature = "jubjub"))]
async fn native_trust_gateway_ring_dkg() {
    native_trust_gateway::run().await;
}

#[tokio::test]
#[cfg(all(
    feature = "unsafe-testing",
    any(feature = "bls12-381", feature = "jubjub")
))]
async fn native_pet_fault_reports() {
    native_pet::run(native_pet::Scenario::ReportFault).await;
}

#[cfg(any(feature = "bls12-381", feature = "jubjub"))]
async fn distributed_threshold_workflows(signing_only: bool) {
    use alloy_sol_types::SolCall;
    use authn::jwt_builder::{create_authenticated_request, JwtSigner};
    use crypto::r#trait::{CryptoDeserialize, ThresholdSigner};
    use proto::{
        info_service::GetRingStateRequest,
        v0::{
            dkg::{dkg_service_client::DkgServiceClient, StartDkgRequest},
            sign::{sign_service_client::SignServiceClient, StartSignRequest},
        },
    };
    use vera_client::{
        create_scoped_bearer_token,
        nodes::{encode_node_request, sign_node_request, NodeCommand, NodeRequest, NodeTarget},
        rings::{encode_ring_command, RingCommand, RingPublicKeys, RingState, RingUpdate},
        threshold_objects::{encode_threshold_object, KeyDerivation, ThresholdObject},
        DelegationScope,
    };
    let deployment = 9074;
    let native_workflow::NativeWorkflow {
        cluster,
        client,
        trusted,
        root,
        controller,
        actor,
        base,
        mut nodes,
        mut addresses,
        mut logs,
        mut infos,
        worker,
        policy,
        policy_bytes,
        ring_id,
        now,
        headers: _headers,
        deployment: _,
    } = native_workflow::NativeWorkflow::start(deployment, false, false).await;
    let response = DkgServiceClient::connect(
        tonic::transport::Endpoint::from_shared(format!("http://{}", addresses[0]))
            .unwrap()
            .timeout(Duration::from_secs(30)),
    )
    .await
    .unwrap()
    .start_dkg(StartDkgRequest {
        ring_id: ring_id.clone(),
    })
    .await
    .unwrap()
    .into_inner();
    assert!(!response.session_id.is_empty());
    let ring_pk = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            let ring = client
                .read_threshold_ring(&ring_id, 1, &trusted)
                .await
                .unwrap()
                .record
                .unwrap();
            match ring.state {
                RingState::Active { keys } => break keys.public_key,
                RingState::Pending { .. } => (),
                state => panic!("DKG terminated: {state:?}"),
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "DKG did not finalize: {}",
            logs.iter()
                .map(|path| fs::read_to_string(path).unwrap())
                .collect::<Vec<_>>()
                .join("\n")
        )
    });
    let mut polynomials = Vec::new();
    for addr in &addresses {
        let state = InfoServiceClient::connect(format!("http://{addr}"))
            .await
            .unwrap()
            .get_ring_state(GetRingStateRequest {
                ring_pk_hex: ring_pk.clone(),
            })
            .await
            .unwrap()
            .into_inner();
        polynomials.push(state.public_polynomial);
    }
    assert!(!polynomials[0].is_empty());
    assert!(polynomials
        .iter()
        .all(|polynomial| polynomial == &polynomials[0]));

    for node in &mut nodes {
        if signing_only {
            node.stop().await;
        } else {
            assert!(node.0.try_wait().unwrap().is_none());
            node.0.kill().unwrap();
            assert!(!node.0.wait().unwrap().success());
        }
    }
    for index in 0..nodes.len() {
        let directory = base.path().join(format!("node-{index}"));
        let log = directory.join("restart.log");
        nodes[index] = Node::restart(cluster.project_name(), index, &log);
        let recovered = nodes[index].ready(&addresses[index], &log).await;
        assert_eq!(recovered.node_key, infos[index].node_key);
        assert_eq!(recovered.p2p_address, infos[index].p2p_address);
        assert_eq!(recovered.managed_ring_count, 1);
        let state = InfoServiceClient::connect(format!("http://{}", addresses[index]))
            .await
            .unwrap()
            .get_ring_state(GetRingStateRequest {
                ring_pk_hex: ring_pk.clone(),
            })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(state.public_polynomial, polynomials[index]);
    }

    let derivation = KeyDerivation {
        ring_id,
        derivation: "native-signing".into(),
        policy_id: policy.clone(),
        resource: "key".into(),
        permission: "sign".into(),
    };
    let object = ThresholdObject::KeyDerivation(derivation.clone());
    let derivation_id = object.id().unwrap();
    let token = create_scoped_bearer_token(
        &controller,
        worker.did(),
        deployment,
        now,
        now + 300,
        DelegationScope::StoreThresholdObject,
    )
    .unwrap();
    submit(
        &client,
        &worker,
        &trusted,
        encode_threshold_object(&object, &token).unwrap(),
        "store threshold object",
        &cluster,
    )
    .await;
    let registered = client
        .native_register_object(&worker, policy_bytes, &derivation_id, "key")
        .await
        .unwrap();
    confirmed(&client, registered.transaction_hash, &trusted).await;
    let reader_seed = [91u8; 32];
    let reader = JwtSigner::from_key_pair(did_key::generate::<did_key::Ed25519KeyPair>(Some(
        &reader_seed,
    )));
    let public_key = crypto::GroupAffine::from_bytes(&hex::decode(&ring_pk).unwrap()).unwrap();
    let metadata = crypto::SignImpl::encode_metadata(&policy, "key", "sign");
    let derived_key = crypto::SignImpl::derive_public_key(
        &public_key,
        derivation.derivation.as_bytes(),
        Some(&metadata),
    )
    .unwrap();
    #[cfg(feature = "bls12-381")]
    let defra = {
        let service_identity = std::sync::Arc::new(
            defra_identity::RawIdentity::from_ed25519(
                defra_crypto::Ed25519PrivateKey::from_bytes(
                    &defra_crypto::ed25519_key_from_seed(&reader_seed).unwrap(),
                )
                .unwrap(),
            )
            .unwrap(),
        );
        assert_eq!(
            defra_identity::Identity::did(service_identity.as_ref())
                .unwrap()
                .to_string(),
            reader.did_uri
        );
        std::sync::Arc::new(
            defra_orbis::OrbisClient::new(
                format!("http://{}", addresses[1]),
                derivation_id.clone(),
                derived_key.to_bytes().unwrap(),
                service_identity,
            )
            .await
            .unwrap(),
        )
    };
    #[cfg(feature = "bls12-381")]
    let documents =
        defra_documents::Documents::new(&base.path().join("defra"), defra.clone()).await;
    #[cfg(feature = "bls12-381")]
    let defra_sign = || {
        let defra = std::sync::Arc::clone(&defra);
        tokio::task::spawn_blocking(move || {
            defra_core::signing::RemoteSigner::sign_sync(
                defra.as_ref(),
                b"native Vera threshold signing",
                None,
            )
        })
    };

    let message = b"native Vera threshold signing".to_vec();
    let sign_request = || {
        create_authenticated_request(
            StartSignRequest {
                message: message.clone(),
                derivation_id: derivation_id.clone(),
                valid_window: None,
            },
            &reader.create_sign_jwt(&derivation_id, &message).unwrap(),
        )
        .unwrap()
    };
    let mut signing = SignServiceClient::connect(
        tonic::transport::Endpoint::from_shared(format!("http://{}", addresses[1]))
            .unwrap()
            .timeout(Duration::from_secs(30)),
    )
    .await
    .unwrap();
    assert_eq!(
        signing.start_sign(sign_request()).await.unwrap_err().code(),
        tonic::Code::Unauthenticated
    );
    #[cfg(feature = "bls12-381")]
    {
        assert!(defra_sign().await.unwrap().is_err());
        assert!(documents.create("denied").await.is_err());
        assert_eq!(documents.count().await, 0);
    }
    let granted = client
        .native_set_relationship(
            &worker,
            policy_bytes,
            "key",
            &derivation_id,
            "signer",
            &reader.did_uri,
        )
        .await
        .unwrap();
    confirmed(&client, granted.transaction_hash, &trusted).await;
    let signed = signing
        .start_sign(sign_request())
        .await
        .unwrap()
        .into_inner();
    let signature =
        crypto::SignaturePoint::from_bytes(&hex::decode(signed.signature).unwrap()).unwrap();
    crypto::SignImpl::new()
        .verify(&derived_key, &message, &signature)
        .unwrap();
    #[cfg(feature = "bls12-381")]
    let (documents, peers, created) = {
        let defra_signature = defra_sign()
            .await
            .unwrap()
            .expect("Defra threshold signature");
        assert_eq!(defra_signature, signature.to_bytes().unwrap());
        let peers = defra_peers::Peers::new(&base.path().join("peers"), defra.clone()).await;
        peers.verify_replication().await;
        let peers = peers.verify_restart().await;
        let created = documents.create("signed").await.expect("signed document");
        documents.verify(&created, defra.signer_did()).await;
        assert_eq!(documents.count().await, 1);
        documents.verify_contents().await;
        let replica =
            defra_documents::Documents::new(&base.path().join("replica"), defra.clone()).await;
        documents.replicate_to(&replica, &created).await;
        replica.verify(&created, defra.signer_did()).await;
        let replica = replica.reopen().await;
        replica.verify_contents().await;
        replica.verify(&created, defra.signer_did()).await;
        let documents = documents.reopen().await;
        documents.verify(&created, defra.signer_did()).await;
        assert_eq!(documents.count().await, 1);
        (documents, peers, created)
    };

    policy_generations::replace(
        &client,
        &worker,
        &trusted,
        policy_bytes,
        policy_generations::definition(false, true),
    )
    .await;
    assert_eq!(
        signing.start_sign(sign_request()).await.unwrap_err().code(),
        tonic::Code::Unauthenticated
    );
    #[cfg(feature = "bls12-381")]
    {
        assert!(defra_sign().await.unwrap().is_err());
        assert!(documents.create("policy-revoked").await.is_err());
        assert_eq!(documents.count().await, 1);
    }
    nodes[1].stop().await;
    let log = base.path().join("node-1/policy-edit-restart.log");
    nodes[1] = Node::restart(cluster.project_name(), 1, &log);
    let recovered = nodes[1].ready(&addresses[1], &log).await;
    assert_eq!(recovered.node_key, infos[1].node_key);
    signing = SignServiceClient::connect(
        tonic::transport::Endpoint::from_shared(format!("http://{}", addresses[1]))
            .unwrap()
            .timeout(Duration::from_secs(30)),
    )
    .await
    .unwrap();
    policy_generations::replace(
        &client,
        &worker,
        &trusted,
        policy_bytes,
        policy_generations::definition(true, true),
    )
    .await;
    assert_eq!(
        signing.start_sign(sign_request()).await.unwrap_err().code(),
        tonic::Code::Unauthenticated
    );
    #[cfg(feature = "bls12-381")]
    {
        assert!(defra_sign().await.unwrap().is_err());
        assert!(documents.create("policy-recreated").await.is_err());
        assert_eq!(documents.count().await, 1);
    }
    let regranted = client
        .native_set_relationship(
            &worker,
            policy_bytes,
            "key",
            &derivation_id,
            "signer",
            &reader.did_uri,
        )
        .await
        .unwrap();
    confirmed(&client, regranted.transaction_hash, &trusted).await;
    #[cfg(feature = "bls12-381")]
    assert_eq!(
        defra_sign().await.unwrap().unwrap(),
        signature.to_bytes().unwrap()
    );
    #[cfg(feature = "jubjub")]
    {
        let signed = signing
            .start_sign(sign_request())
            .await
            .unwrap()
            .into_inner();
        let signature =
            crypto::SignaturePoint::from_bytes(&hex::decode(signed.signature).unwrap()).unwrap();
        crypto::SignImpl::new()
            .verify(&derived_key, &message, &signature)
            .unwrap();
    }

    let revoked = client
        .native_delete_relationship(
            &worker,
            policy_bytes,
            "key",
            &derivation_id,
            "signer",
            &reader.did_uri,
        )
        .await
        .unwrap();
    confirmed(&client, revoked.transaction_hash, &trusted).await;
    assert_eq!(
        signing.start_sign(sign_request()).await.unwrap_err().code(),
        tonic::Code::Unauthenticated
    );
    #[cfg(feature = "bls12-381")]
    {
        assert!(defra_sign().await.unwrap().is_err());
        assert!(documents.create("revoked").await.is_err());
        assert_eq!(documents.count().await, 1);
        documents.verify(&created, defra.signer_did()).await;
        peers.verify_revocation().await;
        peers.shutdown().await;
    }
    if signing_only {
        return;
    }
    #[cfg(feature = "bls12-381")]
    use ark_ec::{AffineRepr, CurveGroup};
    use crypto::r#trait::{CryptoSerialize, ThresholdDealer};
    use proto::v0::{
        pre::{
            pre_service_client::PreServiceClient, ReaderAuthorizationSignature, StartPreRequest,
        },
        store_secret::{store_secret_service_client::StoreSecretServiceClient, StoreSecretRequest},
    };
    let plaintext = b"native Vera encrypted document";
    let context = crypto::context::CiphertextContext {
        ring_pk: hex::decode(&ring_pk).unwrap(),
        policy_id: policy.clone(),
        resource: "document".into(),
        permission: "read".into(),
        tier: None,
        timestamp: None,
        salt: None,
        pet_tag: None,
    };
    let (commitment, secret, proof) =
        crypto::PreImpl::encrypt_secret(&public_key, plaintext, None, &context).unwrap();
    let encrypted_document = serde_json::to_vec(&secret).unwrap();
    let commitment = commitment.to_bytes().unwrap();
    let token = reader
        .create_store_secret_jwt(
            &encrypted_document,
            commitment.clone(),
            &derivation.ring_id,
            &policy,
            "document",
            "read",
            proof.challenge.clone(),
            proof.response.clone(),
            false,
            None,
            None,
        )
        .unwrap();
    let request = create_authenticated_request(
        StoreSecretRequest {
            encrypted_document,
            enc_cmt: commitment,
            ring_id: derivation.ring_id.clone(),
            policy_id: policy.clone(),
            resource: "document".into(),
            permission: "read".into(),
            challenge: proof.challenge,
            response: proof.response,
            with_proof: false,
            tier: None,
            timestamp: None,
            pet_tag: None,
        },
        &token,
    )
    .unwrap();
    let endpoint = tonic::transport::Endpoint::from_shared(format!("http://{}", addresses[2]))
        .unwrap()
        .timeout(Duration::from_secs(30));
    let stored = StoreSecretServiceClient::connect(endpoint.clone())
        .await
        .unwrap()
        .store_secret(request)
        .await
        .unwrap()
        .into_inner();
    let registered = client
        .native_register_object(&worker, policy_bytes, &stored.object_id, "document")
        .await
        .unwrap();
    confirmed(&client, registered.transaction_hash, &trusted).await;
    let reader_secret = crypto::ScalarField::from(47u64);
    #[cfg(feature = "bls12-381")]
    let reader_public = (crypto::GroupAffine::generator() * reader_secret).into_affine();
    #[cfg(feature = "jubjub")]
    let reader_public = crypto::GroupAffine::generator() * reader_secret;
    let reader_bytes = reader_public.to_bytes().unwrap();
    let chain_id = vera_client::rings::ring_deployment_label(root.0, deployment);
    let ring_pk_bytes = hex::decode(&ring_pk).unwrap();
    let pre_request = || {
        let (pre_token, token_metadata) = reader
            .create_pre_jwt(reader_bytes.clone(), &stored.object_id, None, None)
            .unwrap();
        let authorization_context = crypto::context::ReaderAuthorizationContext {
            chain_id: chain_id.clone(),
            ring_pk: ring_pk_bytes.clone(),
            jwt_issuer: reader.did_uri.clone(),
            jwt_subject: None,
            resolved_actor: reader.did_uri.clone(),
            jwt_id: token_metadata.jwt_id,
            jwt_issued_time: token_metadata.issued_time,
            jwt_expiration_time: token_metadata.expiration_time,
            jwt_not_before: token_metadata.not_before,
            object_id: stored.object_id.clone(),
            recipient_pk: reader_bytes.clone(),
            derivation: None,
            salt: None,
            valid_window: None,
            audit_target_object_id: None,
        };
        let reader_signature = crypto::PreImpl::sign_reader_authorization(
            &reader_secret,
            &reader_public,
            &authorization_context,
        )
        .unwrap();
        create_authenticated_request(
            StartPreRequest {
                rdr_pk: reader_bytes.clone(),
                object_id: stored.object_id.clone(),
                derivation: None,
                salt: None,
                valid_window: None,
                document: None,
                audit_target_object_id: None,
                rdr_pk_signature: Some(ReaderAuthorizationSignature {
                    challenge: reader_signature.challenge,
                    response: reader_signature.response,
                }),
            },
            &pre_token,
        )
        .unwrap()
    };
    let mut pre = PreServiceClient::connect(endpoint).await.unwrap();
    assert_eq!(
        pre.start_pre(pre_request()).await.unwrap_err().code(),
        tonic::Code::Unauthenticated
    );
    let granted = client
        .native_set_relationship(
            &worker,
            policy_bytes,
            "document",
            &stored.object_id,
            "reader",
            &reader.did_uri,
        )
        .await
        .unwrap();
    confirmed(&client, granted.transaction_hash, &trusted).await;
    let reencrypted = pre.start_pre(pre_request()).await.unwrap().into_inner();
    let response: serde_json::Value =
        serde_json::from_slice(&reencrypted.encrypted_secret).unwrap();
    let point = crypto::GroupAffine::from_bytes(
        &hex::decode(response["xnc_cmt"].as_str().unwrap()).unwrap(),
    )
    .unwrap();
    assert_eq!(
        crypto::PreImpl::decrypt_secret(&public_key, &point, &reader_secret, &secret, &context)
            .unwrap(),
        plaintext
    );
    for reader_relation in [false, true] {
        policy_generations::replace(
            &client,
            &worker,
            &trusted,
            policy_bytes,
            policy_generations::definition(true, reader_relation),
        )
        .await;
        assert_eq!(
            pre.start_pre(pre_request()).await.unwrap_err().code(),
            tonic::Code::Unauthenticated
        );
    }
    let regranted = client
        .native_set_relationship(
            &worker,
            policy_bytes,
            "document",
            &stored.object_id,
            "reader",
            &reader.did_uri,
        )
        .await
        .unwrap();
    confirmed(&client, regranted.transaction_hash, &trusted).await;
    let reencrypted = pre.start_pre(pre_request()).await.unwrap().into_inner();
    let response: serde_json::Value =
        serde_json::from_slice(&reencrypted.encrypted_secret).unwrap();
    let point = crypto::GroupAffine::from_bytes(
        &hex::decode(response["xnc_cmt"].as_str().unwrap()).unwrap(),
    )
    .unwrap();
    assert_eq!(
        crypto::PreImpl::decrypt_secret(&public_key, &point, &reader_secret, &secret, &context)
            .unwrap(),
        plaintext
    );
    let revoked = client
        .native_delete_relationship(
            &worker,
            policy_bytes,
            "document",
            &stored.object_id,
            "reader",
            &reader.did_uri,
        )
        .await
        .unwrap();
    confirmed(&client, revoked.transaction_hash, &trusted).await;
    assert_eq!(
        pre.start_pre(pre_request()).await.unwrap_err().code(),
        tonic::Code::Unauthenticated
    );
    let (mut incoming, addr) = add_orbis_node4(&cluster, base.path());
    let info = incoming
        .ready(&addr, &base.path().join("node-3/node.log"))
        .await;
    assert_eq!(info.managed_ring_count, 0);
    for (command_name, command) in [
        ("set peer", NodeCommand::SetPeer(info.p2p_address.clone())),
        (
            "allow policy",
            NodeCommand::Allow(NodeTarget::Policy(policy.clone())),
        ),
    ] {
        let current = client
            .read_threshold_node(&info.node_key, 1, &trusted)
            .await
            .unwrap()
            .record
            .unwrap();
        let signed = sign_node_request(
            NodeRequest {
                deployment_root: root.0,
                deployment_id: deployment,
                node_key: info.node_key.clone(),
                sequence: current.sequence,
                expires_at: now + 300,
                command,
            },
            &controller,
        )
        .unwrap();
        submit(
            &client,
            &worker,
            &trusted,
            encode_node_request(&signed).unwrap(),
            &format!("authorize incoming node: {command_name}"),
            &cluster,
        )
        .await;
    }
    nodes.push(incoming);
    infos.push(info);
    addresses.push(addr);
    logs.push(log);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let token = create_scoped_bearer_token(
        &controller,
        worker.did(),
        deployment,
        now,
        now + 300,
        DelegationScope::PolicyCommands,
    )
    .unwrap();
    let grant = vera_acp::Relationship::with_entity(
        "ring",
        &derivation.ring_id,
        "operator",
        actor.parse().unwrap(),
    );
    let call = vera_modules::acp::abi::IAcp::bearerPolicyCmdCall {
        bearerToken: token,
        policyId: policy_bytes,
        cmd: serde_json::to_vec(&vera_modules::acp::types::PolicyCmd::SetRelationship(
            grant.clone(),
        ))
        .unwrap()
        .into(),
    }
    .abi_encode();
    let wire = worker
        .sign_native_tx(vera_client::ACP_ADDRESS, call.into())
        .unwrap();
    let id = vera_domain::NativeTx::decode_wire(&wire).unwrap().tx_id().0;
    assert_eq!(client.send_native_tx(&wire).await.unwrap(), id);
    confirmed(&client, id, &trusted).await;
    policy_generations::assert_relationship(&client, policy_bytes, &trusted, &grant).await;
    let previous = client
        .read_threshold_ring(&derivation.ring_id, 1, &trusted)
        .await
        .unwrap()
        .record
        .unwrap();
    let mut target: Vec<_> = infos[1..]
        .iter()
        .map(|info| info.node_key.clone())
        .collect();
    target.sort();
    // Pause the actual next leader so current members must forward before
    // the coordinator can begin the transition.
    let leader = infos
        .iter()
        .position(|info| info.node_key == target[0])
        .unwrap();
    nodes[leader].0.pause().unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let token = create_scoped_bearer_token(
        &controller,
        worker.did(),
        deployment,
        now,
        now + 300,
        DelegationScope::ManageRings,
    )
    .unwrap();
    submit(
        &client,
        &worker,
        &trusted,
        encode_ring_command(
            &RingCommand::Update {
                ring_id: derivation.ring_id.clone(),
                expected_sequence: previous.sequence,
                update: RingUpdate::StartReshare {
                    peer_node_keys: Some(target.clone()),
                    threshold: Some(2),
                },
            },
            &token,
        )
        .unwrap(),
        "start reshare",
        &cluster,
    )
    .await;
    let forwarding = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let mut started = false;
            for (index, node) in nodes.iter().take(nodes.len() - 1).enumerate() {
                node.0.refresh_logs().await.unwrap();
                if tokio::fs::read_to_string(base.path().join(format!("node-{index}/restart.log")))
                    .await
                    .unwrap()
                    .contains("forwarding pending reshare to canonical next-committee leader")
                {
                    started = true;
                    break;
                }
            }
            if started {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    if forwarding.is_err() {
        let logs = base.keep();
        panic!("current members did not forward reshare to paused leader; logs: {logs:?}");
    }
    let pending = client
        .read_threshold_ring(
            &derivation.ring_id,
            previous.revision.block_height,
            &trusted,
        )
        .await
        .unwrap()
        .record
        .unwrap();
    assert!(pending.current_settings().pending_reshare.is_some());
    for node in &mut nodes {
        assert!(node.0.try_wait().unwrap().is_none());
        node.0.kill().unwrap();
        assert!(!node.0.wait().unwrap().success());
    }
    for index in 0..nodes.len() {
        let log = base
            .path()
            .join(format!("node-{index}/reshare-restart.log"));
        nodes[index] = Node::restart(cluster.project_name(), index, &log);
        let recovered = nodes[index].ready(&addresses[index], &log).await;
        assert_eq!(recovered.node_key, infos[index].node_key);
    }
    tokio::time::timeout(Duration::from_secs(75), async {
        loop {
            let current = client
                .read_threshold_ring(
                    &derivation.ring_id,
                    previous.revision.block_height,
                    &trusted,
                )
                .await
                .unwrap()
                .record
                .unwrap();
            let settings = current.current_settings();
            assert_eq!(
                current.state,
                RingState::Active {
                    keys: RingPublicKeys {
                        public_key: ring_pk.clone(),
                        pet_public_key: None
                    }
                }
            );
            if settings.peer_node_keys == target && settings.pending_reshare.is_none() {
                assert_eq!(current.sequence, previous.sequence + 2);
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        let mut output = String::new();
        for index in 0..nodes.len() {
            for name in ["node.log", "restart.log", "reshare-restart.log"] {
                if let Ok(log) =
                    fs::read_to_string(base.path().join(format!("node-{index}/{name}")))
                {
                    output.push_str(&log.lines().rev().take(25).collect::<Vec<_>>().join("\n"));
                }
            }
        }
        panic!("reshare did not finalize: {output}")
    });
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let mut refreshed = Vec::new();
            for addr in &addresses[1..] {
                let mut client = InfoServiceClient::connect(format!("http://{addr}"))
                    .await
                    .unwrap();
                if let Ok(response) = client
                    .get_ring_state(GetRingStateRequest {
                        ring_pk_hex: ring_pk.clone(),
                    })
                    .await
                {
                    refreshed.push(response.into_inner().public_polynomial);
                }
            }
            if refreshed.len() == 3
                && refreshed[0] != polynomials[0]
                && refreshed.iter().all(|poly| poly == &refreshed[0])
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .unwrap();
    assert!(client
        .read_threshold_node_demerits(&derivation.ring_id, &infos[1].node_key, 1, &trusted)
        .await
        .unwrap()
        .record
        .is_none());
    nodes[0].stop().await;
    nodes[1].stop().await;
    let endpoint = tonic::transport::Endpoint::from_shared(format!("http://{}", addresses[3]))
        .unwrap()
        .timeout(Duration::from_secs(30));
    let mut signing = SignServiceClient::connect(endpoint).await.unwrap();
    assert_eq!(
        signing.start_sign(sign_request()).await.unwrap_err().code(),
        tonic::Code::Unauthenticated
    );
    assert_eq!(
        pre.start_pre(pre_request()).await.unwrap_err().code(),
        tonic::Code::Unauthenticated
    );
    for (resource, object, relation) in [
        ("key", derivation_id.as_str(), "signer"),
        ("document", stored.object_id.as_str(), "reader"),
    ] {
        let grant = client
            .native_set_relationship(
                &worker,
                policy_bytes,
                resource,
                object,
                relation,
                &reader.did_uri,
            )
            .await
            .unwrap();
        confirmed(&client, grant.transaction_hash, &trusted).await;
    }
    let signed = signing
        .start_sign(sign_request())
        .await
        .unwrap()
        .into_inner();
    let signature =
        crypto::SignaturePoint::from_bytes(&hex::decode(signed.signature).unwrap()).unwrap();
    crypto::SignImpl::new()
        .verify(&derived_key, &message, &signature)
        .unwrap();
    let reencrypted = pre.start_pre(pre_request()).await.unwrap().into_inner();
    let response: serde_json::Value =
        serde_json::from_slice(&reencrypted.encrypted_secret).unwrap();
    let point = crypto::GroupAffine::from_bytes(
        &hex::decode(response["xnc_cmt"].as_str().unwrap()).unwrap(),
    )
    .unwrap();
    assert_eq!(
        crypto::PreImpl::decrypt_secret(&public_key, &point, &reader_secret, &secret, &context)
            .unwrap(),
        plaintext
    );
    tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            match client
                .read_threshold_node_demerits(&derivation.ring_id, &infos[1].node_key, 1, &trusted)
                .await
            {
                Ok(score) => {
                    if let Some(score) = score.record {
                        assert!(score.points > 0);
                        break;
                    }
                }
                Err(error) if error.is_throttled() => {
                    eprintln!("waiting for certified offline report: {error}");
                }
                Err(error) => panic!("offline report evidence failed: {error}"),
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        let mut output = String::new();
        for index in 2..nodes.len() {
            for name in ["node.log", "restart.log", "reshare-restart.log"] {
                if let Ok(log) =
                    fs::read_to_string(base.path().join(format!("node-{index}/{name}")))
                {
                    output.push_str(&log.lines().rev().take(40).collect::<Vec<_>>().join("\n"));
                }
            }
        }
        panic!("offline report did not reach certified state: {output}")
    });
    for info in &infos[2..] {
        assert!(client
            .read_threshold_node_demerits(&derivation.ring_id, &info.node_key, 1, &trusted)
            .await
            .unwrap()
            .record
            .is_none());
    }
    for node in &mut nodes {
        node.stop().await;
    }
}
