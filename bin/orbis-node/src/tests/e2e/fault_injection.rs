//! Fault-injection integration tests: byte-level/directional protocol faults
//! (lost Gossip probes, stalled private responses, corrupted control
//! messages) that only an in-process `FaultNetwork` can express — Docker-
//! Compose's `stop_node`/`UnsafeTestingService` have no equivalent for
//! "stall exactly the Nth message on protocol X" or "block only my outbound
//! view of peer Y." The plain node-dropout/below-threshold tests live in
//! `e2e/fault_*.rs`.
//!
//! The chain is a native Vera cluster of `verad` processes
//! (`vera_harness::cluster::TestCluster`); the three Orbis nodes run in this
//! process on the native authorization and bulletin backends. Requires
//! `fault-injection`, `integration-test` and `vera`, and a built `verad`:
//!   VERAD_BINARY=/path/to/verad cargo test -p orbis-node --no-default-features \
//!     --features integration-test,vera,test-support/vera,redb,iroh,bls12-381,fault-injection \
//!     --lib fault_injection -- --ignored --test-threads=1

use super::vera_confirmation::confirmed;
use crate::dkg::v0::service::DkgServiceImpl;
use crate::info::InfoServiceImpl;
use crate::pre::v0::service::PreServiceImpl;
use crate::sign::v0::service::SignServiceImpl;
use crate::store_secret::StoreSecretServiceImpl;
use crate::{
    constants::{
        GRPC_CONCURRENCY_LIMIT_PER_CONNECTION, GRPC_MAX_CONCURRENT_STREAMS, MAX_PRE_REQUEST_BYTES,
        MAX_SIGN_REQUEST_BYTES, MAX_SMALL_GRPC_REQUEST_BYTES, MAX_STORE_SECRET_REQUEST_BYTES,
        PEER_RESPONSE_TIMEOUT,
    },
    dkg::v0::transport::{self, DkgControlMessage, DkgPrivateMessage},
    helpers::{
        launch::{CorsPolicy, LogLevel},
        test_helpers::{cleanup_db, test_db_path, wait_for_nodes_ready},
    },
    init_node, Args, NetworkIngressArgs, NodeConfig,
};
use alloy_primitives::{Bytes, B256};
use async_trait::async_trait;
use authz::r#trait::Authz;
use authz::vera::VeraAuth;
use bulletin::r#trait::{
    Bulletin, BulletinKind, BulletinPost, BulletinReportSubmission, BulletinWriteKind, NodeInfo,
    RingFinalizationStatus,
};
use bulletin::vera::{startup::initialize_identity, VeraBulletin, VeraClient as WorkerClient};
use crypto::{DkgImpl, PreImpl, SignImpl};
use local_storage::{r#trait::LocalStorage, LocalStorageImpl};
use network::{FaultNetwork, FaultNetworkController, Network, NetworkImpl};
use proto::{
    info_service::info_service_server::InfoServiceServer,
    v0::dkg::dkg_service_server::DkgServiceServer, v0::pre::pre_service_server::PreServiceServer,
    v0::sign::sign_service_server::SignServiceServer,
    v0::store_secret::store_secret_service_server::StoreSecretServiceServer,
};
use std::sync::{Arc, Mutex};
use tokio::time::Duration;
use vera_client::{
    create_scoped_bearer_token, predict_policy_id, random_policy_nonce,
    rings::{encode_ring_command, ReportingConfig, RingCommand, RingConfig, RingState, RingUpdate},
    BlsSigner, DelegationScope, PolicyMarshalingType, VeraClient,
};
use vera_domain::{ConsensusPublicKey, NativeTx};
use vera_harness::cluster::{ConsensusPreset, KeySet, TestCluster};

const MAX_TEST_CONTROL_MESSAGE_BYTES: usize = 2 * 1024 * 1024;
const RING_POLICY_YAML: &str = r#"
name: fault-injection-ring-policy
resources:
  - name: ring_policy
    relations:
      - name: creator
    permissions:
      - name: create_ring
        expr: creator
  - name: ring
    relations:
      - name: operator
    permissions:
      - name: update_ring
        expr: operator
"#;

// =========================================================================
// Test infrastructure
// =========================================================================

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock after the Unix epoch")
        .as_secs()
}

/// A four-validator native Vera cluster plus the administrative identities
/// the tests use to create policies and rings and to announce reshares.
struct NativeChain {
    cluster: TestCluster,
    deployment: u64,
    client: VeraClient,
    trusted: ConsensusPublicKey,
    root: B256,
    /// Ring administrator: the ACP `creator` of the ring policy and the
    /// issuer of the scoped ring-management delegations.
    controller: k256::ecdsa::SigningKey,
    actor: String,
    /// Worker that submits the administrator's requests.
    worker: BlsSigner,
}

impl NativeChain {
    async fn start(deployment: u64) -> Self {
        let trusted = *KeySet::builder()
            .seed(deployment)
            .build()
            .expect("validator key set")
            .epoch_info()
            .output
            .public()
            .public();
        let cluster = TestCluster::builder()
            .nodes(4)
            .seed(deployment)
            .chain_id(deployment)
            .preset(ConsensusPreset::Normal)
            .build()
            .await
            .expect("start native Vera cluster");
        cluster
            .wait_ready(Duration::from_secs(30))
            .await
            .expect("native Vera cluster ready");
        cluster
            .observe(Duration::from_millis(100))
            .wait_for_height(3, Duration::from_secs(30))
            .await
            .expect("native Vera cluster finalizes blocks");
        let client = VeraClient::new(cluster.node(0).rpc_url());
        let first = client
            .read_finalized_revision(1, &trusted)
            .await
            .expect("read the first finalized revision");
        let root: B256 = first.parent_hash.parse().expect("deployment root");
        let controller = k256::ecdsa::SigningKey::from_slice(&[34; 32]).expect("controller key");
        let actor = vera_crypto::secp256k1::did_from_secp256k1_pubkey(
            controller.verifying_key().to_sec1_bytes().as_ref(),
        )
        .expect("controller DID");
        let worker = BlsSigner::new(7u64.into(), deployment).expect("administrator worker");
        Self {
            cluster,
            deployment,
            client,
            trusted,
            root,
            controller,
            actor,
            worker,
        }
    }

    fn rpc_url(&self, index: usize) -> String {
        self.cluster.node(index).rpc_url()
    }

    async fn submit(&self, call: Bytes) {
        let wire = self
            .worker
            .sign_native_tx(vera_client::VERA_ADDRESS, call)
            .expect("sign administrator request");
        let id = NativeTx::decode_wire(&wire)
            .expect("decode administrator request")
            .tx_id()
            .0;
        assert_eq!(
            self.client
                .send_native_tx(&wire)
                .await
                .expect("submit administrator request"),
            id
        );
        confirmed(&self.client, id, &self.trusted).await;
    }

    fn ring_token(&self) -> String {
        let now = unix_now();
        create_scoped_bearer_token(
            &self.controller,
            self.worker.did(),
            self.deployment,
            now,
            now + 300,
            DelegationScope::ManageRings,
        )
        .expect("ring-management delegation")
    }

    /// Create the ring policy, register it as a `ring_policy` object and
    /// make the administrator its `creator`.
    async fn create_ring_policy(&self) -> String {
        let nonce = random_policy_nonce();
        let policy_id = predict_policy_id(
            RING_POLICY_YAML,
            &PolicyMarshalingType::ShortYaml,
            &nonce,
            self.worker.did(),
        )
        .expect("predict ring policy id");
        let created = self
            .client
            .native_create_policy(&self.worker, RING_POLICY_YAML.as_bytes(), 1, nonce)
            .await
            .expect("create ring policy");
        confirmed(&self.client, created.transaction_hash, &self.trusted).await;
        assert!(
            self.client
                .get_policy_ids()
                .await
                .expect("list policies")
                .contains(&policy_id),
            "created ring policy must match its prediction"
        );
        let policy_bytes = B256::from_slice(&hex::decode(&policy_id).expect("policy id is hex"));
        let registered = self
            .client
            .native_register_object(&self.worker, policy_bytes, &policy_id, "ring_policy")
            .await
            .expect("register ring policy object");
        confirmed(&self.client, registered.transaction_hash, &self.trusted).await;
        let granted = self
            .client
            .native_set_relationship(
                &self.worker,
                policy_bytes,
                "ring_policy",
                &policy_id,
                "creator",
                &self.actor,
            )
            .await
            .expect("grant ring creation");
        confirmed(&self.client, granted.transaction_hash, &self.trusted).await;
        policy_id
    }

    async fn create_ring(&self, node_keys: &[String], threshold: u32, policy_id: &str) -> String {
        let mut members = node_keys.to_vec();
        members.sort();
        let config = RingConfig {
            policy_id: policy_id.to_string(),
            peer_node_keys: members,
            threshold,
            pss_interval: 86_400,
            current_version: 0,
            requires_pet: false,
            nonce: [2; 32],
            trusted_auth_relay_dids: None,
            reporting: ReportingConfig::default(),
            pre_share_endpoints: Vec::new(),
        };
        let ring_id = config.id().expect("ring id");
        self.submit(
            encode_ring_command(&RingCommand::Create(config), &self.ring_token())
                .expect("encode ring creation"),
        )
        .await;
        ring_id
    }

    /// Wait for the ring to become active and return its public key.
    async fn wait_for_ring_finalized(&self, ring_id: &str, timeout: Duration) -> String {
        tokio::time::timeout(timeout, async {
            loop {
                match self
                    .client
                    .read_threshold_ring(ring_id, 1, &self.trusted)
                    .await
                {
                    Ok(response) => {
                        if let Some(RingState::Active { keys }) =
                            response.record.map(|record| record.state)
                        {
                            return keys.public_key;
                        }
                    }
                    Err(error) if error.is_throttled() => {}
                    Err(error) => panic!("certified ring read failed: {error}"),
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("Timed out waiting for ring {ring_id} to be finalized"))
    }

    /// Announce a reshare to `members` at `threshold`.
    async fn start_reshare(&self, ring_id: &str, members: &[String], threshold: u32) {
        let mut members = members.to_vec();
        members.sort();
        let record = self
            .client
            .read_threshold_ring(ring_id, 1, &self.trusted)
            .await
            .expect("read ring before reshare")
            .record
            .expect("ring must exist");
        self.submit(
            encode_ring_command(
                &RingCommand::Update {
                    ring_id: ring_id.to_string(),
                    expected_sequence: record.sequence,
                    update: RingUpdate::StartReshare {
                        peer_node_keys: Some(members),
                        threshold: Some(threshold),
                    },
                },
                &self.ring_token(),
            )
            .expect("encode reshare announcement"),
        )
        .await;
    }

    /// Certified demerits of `node_key` in `ring_id`, waiting up to 15
    /// seconds for the record to reach the queried validator.
    async fn node_demerits(&self, ring_id: &str, node_key: &str) -> u64 {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
        loop {
            let points = self
                .client
                .read_threshold_node_demerits(ring_id, node_key, 1, &self.trusted)
                .await
                .expect("read node demerits")
                .record
                .map(|demerits| demerits.points)
                .unwrap_or(0);
            if points > 0 || tokio::time::Instant::now() >= deadline {
                return points;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }
}

/// Fault reports the chain accepted: the native backend's `submit_report`
/// returns only after a certified successful receipt, so a submission is
/// recorded here only once Vera has accepted it.
#[derive(Clone, Default)]
struct AcceptedReports(Arc<Mutex<Vec<BulletinReportSubmission>>>);

impl AcceptedReports {
    async fn wait_for_matching(
        &self,
        ring_id: &str,
        timeout: Duration,
        matches: impl Fn(&BulletinReportSubmission) -> bool,
    ) -> Option<BulletinReportSubmission> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let found = self
                .0
                .lock()
                .expect("accepted report log")
                .iter()
                .find(|report| report.ring_id == ring_id && matches(report))
                .cloned();
            if found.is_some() {
                return found;
            }
            if tokio::time::Instant::now() >= deadline {
                return None;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }
}

/// The node's native bulletin, recording every report the chain accepted.
struct RecordingBulletin {
    inner: Arc<dyn Bulletin + Send + Sync>,
    accepted: AcceptedReports,
}

#[async_trait]
impl Bulletin for RecordingBulletin {
    async fn post(
        &self,
        kind: BulletinWriteKind,
        payload: Vec<u8>,
    ) -> bulletin::error::Result<String> {
        self.inner.post(kind, payload).await
    }

    async fn update(
        &self,
        id: String,
        signature_scheme: String,
        signature: Vec<u8>,
    ) -> bulletin::error::Result<()> {
        self.inner.update(id, signature_scheme, signature).await
    }

    async fn read(&self, id: String, kind: BulletinKind) -> bulletin::error::Result<BulletinPost> {
        self.inner.read(id, kind).await
    }

    async fn ring_finalization_status(
        &self,
        id: String,
    ) -> bulletin::error::Result<RingFinalizationStatus> {
        self.inner.ring_finalization_status(id).await
    }

    async fn submit_report(
        &self,
        submission: BulletinReportSubmission,
    ) -> bulletin::error::Result<()> {
        self.inner.submit_report(submission.clone()).await?;
        self.accepted
            .0
            .lock()
            .expect("accepted report log")
            .push(submission);
        Ok(())
    }

    async fn accepted_report_session(
        &self,
        ring_id: &str,
        report_type: &str,
        origin_protocol: &str,
        accused_node_key: &str,
        session_id: &str,
    ) -> bulletin::error::Result<bool> {
        self.inner
            .accepted_report_session(
                ring_id,
                report_type,
                origin_protocol,
                accused_node_key,
                session_id,
            )
            .await
    }

    fn chain_id(&self) -> String {
        self.inner.chain_id()
    }

    fn ring_reshare_finalize_sign_bytes(
        &self,
        chain_id: &str,
        ring_id: &str,
        ring_pk: &str,
        current_ring_sha256: Vec<u8>,
        finalized_ring_sha256: Vec<u8>,
        block_number_nonce: u64,
    ) -> bulletin::error::Result<Vec<u8>> {
        self.inner.ring_reshare_finalize_sign_bytes(
            chain_id,
            ring_id,
            ring_pk,
            current_ring_sha256,
            finalized_ring_sha256,
            block_number_nonce,
        )
    }
}

/// A running in-process orbis node backed by a FaultNetwork.
struct FaultableNodeHandle {
    grpc_endpoint: String,
    _peer_addr: String,
    db_path: String,
    task: tokio::task::JoinHandle<()>,
    /// Fault controller for this node's outbound connections.
    fault_ctrl: FaultNetworkController,
    /// `None` when `reshare_interval_secs` is 0. Dropping this (implicitly, with the rest of
    /// the handle) closes its internal shutdown channel, which is what actually stops the
    /// scheduler's background task — see the comment where it's spawned for why this needs to
    /// be spawned here at all rather than coming for free from `init_node`.
    _pss_scheduler: Option<crate::pss::v0::PssSchedulerHandle>,
    _identity: tempfile::TempDir,
}

impl Drop for FaultableNodeHandle {
    fn drop(&mut self) {
        self.task.abort();
        cleanup_db(&self.db_path);
    }
}

/// Three in-process orbis nodes where each node's outbound connections can be
/// blocked via its `FaultNetworkController`.
struct FaultableThreeNodeNetwork {
    alice: FaultableNodeHandle,
    bob: FaultableNodeHandle,
    charlie: FaultableNodeHandle,
    /// ACP policy ID all three nodes are whitelisted for.
    policy_id: String,
    /// Compressed pubkeys of alice, bob, charlie (in that order).
    node_keys: Vec<String>,
    /// Reports any of the three nodes got accepted on chain.
    reports: AcceptedReports,
    /// Declared last: the nodes stop before the validators do.
    chain: NativeChain,
}

/// Build and spawn a gRPC server from an `InitializedNode`.
fn spawn_test_grpc_server(node: crate::InitializedNode) -> tokio::task::JoinHandle<()> {
    let dkg_service = DkgServiceImpl::<DkgImpl>::with_routes(node.app_state.clone(), &network::V0);
    let pre_service =
        PreServiceImpl::<DkgImpl, PreImpl>::with_routes(node.app_state.clone(), &network::V0);
    let info_service =
        InfoServiceImpl::<DkgImpl>::new((*node.app_state).clone(), node.identity.clone());
    let store_secret_service = StoreSecretServiceImpl::<DkgImpl, SignImpl>::with_routes(
        node.app_state.clone(),
        &network::V0,
    );
    let sign_service =
        SignServiceImpl::<DkgImpl, SignImpl>::with_routes(node.app_state.clone(), &network::V0);

    tokio::spawn(async move {
        let _ = tonic::transport::Server::builder()
            .add_service(
                DkgServiceServer::new(dkg_service)
                    .max_decoding_message_size(MAX_SMALL_GRPC_REQUEST_BYTES),
            )
            .add_service(
                PreServiceServer::new(pre_service).max_decoding_message_size(MAX_PRE_REQUEST_BYTES),
            )
            .add_service(
                InfoServiceServer::new(info_service)
                    .max_decoding_message_size(MAX_SMALL_GRPC_REQUEST_BYTES),
            )
            .add_service(
                StoreSecretServiceServer::new(store_secret_service)
                    .max_decoding_message_size(MAX_STORE_SECRET_REQUEST_BYTES),
            )
            .add_service(
                SignServiceServer::new(sign_service)
                    .max_decoding_message_size(MAX_SIGN_REQUEST_BYTES),
            )
            .serve(node.grpc_addr)
            .await;
        let _ = node.router.shutdown().await;
    })
}

/// Start a native Vera cluster and three in-process orbis nodes, each wrapped
/// with a `FaultNetwork` for test-time network partition simulation.
async fn setup_fault_three_node_network(
    db_prefix: &str,
    base_port: u16,
    deployment: u64,
) -> FaultableThreeNodeNetwork {
    setup_fault_three_node_network_with_reshare_interval(db_prefix, base_port, deployment, 0).await
}

/// Same as [`setup_fault_three_node_network`], but lets the caller enable the
/// background PSS scheduler (`reshare_interval_secs = 0` disables it
/// entirely — see `pss::spawn_pss_scheduler`'s own doc comment). Needed by
/// any test that expects a pending on-chain reshare/refresh to be picked up
/// and driven automatically, the way a real node would, rather than relying
/// on an explicit client-triggered ceremony like `do_dkg`.
async fn setup_fault_three_node_network_with_reshare_interval(
    db_prefix: &str,
    base_port: u16,
    deployment: u64,
    reshare_interval_secs: u64,
) -> FaultableThreeNodeNetwork {
    // Node logs follow `RUST_LOG`; silent without it.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_test_writer()
        .try_init();
    let chain = NativeChain::start(deployment).await;
    let policy_id = chain.create_ring_policy().await;
    let reports = AcceptedReports::default();

    let mut handles: Vec<FaultableNodeHandle> = Vec::new();
    let mut node_keys: Vec<String> = Vec::new();

    for i in 0..3u16 {
        let port = base_port + i;
        let db_path = test_db_path(&format!("{}_{}", db_prefix, i));
        cleanup_db(&db_path);

        let local_storage = LocalStorageImpl::new("test-password".to_string(), db_path.clone())
            .expect("local storage");
        let identity_dir = tempfile::tempdir().expect("identity directory");
        let identity = initialize_identity(&local_storage, identity_dir.path(), None)
            .expect("create node signing key");
        let node_key = identity.node_key.clone();

        // Each node writes through its own validator and reads through
        // another, as a deployment spreads load across replicas.
        let writer = WorkerClient::open(
            VeraClient::new(chain.rpc_url(usize::from(i))),
            chain.trusted,
            chain.root.0,
            deployment,
            &identity_dir.path().join("vera"),
            &local_storage,
        )
        .expect("open node worker");
        let inner: Arc<dyn Bulletin + Send + Sync> = Arc::new(
            VeraBulletin::connect(
                writer,
                VeraClient::new(chain.rpc_url(usize::from(i) + 1)),
                30,
                Duration::from_secs(60),
            )
            .await
            .expect("connect native bulletin"),
        );
        let bulletin: Arc<dyn Bulletin + Send + Sync> = Arc::new(RecordingBulletin {
            inner,
            accepted: reports.clone(),
        });

        let authz: Arc<dyn Authz> = Arc::new(
            VeraAuth::connect(
                VeraClient::new(chain.rpc_url(usize::from(i) + 1)),
                chain.trusted,
                chain.root.0,
                30,
            )
            .await
            .expect("connect native authorization"),
        );

        // Create the real iroh network first to extract peer info
        let real_net = NetworkImpl::new().await.expect("NetworkImpl");

        // Extract peer addressing info before wrapping (local_address = 64-char hex node ID)
        let peer_hex = real_net.local_address().expect("network local_address");
        let p2p_socket = real_net
            .bound_addresses()
            .first()
            .copied()
            .map(|a| a.to_string())
            .unwrap_or_else(|| "127.0.0.1:0".to_string());
        let peer_addr = format!("{}@{}", peer_hex, p2p_socket);

        // Register NodeInfo on-chain so the DKG service can look up this node's peer_id.
        let node_info_bytes: Vec<u8> = NodeInfo {
            peer_id: peer_addr.clone(),
            controller_key: node_key.clone(),
            whitelisted_policy_ids: vec![policy_id.clone()],
            whitelisted_ring_ids: vec![],
        }
        .try_into()
        .expect("serialize NodeInfo");
        assert_eq!(
            bulletin
                .post(BulletinWriteKind::NodeInfo, node_info_bytes)
                .await
                .expect("register NodeInfo on-chain"),
            node_key,
            "node info must be registered under the node's own key"
        );

        node_keys.push(node_key.clone());

        // Wrap with FaultNetwork to enable test-time connection blocking
        let (fault_net, fault_ctrl) = FaultNetwork::new(Arc::new(real_net));
        let network: Arc<dyn Network> = Arc::new(fault_net);

        let grpc_bind = format!("127.0.0.1:{}", port);
        let config = NodeConfig {
            args: Args {
                services_config: None,
                addr: grpc_bind.clone(),
                cors_allow_origins: vec![],
                cors_permissive: false,
                log_level: LogLevel::Info,
                metrics_addr: None,
                loki_url: None,
                runtime_base_path: None,
                reshare_interval_secs,
                network_private_routes_only: false,
                network_bind_addr: None,
                node_controller_key: node_key.clone(),
                node_peer_id: None,
                node_whitelisted_policy_ids: vec![policy_id.clone()],
                node_whitelisted_ring_ids: vec![],
                grpc_concurrency_limit_per_connection: GRPC_CONCURRENCY_LIMIT_PER_CONNECTION,
                grpc_max_concurrent_streams: GRPC_MAX_CONCURRENT_STREAMS,
                network_ingress: NetworkIngressArgs::default(),
            },
            cors_policy: CorsPolicy::Disabled,
            identity,
            backend_names: ("injected".into(), "injected".into()),
            network,
            local_storage,
            authz,
            bulletin,
            authorized_peers: None,
        };

        let node = init_node(config).await.expect("init_node");
        // `init_node` alone never starts this — the production binary only spawns it from
        // `run_server` (`runtime.rs`), which this harness deliberately doesn't call (it builds
        // its own minimal tonic server in `spawn_test_grpc_server` instead of the full
        // production server loop). Must spawn it here, before `node` moves into
        // `spawn_test_grpc_server`, for any test that needs a pending on-chain reshare/refresh
        // to be picked up and driven automatically.
        let pss_scheduler =
            crate::pss::spawn_pss_scheduler(node.app_state.clone(), node.reshare_interval);
        let task = spawn_test_grpc_server(node);

        handles.push(FaultableNodeHandle {
            grpc_endpoint: format!("http://{}", grpc_bind),
            _peer_addr: peer_addr,
            db_path,
            task,
            fault_ctrl,
            _pss_scheduler: pss_scheduler,
            _identity: identity_dir,
        });
    }

    let endpoints: Vec<&str> = handles.iter().map(|h| h.grpc_endpoint.as_str()).collect();
    wait_for_nodes_ready(&endpoints, 30, Duration::from_millis(200)).await;

    let mut it = handles.into_iter();
    FaultableThreeNodeNetwork {
        alice: it.next().unwrap(),
        bob: it.next().unwrap(),
        charlie: it.next().unwrap(),
        policy_id,
        node_keys,
        reports,
        chain,
    }
}

/// Create a ring on-chain, run DKG, and return `(ring_pk_hex, ring_id)` once
/// all participant nodes have called FinalizeRing and the chain confirms.
async fn setup_ring(
    chain: &NativeChain,
    endpoint: &str,
    node_keys: &[String],
    threshold: u32,
    policy_id: &str,
) -> (String, String) {
    let ring_id = chain.create_ring(node_keys, threshold, policy_id).await;

    cli_tool::do_dkg(endpoint.to_string(), ring_id.clone())
        .await
        .expect("DKG initiation");

    let ring_pk = chain
        .wait_for_ring_finalized(&ring_id, Duration::from_secs(90))
        .await;
    (ring_pk, ring_id)
}

// =========================================================================
// Tests
// =========================================================================

/// Fresh DKG retransmits a silently lost topology probe and does not turn
/// transient Gossip neighbor changes into a rejoin cascade.
#[tokio::test]
#[ignore = "requires a built verad supplied through VERAD_BINARY"]
#[serial_test::serial]
async fn test_dkg_recovers_lost_topology_probe_and_neighbor_flaps() {
    let net = setup_fault_three_node_network("fault_dkg_topology_recovery", 51057, 9081).await;

    let leader_node_key = net.node_keys.iter().min().expect("committee").clone();

    for controller in [
        &net.alice.fault_ctrl,
        &net.bob.fault_ctrl,
        &net.charlie.fault_ctrl,
    ] {
        controller.drop_gossip_broadcasts_after(0, 1).await;
        controller.inject_gossip_neighbor_flaps(2).await;
        controller
            .fail_protocol_responses_after(network::V0.dkg_control_alpn, 0, 1)
            .await;
    }

    let initiator = [
        (&net.node_keys[0], &net.alice.grpc_endpoint),
        (&net.node_keys[1], &net.bob.grpc_endpoint),
        (&net.node_keys[2], &net.charlie.grpc_endpoint),
    ]
    .into_iter()
    .min_by(|left, right| left.0.cmp(right.0))
    .expect("committee")
    .1
    .clone();

    let (ring_pk, ring_id) =
        setup_ring(&net.chain, &initiator, &net.node_keys, 2, &net.policy_id).await;

    assert!(!ring_pk.is_empty(), "retransmitted-probe DKG must finalize");
    assert!(
        !ring_id.is_empty(),
        "retransmitted-probe DKG keeps its ring ID"
    );

    for (node_key, controller) in [
        (&net.node_keys[0], &net.alice.fault_ctrl),
        (&net.node_keys[1], &net.bob.fault_ctrl),
        (&net.node_keys[2], &net.charlie.fault_ctrl),
    ] {
        if node_key == &leader_node_key {
            continue;
        }
        let acknowledgements = controller
            .sent_protocol_messages(network::V0.dkg_control_alpn)
            .await
            .into_iter()
            .filter(|bytes| {
                matches!(
                    transport::decode::<DkgControlMessage>(bytes, MAX_TEST_CONTROL_MESSAGE_BYTES,),
                    Ok(DkgControlMessage::TopologyProbeAck { .. })
                )
            })
            .collect::<Vec<_>>();
        assert!(
            acknowledgements.len() >= 2,
            "lost acknowledgement response must cause a retransmission"
        );
        assert!(
            acknowledgements.windows(2).all(|pair| pair[0] == pair[1]),
            "topology acknowledgement retries must be byte-identical"
        );
    }
}

/// A nonleader API node must preserve the leader's concrete preparation error
/// instead of hiding it behind the forwarded StartFresh response timeout.
#[tokio::test]
#[ignore = "requires a built verad supplied through VERAD_BINARY"]
#[serial_test::serial]
async fn test_nonleader_dkg_start_returns_leader_preparation_error() {
    let net = setup_fault_three_node_network("fault_dkg_forwarded_error", 51075, 9082).await;
    let leader_index = net
        .node_keys
        .iter()
        .enumerate()
        .min_by(|left, right| left.1.cmp(right.1))
        .expect("committee")
        .0;
    let controllers = [
        &net.alice.fault_ctrl,
        &net.bob.fault_ctrl,
        &net.charlie.fault_ctrl,
    ];
    controllers[leader_index]
        .corrupt_protocol_responses_after(network::V0.dkg_control_alpn, 0, 1)
        .await;

    let endpoints = [
        &net.alice.grpc_endpoint,
        &net.bob.grpc_endpoint,
        &net.charlie.grpc_endpoint,
    ];
    let initiator_index = (0..endpoints.len())
        .find(|index| *index != leader_index)
        .expect("nonleader API node");
    let ring_id = net
        .chain
        .create_ring(&net.node_keys, 2, &net.policy_id)
        .await;
    let error = cli_tool::do_dkg(endpoints[initiator_index].clone(), ring_id)
        .await
        .expect_err("malformed Prepared response must fail the attempt");
    let error = format!("{error:#}");

    assert!(
        error.contains("Deserialization error"),
        "forwarded caller must receive the leader's preparation error: {error}"
    );
    assert!(
        !error.contains("control start-fresh response timed out"),
        "leader error must arrive before the forwarded response margin: {error}"
    );
}

/// Fresh DKG completes after public Gossip loss and retryable private QUIC
/// stream failures.
///
/// Every subscriber accepts the first public delivery (the topology probe),
/// then loses the next four public deliveries. The fault wrapper reports those
/// losses as subscriber lag so the production rejoin/direct-repair path runs.
/// The first private pair stream opened by every possible deterministic opener
/// fails, and the next response silently stalls beyond the peer timeout. This
/// proves both failure modes retry without regenerating share bytes.
#[tokio::test]
#[ignore = "requires a built verad supplied through VERAD_BINARY"]
#[serial_test::serial]
async fn test_dkg_repairs_gossip_loss_and_private_disconnects() {
    let net = setup_fault_three_node_network("fault_dkg_transport_repair", 51058, 9083).await;

    for controller in [
        &net.alice.fault_ctrl,
        &net.bob.fault_ctrl,
        &net.charlie.fault_ctrl,
    ] {
        controller.drop_gossip_deliveries_after(1, 4).await;
        controller
            .fail_protocol_streams_after(network::V0.dkg_private_alpn, 0, 1)
            .await;
        controller
            .stall_protocol_responses_after(
                network::V0.dkg_private_alpn,
                0,
                1,
                PEER_RESPONSE_TIMEOUT + Duration::from_secs(1),
            )
            .await;
    }

    let (ring_pk, ring_id) = setup_ring(
        &net.chain,
        &net.alice.grpc_endpoint,
        &net.node_keys,
        2,
        &net.policy_id,
    )
    .await;

    assert!(
        !ring_pk.is_empty(),
        "repaired DKG must finalize a public key"
    );
    assert!(
        !ring_id.is_empty(),
        "repaired DKG must preserve its ring ID"
    );

    let mut saw_identical_retransmission = false;
    for controller in [
        &net.alice.fault_ctrl,
        &net.bob.fault_ctrl,
        &net.charlie.fault_ctrl,
    ] {
        let mut deliveries = std::collections::HashMap::<_, Vec<_>>::new();
        for bytes in controller
            .sent_protocol_messages(network::V0.dkg_private_alpn)
            .await
        {
            if let Ok(DkgPrivateMessage::ShareDelivery { message_id, .. }) =
                transport::decode(&bytes, MAX_TEST_CONTROL_MESSAGE_BYTES)
            {
                deliveries.entry(message_id).or_default().push(bytes);
            }
        }
        saw_identical_retransmission |= deliveries.values().any(|attempts| {
            attempts.len() >= 2 && attempts.windows(2).all(|pair| pair[0] == pair[1])
        });
    }
    assert!(
        saw_identical_retransmission,
        "a silently stalled private response must retransmit the exact cached share"
    );
}

/// A private DKG-share pair partner that silently stalls every response (never
/// hangs up, never replies) is reported `node_offline` once the ceremony's
/// hard attempt deadline passes — distinct from `test_dkg_repairs_gossip_loss_
/// and_private_disconnects` above, which stalls exactly one response and
/// proves the retry path recovers. Here every response stalls for the whole
/// ceremony, so retries never succeed and the sender's terminal-offline check
/// (`open_private_pair` in `network.rs`) fires at the deadline.
///
/// Fault injection here only wraps a node's own *outbound* connections, not
/// its inbound/server side, and is scoped by protocol, not by peer — so it
/// can't target "peer X's responses to peer Y" directly. Instead this stalls
/// the canonical-middle node's outbound view: in a 3-node ring the two lower
/// node IDs each open exactly one private pair with a higher ID, and the
/// middle ID opens a stream only to the highest ID (it's a pure responder for
/// the lowest ID's pair) — so stalling the middle node's outbound private
/// responses deterministically implicates only the highest-ID node. This
/// reasoning carries over unchanged to a same-committee Reshare below:
/// `CeremonyConfig::canonical_pair_opener` resolves by comparing node *keys*
/// rather than raw numeric IDs, but since old and new committees are
/// identical here, Current- and Next-scope node IDs land in the same sorted
/// order as Fresh DKG's, so it's the same three pairs.
///
/// Must be a Reshare, not a Fresh DKG, for the same reason as
/// `test_reshare_missing_topology_ack_triggers_on_chain_report`:
/// `spawn_pss_offline_observations` unconditionally skips `SessionKind::
/// Fresh` because a report is threshold-signed under the ring's own key,
/// which a Fresh DKG that stalls has never produced. The accused (highest
/// key) can never be the reshare's canonical leader (lowest key), so unlike
/// that sibling test there's no leader/accused collision to avoid here — the
/// existing sort-by-key selection already guarantees it.
#[tokio::test]
#[ignore = "requires a built verad supplied through VERAD_BINARY"]
#[serial_test::serial]
async fn test_reshare_private_pair_terminal_stall_triggers_on_chain_report() {
    let net = setup_fault_three_node_network_with_reshare_interval(
        "fault_reshare_private_terminal",
        51078,
        9084,
        1,
    )
    .await;

    let mut ordered: Vec<(&str, &FaultableNodeHandle)> = vec![
        (net.node_keys[0].as_str(), &net.alice),
        (net.node_keys[1].as_str(), &net.bob),
        (net.node_keys[2].as_str(), &net.charlie),
    ];
    ordered.sort_by(|left, right| left.0.cmp(right.0));
    let (_lowest_key, lowest) = ordered[0];
    let (_middle_key, middle) = ordered[1];
    let (highest_key, _highest) = ordered[2];

    let ring_id = net
        .chain
        .create_ring(&net.node_keys, 2, &net.policy_id)
        .await;

    println!("Running the initial DKG so the ring has a real key to reshare...");
    cli_tool::do_dkg(lowest.grpc_endpoint.clone(), ring_id.clone())
        .await
        .expect("initial DKG should succeed");
    net.chain
        .wait_for_ring_finalized(&ring_id, Duration::from_secs(90))
        .await;

    println!("The middle node's outbound pair to the highest node will stall for the reshare...");
    // Every private-plane response the middle node's own outbound connections
    // receive stalls for the rest of the ceremony (a huge pass-through-0
    // count), well past PEER_RESPONSE_TIMEOUT, so retries never succeed and
    // the sender never observes a real reply from its higher-ID partner.
    middle
        .fault_ctrl
        .stall_protocol_responses_after(
            network::V0.dkg_private_alpn,
            0,
            1000,
            PEER_RESPONSE_TIMEOUT + Duration::from_secs(1),
        )
        .await;
    // See test_reshare_missing_topology_ack_triggers_on_chain_report's doc comment: an
    // independent co-signer separately health-probes the accused over a dedicated direct QUIC
    // protocol before signing, unaffected by the private-plane stall above, and correctly
    // refuses to sign against a peer it can still reach — block it on both non-accused members,
    // since either could end up being asked to co-sign.
    for signer in [lowest, middle] {
        signer
            .fault_ctrl
            .fail_protocol_responses_after(network::V0.reporting_health_alpn, 0, 1000)
            .await;
    }

    println!("Triggering reshare (same committee, new threshold)...");
    net.chain.start_reshare(&ring_id, &net.node_keys, 3).await;

    println!("Waiting for organic private-pair-stall report accepted on chain (up to 240s)...");
    let event = net
        .reports
        .wait_for_matching(&ring_id, Duration::from_secs(240), |event| {
            event.report_type == "node_offline" && event.accused_node_key == highest_key
        })
        .await
        .expect("stalled private pair should organically report the silent partner");

    println!(
        "Private-pair-stall Report accepted on chain: report_id={} accused={} reporter={}",
        event.report_id, event.accused_node_key, event.reporter_node_key
    );

    assert_eq!(event.report_type, "node_offline", "unexpected report_type");
    assert_eq!(
        event.accused_node_key, highest_key,
        "the highest-ID node should be accused, since only the middle node's \
         outbound pair to it was stalled"
    );
    assert_eq!(event.ring_id, ring_id, "ring_id mismatch");
    assert!(!event.report_id.is_empty(), "report_id should be set");
    assert_ne!(
        event.reporter_node_key, highest_key,
        "the accused node should not be its own reporter"
    );

    let demerits = net.chain.node_demerits(&ring_id, highest_key).await;
    assert!(
        demerits > 0,
        "silent private-pair partner should receive at least one demerit"
    );
}

/// A committee member that never receives (hence never acks) the leader's
/// Gossip topology probe during a **Reshare** is reported `node_offline` and
/// the ceremony aborts at the preparation barrier — gated by
/// `DKG_PREPARATION_TIMEOUT` (2 minutes, unaffected by the `DKG_ATTEMPT_
/// TIMEOUT` test-mode shrink), not the ceremony's overall hard deadline.
///
/// This must be a Reshare (not a Fresh DKG): `spawn_pss_offline_observations`
/// (`dkg/v0/coordinator/reporting.rs`) unconditionally skips
/// `SessionKind::Fresh`, because every report is threshold-signed under the
/// ring's own key (`sign_and_submit_report` → `SignCoordinator::
/// initiate_signing`) — a Fresh DKG that fails before completing has no key
/// yet to sign with, so a Fresh-DKG topology-ack failure can never
/// organically produce a signed report. Reusing the same 3-node committee
/// for both old and new (triggered by an ACP threshold-only change, no
/// membership change) is the simplest way to get a Reshare with a real,
/// already-completed ring key to sign under.
///
/// `drop_gossip_deliveries_after` drops every authenticated Gossip delivery
/// the accused's own subscription receives, not just the topology probe —
/// but nothing else is gossiped this early in a ceremony, so it's an
/// effective stand-in for "the probe specifically never arrived." It's
/// applied only after the initial DKG succeeds, so the accused participates
/// normally in establishing the ring key and only goes silent for the
/// reshare. The accused must not be the reshare's canonical leader — a
/// leader self-acks its own topology probe immediately
/// (`begin_topology_probe`) and never needs to receive it via Gossip, so
/// blocking a leader's inbound Gossip would be a no-op (the ceremony
/// completes normally in under a second and no report is ever due). Node
/// keys are freshly randomized every run, so which physical node ends up as
/// leader (`transport::canonical_leader`, `.min()` of the committee's keys)
/// isn't fixed — the test picks whichever committee member is guaranteed
/// *not* to be leader (the one with the largest key) as the accused.
///
/// Uses `setup_fault_three_node_network_with_reshare_interval` (not the
/// plain helper) — a pending on-chain reshare is only ever picked up and
/// driven by each node's own background PSS scheduler
/// (`pss::spawn_pss_scheduler`), which every other test in this file
/// deliberately disables (`reshare_interval_secs: 0`). Unlike Fresh DKG
/// there is no explicit client RPC to start a reshare ceremony directly, so
/// without a running scheduler the on-chain announcement here would never
/// be discovered by anyone and the ceremony would simply never start.
#[tokio::test]
#[ignore = "requires a built verad supplied through VERAD_BINARY"]
#[serial_test::serial]
async fn test_reshare_missing_topology_ack_triggers_on_chain_report() {
    let net = setup_fault_three_node_network_with_reshare_interval(
        "fault_reshare_topology_ack",
        51084,
        9085,
        1,
    )
    .await;

    // The reshare's canonical leader is whichever committee member has the lexicographically
    // *smallest* node key (`transport::canonical_leader`, `.min()`) — a leader self-acks its own
    // topology probe immediately (`begin_topology_probe` inserts itself before broadcasting) and
    // never needs to receive it via Gossip at all, so blocking a leader's inbound Gossip is a
    // no-op: the ceremony completes normally in well under a second and no report is ever due.
    // Node keys are freshly randomized every run, so which of our three handles ends up as leader
    // isn't fixed — accuse whichever one is guaranteed *not* to be it (the largest key) instead.
    let handles = [&net.alice, &net.bob, &net.charlie];
    let (accused_index, _) = net
        .node_keys
        .iter()
        .enumerate()
        .max_by_key(|(_, key)| key.as_str())
        .expect("three node keys");
    let accused = handles[accused_index];
    let accused_key = net.node_keys[accused_index].clone();
    let signers: Vec<&FaultableNodeHandle> = handles
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != accused_index)
        .map(|(_, handle)| *handle)
        .collect();

    let ring_id = net
        .chain
        .create_ring(&net.node_keys, 2, &net.policy_id)
        .await;

    println!("Running the initial DKG so the ring has a real key to reshare...");
    cli_tool::do_dkg(net.alice.grpc_endpoint.clone(), ring_id.clone())
        .await
        .expect("initial DKG should succeed");
    net.chain
        .wait_for_ring_finalized(&ring_id, Duration::from_secs(90))
        .await;

    println!("The accused (non-leader) member will never see the reshare's topology probe...");
    accused
        .fault_ctrl
        .drop_gossip_deliveries_after(0, usize::MAX)
        .await;
    // Blocking Gossip alone isn't enough to make the eventual `node_offline` report land:
    // an independent co-signer separately health-probes the accused over a dedicated direct
    // QUIC protocol (`reporting_health_alpn`, unaffected by the Gossip fault above) before
    // signing, and correctly refuses to sign a report against a peer that's still reachable
    // (`require_peer_offline`, `reporting/v0/health.rs`). `FaultNetworkController` only
    // intercepts outbound connections, not inbound/server-side ones, so the accused's own
    // controller can't block it from *answering* the probe — instead, block the other two
    // members' outbound probes to it (the only ones who could ever be asked to co-sign here).
    for signer in &signers {
        signer
            .fault_ctrl
            .fail_protocol_responses_after(network::V0.reporting_health_alpn, 0, 1000)
            .await;
    }

    println!("Triggering reshare (same committee, new threshold)...");
    net.chain.start_reshare(&ring_id, &net.node_keys, 3).await;

    println!("Waiting for organic missing-topology-ack report accepted on chain (up to 180s)...");
    let event = net
        .reports
        .wait_for_matching(&ring_id, Duration::from_secs(180), |event| {
            event.report_type == "node_offline" && event.accused_node_key == accused_key
        })
        .await
        .expect("aborted reshare topology barrier should organically report the silent member");

    println!(
        "Missing-topology-ack Report accepted on chain: report_id={} accused={} reporter={}",
        event.report_id, event.accused_node_key, event.reporter_node_key
    );

    assert_eq!(event.report_type, "node_offline", "unexpected report_type");
    assert_eq!(
        event.accused_node_key, accused_key,
        "the member that never received the reshare's topology probe should be accused"
    );
    assert_eq!(event.ring_id, ring_id, "ring_id mismatch");
    assert!(!event.report_id.is_empty(), "report_id should be set");
    assert_ne!(
        event.reporter_node_key, accused_key,
        "the accused node should not be its own reporter"
    );

    let demerits = net.chain.node_demerits(&ring_id, &accused_key).await;
    assert!(
        demerits > 0,
        "silent topology-probe partner should receive at least one demerit"
    );
}
