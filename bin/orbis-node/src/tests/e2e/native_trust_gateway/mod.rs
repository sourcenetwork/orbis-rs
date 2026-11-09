//! Real Trust gateway ring admission and DKG against the shared native network.

use super::native_confirmation::{confirmed, submit};
use super::native_lifecycle::{bring_up_orbis_nodes, Node, TestCluster};
use alloy_primitives::B256;
use commonware_codec::Encode as _;
use crypto::r#trait::{CryptoDeserialize as _, CryptoSerialize as _};
use local_storage::{r#trait::LocalStorage as _, LocalStorageImpl};
use proto::info_service::GetNodeInfoResponse;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::{
    fs::{self, DirBuilder, File, OpenOptions},
    io::{Read as _, Write as _},
    net::TcpListener,
    os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use vera_client::{
    administration::{
        approve_administration, AdministrativeCommand, AdministrativeRequest, OperatorPolicy,
        SignedAdministrativeRequest,
    },
    create_scoped_bearer_token,
    nodes::{encode_node_request, sign_node_request, NodeCommand, NodeRequest, NodeTarget},
    rings::{
        encode_ring_command, ReportingConfig, RingCommand, RingConfig, RingPublicKeys, RingState,
    },
    BlsSigner, DelegationScope, VeraClient,
};
use vera_harness::cluster::{GenesisBuilder, KeySet};
use vera_modules::vera::relay::RelayGrant;

mod runner;

#[derive(Serialize)]
struct Descriptor {
    version: u32,
    endpoint: String,
    trusted_key: String,
    genesis: String,
    deployment: u64,
    root_directory: PathBuf,
    provider_address: String,
    policy_id: String,
    minimum_revision: u64,
    relay_grant_sequence: u64,
    nodes: Vec<Peer>,
    trusted_orbis_relay_did: String,
}

#[derive(Serialize)]
struct Peer {
    address: String,
    node_key: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Results {
    version: u32,
    actor: String,
    rings: [RingResult; 2],
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum Mode {
    Relay,
    Direct,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RingResult {
    mode: Mode,
    operation_id: String,
    ring_id: String,
    creation_revision: u64,
    active_revision: u64,
    public_key: String,
    pet_public_key: String,
}

pub async fn run() {
    let go_binary = runner::artifacts();
    for name in [
        "ORBIS_LOCAL_STORAGE_KDF_M_COST_KIB",
        "ORBIS_LOCAL_STORAGE_KDF_T_COST",
    ] {
        assert!(
            std::env::var_os(name).is_none(),
            "KDF overrides are not permitted"
        );
    }
    let deployment = 9097;
    let operator_keys = operators();
    let policy = OperatorPolicy {
        threshold: 2,
        keys: operator_keys
            .iter()
            .map(|key| hex::encode(key.verifying_key().to_sec1_bytes()))
            .collect(),
    };
    let cluster =
        TestCluster::start_with_genesis(deployment, GenesisBuilder::devnet().operators(policy))
            .await;
    let mut network = GatewayNetwork::start(deployment, cluster).await;
    let root = network.base.path().canonicalize().unwrap();
    let go_root = root.join("trust");
    DirBuilder::new().mode(0o700).create(&go_root).unwrap();
    let provider = TcpListener::bind("127.0.0.1:0").unwrap();
    let provider_address = provider.local_addr().unwrap().to_string();
    let actor = format!(
        "did:opk:{}",
        hex::encode(Sha256::digest(format!("https://{provider_address}#me")))
    );
    let granted = network
        .client
        .native_set_relationship(
            &network.worker,
            network.policy_bytes,
            "ring_policy",
            &network.policy,
            "creator",
            &actor,
        )
        .await
        .unwrap();
    confirmed(&network.client, granted.transaction_hash, &network.trusted).await;
    let relationship = vera_acp::Relationship::with_entity(
        "ring_policy",
        &network.policy,
        "creator",
        actor.parse().unwrap(),
    );
    super::policy_generations::assert_relationship(
        &network.client,
        network.policy_bytes,
        &network.trusted,
        &relationship,
    )
    .await;
    let minimum = grant_relay(&network, &operator_keys).await;
    // The Orbis authentication relay is Ed25519. It is distinct from the secp256k1
    // native submission relay and is only recorded as an allowed relay in this test.
    let trusted_orbis_relay_did = authn::jwt_builder::JwtSigner::from_seed([43; 32]).did_uri;
    let descriptor = Descriptor {
        version: 1,
        endpoint: network.cluster.node(0).rpc_url(),
        trusted_key: hex::encode(network.trusted.encode()),
        genesis: hex::encode(network.root),
        deployment,
        root_directory: go_root.clone(),
        provider_address,
        policy_id: network.policy.clone(),
        minimum_revision: minimum,
        relay_grant_sequence: 0,
        nodes: network
            .addresses
            .iter()
            .zip(&network.infos)
            .map(|(address, info)| Peer {
                address: address.clone(),
                node_key: info.node_key.clone(),
            })
            .collect(),
        trusted_orbis_relay_did,
    };
    let descriptor_path = root.join("trust-ring-fixture.json");
    private_file(&descriptor_path)
        .write_all(&serde_json::to_vec(&descriptor).unwrap())
        .unwrap();
    // The Go OIDC server binds this exact address; keep it reserved until launch.
    drop(provider);
    runner::run(&go_binary, &descriptor_path, &root).await;
    let results = results(&go_root.join("ring-results.json"));
    verify_results(&network, &descriptor, &actor, &results).await;
    for node in &mut network.nodes {
        node.stop().await;
    }
    for index in 0..network.nodes.len() {
        let directory = root.join(format!("node-{index}"));
        let path = directory.join("dbs/orbis.redb");
        assert!(
            path.is_file(),
            "must reopen the stopped node's existing store"
        );
        let storage = LocalStorageImpl::new(
            fs::read_to_string(directory.join("password")).unwrap(),
            path.to_str().unwrap().into(),
        )
        .unwrap();
        assert_eq!(
            storage.stored_kdf_params().unwrap(),
            local_storage::common::StoredKdfParams {
                m_cost_kib: 262_144,
                t_cost: 3,
                p_cost: 1,
                version: 0x13,
            },
            "gateway DKG stores must retain production KDF parameters"
        );
    }
    eprintln!(
        "native Trust phase=ring-dkg rings=2 replicas=4 paired_keys=true production_kdf=true"
    );
}

struct GatewayNetwork {
    cluster: TestCluster,
    client: VeraClient,
    trusted: vera_domain::ConsensusPublicKey,
    root: B256,
    base: tempfile::TempDir,
    nodes: Vec<Node>,
    addresses: Vec<String>,
    infos: Vec<GetNodeInfoResponse>,
    worker: BlsSigner,
    policy: String,
    policy_bytes: B256,
}

impl GatewayNetwork {
    /// Three normal Orbis nodes, their policy, and the baseline PET ring.
    /// The unsafe diagnostic image stays off. The Go contract creates its
    /// own two rings after this returns.
    async fn start(deployment: u64, cluster: TestCluster) -> Self {
        let trusted = *KeySet::builder()
            .seed(deployment)
            .build()
            .unwrap()
            .epoch_info()
            .output
            .public()
            .public();
        let url = cluster.node(0).rpc_url();
        let client = VeraClient::new(&url);
        let first = client.read_finalized_revision(1, &trusted).await.unwrap();
        let headers = acp_light_client::header_sync::HeaderChain::connect(
            &url.replacen("http://", "ws://", 1),
            acp_light_client::ProofClient::new(&url, &hex::encode(trusted.encode())).unwrap(),
        )
        .await
        .unwrap();
        headers
            .wait_for_height(first.height + 1, Duration::from_secs(15))
            .await
            .unwrap();
        assert!(headers.fresh_state().unwrap().height > first.height);
        let root: B256 = first.parent_hash.parse().unwrap();
        let controller = vera_client::Secp256k1SigningKey::from_slice(&[34; 32]).unwrap();
        let actor = vera_crypto::secp256k1::did_from_secp256k1_pubkey(
            controller.verifying_key().to_sec1_bytes().as_ref(),
        )
        .unwrap();
        let base = super::native_lifecycle::run_directory(
            deployment,
            std::env::var_os("ORBIS_NATIVE_E2E_DIR").map(PathBuf::from),
            std::env::var("VERA_E2E_KEEP").is_ok_and(|value| value == "1"),
        );
        let addresses = bring_up_orbis_nodes(&cluster, base.path(), 3, 1, false);
        let mut nodes = Vec::new();
        let mut logs = Vec::new();
        for index in 0..3 {
            let directory = base.path().join(format!("node-{index}"));
            logs.push(directory.join("node.log"));
            nodes.push(Node::attach(cluster.project_name(), index, &logs[index]));
        }
        let mut infos = Vec::new();
        for index in 0..nodes.len() {
            infos.push(nodes[index].ready(&addresses[index], &logs[index]).await);
        }
        let worker = BlsSigner::new(7u64.into(), deployment).unwrap();
        let created = client
            .native_create_policy(
                &worker,
                super::policy_generations::definition(true, true).as_bytes(),
                1,
            )
            .await
            .unwrap();
        confirmed(&client, created.transaction_hash, &trusted).await;
        let policy = client.get_policy_ids().await.unwrap().pop().unwrap();
        let policy_bytes = B256::from_slice(&hex::decode(&policy).unwrap());
        let registered = client
            .native_register_object(&worker, policy_bytes, &policy, "ring_policy")
            .await
            .unwrap();
        confirmed(&client, registered.transaction_hash, &trusted).await;
        let granted = client
            .native_set_relationship(
                &worker,
                policy_bytes,
                "ring_policy",
                &policy,
                "creator",
                &actor,
            )
            .await
            .unwrap();
        confirmed(&client, granted.transaction_hash, &trusted).await;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        for info in &infos {
            for command in [
                NodeCommand::SetPeer(info.p2p_address.clone()),
                NodeCommand::Allow(NodeTarget::Policy(policy.clone())),
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
                    "authorize gateway node",
                    &cluster,
                )
                .await;
            }
        }
        let mut members: Vec<_> = infos.iter().map(|info| info.node_key.clone()).collect();
        members.sort();
        let config = RingConfig {
            policy_id: policy.clone(),
            peer_node_keys: members,
            threshold: 2,
            pss_interval: 86_400,
            current_version: 0,
            requires_pet: true,
            nonce: [2; 32],
            trusted_auth_relay_dids: None,
            pre_share_endpoints: Vec::new(),
            reporting: ReportingConfig::default(),
        };
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
            encode_ring_command(&RingCommand::Create(config), &token).unwrap(),
            "create gateway baseline ring",
            &cluster,
        )
        .await;
        Self {
            cluster,
            client,
            trusted,
            root,
            base,
            nodes,
            addresses,
            infos,
            worker,
            policy,
            policy_bytes,
        }
    }
}

fn operators() -> Vec<vera_client::Secp256k1SigningKey> {
    let mut keys: Vec<_> = [1, 2]
        .map(|byte| vera_client::Secp256k1SigningKey::from_slice(&[byte; 32]).unwrap())
        .into();
    keys.sort_by_key(|key| key.verifying_key().to_sec1_bytes().to_vec());
    keys
}

async fn grant_relay(network: &GatewayNetwork, keys: &[vera_client::Secp256k1SigningKey]) -> u64 {
    let relay = vera_client::Secp256k1SigningKey::from_slice(&[42; 32]).unwrap();
    let issuer = vera_crypto::secp256k1::did_from_secp256k1_pubkey(
        relay.verifying_key().to_sec1_bytes().as_ref(),
    )
    .unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let grant = RelayGrant {
        issuer: issuer.clone(),
        scopes: vec![DelegationScope::ManageRings],
        expires_at: now + 600,
    };
    let request = AdministrativeRequest {
        genesis_id: network.root.0,
        sequence: 0,
        expires_at: now + 300,
        command: AdministrativeCommand::SetRelay(grant.clone()),
    };
    let approvals = keys
        .iter()
        .enumerate()
        .map(|(index, key)| approve_administration(&request, index as u16, key).unwrap())
        .collect();
    let result = network
        .client
        .native_apply_administration(
            &network.worker,
            &SignedAdministrativeRequest { request, approvals },
        )
        .await
        .unwrap();
    confirmed(&network.client, result.transaction_hash, &network.trusted).await;
    let certified = network
        .client
        .read_relay_grant(&issuer, 1, &network.trusted)
        .await
        .unwrap();
    let state = certified.value.expect("operator-approved relay grant");
    assert_eq!(state.grant, grant);
    assert_eq!(state.sequence, 0);
    certified.revision
}

async fn verify_results(
    network: &GatewayNetwork,
    input: &Descriptor,
    actor: &str,
    results: &Results,
) {
    assert_eq!(results.version, 1);
    assert_eq!(results.actor, actor);
    assert_ne!(results.rings[0].ring_id, results.rings[1].ring_id);
    assert_ne!(results.rings[0].operation_id, results.rings[1].operation_id);
    let mut members: Vec<_> = network
        .infos
        .iter()
        .map(|info| info.node_key.clone())
        .collect();
    members.sort();
    for (result, (mode, nonce)) in results
        .rings
        .iter()
        .zip([(Mode::Relay, 71), (Mode::Direct, 72)])
    {
        assert_eq!(result.mode, mode);
        let operation = result
            .operation_id
            .strip_prefix("0x")
            .expect("operation ID prefix");
        assert!(
            operation.len() == 64 && hex::decode(operation).is_ok(),
            "invalid operation ID"
        );
        assert!(result.creation_revision >= input.minimum_revision);
        assert!(result.active_revision >= result.creation_revision);
        let config = RingConfig {
            policy_id: input.policy_id.clone(),
            peer_node_keys: members.clone(),
            threshold: 2,
            pss_interval: 86_400,
            current_version: 0,
            requires_pet: true,
            nonce: [nonce; 32],
            trusted_auth_relay_dids: (mode == Mode::Relay)
                .then(|| vec![input.trusted_orbis_relay_did.clone()]),
            pre_share_endpoints: Vec::new(),
            reporting: ReportingConfig::default(),
        };
        assert_eq!(config.id(network.root.0, actor).unwrap(), result.ring_id);
        let keys = RingPublicKeys {
            public_key: result.public_key.clone(),
            pet_public_key: Some(result.pet_public_key.clone()),
        };
        for key in [&result.public_key, &result.pet_public_key] {
            let encoded = hex::decode(key).unwrap();
            let point = crypto::GroupAffine::from_bytes(&encoded).unwrap();
            assert_eq!(point.to_bytes().unwrap(), encoded);
        }
        for index in 0..network.cluster.node_count() {
            let client = VeraClient::new(network.cluster.node(index).rpc_url());
            let record = tokio::time::timeout(Duration::from_secs(30), async {
                loop {
                    match client
                        .read_threshold_ring(
                            &result.ring_id,
                            result.active_revision,
                            &network.trusted,
                        )
                        .await
                    {
                        Ok(read) => break read.record.expect("Go-created certified ring"),
                        Err(error) if error.is_throttled() => {
                            tokio::time::sleep(Duration::from_millis(100)).await
                        }
                        Err(_) => panic!("certified ring read failed"),
                    }
                }
            })
            .await
            .expect("certified replica read deadline");
            assert_eq!(record.deployment_root, network.root.0);
            assert_eq!(record.creator, actor);
            assert_eq!(record.config, config);
            assert!(
                record.settings.is_none(),
                "fixture must not reconfigure the ring"
            );
            assert_eq!(record.state, RingState::Active { keys: keys.clone() });
        }
    }
}

fn private_file(path: &Path) -> File {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap()
}

fn results(path: &Path) -> Results {
    let metadata = fs::symlink_metadata(path).unwrap();
    assert!(metadata.is_file() && metadata.permissions().mode() & 0o077 == 0);
    assert!(
        metadata.len() > 0 && metadata.len() <= 65_536,
        "invalid private result size"
    );
    let mut bytes = Vec::new();
    File::open(path)
        .unwrap()
        .take(65_537)
        .read_to_end(&mut bytes)
        .unwrap();
    assert!(bytes.len() <= 65_536);
    serde_json::from_slice(&bytes).expect("strict private ring result contract")
}
