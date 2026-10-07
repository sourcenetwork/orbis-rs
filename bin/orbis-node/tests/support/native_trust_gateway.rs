//! Real Trust gateway ring admission and DKG against the shared native network.

use super::{confirmed, native_workflow::NativeWorkflow, TestCluster};
use commonware_codec::Encode as _;
use crypto::r#trait::{CryptoDeserialize as _, CryptoSerialize as _};
use local_storage::{r#trait::LocalStorage as _, LocalStorageImpl};
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
    rings::{ReportingConfig, RingConfig, RingPublicKeys, RingState},
    DelegationScope, VeraClient,
};
use vera_harness::cluster::GenesisBuilder;
use vera_modules::vera::relay::RelayGrant;

#[path = "native_trust_gateway/runner.rs"]
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
    let mut workflow = NativeWorkflow::start_with_network(deployment, true, false, cluster).await;
    let root = workflow.base.path().canonicalize().unwrap();
    let go_root = root.join("trust");
    DirBuilder::new().mode(0o700).create(&go_root).unwrap();
    let provider = TcpListener::bind("127.0.0.1:0").unwrap();
    let provider_address = provider.local_addr().unwrap().to_string();
    let actor = format!(
        "did:opk:{}",
        hex::encode(Sha256::digest(format!("https://{provider_address}#me")))
    );
    let granted = workflow
        .client
        .native_set_relationship(
            &workflow.worker,
            workflow.policy_bytes,
            "ring_policy",
            &workflow.policy,
            "creator",
            &actor,
        )
        .await
        .unwrap();
    confirmed(
        &workflow.client,
        granted.transaction_hash,
        &workflow.trusted,
    )
    .await;
    let relationship = vera_acp::Relationship::with_entity(
        "ring_policy",
        &workflow.policy,
        "creator",
        actor.parse().unwrap(),
    );
    super::policy_generations::assert_relationship(
        &workflow.client,
        workflow.policy_bytes,
        &workflow.trusted,
        &relationship,
    )
    .await;
    let minimum = grant_relay(&workflow, &operator_keys).await;
    // The Orbis authentication relay is Ed25519. It is distinct from the secp256k1
    // native submission relay and is only recorded as an allowed relay in this test.
    let trusted_orbis_relay_did = authn::jwt_builder::JwtSigner::from_key_pair(
        did_key::generate::<did_key::Ed25519KeyPair>(Some(&[43; 32])),
    )
    .did_uri;
    let descriptor = Descriptor {
        version: 1,
        endpoint: workflow.cluster.node(0).rpc_url(),
        trusted_key: hex::encode(workflow.trusted.encode()),
        genesis: hex::encode(workflow.root),
        deployment,
        root_directory: go_root.clone(),
        provider_address,
        policy_id: workflow.policy.clone(),
        minimum_revision: minimum,
        relay_grant_sequence: 0,
        nodes: workflow
            .addresses
            .iter()
            .zip(&workflow.infos)
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
    verify_results(&workflow, &descriptor, &actor, &results).await;
    for node in &mut workflow.nodes {
        node.stop().await;
    }
    for index in 0..workflow.nodes.len() {
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

fn operators() -> Vec<k256::ecdsa::SigningKey> {
    let mut keys: Vec<_> = [1, 2]
        .map(|byte| k256::ecdsa::SigningKey::from_slice(&[byte; 32]).unwrap())
        .into();
    keys.sort_by_key(|key| key.verifying_key().to_sec1_bytes().to_vec());
    keys
}

async fn grant_relay(workflow: &NativeWorkflow, keys: &[k256::ecdsa::SigningKey]) -> u64 {
    let relay = k256::ecdsa::SigningKey::from_slice(&[42; 32]).unwrap();
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
        genesis_id: workflow.root.0,
        sequence: 0,
        expires_at: now + 300,
        command: AdministrativeCommand::SetRelay(grant.clone()),
    };
    let approvals = keys
        .iter()
        .enumerate()
        .map(|(index, key)| approve_administration(&request, index as u16, key).unwrap())
        .collect();
    let result = workflow
        .client
        .native_apply_administration(
            &workflow.worker,
            &SignedAdministrativeRequest { request, approvals },
        )
        .await
        .unwrap();
    confirmed(&workflow.client, result.transaction_hash, &workflow.trusted).await;
    let certified = workflow
        .client
        .read_relay_grant(&issuer, 1, &workflow.trusted)
        .await
        .unwrap();
    let state = certified.value.expect("operator-approved relay grant");
    assert_eq!(state.grant, grant);
    assert_eq!(state.sequence, 0);
    certified.revision
}

async fn verify_results(
    workflow: &NativeWorkflow,
    input: &Descriptor,
    actor: &str,
    results: &Results,
) {
    assert_eq!(results.version, 1);
    assert_eq!(results.actor, actor);
    assert_ne!(results.rings[0].ring_id, results.rings[1].ring_id);
    assert_ne!(results.rings[0].operation_id, results.rings[1].operation_id);
    let mut members: Vec<_> = workflow
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
            reporting: ReportingConfig::default(),
        };
        assert_eq!(config.id(workflow.root.0, actor).unwrap(), result.ring_id);
        let keys = RingPublicKeys {
            public_key: result.public_key.clone(),
            pet_public_key: Some(result.pet_public_key.clone()),
        };
        for key in [&result.public_key, &result.pet_public_key] {
            let encoded = hex::decode(key).unwrap();
            let point = crypto::GroupAffine::from_bytes(&encoded).unwrap();
            assert_eq!(point.to_bytes().unwrap(), encoded);
        }
        for index in 0..workflow.cluster.node_count() {
            let client = VeraClient::new(workflow.cluster.node(index).rpc_url());
            let record = tokio::time::timeout(Duration::from_secs(30), async {
                loop {
                    match client
                        .read_threshold_ring(
                            &result.ring_id,
                            result.active_revision,
                            &workflow.trusted,
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
            assert_eq!(record.deployment_root, workflow.root.0);
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
