use super::{confirmed, submit, Node};
use alloy_primitives::B256;
use commonware_codec::Encode;
use proto::info_service::GetNodeInfoResponse;
use std::{fs, net::TcpListener, path::PathBuf, time::Duration};
use test_support::NativeTestNetwork as TestCluster;
use vera_client::{
    create_scoped_bearer_token,
    nodes::{encode_node_request, sign_node_request, NodeCommand, NodeRequest, NodeTarget},
    rings::{encode_ring_command, ReportingConfig, RingCommand, RingConfig},
    BlsSigner, DelegationScope, VeraClient,
};
use vera_domain::ConsensusPublicKey;
use vera_harness::cluster::KeySet;

pub(super) struct NativeWorkflow {
    pub cluster: TestCluster,
    pub client: VeraClient,
    pub trusted: ConsensusPublicKey,
    pub root: B256,
    pub controller: k256::ecdsa::SigningKey,
    pub controller_key: String,
    pub actor: String,
    pub base: tempfile::TempDir,
    pub nodes: Vec<Node>,
    pub addresses: Vec<String>,
    pub logs: Vec<PathBuf>,
    pub infos: Vec<GetNodeInfoResponse>,
    pub worker: BlsSigner,
    pub policy: String,
    pub policy_bytes: B256,
    pub ring_id: String,
    pub now: u64,
    pub headers: acp_light_client::header_sync::HeaderChain,
}

impl NativeWorkflow {
    pub async fn start(deployment: u64, requires_pet: bool, report_fault: bool) -> Self {
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
        let controller = k256::ecdsa::SigningKey::from_slice(&[34; 32]).unwrap();
        let controller_key = hex::encode(controller.verifying_key().to_sec1_bytes());
        let actor = vera_crypto::secp256k1::did_from_secp256k1_pubkey(
            controller.verifying_key().to_sec1_bytes().as_ref(),
        )
        .unwrap();
        let base = run_directory(
            deployment,
            std::env::var_os("ORBIS_NATIVE_E2E_DIR").map(PathBuf::from),
            std::env::var("VERA_E2E_KEEP").is_ok_and(|value| value == "1"),
        );
        let mut nodes = Vec::new();
        let mut addresses = Vec::new();
        let mut logs = Vec::new();
        for index in 0..3 {
            let directory = base.path().join(format!("node-{index}"));
            fs::create_dir(&directory).unwrap();
            fs::write(directory.join("password"), "native-dkg-test").unwrap();
            fs::write(
            directory.join("vera.json"),
            serde_json::to_vec(&serde_json::json!({
                "endpoint": url, "deployment_id": deployment, "deployment_root": hex::encode(root),
                "consensus_key": hex::encode(trusted.encode()),
            }))
            .unwrap(),
        )
        .unwrap();
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap().to_string();
            drop(listener);
            let log = directory.join("node.log");
            nodes.push(Node::start_configured(
                &directory,
                &addr,
                &controller_key,
                &log,
                "127.0.0.1:0",
                report_fault,
            ));
            addresses.push(addr);
            logs.push(log);
        }
        let mut infos = Vec::new();
        for index in 0..nodes.len() {
            infos.push(nodes[index].ready(&addresses[index], &logs[index]).await);
        }
        let worker = BlsSigner::new(7u64.into(), deployment).unwrap();
        let policy_schema = super::policy_generations::definition(true, true);
        let created = client
            .native_create_policy(&worker, policy_schema.as_bytes(), 1)
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
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        for (index, info) in infos.iter().enumerate() {
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
                    &format!("authorize node {index}: {command_name}"),
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
            pss_interval: 86400,
            current_version: 0,
            requires_pet,
            nonce: [2; 32],
            trusted_auth_relay_dids: None,
            reporting: ReportingConfig::default(),
        };
        let ring_id = config.id(root.0, &actor).unwrap();
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
            "create ring",
            &cluster,
        )
        .await;
        Self {
            cluster,
            client,
            trusted,
            root,
            controller,
            controller_key,
            actor,
            base,
            nodes,
            addresses,
            logs,
            infos,
            worker,
            policy,
            policy_bytes,
            ring_id,
            now,
            headers,
        }
    }
}

fn run_directory(deployment: u64, parent: Option<PathBuf>, keep: bool) -> tempfile::TempDir {
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
