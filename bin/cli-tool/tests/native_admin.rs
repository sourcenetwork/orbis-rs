use alloy_primitives::B256;
use commonware_codec::Encode;
use hub_client::{
    create_scoped_bearer_token,
    nodes::{sign_node_request, NodeCommand, NodeInfo, NodeRequest, NodeTarget},
    rings::{ReportingConfig, RingCommand, RingConfig},
    BlsSigner, DelegationScope, HubClient,
};
use hub_domain::ConsensusPublicKey;
use hub_harness::cluster::{ConsensusPreset, KeySet, TestCluster};
use k256::ecdsa::SigningKey;
use serde_json::{json, Value};
use std::{
    path::Path,
    process::Output,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

async fn admin(base: &Path, args: &[&str], success: bool) -> Value {
    let output: Output = tokio::time::timeout(
        Duration::from_secs(35),
        tokio::process::Command::new(env!("CARGO_BIN_EXE_vera-admin"))
            .arg("--vera-config")
            .arg(base.join("vera.json"))
            .arg("--directory")
            .arg(base.join("operator"))
            .arg("--password-file")
            .arg(base.join("password"))
            .args(args)
            .env("ORBIS_LOCAL_STORAGE_KDF_M_COST_KIB", "8")
            .env("ORBIS_LOCAL_STORAGE_KDF_T_COST", "1")
            .current_dir(base)
            .kill_on_drop(true)
            .output(),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        output.status.success(),
        success,
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    if output.stdout.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&output.stdout).unwrap()
    }
}

async fn receipt(client: &HubClient, id: B256, trusted: &ConsensusPublicKey) {
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let Some(proof) = client.read_receipt(id, trusted).await.unwrap() {
                assert!(proof.verify(id, trusted).unwrap().success());
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap();
}

async fn change_node(
    base: &Path,
    node: &str,
    sequence: u64,
    command: NodeCommand,
    key_file: &str,
    success: bool,
) {
    std::fs::write(
        base.join("command.json"),
        serde_json::to_vec(&command).unwrap(),
    )
    .unwrap();
    let expires_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 300;
    let signed = admin(
        base,
        &[
            "sign-node",
            "command.json",
            "--node-key",
            node,
            "--sequence",
            &sequence.to_string(),
            "--expires-at",
            &expires_at.to_string(),
            "--key-file",
            key_file,
        ],
        true,
    )
    .await;
    std::fs::write(
        base.join("signed.json"),
        serde_json::to_vec(&signed).unwrap(),
    )
    .unwrap();
    let prepared = admin(base, &["prepare-node", "signed.json"], true).await;
    assert_eq!(
        admin(base, &["prepare-node", "signed.json"], true).await,
        prepared
    );
    let result = admin(base, &["submit"], success).await;
    assert_eq!(result["submission_id"], prepared["submission_id"]);
    assert_eq!(result["success"], success);
    admin(
        base,
        &["acknowledge", prepared["submission_id"].as_str().unwrap()],
        true,
    )
    .await;
}

#[tokio::test]
#[ignore = "requires a built hubd supplied through HUBD_BINARY"]
async fn native_admin_controls_nodes_with_signed_current_authority() {
    let deployment = 9078;
    let trusted = *KeySet::builder()
        .seed(deployment)
        .build()
        .unwrap()
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
        .unwrap();
    cluster.wait_ready(Duration::from_secs(30)).await.unwrap();
    cluster
        .observe(Duration::from_millis(100))
        .wait_for_height(3, Duration::from_secs(30))
        .await
        .unwrap();
    let client = HubClient::new(cluster.node(0).rpc_url());
    let root: B256 = client
        .read_finalized_revision(1, &trusted)
        .await
        .unwrap()
        .parent_hash
        .parse()
        .unwrap();
    let local = tempfile::tempdir().unwrap();
    let base = local.path();
    let config = json!({"endpoint": cluster.node(0).rpc_url(), "deployment_id": deployment,
        "deployment_root": hex::encode(root), "consensus_key": hex::encode(trusted.encode())});
    std::fs::write(base.join("vera.json"), serde_json::to_vec(&config).unwrap()).unwrap();
    std::fs::write(base.join("password"), "test password\n").unwrap();
    let node_key = hex::encode(
        SigningKey::from_slice(&[31; 32])
            .unwrap()
            .verifying_key()
            .to_sec1_bytes(),
    );
    let controller = hex::encode(
        SigningKey::from_slice(&[32; 32])
            .unwrap()
            .verifying_key()
            .to_sec1_bytes(),
    );
    std::fs::write(base.join("node-key"), [31; 32]).unwrap();
    std::fs::write(
        base.join("controller-key"),
        format!("0x{}\n", hex::encode([32; 32])),
    )
    .unwrap();
    assert!(admin(base, &["node", &node_key], true).await["node"].is_null());
    assert!(!base.join("operator").exists());
    change_node(
        base,
        &node_key,
        0,
        NodeCommand::Register(NodeInfo {
            peer_id: "ab".repeat(32),
            controller_key: controller.clone(),
            allowed_policy_ids: Vec::new(),
            allowed_ring_ids: Vec::new(),
        }),
        "node-key",
        true,
    )
    .await;
    let original = admin(base, &["node", &node_key], true).await;
    assert_eq!(original["node"]["sequence"], 1);
    assert_eq!(original["node"]["info"]["controller_key"], controller);

    let mut wrong_deployment: Value =
        serde_json::from_slice(&std::fs::read(base.join("signed.json")).unwrap()).unwrap();
    wrong_deployment["request"]["deployment_id"] = json!(deployment + 1);
    std::fs::write(
        base.join("wrong-deployment.json"),
        serde_json::to_vec(&wrong_deployment).unwrap(),
    )
    .unwrap();
    let journal = base
        .join("operator")
        .join(hex::encode(root))
        .join("worker/state.json");
    let before = std::fs::read(&journal).unwrap();
    admin(base, &["prepare-node", "wrong-deployment.json"], false).await;
    assert_eq!(std::fs::read(&journal).unwrap(), before);

    let route = format!("{}@127.0.0.1:4555", "ab".repeat(32));
    change_node(
        base,
        &node_key,
        1,
        NodeCommand::SetPeer(route.clone()),
        "node-key",
        false,
    )
    .await;
    assert_eq!(
        admin(base, &["node", &node_key], true).await["node"],
        original["node"]
    );
    change_node(
        base,
        &node_key,
        1,
        NodeCommand::SetPeer(route.clone()),
        "controller-key",
        true,
    )
    .await;
    change_node(
        base,
        &node_key,
        2,
        NodeCommand::Allow(NodeTarget::Policy("11".repeat(32))),
        "controller-key",
        true,
    )
    .await;
    change_node(
        base,
        &node_key,
        3,
        NodeCommand::Allow(NodeTarget::Ring("22".repeat(32))),
        "controller-key",
        true,
    )
    .await;
    let allowed = admin(base, &["node", &node_key], true).await;
    assert_eq!(allowed["node"]["info"]["peer_id"], route);
    assert_eq!(
        allowed["node"]["info"]["allowed_policy_ids"],
        json!(["11".repeat(32)])
    );
    assert_eq!(
        allowed["node"]["info"]["allowed_ring_ids"],
        json!(["22".repeat(32)])
    );
    change_node(
        base,
        &node_key,
        4,
        NodeCommand::TransferController(node_key.clone()),
        "controller-key",
        true,
    )
    .await;
    change_node(
        base,
        &node_key,
        5,
        NodeCommand::Disallow(NodeTarget::Policy("11".repeat(32))),
        "controller-key",
        false,
    )
    .await;
    change_node(
        base,
        &node_key,
        5,
        NodeCommand::Disallow(NodeTarget::Policy("11".repeat(32))),
        "node-key",
        true,
    )
    .await;
    change_node(
        base,
        &node_key,
        6,
        NodeCommand::Disallow(NodeTarget::Ring("22".repeat(32))),
        "node-key",
        true,
    )
    .await;
    let final_state = admin(base, &["node", &node_key], true).await;
    assert_eq!(final_state["node"]["node_key"], node_key);
    assert_eq!(final_state["node"]["info"]["controller_key"], node_key);
    assert_eq!(final_state["node"]["info"]["allowed_policy_ids"], json!([]));
    assert_eq!(final_state["node"]["info"]["allowed_ring_ids"], json!([]));
    assert_eq!(final_state["node"]["sequence"], 7);
}

#[tokio::test]
#[ignore = "requires a built hubd supplied through HUBD_BINARY"]
async fn native_admin_provisions_ring_and_recovers_exact_results() {
    let deployment = 9077;
    let trusted = *KeySet::builder()
        .seed(deployment)
        .build()
        .unwrap()
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
        .unwrap();
    cluster.wait_ready(Duration::from_secs(30)).await.unwrap();
    cluster
        .observe(Duration::from_millis(100))
        .wait_for_height(3, Duration::from_secs(30))
        .await
        .unwrap();
    let client = HubClient::new(cluster.node(0).rpc_url());
    let root: B256 = client
        .read_finalized_revision(1, &trusted)
        .await
        .unwrap()
        .parent_hash
        .parse()
        .unwrap();
    let local = tempfile::tempdir().unwrap();
    let base = local.path();
    let mut config = json!({"endpoint": cluster.node(0).rpc_url(), "deployment_id": deployment,
        "deployment_root": hex::encode([99; 32]), "consensus_key": hex::encode(trusted.encode())});
    std::fs::write(base.join("password"), "test password\n").unwrap();
    std::fs::write(base.join("vera.json"), serde_json::to_vec(&config).unwrap()).unwrap();
    admin(base, &["worker"], false).await;
    assert!(!base.join("operator").exists());
    config["deployment_root"] = json!(hex::encode(root));
    std::fs::write(base.join("vera.json"), serde_json::to_vec(&config).unwrap()).unwrap();
    let identity = admin(base, &["worker"], true).await;
    let authority = SigningKey::from_slice(&[31; 32]).unwrap();
    let node_key = hex::encode(authority.verifying_key().to_sec1_bytes());
    let actor = hub_crypto::secp256k1::did_from_secp256k1_pubkey(
        authority.verifying_key().to_sec1_bytes().as_ref(),
    )
    .unwrap();
    let worker = BlsSigner::new(7u64.into(), deployment).unwrap();
    let created = client.native_create_policy(&worker, b"name: native_admin\nresources:\n  - name: ring_policy\n    relations:\n      - name: creator\n    permissions:\n      - name: create_ring\n        expr: creator\n  - name: ring\n", 1).await.unwrap();
    receipt(&client, created.transaction_hash, &trusted).await;
    let policy = client.get_policy_ids().await.unwrap().pop().unwrap();
    let policy_bytes = B256::from_slice(&hex::decode(&policy).unwrap());
    let registered = client
        .native_register_object(&worker, policy_bytes, &policy, "ring_policy")
        .await
        .unwrap();
    receipt(&client, registered.transaction_hash, &trusted).await;
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
    receipt(&client, granted.transaction_hash, &trusted).await;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let registration = sign_node_request(
        NodeRequest {
            deployment_root: root.0,
            deployment_id: deployment,
            node_key: node_key.clone(),
            sequence: 0,
            command: NodeCommand::Register(NodeInfo {
                peer_id: "ab".repeat(32),
                controller_key: node_key.clone(),
                allowed_policy_ids: vec![policy.clone()],
                allowed_ring_ids: Vec::new(),
            }),
            expires_at: now + 300,
        },
        &authority,
    )
    .unwrap();
    let id = client
        .submit_node_request(&worker, &registration)
        .await
        .unwrap();
    receipt(&client, id, &trusted).await;
    let token = create_scoped_bearer_token(
        &authority,
        identity["worker_did"].as_str().unwrap(),
        deployment,
        now,
        now + 300,
        DelegationScope::ManageRings,
    )
    .unwrap();
    std::fs::write(base.join("token"), token).unwrap();
    let ring = RingConfig {
        policy_id: policy,
        peer_node_keys: vec![node_key],
        threshold: 1,
        pss_interval: 86400,
        current_version: 0,
        nonce: [1; 32],
        trusted_auth_relay_dids: None,
        reporting: ReportingConfig::default(),
    };
    let ring_id = ring.id(root.0, &actor).unwrap();
    std::fs::write(
        base.join("create.json"),
        serde_json::to_vec(&RingCommand::Create(ring)).unwrap(),
    )
    .unwrap();
    assert_eq!(
        admin(base, &["ring-id", "create.json", "--actor", &actor], true).await["ring_id"],
        ring_id
    );
    let prepared = admin(
        base,
        &["prepare-ring", "create.json", "--token-file", "token"],
        true,
    )
    .await;
    let journal = base
        .join("operator")
        .join(hex::encode(root))
        .join("worker/state.json");
    let pending = std::fs::read(&journal).unwrap();
    assert_eq!(
        admin(
            base,
            &["prepare-ring", "create.json", "--token-file", "token"],
            true
        )
        .await,
        prepared
    );
    std::fs::write(
        base.join("cancel.json"),
        serde_json::to_vec(&RingCommand::Cancel {
            ring_id: "ff".repeat(32),
        })
        .unwrap(),
    )
    .unwrap();
    admin(
        base,
        &["prepare-ring", "cancel.json", "--token-file", "token"],
        false,
    )
    .await;
    let result = admin(base, &["submit"], true).await;
    assert_eq!(result["submission_id"], prepared["submission_id"]);
    assert_eq!(admin(base, &["submit"], true).await, result);
    assert_eq!(std::fs::read(&journal).unwrap(), pending);
    let read = admin(base, &["ring", &ring_id], true).await;
    assert_eq!(read["ring"]["id"], ring_id);
    admin(
        base,
        &["acknowledge", &format!("0x{}", "ff".repeat(32))],
        false,
    )
    .await;
    assert_eq!(std::fs::read(&journal).unwrap(), pending);
    admin(
        base,
        &["acknowledge", prepared["submission_id"].as_str().unwrap()],
        true,
    )
    .await;
    let recovered = admin(base, &["worker"], true).await;
    assert_eq!(recovered["worker_did"], identity["worker_did"]);
    assert!(recovered["pending_id"].is_null());
    admin(
        base,
        &["prepare-ring", "cancel.json", "--token-file", "token"],
        true,
    )
    .await;
    let rejected = admin(base, &["submit"], false).await;
    assert_eq!(rejected["success"], false);
    assert_eq!(admin(base, &["submit"], false).await, rejected);
    admin(
        base,
        &["acknowledge", rejected["submission_id"].as_str().unwrap()],
        true,
    )
    .await;
}
