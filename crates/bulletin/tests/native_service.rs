use alloy_primitives::{Bytes, B256};
use bulletin::{
    native::{NativeBulletin, NativeVeraClient},
    r#trait::{
        Bulletin, BulletinKind, BulletinWriteKind, DocumentPayload, KeyDerivation, NodeInfo,
        RingCancellationPayload, RingFinalizationPayload, RingPayload,
    },
};
use hub_client::{
    create_scoped_bearer_token,
    rings::{encode_ring_command, ReportingConfig, RingCommand, RingConfig},
    BlsSigner, DelegationScope, HubClient, HUB_ADDRESS,
};
use hub_domain::{ConsensusPublicKey, NativeTx};
use hub_harness::cluster::{ConsensusPreset, KeySet, TestCluster};
use k256::ecdsa::SigningKey;
use local_storage::{
    r#trait::{LocalStorage, LocalStorageKeys},
    redb::RedbStorage,
};
use std::{
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;

async fn receipt(reader: &HubClient, id: B256, trusted: &ConsensusPublicKey) {
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let Some(proof) = reader.read_receipt(id, trusted).await.unwrap() {
                assert!(proof.verify(id, trusted).unwrap().success());
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap();
}
async fn submit(client: &HubClient, worker: &BlsSigner, trusted: &ConsensusPublicKey, call: Bytes) {
    let wire = worker.sign_native_tx(HUB_ADDRESS, call).unwrap();
    let id = NativeTx::decode_wire(&wire).unwrap().tx_id().0;
    assert_eq!(client.send_native_tx(&wire).await.unwrap(), id);
    receipt(client, id, trusted).await;
}
fn open(
    url: &str,
    trusted: ConsensusPublicKey,
    root: [u8; 32],
    directory: &Path,
    storage: &RedbStorage,
) -> NativeVeraClient {
    NativeVeraClient::open(HubClient::new(url), trusted, root, 9072, directory, storage).unwrap()
}

#[tokio::test]
#[ignore = "requires a built hubd supplied through HUBD_BINARY"]
async fn native_bulletin_recovers_pending_writes_and_serves_threshold_objects() {
    let deployment = 9072;
    let trusted = *KeySet::builder()
        .seed(deployment)
        .build()
        .unwrap()
        .epoch_info()
        .output
        .public()
        .public();
    let mut cluster = TestCluster::builder()
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
    let url = cluster.node(0).rpc_url();
    let reader_url = cluster.node(3).rpc_url();
    let client = HubClient::new(&url);
    let first = client.read_finalized_revision(1, &trusted).await.unwrap();
    let root: B256 = first.parent_hash.parse().unwrap();
    let local = tempfile::tempdir().unwrap();
    let storage = RedbStorage::new(
        "native".into(),
        local.path().join("keys.redb").to_string_lossy().into(),
    )
    .unwrap();
    storage
        .set_encrypted(
            LocalStorageKeys::NodeSigningKey,
            Zeroizing::new(vec![31; 32]),
        )
        .unwrap();
    let authority = SigningKey::from_slice(&[31; 32]).unwrap();
    let actor = hub_crypto::secp256k1::did_from_secp256k1_pubkey(
        authority.verifying_key().to_sec1_bytes().as_ref(),
    )
    .unwrap();
    let directory = local.path().join("worker");
    let writer = open("http://127.0.0.1:1", trusted, root.0, &directory, &storage);
    let node_key = writer.node_key();
    let info = NodeInfo {
        peer_id: node_key.clone(),
        controller_key: node_key.clone(),
        whitelisted_policy_ids: vec![],
        whitelisted_ring_ids: vec![],
    };
    let backend = NativeBulletin::connect(
        writer,
        HubClient::new(&reader_url),
        30,
        Duration::from_secs(1),
    )
    .await
    .unwrap();
    let node_payload = serde_json::to_vec(&info).unwrap();
    assert!(backend
        .post(BulletinWriteKind::NodeInfo, node_payload.clone())
        .await
        .is_err());
    drop(backend);
    let writer = open(&url, trusted, root.0, &directory, &storage);
    assert!(writer.pending_id().unwrap().is_some());
    let backend = NativeBulletin::connect(
        writer,
        HubClient::new(&reader_url),
        30,
        Duration::from_secs(30),
    )
    .await
    .unwrap();
    assert_eq!(
        backend
            .post(BulletinWriteKind::NodeInfo, node_payload.clone())
            .await
            .unwrap(),
        node_key
    );
    assert_eq!(
        backend
            .post(BulletinWriteKind::NodeInfo, node_payload)
            .await
            .unwrap(),
        node_key
    );
    let restored: NodeInfo = backend
        .read(node_key.clone(), BulletinKind::NodeInfo)
        .await
        .unwrap()
        .try_into()
        .unwrap();
    assert_eq!(restored, info);

    let worker = BlsSigner::new(7u64.into(), deployment).unwrap();
    let created = client.native_create_policy(&worker, b"name: ring_objects\nresources:\n  - name: ring_policy\n    relations:\n      - name: creator\n    permissions:\n      - name: create_ring\n        expr: creator\n  - name: ring\n", 1).await.unwrap();
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
    let token = create_scoped_bearer_token(
        &authority,
        worker.did(),
        deployment,
        now,
        now + 300,
        DelegationScope::ManageRings,
    )
    .unwrap();
    let mut config = RingConfig {
        policy_id: policy.clone(),
        peer_node_keys: vec![node_key],
        threshold: 1,
        pss_interval: 86400,
        current_version: 0,
        nonce: [1; 32],
        trusted_auth_relay_dids: None,
        reporting: ReportingConfig::default(),
    };
    let ring_id = config.id(root.0, &actor).unwrap();
    submit(
        &client,
        &worker,
        &trusted,
        encode_ring_command(&RingCommand::Create(config.clone()), &token).unwrap(),
    )
    .await;
    let ring_key = hex::encode(
        blst::min_pk::SecretKey::key_gen(&[42; 32], &[])
            .unwrap()
            .sk_to_pk()
            .to_bytes(),
    );
    let finalization = serde_json::to_vec(&RingFinalizationPayload {
        ring_id: ring_id.clone(),
        ring_pk: ring_key.clone(),
    })
    .unwrap();
    assert!(backend
        .post(BulletinWriteKind::Finalize, finalization.clone())
        .await
        .is_err());
    let node_key = config.peer_node_keys[0].clone();
    let sequence = client
        .read_threshold_node(&node_key, 0, &trusted)
        .await
        .unwrap()
        .record
        .unwrap()
        .sequence;
    let allow = hub_client::nodes::sign_node_request(
        hub_client::nodes::NodeRequest {
            deployment_root: root.0,
            deployment_id: deployment,
            node_key,
            sequence,
            expires_at: now + 300,
            command: hub_client::nodes::NodeCommand::Allow(hub_client::nodes::NodeTarget::Policy(
                policy.clone(),
            )),
        },
        &authority,
    )
    .unwrap();
    submit(
        &client,
        &worker,
        &trusted,
        hub_client::nodes::encode_node_request(&allow).unwrap(),
    )
    .await;
    assert_eq!(
        backend
            .post(BulletinWriteKind::Finalize, finalization.clone())
            .await
            .unwrap(),
        ring_id
    );
    assert_eq!(
        backend
            .post(BulletinWriteKind::Finalize, finalization)
            .await
            .unwrap(),
        ring_id
    );
    let ring: RingPayload = backend
        .read(ring_id.clone(), BulletinKind::Ring)
        .await
        .unwrap()
        .try_into()
        .unwrap();
    assert_eq!(ring.ring_pk, ring_key);
    let document = DocumentPayload {
        ring_id: ring_id.clone(),
        document: r#"{"enc_cmt":[1],"encrypted_data":[2],"nonce":[3]}"#.into(),
        proof: r#"{"challenge":[4],"response":[5]}"#.into(),
        policy_id: policy.clone(),
        resource: "document".into(),
        permission: "read".into(),
        tier: Some("gold".into()),
        timestamp: Some(now),
    };
    let payload = serde_json::to_vec(&document).unwrap();
    let document_id = backend
        .post(BulletinWriteKind::Document, payload.clone())
        .await
        .unwrap();
    assert_eq!(
        backend
            .post(BulletinWriteKind::Document, payload)
            .await
            .unwrap(),
        document_id
    );
    let restored: DocumentPayload = backend
        .read(document_id.clone(), BulletinKind::Document)
        .await
        .unwrap()
        .try_into()
        .unwrap();
    assert_eq!(restored, document);
    let derivation = KeyDerivation {
        ring_id,
        derivation: "tenant/key".into(),
        policy_id: policy,
        resource: "document".into(),
        permission: "sign".into(),
    };
    let derivation_id = backend
        .post(
            BulletinWriteKind::KeyDerivation,
            serde_json::to_vec(&derivation).unwrap(),
        )
        .await
        .unwrap();
    let restored: KeyDerivation = backend
        .read(derivation_id.clone(), BulletinKind::KeyDerivation)
        .await
        .unwrap()
        .try_into()
        .unwrap();
    assert_eq!(restored, derivation);
    config.nonce = [2; 32];
    let pending_id = config.id(root.0, &actor).unwrap();
    submit(
        &client,
        &worker,
        &trusted,
        encode_ring_command(&RingCommand::Create(config), &token).unwrap(),
    )
    .await;
    let cancel = serde_json::to_vec(&RingCancellationPayload {
        ring_id: pending_id.clone(),
    })
    .unwrap();
    backend
        .post(BulletinWriteKind::CancelPendingRing, cancel.clone())
        .await
        .unwrap();
    backend
        .post(BulletinWriteKind::CancelPendingRing, cancel)
        .await
        .unwrap();
    assert!(backend.read(pending_id, BulletinKind::Ring).await.is_err());
    drop(backend);
    cluster.restart_node(3).unwrap();
    cluster.wait_ready(Duration::from_secs(30)).await.unwrap();
    let writer = open(&url, trusted, root.0, &directory, &storage);
    assert!(writer.pending_id().unwrap().is_none());
    let backend = NativeBulletin::connect(
        writer,
        HubClient::new(&reader_url),
        30,
        Duration::from_secs(30),
    )
    .await
    .unwrap();
    let restored: DocumentPayload = backend
        .read(document_id, BulletinKind::Document)
        .await
        .unwrap()
        .try_into()
        .unwrap();
    assert_eq!(restored, document);
    let restored: KeyDerivation = backend
        .read(derivation_id, BulletinKind::KeyDerivation)
        .await
        .unwrap()
        .try_into()
        .unwrap();
    assert_eq!(restored, derivation);
}

#[tokio::test]
#[ignore = "requires a built hubd supplied through HUBD_BINARY"]
async fn native_report_and_reshare_recover_certified_completion() {
    use bulletin::native::{RingParticipantCommand, RingUpdate};
    use bulletin::r#trait::BulletinReportSubmission;
    use hub_client::rings::{CommitteeScope, NodeOffline, ReportEnvelope};
    let deployment = 9072;
    let trusted = *KeySet::builder()
        .seed(deployment)
        .build()
        .unwrap()
        .epoch_info()
        .output
        .public()
        .public();
    let mut cluster = TestCluster::builder()
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
    let url = cluster.node(0).rpc_url();
    let reader_url = cluster.node(3).rpc_url();
    let client = HubClient::new(&url);
    let root: B256 = client
        .read_finalized_revision(1, &trusted)
        .await
        .unwrap()
        .parent_hash
        .parse()
        .unwrap();
    let worker = BlsSigner::new(7u64.into(), deployment).unwrap();
    let authority = SigningKey::from_slice(&[40; 32]).unwrap();
    let actor = hub_crypto::secp256k1::did_from_secp256k1_pubkey(
        authority.verifying_key().to_sec1_bytes().as_ref(),
    )
    .unwrap();
    let created = client.native_create_policy(&worker, b"name: recovery\nresources:\n  - name: ring_policy\n    relations:\n      - name: creator\n    permissions:\n      - name: create_ring\n        expr: creator\n  - name: ring\n    relations:\n      - name: operator\n    permissions:\n      - name: update_ring\n        expr: operator\n", 1).await.unwrap();
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
    let local = tempfile::tempdir().unwrap();
    let mut stores = Vec::new();
    let mut writers = Vec::new();
    let mut peers = Vec::new();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    for index in 0..3u8 {
        let storage = RedbStorage::new(
            "test".into(),
            local
                .path()
                .join(format!("keys-{index}.redb"))
                .to_string_lossy()
                .into(),
        )
        .unwrap();
        storage
            .set_encrypted(
                LocalStorageKeys::NodeSigningKey,
                Zeroizing::new(vec![40 + index; 32]),
            )
            .unwrap();
        let mut writer = open(
            &url,
            trusted,
            root.0,
            &local.path().join(format!("worker-{index}")),
            &storage,
        );
        let key = writer.node_key();
        writer
            .prepare_node_registration(
                NodeInfo {
                    peer_id: key.clone(),
                    controller_key: key.clone(),
                    whitelisted_policy_ids: vec![policy.clone()],
                    whitelisted_ring_ids: vec![],
                },
                now + 300,
            )
            .unwrap();
        let id = writer.submit_pending().await.unwrap();
        receipt(&client, id, &trusted).await;
        assert!(writer.confirm_pending().await.unwrap().unwrap().success());
        peers.push(key);
        writers.push(writer);
        stores.push(storage);
    }
    let mut sorted = peers.clone();
    sorted.sort();
    let config = RingConfig {
        policy_id: policy.clone(),
        peer_node_keys: sorted,
        threshold: 2,
        pss_interval: 86400,
        current_version: 0,
        nonce: [4; 32],
        trusted_auth_relay_dids: None,
        reporting: ReportingConfig::default(),
    };
    let ring_id = config.id(root.0, &actor).unwrap();
    let token = create_scoped_bearer_token(
        &authority,
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
    )
    .await;
    let ring_secret = blst::min_pk::SecretKey::key_gen(&[53; 32], &[]).unwrap();
    let ring_pk = hex::encode(ring_secret.sk_to_pk().to_bytes());
    for writer in &mut writers {
        writer
            .prepare_ring_participant_request(
                ring_id.clone(),
                RingParticipantCommand::Confirm(ring_pk.clone()),
                now + 300,
            )
            .unwrap();
        let id = writer.submit_pending().await.unwrap();
        receipt(&client, id, &trusted).await;
        assert!(writer.confirm_pending().await.unwrap().unwrap().success());
    }
    drop(writers);
    let current = client
        .read_threshold_ring(&ring_id, 1, &trusted)
        .await
        .unwrap()
        .record
        .unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let report = ReportEnvelope {
        domain: "orbis-mpc-fault-report".into(),
        report_type: "node_offline".into(),
        chain_id: format!("vera:{deployment}:{}", hex::encode(root)),
        ring_id: ring_id.clone(),
        ring_pk,
        ring_state_sha256: current.report_state_hash().unwrap(),
        reporter_node_key: peers[0].clone(),
        accused_node_key: peers[1].clone(),
        accused_peer_id: peers[1].clone(),
        observed_at: now - 10,
        expires_at: now + 110,
        session_id: "report-recovery".into(),
        payload: NodeOffline {
            origin_protocol: "pre".into(),
            origin_protocol_version: 0,
            accused_committee_scope: CommitteeScope::Current,
            signing_committee_scope: CommitteeScope::Current,
        }
        .canonical_bytes(),
    };
    let scheme = "bls12_381_g1_pk_g2_sig_nul";
    let signature = ring_secret
        .sign(
            &report.canonical_bytes(),
            b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_",
            &[],
        )
        .to_bytes()
        .to_vec();
    let report = BulletinReportSubmission {
        report_id: report.report_id(),
        domain: report.domain,
        report_type: report.report_type,
        chain_id: report.chain_id,
        ring_id: report.ring_id,
        ring_pk: report.ring_pk,
        ring_state_sha256: report.ring_state_sha256,
        reporter_node_key: report.reporter_node_key,
        accused_node_key: report.accused_node_key,
        accused_peer_id: report.accused_peer_id,
        observed_at: report.observed_at,
        expires_at: report.expires_at,
        payload: report.payload,
        session_id: report.session_id,
        signature_scheme: scheme.into(),
        signature,
    };
    let directory = local.path().join("worker-0");
    let journal = directory.join("state.json");
    let disconnected = || {
        open(
            "http://127.0.0.1:1",
            trusted,
            root.0,
            &directory,
            &stores[0],
        )
    };
    let backend = NativeBulletin::connect(
        disconnected(),
        HubClient::new(&reader_url),
        30,
        Duration::from_secs(1),
    )
    .await
    .unwrap();
    assert!(backend.submit_report(report.clone()).await.is_err());
    drop(backend);
    let writer = open(&url, trusted, root.0, &directory, &stores[0]);
    let report_id = writer.pending_id().unwrap().unwrap();
    writer.submit_pending().await.unwrap();
    receipt(&client, report_id, &trusted).await;
    drop(writer);
    cluster.restart_node(3).unwrap();
    cluster.wait_ready(Duration::from_secs(30)).await.unwrap();
    let retained = std::fs::read(&journal).unwrap();
    let backend = NativeBulletin::connect(
        disconnected(),
        HubClient::new(&reader_url),
        30,
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    backend.submit_report(report.clone()).await.unwrap();
    backend.submit_report(report).await.unwrap();
    assert_eq!(retained, std::fs::read(&journal).unwrap());

    let granted = client
        .native_set_relationship(&worker, policy_bytes, "ring", &ring_id, "operator", &actor)
        .await
        .unwrap();
    receipt(&client, granted.transaction_hash, &trusted).await;
    let current = client
        .read_threshold_ring(&ring_id, 1, &trusted)
        .await
        .unwrap()
        .record
        .unwrap();
    submit(
        &client,
        &worker,
        &trusted,
        encode_ring_command(
            &RingCommand::Update {
                ring_id: ring_id.clone(),
                expected_sequence: current.sequence,
                update: RingUpdate::StartReshare {
                    peer_node_keys: None,
                    threshold: Some(3),
                },
            },
            &token,
        )
        .unwrap(),
    )
    .await;
    let pending = client
        .read_threshold_ring(&ring_id, 1, &trusted)
        .await
        .unwrap()
        .record
        .unwrap();
    let signature = ring_secret
        .sign(
            &pending.reshare_signing_bytes(deployment).unwrap(),
            b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_",
            &[],
        )
        .to_bytes()
        .to_vec();
    assert!(backend
        .update(ring_id.clone(), scheme.into(), signature.clone())
        .await
        .is_err());
    drop(backend);
    let writer = open(&url, trusted, root.0, &directory, &stores[0]);
    let reshare_id = writer.pending_id().unwrap().unwrap();
    assert_ne!(report_id, reshare_id);
    writer.submit_pending().await.unwrap();
    receipt(&client, reshare_id, &trusted).await;
    drop(writer);
    let retained = std::fs::read(&journal).unwrap();
    let backend = NativeBulletin::connect(
        disconnected(),
        HubClient::new(&reader_url),
        30,
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    backend
        .update(ring_id.clone(), scheme.into(), signature.clone())
        .await
        .unwrap();
    backend
        .update(ring_id.clone(), scheme.into(), signature)
        .await
        .unwrap();
    assert_eq!(retained, std::fs::read(&journal).unwrap());
    let finalized = client
        .read_threshold_ring(&ring_id, 1, &trusted)
        .await
        .unwrap()
        .record
        .unwrap();
    assert_eq!(finalized.sequence, pending.sequence + 1);
    assert_eq!(finalized.current_settings().threshold, 3);
    assert!(finalized.current_settings().pending_reshare.is_none());
}
