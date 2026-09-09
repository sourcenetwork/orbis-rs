#[cfg(feature = "bls12-381")]
#[path = "support/defra_peers.rs"]
mod defra_peers;

#[cfg(feature = "bls12-381")]
#[path = "support/defra_documents.rs"]
mod defra_documents;

use commonware_codec::Encode;
use hub_client::HubClient;
use hub_harness::cluster::{ConsensusPreset, KeySet, TestCluster};
use proto::info_service::{
    info_service_client::InfoServiceClient, GetNodeInfoRequest, GetNodeInfoResponse, NodeStatus,
};
use std::{
    fs,
    net::TcpListener,
    path::Path,
    process::{Child, Command, Stdio},
    time::Duration,
};

struct Node(Child);
impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
impl Node {
    fn start(base: &Path, addr: &str, controller: &str, log: &Path) -> Self {
        Self::start_bound(base, addr, controller, log, "127.0.0.1:0")
    }

    fn start_bound(base: &Path, addr: &str, controller: &str, log: &Path, bind: &str) -> Self {
        let output = fs::File::create(log).unwrap();
        Self(
            Command::new(env!("CARGO_BIN_EXE_orbis-node"))
                .arg("--vera-config")
                .arg(base.join("vera.json"))
                .args([
                    "--addr",
                    addr,
                    "--node-controller-key",
                    controller,
                    "--network-private-routes-only",
                    "--network-bind-addr",
                    bind,
                    "--reshare-interval-secs",
                    "1",
                ])
                .arg("--runtime-base-path")
                .arg(base)
                .env("ORBIS_PASSWORD_FILE", base.join("password"))
                .stdin(Stdio::null())
                .stdout(output.try_clone().unwrap())
                .stderr(output)
                .spawn()
                .unwrap(),
        )
    }
    async fn ready(&mut self, addr: &str, log: &Path) -> GetNodeInfoResponse {
        tokio::time::timeout(Duration::from_secs(40), async {
            loop {
                assert!(
                    self.0.try_wait().unwrap().is_none(),
                    "node exited: {}",
                    fs::read_to_string(log).unwrap()
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
        .unwrap_or_else(|_| panic!("startup timed out: {}", fs::read_to_string(log).unwrap()))
    }
    async fn stop(&mut self) {
        if let Some(status) = self.0.try_wait().unwrap() {
            assert!(status.success(), "{status}");
            return;
        }
        assert!(Command::new("kill")
            .args(["-INT", &self.0.id().to_string()])
            .status()
            .unwrap()
            .success());
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if let Some(status) = self.0.try_wait().unwrap() {
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

#[tokio::test]
#[ignore = "requires a built hubd supplied through HUBD_BINARY"]
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
    let url = cluster.node(0).rpc_url();
    let client = HubClient::new(&url);
    let first = client.read_finalized_revision(1, &trusted).await.unwrap();
    let root = first.parent_hash.trim_start_matches("0x");
    let base = tempfile::tempdir().unwrap();
    fs::write(base.path().join("password"), "native-startup-test").unwrap();
    fs::write(
        base.path().join("vera.json"),
        serde_json::to_vec(&serde_json::json!({
            "endpoint": url, "deployment_id": deployment, "deployment_root": root,
            "consensus_key": hex::encode(trusted.encode()),
        }))
        .unwrap(),
    )
    .unwrap();
    let controller = hex::encode(
        k256::ecdsa::SigningKey::from_slice(&[33; 32])
            .unwrap()
            .verifying_key()
            .to_sec1_bytes(),
    );
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    drop(listener);
    let log = base.path().join("first.log");
    let mut node = Node::start(base.path(), &addr, &controller, &log);
    let first_info = node.ready(&addr, &log).await;
    assert_eq!(first_info.node_key, first_info.public_address);
    assert_eq!(
        fs::read_to_string(base.path().join("public_key.txt")).unwrap(),
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
        .join("native-vera")
        .join(root)
        .join("state.json");
    let before = fs::read(&journal).unwrap();
    let log = base.path().join("restart.log");
    let mut restarted = Node::start(base.path(), &addr, &controller, &log);
    let second_info = restarted.ready(&addr, &log).await;
    assert_eq!(first_info.node_key, second_info.node_key);
    assert_eq!(first_info.peer_id, second_info.peer_id);
    restarted.stop().await;
    assert_eq!(before, fs::read(&journal).unwrap());
}

async fn confirmed(
    client: &HubClient,
    id: alloy_primitives::B256,
    trusted: &hub_domain::ConsensusPublicKey,
) {
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

async fn submit(
    client: &HubClient,
    worker: &hub_client::BlsSigner,
    trusted: &hub_domain::ConsensusPublicKey,
    call: alloy_primitives::Bytes,
) {
    let wire = worker
        .sign_native_tx(hub_client::HUB_ADDRESS, call)
        .unwrap();
    let id = client.send_native_tx(&wire).await.unwrap();
    confirmed(client, id, trusted).await;
}

#[tokio::test]
#[ignore = "requires a built hubd supplied through HUBD_BINARY"]
#[cfg(feature = "bls12-381")]
#[serial_test::serial(defra_signing)]
async fn native_distributed_threshold_workflows() {
    distributed_threshold_workflows(false).await;
}

#[tokio::test]
#[ignore = "requires a built hubd supplied through HUBD_BINARY"]
#[cfg(feature = "bls12-381")]
#[serial_test::serial(defra_signing)]
async fn native_defra_signing() {
    distributed_threshold_workflows(true).await;
}

#[cfg(feature = "bls12-381")]
async fn distributed_threshold_workflows(signing_only: bool) {
    use alloy_primitives::B256;
    use authn::jwt_builder::{create_authenticated_request, JwtSigner};
    use crypto::r#trait::{CryptoDeserialize, ThresholdSigner};
    use hub_client::{
        create_scoped_bearer_token,
        nodes::{encode_node_request, sign_node_request, NodeCommand, NodeRequest, NodeTarget},
        rings::{
            encode_ring_command, ReportingConfig, RingCommand, RingConfig, RingState, RingUpdate,
        },
        threshold_objects::{encode_threshold_object, KeyDerivation, ThresholdObject},
        BlsSigner, DelegationScope,
    };
    use proto::{
        info_service::GetRingStateRequest,
        v0::{
            dkg::{dkg_service_client::DkgServiceClient, StartDkgRequest},
            sign::{sign_service_client::SignServiceClient, StartSignRequest},
        },
    };
    let deployment = 9074;
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
    let url = cluster.node(0).rpc_url();
    let client = HubClient::new(&url);
    let first = client.read_finalized_revision(1, &trusted).await.unwrap();
    let root: B256 = first.parent_hash.parse().unwrap();
    let controller = k256::ecdsa::SigningKey::from_slice(&[34; 32]).unwrap();
    let controller_key = hex::encode(controller.verifying_key().to_sec1_bytes());
    let actor = hub_crypto::secp256k1::did_from_secp256k1_pubkey(
        controller.verifying_key().to_sec1_bytes().as_ref(),
    )
    .unwrap();
    let base = tempfile::tempdir().unwrap();
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
        nodes.push(Node::start(&directory, &addr, &controller_key, &log));
        addresses.push(addr);
        logs.push(log);
    }
    let mut infos = Vec::new();
    for index in 0..nodes.len() {
        infos.push(nodes[index].ready(&addresses[index], &logs[index]).await);
    }
    let worker = BlsSigner::new(7u64.into(), deployment).unwrap();
    let policy_schema = b"name: native_threshold\nresources:\n  - name: ring_policy\n    relations:\n      - name: creator\n    permissions:\n      - name: create_ring\n        expr: creator\n  - name: ring\n    relations:\n      - name: operator\n    permissions:\n      - name: update_ring\n        expr: operator\n  - name: key\n    relations:\n      - name: signer\n    permissions:\n      - name: sign\n        expr: signer\n  - name: document\n    relations:\n      - name: reader\n    permissions:\n      - name: read\n        expr: reader\n";
    let created = client
        .native_create_policy(&worker, policy_schema, 1)
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
    )
    .await;
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
                RingState::Active { public_key } => break public_key,
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
        node.stop().await;
    }
    for index in 0..nodes.len() {
        let directory = base.path().join(format!("node-{index}"));
        let log = directory.join("restart.log");
        let bind = infos[index].p2p_address.split_once('@').unwrap().1;
        nodes[index] =
            Node::start_bound(&directory, &addresses[index], &controller_key, &log, bind);
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
    let defra = std::sync::Arc::new(
        defra_orbis::OrbisClient::new(
            format!("http://{}", addresses[1]),
            derivation_id.clone(),
            derived_key.to_bytes().unwrap(),
            service_identity,
        )
        .await
        .unwrap(),
    );
    let documents =
        defra_documents::Documents::new(&base.path().join("defra"), defra.clone()).await;
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
    assert!(defra_sign().await.unwrap().is_err());
    assert!(documents.create("denied").await.is_err());
    assert_eq!(documents.count().await, 0);
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
    assert!(defra_sign().await.unwrap().is_err());
    assert!(documents.create("revoked").await.is_err());
    assert_eq!(documents.count().await, 1);
    documents.verify(&created, defra.signer_did()).await;
    peers.verify_revocation().await;
    peers.shutdown().await;
    if signing_only {
        return;
    }
    use ark_ec::{AffineRepr, CurveGroup};
    use crypto::r#trait::{CryptoSerialize, ThresholdDealer};
    use proto::v0::{
        pre::{pre_service_client::PreServiceClient, ReaderKeyProof, StartPreRequest},
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
    let reader_public = (crypto::GroupAffine::generator() * reader_secret).into_affine();
    let reader_proof = crypto::PreImpl::prove_reader_key(&reader_secret, &reader_public).unwrap();
    let reader_bytes = reader_public.to_bytes().unwrap();
    let pre_request = || {
        create_authenticated_request(
            StartPreRequest {
                rdr_pk: reader_bytes.clone(),
                object_id: stored.object_id.clone(),
                derivation: None,
                salt: None,
                valid_window: None,
                document: None,
                rdr_pk_proof: Some(ReaderKeyProof {
                    challenge: reader_proof.challenge.clone(),
                    response: reader_proof.response.clone(),
                }),
            },
            &reader
                .create_pre_jwt(reader_bytes.clone(), &stored.object_id, None, None)
                .unwrap(),
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
    let directory = base.path().join("node-3");
    fs::create_dir(&directory).unwrap();
    fs::write(directory.join("password"), "native-dkg-test").unwrap();
    fs::copy(
        base.path().join("node-0/vera.json"),
        directory.join("vera.json"),
    )
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    drop(listener);
    let log = directory.join("node.log");
    let mut incoming = Node::start(&directory, &addr, &controller_key, &log);
    let info = incoming.ready(&addr, &log).await;
    assert_eq!(info.managed_ring_count, 0);
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
        )
        .await;
    }
    nodes.push(incoming);
    infos.push(info);
    addresses.push(addr);
    logs.push(log);
    let granted = client
        .native_set_relationship(
            &worker,
            policy_bytes,
            "ring",
            &derivation.ring_id,
            "operator",
            &actor,
        )
        .await
        .unwrap();
    confirmed(&client, granted.transaction_hash, &trusted).await;
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
    )
    .await;
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
                    public_key: ring_pk.clone()
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
            for name in ["node.log", "restart.log"] {
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
            let score = client
                .read_threshold_node_demerits(&derivation.ring_id, &infos[1].node_key, 1, &trusted)
                .await
                .unwrap();
            if let Some(score) = score.record {
                assert!(score.points > 0);
                break;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        let mut output = String::new();
        for index in 2..nodes.len() {
            for name in ["node.log", "restart.log"] {
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
