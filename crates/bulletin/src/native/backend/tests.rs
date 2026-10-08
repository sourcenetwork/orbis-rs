use super::*;
use commonware_math::algebra::CryptoGroup;
use serde_json::{json, Value};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::TcpListener,
};

#[tokio::test]
async fn completion_retries_failed_submission_without_replacing_pending_request() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let root = tempfile::tempdir().unwrap();
    let storage = RedbStorage::new(
        "test".into(),
        root.path().join("keys.redb").to_string_lossy().into_owned(),
    )
    .unwrap();
    storage
        .set_encrypted(
            LocalStorageKeys::NodeSigningKey,
            Zeroizing::new(hex::encode([31; 32]).into_bytes()),
        )
        .unwrap();
    let mut writer = NativeVeraClient::open(
        VeraClient::new(&url),
        ConsensusPublicKey::generator(),
        [7; 32],
        9001,
        &root.path().join("worker"),
        &storage,
    )
    .unwrap();
    let id = writer.prepare_call(Bytes::from_static(b"pending")).unwrap();
    let wire = writer.worker.pending().unwrap().to_vec();
    let expected_wire = format!("0x{}", hex::encode(&wire));
    let server = tokio::spawn(async move {
        let mut submissions = 0;
        let mut reads = 0;
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = BufReader::new(stream);
            let mut length = None;
            loop {
                let mut line = String::new();
                assert_ne!(stream.read_line(&mut line).await.unwrap(), 0);
                if line == "\r\n" {
                    break;
                }
                if let Some((name, value)) = line.split_once(':') {
                    if name.eq_ignore_ascii_case("content-length") {
                        length = Some(value.trim().parse::<usize>().unwrap());
                    }
                }
            }
            let mut body = vec![0; length.unwrap()];
            stream.read_exact(&mut body).await.unwrap();
            let request: Value = serde_json::from_slice(&body).unwrap();
            let mut response = json!({"jsonrpc": "2.0", "id": request["id"]});
            match request["method"].as_str().unwrap() {
                "vera_getReceiptProof" => {
                    reads += 1;
                    assert_eq!(request["params"], json!([id]));
                    response["result"] = Value::Null;
                }
                "vera_sendNativeTx" => {
                    submissions += 1;
                    assert_eq!(request["params"], json!([expected_wire]));
                    if submissions == 1 {
                        response["error"] = json!({"code": -32000, "message": "busy"});
                    } else {
                        response["result"] = json!(id);
                    }
                }
                method => panic!("unexpected method: {method}"),
            }
            if reads == 4 {
                response.as_object_mut().unwrap().remove("result");
                response["error"] = json!({"code": -32000, "message": "end of fixture"});
            }
            let body = serde_json::to_vec(&response).unwrap();
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(header.as_bytes()).await.unwrap();
            stream.write_all(&body).await.unwrap();
            stream.flush().await.unwrap();
            if reads == 4 {
                return submissions;
            }
        }
    });
    let backend = NativeBulletin {
        reader: VeraClient::new(&url),
        trusted: writer.trusted,
        namespace: writer.deployment_label(),
        writer: Mutex::new(writer),
        minimum: AtomicU64::new(1),
        maximum_age: 30,
        timeout: Duration::from_secs(5),
    };
    let writer = backend.writer.lock().await;
    let result = tokio::time::timeout(backend.timeout, backend.completion(&writer))
        .await
        .unwrap();
    assert!(result.unwrap_err().to_string().contains("end of fixture"));
    assert_eq!(server.await.unwrap(), 2);
    assert_eq!(writer.pending_id().unwrap(), Some(id));
    assert_eq!(writer.worker.pending().unwrap(), wire);
}

#[test]
fn native_report_session_retention_checks_expiry_and_record_integrity() {
    assert!(!report_session_is_current(None, 10).unwrap());
    let mut record = 10_u64.to_be_bytes().to_vec();
    record.extend_from_slice("ab".repeat(32).as_bytes());
    assert!(report_session_is_current(Some(&record), 10).unwrap());
    assert!(!report_session_is_current(Some(&record), 11).unwrap());
    assert!(report_session_is_current(Some(&record[..71]), 10).is_err());
    record[8] = b'X';
    assert!(report_session_is_current(Some(&record), 10).is_err());
}

#[test]
fn native_report_session_key_matches_v1_wire_fixture() {
    let key = unauthorized_report_session_key(
        "vera-9001",
        &"ab".repeat(32),
        "pre",
        "accused",
        "request-1",
    )
    .unwrap();
    assert_eq!(String::from_utf8(key).unwrap(), "orbis/reports/v1/abababababababababababababababababababababababababababababababab/session/a78a03bb7ad825dcab71cad43ee60814b1072afcd1c1ad2ba6f46a83e02492e0");
    assert!(
        unauthorized_report_session_key("vera-9001", "invalid", "pre", "accused", "request-1")
            .is_err()
    );
}

fn read_fixture(url: &str) -> (tempfile::TempDir, NativeBulletin) {
    let root = tempfile::tempdir().unwrap();
    let storage = RedbStorage::new(
        "test".into(),
        root.path().join("keys.redb").to_string_lossy().into_owned(),
    )
    .unwrap();
    storage
        .set_encrypted(
            LocalStorageKeys::NodeSigningKey,
            Zeroizing::new(hex::encode([31; 32]).into_bytes()),
        )
        .unwrap();
    let writer = NativeVeraClient::open(
        VeraClient::new(url),
        ConsensusPublicKey::generator(),
        [7; 32],
        9001,
        &root.path().join("worker"),
        &storage,
    )
    .unwrap();
    let backend = NativeBulletin {
        reader: VeraClient::new(url),
        trusted: writer.trusted,
        namespace: writer.deployment_label(),
        writer: Mutex::new(writer),
        minimum: AtomicU64::new(5),
        maximum_age: 30,
        timeout: Duration::from_millis(200),
    };
    (root, backend)
}

#[test]
fn overlapping_reads_validate_their_requested_minimum() {
    let (_root, backend) = read_fixture("http://127.0.0.1:1");
    let requested = backend.minimum.load(Ordering::Acquire);
    let timestamp = now().unwrap();
    backend.observe(requested, 12, timestamp).unwrap();
    backend.observe(requested, 10, timestamp).unwrap();
    assert_eq!(backend.minimum.load(Ordering::Acquire), 12);
    assert!(backend.observe(12, 10, timestamp).is_err());
    assert!(backend.observe(12, 20, timestamp - 31).is_err());
    assert!(backend.observe(12, 20, timestamp + 60).is_err());
    assert_eq!(backend.minimum.load(Ordering::Acquire), 12);
}

#[tokio::test]
async fn reads_and_ring_status_honor_configured_deadline() {
    for kind in [
        Some(BulletinKind::Ring),
        Some(BulletinKind::Document),
        Some(BulletinKind::KeyDerivation),
        Some(BulletinKind::NodeInfo),
        None,
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (_root, backend) = read_fixture(&format!("http://{}", listener.local_addr().unwrap()));
        let (sent, mut received) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut byte = [0];
            stream.read_exact(&mut byte).await.unwrap();
            sent.send(()).unwrap();
            std::future::pending::<()>().await;
        });
        let result = tokio::time::timeout(Duration::from_secs(1), async {
            match kind {
                Some(kind) => {
                    let id = if kind == BulletinKind::NodeInfo {
                        backend.writer.lock().await.node_key()
                    } else {
                        "ab".repeat(32)
                    };
                    backend.read(id, kind).await.map(|_| ())
                }
                None => backend
                    .ring_finalization_status("ab".repeat(32))
                    .await
                    .map(|_| ()),
            }
        })
        .await
        .expect("configured deadline must precede the client timeout");
        let message = result.unwrap_err().to_string();
        assert!(message.contains("deadline exceeded"), "{message}");
        received.try_recv().expect("read must reach the server");
        server.abort();
        let _ = server.await;
    }
}

fn ring_fixture(writer: &NativeVeraClient, requires_pet: bool, state: RingState) -> RingRecord {
    let creator =
        vera_crypto::secp256k1::did_from_secp256k1_pubkey(&hex::decode(writer.node_key()).unwrap())
            .unwrap();
    let second = SigningKey::from_slice(&[32; 32]).unwrap();
    let mut peers = vec![
        writer.node_key(),
        hex::encode(second.verifying_key().to_sec1_bytes()),
    ];
    peers.sort();
    let config = RingConfig {
        policy_id: "11".repeat(32),
        peer_node_keys: peers,
        threshold: 2,
        pss_interval: 86400,
        current_version: 0,
        requires_pet,
        nonce: [4; 32],
        trusted_auth_relay_dids: None,
        reporting: Default::default(),
    };
    let record = RingRecord {
        id: config.id(writer.deployment_root, &creator).unwrap(),
        deployment_root: writer.deployment_root,
        creator,
        config,
        state,
        revision: serde_json::from_value(json!({"seconds": 100, "block_height": 5})).unwrap(),
        settings: None,
        sequence: 1,
    };
    record.validate(&record.id).unwrap();
    record
}

#[tokio::test]
async fn finalization_retries_require_the_entire_confirmed_pair() {
    for pet_public_key in [None, Some("ccdd".to_owned())] {
        let (root, backend) = read_fixture("http://127.0.0.1:1");
        let mut writer = backend.writer.lock().await;
        let keys = RingPublicKeys {
            public_key: "aabb".into(),
            pet_public_key,
        };
        let journal = root.path().join("worker/state.json");
        let before = std::fs::read(&journal).unwrap();
        for state in [
            RingState::Active { keys: keys.clone() },
            RingState::Pending {
                keys: Some(keys.clone()),
                confirmations: vec![writer.node_key()],
            },
        ] {
            let record = ring_fixture(&writer, keys.pet_public_key.is_some(), state);
            assert!(!prepare_finalization(&mut writer, &record, keys.clone(), 200).unwrap());
            assert!(writer.pending_id().unwrap().is_none());
            assert_eq!(std::fs::read(&journal).unwrap(), before);
        }
    }
}

#[tokio::test]
async fn different_pet_key_or_missing_confirmation_is_not_acknowledged() {
    for (active, confirmed, same_pet) in [
        (true, true, false),
        (false, true, false),
        (false, false, true),
    ] {
        let (_root, backend) = read_fixture("http://127.0.0.1:1");
        let mut writer = backend.writer.lock().await;
        let requested = RingPublicKeys {
            public_key: "aabb".into(),
            pet_public_key: Some("ccdd".into()),
        };
        let stored = RingPublicKeys {
            public_key: requested.public_key.clone(),
            pet_public_key: Some(if same_pet { "ccdd" } else { "eeff" }.into()),
        };
        let state = if active {
            RingState::Active { keys: stored }
        } else {
            let participant = if confirmed {
                writer.node_key()
            } else {
                hex::encode(
                    SigningKey::from_slice(&[32; 32])
                        .unwrap()
                        .verifying_key()
                        .to_sec1_bytes(),
                )
            };
            RingState::Pending {
                keys: Some(stored),
                confirmations: vec![participant],
            }
        };
        let record = ring_fixture(&writer, true, state);
        assert!(prepare_finalization(&mut writer, &record, requested.clone(), 200).unwrap());
        let expected = sign_ring_participant_request(
            RingParticipantRequest {
                deployment_root: writer.deployment_root,
                deployment_id: writer.worker.deployment_id(),
                ring_id: record.id,
                node_key: writer.node_key(),
                command: RingParticipantCommand::Confirm(requested),
                expires_at: 200,
            },
            &writer.authority,
        )
        .unwrap();
        assert_eq!(
            writer.pending_call().unwrap(),
            Some(encode_ring_participant_request(&expected).unwrap())
        );
    }
}

#[tokio::test]
async fn invalid_finalization_pair_leaves_the_journal_unchanged() {
    let (root, backend) = read_fixture("http://127.0.0.1:1");
    let mut writer = backend.writer.lock().await;
    let journal = root.path().join("worker/state.json");
    let before = std::fs::read(&journal).unwrap();
    for (requires_pet, public_key, pet_public_key) in [
        (true, "aabb", None),
        (false, "aabb", Some("ccdd")),
        (true, "aabb", Some("")),
        (true, "aabb", Some("CCDD")),
        (true, "aabb", Some("not-hex")),
        (true, "AABB", Some("ccdd")),
    ] {
        let record = ring_fixture(
            &writer,
            requires_pet,
            RingState::Pending {
                keys: None,
                confirmations: vec![],
            },
        );
        let requested = RingPublicKeys {
            public_key: public_key.into(),
            pet_public_key: pet_public_key.map(str::to_owned),
        };
        assert!(prepare_finalization(&mut writer, &record, requested, 200).is_err());
        assert!(writer.pending_id().unwrap().is_none());
        assert_eq!(std::fs::read(&journal).unwrap(), before);
    }
}

#[tokio::test]
async fn ring_readback_retains_pet_mode_and_only_finalized_keys() {
    let (_root, backend) = read_fixture("http://127.0.0.1:1");
    let writer = backend.writer.lock().await;
    let keys = RingPublicKeys {
        public_key: "aabb".into(),
        pet_public_key: Some("ccdd".into()),
    };
    let mut record = ring_fixture(
        &writer,
        true,
        RingState::Pending {
            keys: Some(keys.clone()),
            confirmations: vec![writer.node_key()],
        },
    );
    let pending = RingPayload::try_from(ring_post(record.clone()).unwrap()).unwrap();
    assert!(pending.requires_pet);
    assert!(pending.ring_pk.is_empty());
    assert_eq!(pending.pet_pk, None);
    record.state = RingState::Active { keys: keys.clone() };
    let active = RingPayload::try_from(ring_post(record).unwrap()).unwrap();
    assert!(active.requires_pet);
    assert_eq!(active.ring_pk, keys.public_key);
    assert_eq!(active.pet_pk, keys.pet_public_key);
}

#[tokio::test]
async fn incomplete_or_malformed_pet_documents_are_rejected_without_journaling() {
    let (root, backend) = read_fixture("http://127.0.0.1:1");
    let journal = root.path().join("worker/state.json");
    let before = std::fs::read(&journal).unwrap();
    let tag = r#"{"ephemeral_point":[1,1],"masked_fingerprint":[2,2]}"#;
    let proof = r#"{"challenge":[3,3],"response":[4,4]}"#;
    for (pet_tag, pet_tag_proof) in [
        (Some(tag), None),
        (None, Some(proof)),
        (Some("{}"), Some(proof)),
        (Some(tag), Some("not-json")),
    ] {
        let request = DocumentPayload {
            ring_id: "11".repeat(32),
            document: r#"{"enc_cmt":[1],"encrypted_data":[2],"nonce":[3]}"#.into(),
            proof: r#"{"challenge":[4],"response":[5]}"#.into(),
            policy_id: "22".repeat(32),
            resource: "document".into(),
            permission: "read".into(),
            pet_tag: pet_tag.map(str::to_owned),
            pet_tag_proof: pet_tag_proof.map(str::to_owned),
            ..Default::default()
        };
        let expected = ThresholdObject::Document(native_document(request.clone()))
            .validate()
            .unwrap_err()
            .to_string();
        let failure = backend
            .post_inner(
                BulletinWriteKind::Document,
                &serde_json::to_vec(&request).unwrap(),
            )
            .await
            .unwrap_err();
        assert!(failure.to_string().contains(&expected), "{failure}");
        assert!(backend.writer.lock().await.pending_id().unwrap().is_none());
        assert_eq!(std::fs::read(&journal).unwrap(), before);
        assert!(backend
            .writer
            .lock()
            .await
            .prepare_document(request, "token")
            .is_err());
        assert_eq!(std::fs::read(&journal).unwrap(), before);
    }
}
