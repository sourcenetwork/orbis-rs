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

#[tokio::test]
async fn unsupported_pet_fields_are_rejected_without_journaling() {
    let (_root, backend) = read_fixture("http://127.0.0.1:1");
    for field in ["pet_tag", "pet_tag_proof"] {
        let request = json!({field: "attachment"});
        let failure = backend
            .post_inner(
                BulletinWriteKind::Document,
                &serde_json::to_vec(&request).unwrap(),
            )
            .await
            .unwrap_err();
        assert!(failure
            .to_string()
            .contains("does not support PET documents"));
        assert!(backend.writer.lock().await.pending_id().unwrap().is_none());
    }
    let request = RingFinalizationPayload {
        ring_id: "11".repeat(32),
        ring_pk: "22".repeat(48),
        pet_pk: Some("33".repeat(48)),
    };
    let failure = backend
        .post_inner(
            BulletinWriteKind::Finalize,
            &serde_json::to_vec(&request).unwrap(),
        )
        .await
        .unwrap_err();
    assert!(failure
        .to_string()
        .contains("does not support PET ring finalization"));
    assert!(backend.writer.lock().await.pending_id().unwrap().is_none());
}
