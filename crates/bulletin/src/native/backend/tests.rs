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
            Zeroizing::new(vec![31; 32]),
        )
        .unwrap();
    let mut writer = NativeVeraClient::open(
        HubClient::new(&url),
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
                "hub_getReceiptProof" => {
                    reads += 1;
                    assert_eq!(request["params"], json!([id]));
                    response["result"] = Value::Null;
                }
                "hub_sendNativeTx" => {
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
        reader: HubClient::new(&url),
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
