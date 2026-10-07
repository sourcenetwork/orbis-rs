use alloy_primitives::B256;
use authz::{native::NativeAuth, r#trait::Authz, request::AccessCheckRequest};
use std::time::Duration;
use vera_client::{BlsSigner, VeraClient};
use vera_domain::ConsensusPublicKey;
use vera_harness::cluster::{ConsensusPreset, KeySet, TestCluster};

async fn receipt(reader: &VeraClient, id: B256, trusted: &ConsensusPublicKey) -> u64 {
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let Some(proof) = reader.read_receipt(id, trusted).await.unwrap() {
                assert!(proof.verify(id, trusted).unwrap().success());
                break proof.revision.height;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap()
}

async fn assert_current_permission(
    auth: &NativeAuth,
    request: &[u8],
    subject: &str,
    minimum: u64,
    expected: bool,
) {
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let anchor = auth.current_anchor().await.unwrap();
            let height: u64 = anchor.split(':').nth(1).unwrap().parse().unwrap();
            if height >= minimum {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        // The certified anchor advances NativeAuth's minimum before its permission read.
        assert_eq!(
            auth.check(request.to_vec(), subject).await.unwrap(),
            expected
        );
    })
    .await
    .expect("reader did not publish and authorize the required revision");
}

#[tokio::test]
#[ignore = "requires a built verad supplied through VERAD_BINARY"]
async fn native_authorization_tracks_revocation_and_binds_recovered_anchors() {
    let deployment = 9071;
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
    let writer = VeraClient::new(cluster.node(0).rpc_url());
    let reader = VeraClient::new(cluster.node(3).rpc_url());
    let first = reader.read_finalized_revision(1, &trusted).await.unwrap();
    let root: B256 = first.parent_hash.parse().unwrap();
    assert!(NativeAuth::connect(
        VeraClient::new(cluster.node(3).rpc_url()),
        trusted,
        [9; 32],
        30
    )
    .await
    .is_err());
    let auth = NativeAuth::connect(
        VeraClient::new(cluster.node(3).rpc_url()),
        trusted,
        root.0,
        30,
    )
    .await
    .unwrap();
    let signer = BlsSigner::new(7u64.into(), deployment).unwrap();
    let created = writer.native_create_policy(&signer,
        b"name: native_auth\nresources:\n  - name: document\n    relations:\n      - name: reader\n    permissions:\n      - name: read\n        expr: reader\n", 1).await.unwrap();
    assert_eq!(created.status, 1);
    receipt(&reader, created.transaction_hash, &trusted).await;
    let policies = writer.get_policy_ids().await.unwrap();
    assert_eq!(policies.len(), 1);
    let policy = &policies[0];
    let policy_bytes = B256::from_slice(&hex::decode(policy).unwrap());
    let registered = writer
        .native_register_object(&signer, policy_bytes, "doc", "document")
        .await
        .unwrap();
    let registered_height = receipt(&reader, registered.transaction_hash, &trusted).await;
    let request = AccessCheckRequest::new(
        policy.clone(),
        "document".into(),
        "doc".into(),
        "read".into(),
        None,
        None,
        None,
    )
    .to_bytes()
    .unwrap();
    let subject = "did:key:reader";
    assert_current_permission(&auth, &request, subject, registered_height, false).await;
    let denied_anchor = auth.current_anchor().await.unwrap();
    assert!(auth.anchor_time(&denied_anchor).await.unwrap() > 0);
    assert!(!auth
        .check_at(request.clone(), subject, &denied_anchor)
        .await
        .unwrap());
    let grant = writer
        .native_set_relationship(&signer, policy_bytes, "document", "doc", "reader", subject)
        .await
        .unwrap();
    let grant_height = receipt(&reader, grant.transaction_hash, &trusted).await;
    assert_current_permission(&auth, &request, subject, grant_height, true).await;
    assert_historical_result(
        auth.check_at(request.clone(), subject, &denied_anchor)
            .await,
        false,
    );
    let allowed_anchor = auth.current_anchor().await.unwrap();
    let allowed_time = auth.anchor_time(&allowed_anchor).await.unwrap();
    assert!(auth
        .check_at(request.clone(), subject, &allowed_anchor)
        .await
        .unwrap());
    let archived = writer
        .native_archive_object(&signer, policy_bytes, "doc", "document")
        .await
        .unwrap();
    let archived_height = receipt(&reader, archived.transaction_hash, &trusted).await;
    assert_current_permission(&auth, &request, subject, archived_height, false).await;

    let unarchive = serde_json::from_value(serde_json::json!({
        "command": {"UnarchiveObject": {"resource": "document", "id": "doc"}}
    }))
    .unwrap();
    let unarchived = writer
        .native_policy_command(&signer, policy_bytes, &unarchive)
        .await
        .unwrap();
    let unarchived_height = receipt(&reader, unarchived.transaction_hash, &trusted).await;
    assert_current_permission(&auth, &request, subject, unarchived_height, false).await;

    let regranted = writer
        .native_set_relationship(&signer, policy_bytes, "document", "doc", "reader", subject)
        .await
        .unwrap();
    let regranted_height = receipt(&reader, regranted.transaction_hash, &trusted).await;
    assert_current_permission(&auth, &request, subject, regranted_height, true).await;

    let revoked = writer
        .native_delete_relationship(&signer, policy_bytes, "document", "doc", "reader", subject)
        .await
        .unwrap();
    let revoked_height = receipt(&reader, revoked.transaction_hash, &trusted).await;
    assert_current_permission(&auth, &request, subject, revoked_height, false).await;
    assert_historical_result(
        auth.check_at(request.clone(), subject, &allowed_anchor)
            .await,
        true,
    );
    cluster.restart_node(3).unwrap();
    cluster.wait_ready(Duration::from_secs(30)).await.unwrap();
    assert_eq!(
        auth.anchor_time(&allowed_anchor).await.unwrap(),
        allowed_time
    );
    assert!(!auth.check(request.clone(), subject).await.unwrap());
    let foreign = allowed_anchor.replacen(&hex::encode(root), &"99".repeat(32), 1);
    assert!(auth.check_at(request, subject, &foreign).await.is_err());
}

fn assert_historical_result(result: authz::error::Result<bool>, expected: bool) {
    match result {
        Ok(allowed) => assert_eq!(allowed, expected, "historical permissions changed"),
        // The current store cannot prove a historical root after a policy mutation.
        Err(authz::error::AuthZError::Native(message)) => assert_eq!(
            message,
            "RPC error (-32002): invalid permission evidence: selected module root changed",
        ),
        Err(error) => panic!("unexpected historical authorization error: {error}"),
    }
}
