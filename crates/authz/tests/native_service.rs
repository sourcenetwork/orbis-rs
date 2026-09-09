use alloy_primitives::B256;
use authz::{native::NativeAuth, r#trait::Authz, request::AccessCheckRequest};
use hub_client::{BlsSigner, HubClient};
use hub_domain::ConsensusPublicKey;
use hub_harness::cluster::{ConsensusPreset, KeySet, TestCluster};
use std::time::Duration;

async fn receipt(reader: &HubClient, id: B256, trusted: &ConsensusPublicKey) {
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let Some(proof) = reader.read_receipt(id, trusted).await.unwrap() {
                assert!(proof.verify(id, trusted).unwrap().success());
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
#[ignore = "requires a built hubd supplied through HUBD_BINARY"]
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
    let writer = HubClient::new(cluster.node(0).rpc_url());
    let reader = HubClient::new(cluster.node(3).rpc_url());
    let first = reader.read_finalized_revision(1, &trusted).await.unwrap();
    let root: B256 = first.parent_hash.parse().unwrap();
    assert!(NativeAuth::connect(
        HubClient::new(cluster.node(3).rpc_url()),
        trusted,
        [9; 32],
        30
    )
    .await
    .is_err());
    let auth = NativeAuth::connect(
        HubClient::new(cluster.node(3).rpc_url()),
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
    receipt(&reader, registered.transaction_hash, &trusted).await;
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
    assert!(!auth.check(request.clone(), subject).await.unwrap());
    let denied_anchor = auth.current_anchor().await.unwrap();
    assert!(auth.anchor_time(&denied_anchor).await.unwrap() > 0);
    let grant = writer
        .native_set_relationship(&signer, policy_bytes, "document", "doc", "reader", subject)
        .await
        .unwrap();
    receipt(&reader, grant.transaction_hash, &trusted).await;
    assert!(auth.check(request.clone(), subject).await.unwrap());
    if let Ok(allowed) = auth
        .check_at(request.clone(), subject, &denied_anchor)
        .await
    {
        assert!(!allowed, "historical denial must not use the current grant");
    }
    let allowed_anchor = auth.current_anchor().await.unwrap();
    let allowed_time = auth.anchor_time(&allowed_anchor).await.unwrap();
    let revoked = writer
        .native_delete_relationship(&signer, policy_bytes, "document", "doc", "reader", subject)
        .await
        .unwrap();
    receipt(&reader, revoked.transaction_hash, &trusted).await;
    assert!(!auth.check(request.clone(), subject).await.unwrap());
    if let Ok(allowed) = auth
        .check_at(request.clone(), subject, &allowed_anchor)
        .await
    {
        assert!(
            allowed,
            "historical grant must not use the current revocation"
        );
    }
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
