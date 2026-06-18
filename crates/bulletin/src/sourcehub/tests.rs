use super::{ring_to_bulletin_post, SourceHubBulletin};
use crate::r#trait::{
    Bulletin, BulletinKind, BulletinWriteKind, DocumentPayload, RingCancellationPayload,
    RingPayload, UpgradeInfo,
};
use common::{
    blockchain::{acp::Object, SourceHubClient, TxSigner, TEST_ACCOUNT_HEX_KEY},
    SourceHubTestContainer,
};

const ORBIS_RING_POLICY_YAML: &str = r#"
name: orbis ring policy
resources:
- name: ring_policy
  permissions:
  - name: create_ring
    expr: ring_creator
  relations:
  - name: ring_creator
    types:
    - actor
- name: ring
  permissions:
  - name: update_ring
    expr: operator
  relations:
  - name: operator
    types:
    - actor
"#;

async fn create_orbis_ring_policy(client: &SourceHubClient) -> String {
    let ids_before: std::collections::HashSet<String> = client
        .acp_list_policy_ids()
        .await
        .unwrap()
        .ids
        .into_iter()
        .collect();

    client
        .acp_create_policy(ORBIS_RING_POLICY_YAML, 1)
        .await
        .unwrap();

    let policy_id = client
        .acp_list_policy_ids()
        .await
        .unwrap()
        .ids
        .into_iter()
        .find(|id| !ids_before.contains(id))
        .expect("new policy ID not found");

    client
        .acp_register_object(
            &policy_id,
            Object {
                resource: "ring_policy".to_string(),
                id: policy_id.clone(),
            },
        )
        .await
        .unwrap();

    policy_id
}

#[test]
fn test_name() {
    assert_eq!(SourceHubBulletin::name(), "bulletin/sourcehub");
}

#[test]
fn ring_query_conversion_preserves_upgrade_info() {
    let post = ring_to_bulletin_post(common::blockchain::orbis::Ring {
        id: "ring-1".to_string(),
        upgrade_info: Some(common::blockchain::orbis::UpgradeInfo {
            current_version: 1,
            next_version: Some(2),
            activation_time: Some(500),
        }),
        ..Default::default()
    })
    .expect("convert ring");
    let payload = RingPayload::try_from(post).expect("parse ring payload");
    assert_eq!(
        payload.upgrade_info,
        UpgradeInfo {
            current_version: 1,
            next_version: Some(2),
            activation_time: Some(500),
        }
    );
}

#[tokio::test]
#[serial_test::serial]
async fn test_bulletin_document() {
    let container = SourceHubTestContainer::new();
    let config = container.chain_config();

    let signer = TxSigner::from_hex_key(TEST_ACCOUNT_HEX_KEY, config.clone())
        .expect("Failed to create signer");

    let node_key = signer.public_key_hex();

    let bulletin = SourceHubBulletin::with_signer(container.chain_config_builder(), signer, None)
        .await
        .unwrap();

    let policy_id = create_orbis_ring_policy(&bulletin.chain_client).await;

    bulletin
        .chain_client
        .orbis_create_node_info("test-peer-id", &node_key, vec![], vec![])
        .await
        .unwrap();

    let (_, ring_id) = bulletin
        .chain_client
        .orbis_create_ring_get_id(
            vec![node_key],
            1,
            86400,
            &policy_id,
            Some("document-test".to_string()),
            0,
        )
        .await
        .unwrap();

    bulletin
        .chain_client
        .orbis_finalize_ring(&ring_id, "dummy_ring_pk")
        .await
        .unwrap();

    let payload = DocumentPayload {
        ring_id,
        document: "encrypted-document".to_string(),
        proof: "proof".to_string(),
        policy_id,
        resource: "resource".to_string(),
        permission: "read".to_string(),
        ..Default::default()
    };
    let serialized_payload: Vec<u8> = payload.clone().try_into().unwrap();

    let post_id = bulletin
        .post(BulletinWriteKind::Document, serialized_payload.clone())
        .await
        .unwrap();

    let created_post = bulletin
        .read(post_id, BulletinKind::Document)
        .await
        .unwrap();
    println!("Created post ID: {}", created_post.id);

    assert_eq!(
        created_post.payload,
        serialized_payload.clone(),
        "Payload should match"
    );

    let read_payload: DocumentPayload = created_post.clone().try_into().unwrap();
    assert_eq!(read_payload, payload, "Read payload should match");
}

#[tokio::test]
#[serial_test::serial]
async fn test_bulletin_ring() {
    let container = SourceHubTestContainer::new();
    let config = container.chain_config();

    let signer = TxSigner::from_hex_key(TEST_ACCOUNT_HEX_KEY, config.clone())
        .expect("Failed to create signer");

    let node_key = signer.public_key_hex();

    let bulletin = SourceHubBulletin::with_signer(container.chain_config_builder(), signer, None)
        .await
        .unwrap();

    let policy_id = create_orbis_ring_policy(&bulletin.chain_client).await;

    bulletin
        .chain_client
        .orbis_create_node_info("test-peer-id", &node_key, vec![], vec![])
        .await
        .unwrap();

    let peer_node_keys = vec![node_key];
    let threshold = 1u32;

    let payload = RingPayload {
        ring_pk: String::new(),
        peer_node_keys: peer_node_keys.clone(),
        threshold,
        pss_interval: 86400,
        policy_id: Some(policy_id.clone()),
        ..Default::default()
    };
    let serialized_payload: Vec<u8> = payload.clone().try_into().unwrap();

    let (_, ring_id) = bulletin
        .chain_client
        .orbis_create_ring_get_id(
            peer_node_keys,
            threshold,
            86400,
            &policy_id,
            Some("ring-test".to_string()),
            0,
        )
        .await
        .unwrap();

    let created_post = bulletin
        .read(ring_id.clone(), BulletinKind::Ring)
        .await
        .unwrap();
    println!("Created post ID: {}", created_post.id);

    assert_eq!(created_post.id, ring_id);
    assert_eq!(
        created_post.payload,
        serialized_payload.clone(),
        "Payload should match"
    );

    let read_payload: RingPayload = created_post.clone().try_into().unwrap();
    assert_eq!(read_payload, payload, "Read payload should match");
}

#[tokio::test]
#[serial_test::serial]
async fn test_bulletin_cancel_pending_ring() {
    let container = SourceHubTestContainer::new();
    let config = container.chain_config();
    let signer = TxSigner::from_hex_key(TEST_ACCOUNT_HEX_KEY, config.clone())
        .expect("Failed to create signer");
    let node_key = signer.public_key_hex();
    let bulletin = SourceHubBulletin::with_signer(container.chain_config_builder(), signer, None)
        .await
        .unwrap();

    let policy_id = create_orbis_ring_policy(&bulletin.chain_client).await;
    bulletin
        .chain_client
        .orbis_create_node_info("cancel-test-peer-id", &node_key, vec![], vec![])
        .await
        .unwrap();
    let (_, ring_id) = bulletin
        .chain_client
        .orbis_create_ring_get_id(
            vec![node_key],
            1,
            86_400,
            &policy_id,
            Some("cancel-pending-ring-test".to_string()),
            0,
        )
        .await
        .unwrap();

    let cancellation = RingCancellationPayload {
        ring_id: ring_id.clone(),
    };
    let payload_bytes: Vec<u8> = cancellation.try_into().unwrap();
    let cancelled_id = bulletin
        .post(BulletinWriteKind::CancelPendingRing, payload_bytes)
        .await
        .unwrap();

    assert_eq!(cancelled_id, ring_id);
    assert!(bulletin
        .chain_client
        .orbis_read_ring(&ring_id)
        .await
        .unwrap()
        .is_none());
}
