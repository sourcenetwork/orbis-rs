use super::SourceHubBulletin;
use crate::r#trait::{Bulletin, BulletinKind, BulletinWriteKind, DocumentPayload, RingPayload};
use common::{
    blockchain::{
        acp::Object, ChainConfig, ChainConfigBuilder, SourceHubClient, TxSigner,
        TEST_ACCOUNT_HEX_KEY,
    },
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

#[tokio::test]
#[serial_test::serial]
async fn test_bulletin_document() {
    let _container = SourceHubTestContainer::new();
    let config = ChainConfig::local();

    let signer = TxSigner::from_hex_key(TEST_ACCOUNT_HEX_KEY, config.clone())
        .expect("Failed to create signer");

    let node_key = signer.public_key_hex();

    let bulletin = SourceHubBulletin::with_signer(ChainConfigBuilder::default(), signer, None)
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
            None,
            &policy_id,
            Some("document-test".to_string()),
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
    let _container = SourceHubTestContainer::new();
    let config = ChainConfig::local();

    let signer = TxSigner::from_hex_key(TEST_ACCOUNT_HEX_KEY, config.clone())
        .expect("Failed to create signer");

    let node_key = signer.public_key_hex();

    let bulletin = SourceHubBulletin::with_signer(ChainConfigBuilder::default(), signer, None)
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
        policy_id: Some(policy_id.clone()),
        ..Default::default()
    };
    let serialized_payload: Vec<u8> = payload.clone().try_into().unwrap();

    let (_, ring_id) = bulletin
        .chain_client
        .orbis_create_ring_get_id(
            peer_node_keys,
            threshold,
            None,
            &policy_id,
            Some("ring-test".to_string()),
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
