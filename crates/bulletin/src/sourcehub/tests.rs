use super::SourceHubBulletin;
use crate::r#trait::{Bulletin, BulletinKind, BulletinWriteKind, DocumentPayload, RingPayload};
use common::{
    blockchain::{ChainConfig, ChainConfigBuilder, TxSigner, TEST_ACCOUNT_HEX_KEY},
    SourceHubTestContainer,
};

fn test_ring_payload() -> RingPayload {
    RingPayload {
        ring_pk: String::new(),
        peer_node_keys: vec![
            "peer-1".to_string(),
            "peer-2".to_string(),
            "peer-3".to_string(),
        ],
        threshold: 2,
        policy_id: Some("policy-id".to_string()),
        ..Default::default()
    }
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

    let bulletin = SourceHubBulletin::with_signer(ChainConfigBuilder::default(), signer, None)
        .await
        .unwrap();

    let ring_payload = test_ring_payload();
    let (_, ring_id) = bulletin
        .chain_client
        .orbis_create_ring_get_id(
            ring_payload.peer_node_keys,
            ring_payload.threshold,
            ring_payload.pss_interval,
            ring_payload.policy_id.as_deref().unwrap_or(""),
            None,
            Some("document-test".to_string()),
        )
        .await
        .unwrap();

    let payload = DocumentPayload {
        ring_id,
        document: "encrypted-document".to_string(),
        proof: "proof".to_string(),
        policy_id: "policy-id".to_string(),
        resource: "resource".to_string(),
        permission: "read".to_string(),
        ..Default::default()
    };
    let serialized_payload: Vec<u8> = payload.clone().try_into().unwrap();

    bulletin.register().await.unwrap();

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

    let bulletin = SourceHubBulletin::with_signer(ChainConfigBuilder::default(), signer, None)
        .await
        .unwrap();

    let payload = test_ring_payload();
    let serialized_payload: Vec<u8> = payload.clone().try_into().unwrap();

    bulletin.register().await.unwrap();

    let (_, ring_id) = bulletin
        .chain_client
        .orbis_create_ring_get_id(
            payload.peer_node_keys.clone(),
            payload.threshold,
            payload.pss_interval,
            payload.policy_id.as_deref().unwrap_or(""),
            None,
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
