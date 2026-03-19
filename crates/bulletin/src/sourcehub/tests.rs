use super::SourceHubBulletin;
use crate::r#trait::{Bulletin, DocumentPayload, RingPayload};
use common::{
    blockchain::{ChainConfig, ChainConfigBuilder, TxSigner, TEST_ACCOUNT_HEX_KEY},
    SourceHubTestContainer,
};

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

    let namespace = "test_namespace";
    let payload = DocumentPayload::default();
    let serialized_payload: Vec<u8> = payload.clone().try_into().unwrap();
    let proof = vec![0x01];

    bulletin.register(namespace.to_string()).await.unwrap();

    bulletin
        .post(
            namespace.to_string(),
            serialized_payload.clone(),
            proof,
            None,
        )
        .await
        .unwrap();

    let post_id = bulletin
        .get_post_id(namespace, &serialized_payload)
        .unwrap();

    let created_post = bulletin.read(namespace.to_string(), post_id).await.unwrap();
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

    let namespace = "test_namespace";
    let payload = RingPayload::default();
    let serialized_payload: Vec<u8> = payload.clone().try_into().unwrap();
    let proof = vec![0x01];

    bulletin.register(namespace.to_string()).await.unwrap();

    bulletin
        .post(
            namespace.to_string(),
            serialized_payload.clone(),
            proof,
            None,
        )
        .await
        .unwrap();

    let post_id = bulletin
        .get_post_id(namespace, &serialized_payload)
        .unwrap();

    let created_post = bulletin.read(namespace.to_string(), post_id).await.unwrap();
    println!("Created post ID: {}", created_post.id);

    assert_eq!(
        created_post.payload,
        serialized_payload.clone(),
        "Payload should match"
    );

    let read_payload: RingPayload = created_post.clone().try_into().unwrap();
    assert_eq!(read_payload, payload, "Read payload should match");
}
