use super::SourceHubBulletin;
use crate::r#trait::{Bulletin, BulletinKind, DocumentPayload, RingPayload};
use common::{
    blockchain::{ChainConfig, ChainConfigBuilder, TxSigner, TEST_ACCOUNT_HEX_KEY},
    SourceHubTestContainer,
};

#[test]
fn test_name() {
    assert_eq!(SourceHubBulletin::name(), "bulletin/sourcehub");
}

#[test]
fn test_parse_threshold_signature_artifact() {
    let artifact = Some("reshare-threshold-signature:42:0x0102ff".to_string());
    let (scheme, signature) =
        SourceHubBulletin::parse_threshold_signature_artifact(&artifact).unwrap();
    assert_eq!(scheme, crypto::THRESHOLD_SIGNATURE_SCHEME);
    assert_eq!(signature, vec![0x01, 0x02, 0xff]);

    let artifact = Some(format!(
        "reshare-threshold-signature:42:{}:0102ff",
        crypto::THRESHOLD_SIGNATURE_SCHEME
    ));
    let (scheme, signature) =
        SourceHubBulletin::parse_threshold_signature_artifact(&artifact).unwrap();
    assert_eq!(scheme, crypto::THRESHOLD_SIGNATURE_SCHEME);
    assert_eq!(signature, vec![0x01, 0x02, 0xff]);
}

#[test]
fn test_parse_threshold_signature_artifact_rejects_invalid_inputs() {
    assert!(SourceHubBulletin::parse_threshold_signature_artifact(&None).is_err());

    let artifact = Some("0102ff".to_string());
    assert!(SourceHubBulletin::parse_threshold_signature_artifact(&artifact).is_err());

    let artifact = Some("wrong-prefix:42:0102ff".to_string());
    assert!(SourceHubBulletin::parse_threshold_signature_artifact(&artifact).is_err());

    let artifact = Some("reshare-threshold-signature:42:not-hex".to_string());
    assert!(SourceHubBulletin::parse_threshold_signature_artifact(&artifact).is_err());

    let artifact = Some("reshare-threshold-signature:42:abc".to_string());
    assert!(SourceHubBulletin::parse_threshold_signature_artifact(&artifact).is_err());

    let artifact = Some("reshare-threshold-signature:42:unsupported:0102ff".to_string());
    assert!(SourceHubBulletin::parse_threshold_signature_artifact(&artifact).is_err());

    let artifact = Some("reshare-threshold-signature:42:".to_string());
    assert!(SourceHubBulletin::parse_threshold_signature_artifact(&artifact).is_err());
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

    bulletin.register(namespace.to_string()).await.unwrap();

    bulletin
        .post(namespace.to_string(), BulletinKind::Document, serialized_payload.clone(), None)
        .await
        .unwrap();

    let post_id = bulletin
        .get_post_id(namespace, &serialized_payload)
        .unwrap();

    let created_post = bulletin
        .read(namespace.to_string(), post_id, BulletinKind::Document)
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

    let namespace = "test_namespace";
    let payload = RingPayload::default();
    let serialized_payload: Vec<u8> = payload.clone().try_into().unwrap();

    bulletin.register(namespace.to_string()).await.unwrap();

    bulletin
        .post(namespace.to_string(), BulletinKind::Ring, serialized_payload.clone(), None)
        .await
        .unwrap();

    let post_id = bulletin
        .get_post_id(namespace, &serialized_payload)
        .unwrap();

    let created_post = bulletin
        .read(namespace.to_string(), post_id, BulletinKind::Ring)
        .await
        .unwrap();
    println!("Created post ID: {}", created_post.id);

    assert_eq!(
        created_post.payload,
        serialized_payload.clone(),
        "Payload should match"
    );

    let read_payload: RingPayload = created_post.clone().try_into().unwrap();
    assert_eq!(read_payload, payload, "Read payload should match");
}
