use super::SourceHubBulletin;
use crate::r#trait::Payload;
use common::{
    blockchain::{
        ChainConfig, ChainConfigBuilder, SourceHubClient, TxSigner, TEST_ACCOUNT_HEX_KEY,
    },
    SourceHubTestContainer,
};
use serde::{Deserialize, Serialize};

#[tokio::test]
#[serial_test::serial]
async fn test_read_bulletin() {
    let _container = SourceHubTestContainer::new();
    let config = ChainConfig::local();

    let signer = TxSigner::from_hex_key(TEST_ACCOUNT_HEX_KEY, config.clone())
        .expect("Failed to create signer");

    let client = SourceHubClient::with_signer(config.clone(), signer)
        .await
        .expect("Failed to create client with signer");

    let bulletin = SourceHubBulletin::new(ChainConfigBuilder::default())
        .await
        .unwrap();
    let namespace = "test_namespace";
    let post = b"test_post";
    let payload = Payload::default();
    let serialized_payload: Vec<u8> = payload.clone().try_into().unwrap();
    // TODO: these calls should use bulletin when implemented
    let result_namespace = client.bulletin_register_namespace(namespace).await.unwrap();
    assert_eq!(result_namespace.code, 0, "Transaction should succeed");

    let result_post = client
        .bulletin_create_post_with_proof(namespace, serialized_payload.clone(), vec![0x01])
        .await
        .unwrap();
    assert_eq!(result_post.code, 0, "Create post should succeed");

    // Post ID isn't returned in response - query the namespace to find it
    let posts = client.bulletin_list_posts(namespace).await.unwrap();
    assert!(!posts.is_empty(), "Should have at least one post");
    // TODO: fix get dynamically
    let created_post = &posts[0];
    println!("Created post ID: {}", created_post.id);
    assert_eq!(
        created_post.payload,
        serialized_payload.clone(),
        "Payload should match"
    );

    // Now test reading the single post back using the bulletin trait
    // Note: namespace format is "bulletin/{namespace}"
    let read_post = client
        .bulletin_read_post(&created_post.namespace, &created_post.id)
        .await
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<Payload>(&read_post.payload).unwrap(),
        payload,
        "Read payload should match"
    );
    assert_eq!(read_post.id, created_post.id, "Post ID should match");
}
