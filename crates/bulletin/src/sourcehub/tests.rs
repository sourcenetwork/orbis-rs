use super::SourceHubBulletin;
use common::{
    blockchain::{
        ChainConfig, ChainConfigBuilder, SourceHubClient, TxSigner, TEST_ACCOUNT_HEX_KEY,
    },
    SourceHubTestContainer,
};

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
}
