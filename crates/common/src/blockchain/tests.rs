//! Integration tests for the blockchain module.
//!
//! These tests require Docker to be running and will spin up a SourceHub container.
//! Run with: cargo test -p common --test blockchain_integration -- --nocapture

use crate::blockchain::{ChainConfig, SourceHubClient, TxSigner};
use crate::SourceHubTestContainer;

/// Test that we can connect to the chain and query its status.
#[tokio::test]
#[serial_test::serial]
async fn test_client_connection() {
    // Spin up SourceHub
    let _container = SourceHubTestContainer::new();

    // Create config for local container
    let config = ChainConfig::local();

    // Create client
    let client = SourceHubClient::new(config)
        .await
        .expect("Failed to create client");

    // Query chain status
    let status = client.get_status().await.expect("Failed to get status");
    println!("Chain ID: {}", status.node_info.network);
    println!(
        "Latest block height: {}",
        status.sync_info.latest_block_height
    );

    // Just check that we got a response (height is u64, always >= 0)
    let _ = status.sync_info.latest_block_height.value();
}

/// Test that we can get the latest block height.
#[tokio::test]
#[serial_test::serial]
async fn test_get_latest_height() {
    let _container = SourceHubTestContainer::new();
    let config = ChainConfig::local();
    let client = SourceHubClient::new(config)
        .await
        .expect("Failed to create client");

    let height = client
        .get_latest_height()
        .await
        .expect("Failed to get height");
    println!("Latest height: {}", height);

    // Height should be at least 1 after container is ready
    assert!(height >= 1);
}

/// Test that we can create a signer from a hex key.
#[test]
fn test_signer_creation() {
    // Test private key (32 bytes hex encoded, DO NOT USE IN PRODUCTION)
    let hex_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let config = ChainConfig::local();

    let signer = TxSigner::from_hex_key(hex_key, config).expect("Failed to create signer");

    let address = signer.address();
    println!("Signer address: {}", address);

    // Address should be bech32 encoded with "source" prefix
    assert!(address.starts_with("source1"));
}

/// Test ChainConfig builder.
#[test]
fn test_chain_config_builder() {
    let config = ChainConfig::builder()
        .chain_id(Some("my-chain".to_string()))
        .rpc_url(Some("http://custom:26657".to_string()))
        .rest_url(Some("http://custom:1317".to_string()))
        .account_prefix(Some("myprefix".to_string()))
        .default_gas_limit(Some(500_000))
        .build();

    assert_eq!(config.chain_id, "my-chain");
    assert_eq!(config.rpc_url, "http://custom:26657");
    assert_eq!(config.rest_url, "http://custom:1317");
    assert_eq!(config.account_prefix, "myprefix");
    assert_eq!(config.default_gas_limit, 500_000);
}

/// Test fee calculation.
#[test]
fn test_fee_calculation() {
    let config = ChainConfig::local();

    // With default gas price of 0.025
    let fee = config.calculate_fee(200_000);
    assert_eq!(fee, 5000); // 200_000 * 0.025 = 5000
}
