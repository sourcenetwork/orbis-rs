//! Integration tests for the blockchain module.
//!
//! These tests require Docker to be running and will spin up a Vera container.
//! Run with: cargo test -p common --test blockchain_integration -- --nocapture

use crate::blockchain::{ChainConfig, TxSigner, VeraClient, TEST_ACCOUNT_HEX_KEY};
use crate::VeraTestContainer;
use std::sync::Arc;

/// Test that we can connect to the chain and query its status.
#[tokio::test]
#[serial_test::serial]
async fn test_client_connection() {
    // Spin up Vera
    let container = VeraTestContainer::new();

    // Create config for local container
    let config = container.chain_config();

    // Create client
    let client = VeraClient::new(config)
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
    let container = VeraTestContainer::new();
    let config = container.chain_config();
    let client = VeraClient::new(config)
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

    // Address should be bech32 encoded with "vera" prefix
    assert!(address.starts_with("vera1"));
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

/// Test concurrent transaction nonce management.
///
/// This test verifies that the in-memory nonce management works correctly
/// when multiple transactions are sent concurrently. Each transaction should
/// get a unique, sequential nonce without conflicts.
#[tokio::test]
#[serial_test::serial]
async fn test_concurrent_nonce_management() {
    let container = VeraTestContainer::new();
    let config = container.chain_config();

    let signer = TxSigner::from_hex_key(TEST_ACCOUNT_HEX_KEY, config.clone())
        .expect("Failed to create signer");

    let client = Arc::new(
        VeraClient::with_signer(config.clone(), signer)
            .await
            .expect("Failed to create client with signer"),
    );

    let address = client.signer().unwrap().address();
    println!("Signer address: {}", address);
    println!("Initial nonce: {}", client.signer().unwrap().nonce());

    // Fire off N concurrent transactions (transfers to self)
    const NUM_CONCURRENT_TXS: usize = 5;
    let mut handles = Vec::with_capacity(NUM_CONCURRENT_TXS);

    for i in 0..NUM_CONCURRENT_TXS {
        let client = Arc::clone(&client);
        let to_address = address.clone();

        let handle = tokio::spawn(async move {
            let result = client.transfer(&to_address, 1, "uopen").await;
            (i, result)
        });

        handles.push(handle);
    }

    // Wait for all transactions to complete
    let mut successes = 0;
    let mut failures = Vec::new();

    for handle in handles {
        let (i, result) = handle.await.expect("Task panicked");
        match result {
            Ok(broadcast_result) => {
                println!(
                    "Tx {}: SUCCESS - hash: {}, height: {:?}",
                    i, broadcast_result.tx_hash, broadcast_result.height
                );
                successes += 1;
            }
            Err(e) => {
                println!("Tx {}: FAILED - {}", i, e);
                failures.push((i, e.to_string()));
            }
        }
    }

    println!("\nResults: {}/{} succeeded", successes, NUM_CONCURRENT_TXS);
    println!("Final nonce: {}", client.signer().unwrap().nonce());

    // All transactions should succeed with proper nonce management
    assert_eq!(
        successes, NUM_CONCURRENT_TXS,
        "All concurrent transactions should succeed. Failures: {:?}",
        failures
    );

    // Final nonce should be initial + NUM_CONCURRENT_TXS
    // (we started at some value and incremented for each tx)
}

/// Test gas simulation and auto-gas broadcast.
///
/// This verifies that:
/// 1. Gas simulation returns a reasonable estimate
/// 2. Broadcasting with auto-gas works correctly
#[tokio::test]
#[serial_test::serial]
async fn test_gas_simulation() {
    use crate::blockchain::bank;

    let container = VeraTestContainer::new();
    let config = container.chain_config();

    let signer = TxSigner::from_hex_key(TEST_ACCOUNT_HEX_KEY, config.clone())
        .expect("Failed to create signer");

    let client = VeraClient::with_signer(config.clone(), signer)
        .await
        .expect("Failed to create client with signer");

    let address = client.signer().unwrap().address();
    println!("Signer address: {}", address);

    // Create a simple transfer message
    let coin = bank::Coin {
        denom: "uopen".to_string(),
        amount: "1".to_string(),
    };

    let msg = bank::MsgSend {
        from_address: address.clone(),
        to_address: address.clone(),
        amount: vec![coin],
    };

    // Test 1: Simulate to get gas estimate
    let account_number = client.signer().unwrap().account_number();
    let sequence = client.signer().unwrap().nonce();

    let tx_bytes = client
        .signer()
        .unwrap()
        .sign_tx(
            vec![cosmrs::Any {
                type_url: bank::MsgSend::TYPE_URL.to_string(),
                value: prost::Message::encode_to_vec(&msg),
            }],
            account_number,
            sequence,
            Some(10_000_000), // High gas for simulation
            None,
        )
        .expect("Failed to sign tx");

    let gas_estimate = client
        .simulate_tx(&tx_bytes)
        .await
        .expect("Simulation failed");

    println!("Gas estimate for transfer: {}", gas_estimate);

    // Gas should be reasonable (not 0, not extremely high)
    assert!(gas_estimate > 0, "Gas estimate should be > 0");
    assert!(
        gas_estimate < 1_000_000,
        "Gas estimate should be < 1M for simple transfer"
    );

    // Test 2: Broadcast with auto-gas (1.3x multiplier)
    let result = client
        .broadcast_proto_msg_with_gas(bank::MsgSend::TYPE_URL, &msg, 1.3)
        .await
        .expect("Auto-gas broadcast failed");

    println!(
        "Auto-gas tx succeeded: hash={}, height={:?}",
        result.tx_hash, result.height
    );

    assert_eq!(result.code, 0, "Transaction should succeed");
}

/// Test that several protobuf messages are simulated, signed, and committed in
/// one Vera transaction. The benchmark crate separately exercises bounded
/// batch bisection and bad-item isolation around this client method.
#[tokio::test]
#[serial_test::serial]
async fn test_multi_message_auto_gas_broadcast() {
    use crate::blockchain::bank;
    use prost::Message;

    let container = VeraTestContainer::new();
    let config = container.chain_config();
    let signer =
        TxSigner::from_hex_key(TEST_ACCOUNT_HEX_KEY, config.clone()).expect("create funded signer");
    let client = VeraClient::with_signer(config.clone(), signer)
        .await
        .expect("create signed client");
    let recipient = TxSigner::from_hex_key(
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        config,
    )
    .expect("create recipient")
    .address();
    let sender = client.signer().expect("signed client").address();
    let messages = (0..3)
        .map(|_| {
            let message = bank::MsgSend {
                from_address: sender.clone(),
                to_address: recipient.clone(),
                amount: vec![bank::Coin {
                    denom: "uopen".into(),
                    amount: "1".into(),
                }],
            };
            cosmrs::Any {
                type_url: bank::MsgSend::TYPE_URL.into(),
                value: message.encode_to_vec(),
            }
        })
        .collect();

    let result = client
        .broadcast_proto_msgs_with_gas(messages, 1.3)
        .await
        .expect("multi-message transaction should commit");
    assert_eq!(result.code, 0);
    assert_eq!(client.get_balance(&recipient, "uopen").await.unwrap(), 3);
}

/// Build a signed transfer-to-self tx from `signer` and decode its `AuthInfo.fee`.
fn signed_tx_fee(signer: &TxSigner) -> cosmrs::proto::cosmos::tx::v1beta1::Fee {
    use crate::blockchain::bank;
    use cosmrs::proto::cosmos::tx::v1beta1::{AuthInfo, TxRaw};
    // `bank::MsgSend` is generated against the workspace's `prost`, while
    // `TxRaw`/`AuthInfo` come from `cosmos-sdk-proto`'s own (older) `prost`
    // dependency. Both `Message` traits must be in scope, unnamed to avoid
    // clashing; each call below resolves to the one its concrete type impls.
    use cosmrs::proto::traits::Message as _;
    use prost::Message as _;

    let msg = bank::MsgSend {
        from_address: signer.address(),
        to_address: signer.address(),
        amount: vec![bank::Coin {
            denom: "uopen".to_string(),
            amount: "1".to_string(),
        }],
    };
    let any_msg = cosmrs::Any {
        type_url: bank::MsgSend::TYPE_URL.to_string(),
        value: msg.encode_to_vec(),
    };

    let tx_bytes = signer
        .sign_tx(vec![any_msg], 0, 0, None, None)
        .expect("sign_tx should succeed");

    let tx_raw = TxRaw::decode(tx_bytes.as_slice()).expect("decode TxRaw");
    let auth_info = AuthInfo::decode(tx_raw.auth_info_bytes.as_slice()).expect("decode AuthInfo");
    auth_info.fee.expect("fee should be set")
}

/// Without a configured fee granter, signed transactions must leave
/// `AuthInfo.fee.granter` empty so the signer pays its own fees as before.
#[test]
fn test_sign_tx_without_fee_granter_leaves_granter_empty() {
    let signer =
        TxSigner::from_hex_key(TEST_ACCOUNT_HEX_KEY, ChainConfig::local()).expect("create signer");

    let fee = signed_tx_fee(&signer);

    assert!(
        fee.granter.is_empty(),
        "granter should be empty when no fee granter is configured"
    );
}

/// `with_fee_granter` must cause every subsequently signed transaction to
/// name that address in `AuthInfo.fee.granter`, requesting Vera's
/// x/feegrant module pay fees from the granter instead of the signer.
#[test]
fn test_sign_tx_with_fee_granter_sets_granter() {
    let config = ChainConfig::local();

    // A distinct account whose address we use as the fee granter.
    let granter_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let granter_address = TxSigner::from_hex_key(granter_hex, config.clone())
        .expect("create granter signer")
        .address();

    let signer = TxSigner::from_hex_key(TEST_ACCOUNT_HEX_KEY, config)
        .expect("create signer")
        .with_fee_granter(&granter_address)
        .expect("valid fee granter address should be accepted");

    let fee = signed_tx_fee(&signer);

    assert_eq!(fee.granter, granter_address);
}

/// A malformed `--fee-granter` value must be rejected up front rather than
/// silently producing transactions Vera's ante handler will reject.
#[test]
fn test_with_fee_granter_rejects_invalid_address() {
    let signer =
        TxSigner::from_hex_key(TEST_ACCOUNT_HEX_KEY, ChainConfig::local()).expect("create signer");

    let result = signer.with_fee_granter("not-a-valid-bech32-address");

    assert!(result.is_err());
}
