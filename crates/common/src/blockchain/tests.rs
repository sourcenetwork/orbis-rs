//! Unit tests for the blockchain module (signer, ChainConfig, fee / fee-granter).
//! The live-chain tests are in `test-support/tests/blockchain_vera.rs`.

use crate::blockchain::{ChainConfig, TxSigner, TEST_ACCOUNT_HEX_KEY};

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
