//! Docker-based integration test: protocol version upgrade enforcement.
//!
//! Uses genesis injection to pre-seed a ring at current_version=1 (with a KeyDerivation and
//! DocumentPayload referencing it), bypassing SourceHub's 600-second MinRingUpgradeLeadSeconds
//! constraint. The test then verifies that all three v0 CLI operations refuse the ring.
//!
//! Run with:
//!   cargo test --features integration-test -- test_v0_services_rejected_after_ring_upgrade --nocapture

use common::IntegrationTestNetwork;
use crypto::helpers::generate_keypair;
use crypto::CryptoSerialize;

// Identifiers for genesis-injected objects
const RING_ID: &str = "v1-ring";
const DERIVATION_ID: &str = "v1-derivation";
const DOCUMENT_ID: &str = "v1-document";
// Placeholder ring_pk — non-empty so the ring appears finalized; do_pre version check fires
// before ring_pk is used for decryption, so any non-empty string is fine here.
const RING_PK_PLACEHOLDER: &str = "aabbccdd";
// A valid compressed secp256k1 public key — required by the keeper's peer_node_keys validation,
// though InitGenesis bypasses that; included for correctness.
const NODE_KEY: &str = "024f4e2ad99c34d60b9ba6283c9431a8418af8673212961f97a77b6377fcd05b62";

#[tokio::test]
#[serial_test::serial]
async fn test_v0_services_rejected_after_ring_upgrade() {
    println!("Starting upgrade integration test (genesis injection)...");

    let _network = IntegrationTestNetwork::builder()
        .with_module_genesis(
            "orbis",
            serde_json::json!({
                "rings": [{
                    "id": RING_ID,
                    "ring_pk": RING_PK_PLACEHOLDER,
                    "peer_node_keys": [NODE_KEY],
                    "threshold": 1,
                    "policy_id": "upgrade-test-policy",
                    "upgrade_info": { "current_version": 1 }
                }],
                "key_derivations": [{
                    "id": DERIVATION_ID,
                    "ring_id": RING_ID,
                    "derivation": "upgrade-test-derivation",
                    "policy_id": "upgrade-test-policy",
                    "resource": "document",
                    "permission": "read"
                }],
                "documents": [{
                    "id": DOCUMENT_ID,
                    "ring_id": RING_ID,
                    "document": "upgrade-test-ciphertext",
                    "proof": "upgrade-test-proof",
                    "policy_id": "upgrade-test-policy",
                    "resource": "document",
                    "permission": "read"
                }]
            }),
        )
        .build();

    let endpoint = IntegrationTestNetwork::NODE1_GRPC.to_string();

    // do_pre validates reader_pk before the version check — provide a real keypair
    let (reader_sk, reader_pk) = generate_keypair().expect("generate reader keypair");
    let reader_pk_hex = hex::encode(CryptoSerialize::to_bytes(&reader_pk).expect("serialize pk"));
    let reader_sk_hex = hex::encode(CryptoSerialize::to_bytes(&reader_sk).expect("serialize sk"));

    // DKG: resolve_ring_protocol_version(ring_id) fires before any gRPC connection
    let dkg_err = cli_tool::do_dkg(endpoint.clone(), RING_ID.to_string())
        .await
        .expect_err("v0 DKG must refuse a v1 ring");
    assert!(
        dkg_err.to_string().contains("protocol version 1"),
        "DKG: expected 'protocol version 1' in error, got: {}",
        dkg_err
    );
    println!("DKG correctly rejected: {}", dkg_err);

    // Sign: resolve_derivation_protocol_version(derivation_id) → ring → version check
    let sign_err = cli_tool::do_sign(
        endpoint.clone(),
        b"upgrade-test-message".to_vec(),
        DERIVATION_ID.to_string(),
        None,
        None,
        None,
    )
    .await
    .expect_err("v0 Sign must refuse a derivation whose ring is at v1");
    assert!(
        sign_err.to_string().contains("protocol version 1"),
        "Sign: expected 'protocol version 1' in error, got: {}",
        sign_err
    );
    println!("Sign correctly rejected: {}", sign_err);

    // PRE: reader_pk is parsed first, then resolve_document_protocol_version fires
    let pre_err = cli_tool::do_pre(
        endpoint.clone(),
        RING_PK_PLACEHOLDER.to_string(),
        reader_pk_hex,
        Some(reader_sk_hex),
        DOCUMENT_ID.to_string(),
        None,
        None,
        None,
        None,
        None,
        false,
    )
    .await
    .expect_err("v0 PRE must refuse a document whose ring is at v1");
    assert!(
        pre_err.to_string().contains("protocol version 1"),
        "PRE: expected 'protocol version 1' in error, got: {}",
        pre_err
    );
    println!("PRE correctly rejected: {}", pre_err);

    println!("Upgrade integration test passed: all v0 CLI operations refused the v1 ring.");
}
