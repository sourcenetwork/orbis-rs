//! Docker-based integration test: PRE and Sign offline fault reports submitted on-chain.
//!
//! Spins up a full Docker Compose environment, stops node3, then verifies that:
//! 1. PRE succeeds with 2/3 shares and an offline report for node3 is accepted on SourceHub.
//! 2. Sign (node3 still offline) succeeds with 2/3 shares and a second report is accepted.
//!
//! Run with:
//!   cargo test --features integration-test test_pre_offline_triggers_on_chain_report -- --nocapture

use crate::helpers::test_helpers::wait_for_ring_finalized;
use common::{
    blockchain::{
        events::ReportEventSubscription, orbis::WhitelistTarget, SourceHubClient,
        TxSigner, TEST_ACCOUNT_HEX_KEY,
    },
    IntegrationTestNetwork,
};
use crypto::helpers::generate_keypair;
use crypto::CryptoSerialize;
use tokio::time::{sleep, Duration, Instant};

const RING_ID: &str = "reporting-test-ring";

use super::constants::{NODE_KEY_1, NODE_KEY_2, NODE_KEY_3, RING_GOVERNANCE_POLICY_ID};

#[tokio::test]
#[serial_test::serial]
async fn test_pre_and_sign_offline_triggers_on_chain_report() {
    println!("Starting reporting integration test...");

    let network = IntegrationTestNetwork::builder()
        .with_module_genesis(
            "orbis",
            serde_json::json!({
                "rings": [{
                    "id": RING_ID,
                    "ring_pk": "",
                    "peer_node_keys": [NODE_KEY_1, NODE_KEY_2, NODE_KEY_3],
                    "threshold": 2,
                    "pss_interval": 5,
                    "policy_id": RING_GOVERNANCE_POLICY_ID
                }]
            }),
        )
        .build();

    let chain_config = network.chain_config();
    let endpoints = network.all_endpoints();
    let endpoint = endpoints[0].to_string();

    crate::helpers::test_helpers::wait_for_nodes_ready(&endpoints, 90, Duration::from_secs(1))
        .await;

    let node1_info = cli_tool::query_node_info(endpoints[0].to_string())
        .await
        .expect("query node1 info");
    let node2_info = cli_tool::query_node_info(endpoints[1].to_string())
        .await
        .expect("query node2 info");
    let node3_info = cli_tool::query_node_info(endpoints[2].to_string())
        .await
        .expect("query node3 info");

    assert_eq!(node1_info.node_key, NODE_KEY_1, "node1 key mismatch");
    assert_eq!(node2_info.node_key, NODE_KEY_2, "node2 key mismatch");
    assert_eq!(node3_info.node_key, NODE_KEY_3, "node3 key mismatch");

    let peer1_addr = IntegrationTestNetwork::transform_p2p_address(
        &node1_info.p2p_address,
        IntegrationTestNetwork::NODE1_SERVICE,
    );
    let peer2_addr = IntegrationTestNetwork::transform_p2p_address(
        &node2_info.p2p_address,
        IntegrationTestNetwork::NODE2_SERVICE,
    );
    let peer3_addr = IntegrationTestNetwork::transform_p2p_address(
        &node3_info.p2p_address,
        IntegrationTestNetwork::NODE3_SERVICE,
    );

    let node_keys = [NODE_KEY_1, NODE_KEY_2, NODE_KEY_3];
    let peer_addresses = [peer1_addr, peer2_addr, peer3_addr];

    let controller_client = SourceHubClient::with_signer(
        chain_config.clone(),
        TxSigner::from_hex_key(TEST_ACCOUNT_HEX_KEY, chain_config.clone())
            .expect("test account signer"),
    )
    .await
    .expect("controller chain client");

    let governance_policy_id = crate::helpers::test_helpers::create_ring_governance_with_ring(
        &controller_client,
        RING_ID,
        &node_keys,
    )
    .await;
    assert_eq!(
        governance_policy_id, RING_GOVERNANCE_POLICY_ID,
        "ACP policy ID mismatch — update RING_GOVERNANCE_POLICY_ID to: {governance_policy_id}"
    );

    for (node_key, peer_address) in node_keys.iter().zip(&peer_addresses) {
        wait_for_node_info_on_chain(
            &controller_client,
            node_key,
            Duration::from_secs(60),
            Duration::from_millis(500),
        )
        .await;
        let peer_update = controller_client
            .orbis_update_node_peer_id(node_key, peer_address)
            .await
            .expect("update NodeInfo peer ID");
        assert_eq!(
            peer_update.code, 0,
            "update peer ID failed: {}",
            peer_update.log
        );

        let whitelist_update = controller_client
            .orbis_add_node_to_whitelist(node_key, WhitelistTarget::RingId(RING_ID.to_string()))
            .await
            .expect("add node to whitelist");
        assert_eq!(
            whitelist_update.code, 0,
            "whitelist update failed: {}",
            whitelist_update.log
        );
    }

    println!("Starting DKG for ring {RING_ID}...");
    cli_tool::do_dkg(endpoint.clone(), RING_ID.to_string())
        .await
        .expect("DKG should succeed");

    let ring_pk_hex =
        wait_for_ring_finalized(&chain_config, RING_ID, Duration::from_secs(90)).await;
    println!(
        "DKG finalized. Ring PK: {}...",
        &ring_pk_hex[..40.min(ring_pk_hex.len())]
    );

    // Set up ACP policy and a secret so PRE has something to decrypt.
    let resource = "document".to_string();
    let permission = "read".to_string();
    let did_pk_string = "report-test-did".to_string();
    let policy_id = cli_tool::add_policy_to_chain_with_config(chain_config.clone())
        .await
        .expect("add policy");

    let (reader_sk, reader_pk) = generate_keypair().expect("generate reader keypair");
    let reader_sk_hex = hex::encode(CryptoSerialize::to_bytes(&reader_sk).expect("serialize sk"));
    let reader_pk_hex = hex::encode(CryptoSerialize::to_bytes(&reader_pk).expect("serialize pk"));

    let prepared = cli_tool::prepare_secret(
        b"report-test-secret",
        &ring_pk_hex,
        None,
        policy_id.clone(),
        resource.clone(),
        permission.clone(),
        None,
        None,
        None,
    )
    .expect("prepare_secret");

    let store_result = store_secret_with_retry(
        endpoint.clone(),
        &prepared,
        RING_ID.to_string(),
        policy_id.clone(),
        resource.clone(),
        permission.clone(),
        Some(did_pk_string.clone()),
    )
    .await;
    let object_id = store_result.object_id.clone();

    cli_tool::register_object_to_chain_with_config(
        policy_id.clone(),
        object_id.clone(),
        resource.clone(),
        chain_config.clone(),
    )
    .await
    .expect("register object");

    cli_tool::set_relationship_on_chain_with_config(
        policy_id.clone(),
        object_id.clone(),
        resource.clone(),
        "reader".to_string(),
        Some(did_pk_string.clone()),
        chain_config.clone(),
    )
    .await
    .expect("set relationship");

    // Subscribe before stopping node3 to avoid missing the event.
    println!("Subscribing to report events...");
    let sub = ReportEventSubscription::connect(network.sourcehub_rpc_url())
        .await
        .expect("connect report event subscription");

    // Stop node3 to trigger an offline observation during PRE.
    println!("Stopping node3 to simulate offline node...");
    network.stop_service(IntegrationTestNetwork::NODE3_SERVICE);

    // PRE succeeds with 2/3 shares (threshold=2) and fires an offline report for node3.
    println!("Triggering PRE (expects success with node3 offline)...");
    let _plaintext = pre_with_retry(
        endpoint.clone(),
        ring_pk_hex.clone(),
        reader_pk_hex.clone(),
        reader_sk_hex.clone(),
        object_id.clone(),
        did_pk_string.clone(),
    )
    .await;
    println!("PRE succeeded (2/3 shares collected).");

    // The offline report is threshold-signed and submitted to the chain.
    println!("Waiting for EventReportAccepted on chain (up to 120s)...");
    let event = sub
        .wait_for_report_accepted(RING_ID, Duration::from_secs(120))
        .await
        .expect("EventReportAccepted should be emitted");

    println!(
        "Report accepted on chain: report_id={} accused={}",
        event.report_id, event.accused_node_key
    );

    assert_eq!(event.report_type, "node_offline", "unexpected report_type");
    assert_eq!(
        event.accused_node_key, NODE_KEY_3,
        "node3 should be the accused node"
    );
    assert_eq!(event.ring_id, RING_ID, "ring_id mismatch");
    assert!(!event.report_id.is_empty(), "report_id should be set");
    assert_eq!(
        event.reporter_node_key, NODE_KEY_1,
        "node1 (PRE coordinator) should be the reporter"
    );

    // ── Sign: node3 is still offline ────────────────────────────────────────
    println!("Setting up Sign key derivation (node3 still offline)...");
    let sign_derivation = "sign-report-derivation".to_string();
    let sign_did_pk = "sign-report-test-did".to_string();

    let (derivation_id, _) = cli_tool::post_key_derivation_with_config(
        RING_ID.to_string(),
        sign_derivation,
        policy_id.clone(),
        resource.clone(),
        permission.clone(),
        chain_config.clone(),
    )
    .await
    .expect("post_key_derivation");

    cli_tool::register_object_to_chain_with_config(
        policy_id.clone(),
        derivation_id.clone(),
        resource.clone(),
        chain_config.clone(),
    )
    .await
    .expect("register derivation_id");

    cli_tool::set_relationship_on_chain_with_config(
        policy_id.clone(),
        derivation_id.clone(),
        resource.clone(),
        "reader".to_string(),
        Some(sign_did_pk.clone()),
        chain_config.clone(),
    )
    .await
    .expect("set relationship for sign");

    // Fresh subscription — the previous one was consumed by wait_for_report_accepted.
    println!("Subscribing to report events for Sign...");
    let sign_sub = ReportEventSubscription::connect(network.sourcehub_rpc_url())
        .await
        .expect("connect sign report event subscription");

    // Sign succeeds with 2/3 shares (node3 still offline) and fires an offline report.
    println!("Triggering Sign (expects success with node3 still offline)...");
    let sign_result = sign_with_retry(
        endpoint.clone(),
        b"sign-offline-report-test-message".to_vec(),
        derivation_id.clone(),
        sign_did_pk.clone(),
    )
    .await;
    println!("Sign succeeded: status={}", sign_result.status);

    println!("Waiting for Sign EventReportAccepted on chain (up to 120s)...");
    let sign_event = sign_sub
        .wait_for_report_accepted(RING_ID, Duration::from_secs(120))
        .await
        .expect("Sign EventReportAccepted should be emitted");

    println!(
        "Sign report accepted: report_id={} accused={}",
        sign_event.report_id, sign_event.accused_node_key
    );

    assert_eq!(
        sign_event.report_type, "node_offline",
        "unexpected sign report_type"
    );
    assert_eq!(
        sign_event.accused_node_key, NODE_KEY_3,
        "node3 should be the accused node"
    );
    assert_eq!(sign_event.ring_id, RING_ID, "ring_id mismatch");
    assert!(!sign_event.report_id.is_empty(), "sign report_id should be set");
    assert_eq!(
        sign_event.reporter_node_key, NODE_KEY_1,
        "node1 (Sign coordinator) should be the reporter"
    );
}

async fn wait_for_node_info_on_chain(
    client: &SourceHubClient,
    node_key: &str,
    timeout: Duration,
    poll_interval: Duration,
) {
    let deadline = Instant::now() + timeout;
    loop {
        match client.orbis_read_node_info(node_key).await {
            Ok(Some(_)) => return,
            _ => {}
        }
        assert!(
            Instant::now() < deadline,
            "NodeInfo for {node_key} not found on chain within {timeout:?}"
        );
        sleep(poll_interval).await;
    }
}

async fn store_secret_with_retry(
    endpoint: String,
    prepared: &cli_tool::PreparedSecret,
    ring_id: String,
    policy_id: String,
    resource: String,
    permission: String,
    reader_did_pk: Option<String>,
) -> cli_tool::StoreSecretResult {
    let deadline = Instant::now() + Duration::from_secs(90);
    let mut attempt = 1usize;
    loop {
        match cli_tool::store_prepared_secret(
            endpoint.clone(),
            prepared,
            ring_id.clone(),
            policy_id.clone(),
            resource.clone(),
            permission.clone(),
            reader_did_pk.clone(),
            true,
            None,
            None,
        )
        .await
        {
            Ok(result) => return result,
            Err(e) => {
                assert!(
                    Instant::now() < deadline,
                    "StoreSecret failed after {attempt} attempts: {e}"
                );
                println!("StoreSecret attempt {attempt} failed, retrying: {e}");
                attempt += 1;
                sleep(Duration::from_secs(3)).await;
            }
        }
    }
}

async fn pre_with_retry(
    endpoint: String,
    ring_pk: String,
    reader_pk: String,
    reader_sk: String,
    object_id: String,
    reader_did_pk: String,
) -> Vec<u8> {
    let deadline = Instant::now() + Duration::from_secs(90);
    let mut attempt = 1usize;
    loop {
        match cli_tool::do_pre(
            endpoint.clone(),
            ring_pk.clone(),
            reader_pk.clone(),
            Some(reader_sk.clone()),
            object_id.clone(),
            Some(reader_did_pk.clone()),
            None,
            None,
            None,
            None,
            false,
        )
        .await
        {
            Ok(result) => return result,
            Err(e) => {
                assert!(
                    Instant::now() < deadline,
                    "PRE failed after {attempt} attempts: {e}"
                );
                println!("PRE attempt {attempt} failed, retrying: {e}");
                attempt += 1;
                sleep(Duration::from_secs(3)).await;
            }
        }
    }
}

async fn sign_with_retry(
    endpoint: String,
    message: Vec<u8>,
    derivation_id: String,
    did_pk: String,
) -> cli_tool::SignResult {
    let deadline = Instant::now() + Duration::from_secs(90);
    let mut attempt = 1usize;
    loop {
        match cli_tool::do_sign(
            endpoint.clone(),
            message.clone(),
            derivation_id.clone(),
            Some(did_pk.clone()),
            None,
            None,
        )
        .await
        {
            Ok(result) => return result,
            Err(e) => {
                assert!(
                    Instant::now() < deadline,
                    "Sign failed after {attempt} attempts: {e}"
                );
                println!("Sign attempt {attempt} failed, retrying: {e}");
                attempt += 1;
                sleep(Duration::from_secs(3)).await;
            }
        }
    }
}

