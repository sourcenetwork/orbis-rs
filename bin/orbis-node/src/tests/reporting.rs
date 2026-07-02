//! Docker-based integration test: PRE and Sign offline fault reports submitted on-chain.
//!
//! Spins up a full Docker Compose environment, stops node3, then verifies that:
//! 1. PRE succeeds with 2/3 shares and an offline report for node3 is accepted on SourceHub.
//! 2. Sign (node3 still offline) succeeds with 2/3 shares and a second report is accepted.
//!
//! Run with:
//!   cargo test --features integration-test test_pre_offline_triggers_on_chain_report -- --nocapture

use crate::helpers::test_helpers::wait_for_ring_finalized;
use bulletin::r#trait::{BulletinKind, RingPayload};
use common::{
    blockchain::{
        events::ReportEventSubscription, orbis::WhitelistTarget, SourceHubClient, TxSigner,
        TEST_ACCOUNT_HEX_KEY, TEST_ACCOUNT_PUBKEY_HEX,
    },
    IntegrationTestNetwork,
};
use crypto::helpers::generate_keypair;
use crypto::CryptoSerialize;
use tokio::time::{sleep, Duration, Instant};

const RING_ID: &str = "reporting-test-ring";

use super::constants::{NODE_KEY_1, NODE_KEY_2, NODE_KEY_3, NODE_KEY_4, RING_GOVERNANCE_POLICY_ID};

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
                    "pss_interval": 86400,
                    "policy_id": RING_GOVERNANCE_POLICY_ID,
                    "reporting": {
                        "demerit_config": {
                            "node_offline_demerits": 1,
                            "reset_interval_seconds": 86400
                        },
                        "backup_node_keys": [],
                        "kick_threshold": 3
                    }
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
    assert!(
        [NODE_KEY_1, NODE_KEY_2].contains(&event.reporter_node_key.as_str()),
        "reporter should be one of the non-accused current-committee members, got {}",
        event.reporter_node_key
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
    assert!(
        !sign_event.report_id.is_empty(),
        "sign report_id should be set"
    );
    assert!(
        [NODE_KEY_1, NODE_KEY_2].contains(&sign_event.reporter_node_key.as_str()),
        "reporter should be one of the non-accused current-committee members, got {}",
        event.reporter_node_key
    );

    // Both the PRE and Sign reports were accepted: node3 should have demerits.
    println!("Checking node3 demerit points...");
    let demerits = controller_client
        .orbis_read_node_demerits(RING_ID, NODE_KEY_3)
        .await
        .expect("query node3 demerits");
    assert_eq!(
        demerits, 2,
        "node3 should have exactly 2 demerits after 2 accepted offline reports"
    );
    println!("node3 demerit points: {demerits}");
}

async fn wait_for_node_info_on_chain(
    client: &SourceHubClient,
    node_key: &str,
    timeout: Duration,
    poll_interval: Duration,
) {
    let deadline = Instant::now() + timeout;
    loop {
        if let Ok(Some(_)) = client.orbis_read_node_info(node_key).await {
            return;
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

#[tokio::test]
#[serial_test::serial]
async fn test_refresh_offline_triggers_on_chain_report() {
    println!("Starting PSS refresh offline reporting integration test...");

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
                    "policy_id": RING_GOVERNANCE_POLICY_ID,
                    "reporting": {
                        "demerit_config": {
                            "node_offline_demerits": 3,
                            "reset_interval_seconds": 86400
                        },
                        "backup_node_keys": [],
                        "kick_threshold": 3
                    }
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

    // Subscribe before stopping node3 so we don't miss the event.
    println!("Subscribing to report events...");
    let sub = ReportEventSubscription::connect(network.sourcehub_rpc_url())
        .await
        .expect("connect report event subscription");

    // Stop node3 — the PSS scheduler fires every 5s and will try to contact node3.
    println!("Stopping node3 to simulate offline node during PSS refresh...");
    network.stop_service(IntegrationTestNetwork::NODE3_SERVICE);

    // The scheduler tick will attempt refresh within ≤5s. However if node3 dies mid-session
    // (while node1 is waiting to receive node3's commitment, not sending), the stuck session
    // must expire first: DKG_PHASE_TIMEOUT (120s) + SESSION_EXPIRATION_CHECK_INTERVAL (60s) =
    // up to 180s before the PSS claim is cleared and a fresh session (which fails the connect
    // immediately) can start. Add margin for report signing: 300s total.
    println!("Waiting for PSS refresh EventReportAccepted on chain (up to 300s)...");
    let event = sub
        .wait_for_report_accepted(RING_ID, Duration::from_secs(300))
        .await
        .expect("EventReportAccepted should be emitted after PSS refresh detects node3 offline");

    println!(
        "Refresh report accepted on chain: report_id={} accused={}",
        event.report_id, event.accused_node_key
    );

    assert_eq!(event.report_type, "node_offline", "unexpected report_type");
    assert_eq!(
        event.accused_node_key, NODE_KEY_3,
        "node3 should be the accused node"
    );
    assert_eq!(event.ring_id, RING_ID, "ring_id mismatch");
    assert!(!event.report_id.is_empty(), "report_id should be set");
    assert!(
        [NODE_KEY_1, NODE_KEY_2].contains(&event.reporter_node_key.as_str()),
        "reporter should be one of the non-accused current-committee members, got {}",
        event.reporter_node_key
    );

    println!("Checking node3 demerit points...");
    let demerits = controller_client
        .orbis_read_node_demerits(RING_ID, NODE_KEY_3)
        .await
        .expect("query node3 demerits");
    assert!(
        demerits >= 3 && demerits % 3 == 0,
        "node3 should have demerits in configured increments of 3 after accepted offline report, got {demerits}"
    );
    println!("node3 demerit points: {demerits}");
}

#[tokio::test]
#[serial_test::serial]
async fn test_reshare_offline_triggers_on_chain_report() {
    println!("Starting PSS reshare offline reporting integration test...");

    // pss_interval=86400 prevents any PSS refresh from firing during the test window.
    // After DKG, Phase 4 writes last_pss=now_secs, so elapsed≈0 which is far below
    // 86400 — the scheduler always skips refresh and never acquires the PSS claim.
    // Reshare bypasses the pss_interval check entirely, so it still fires immediately
    // once new_peer_node_keys is announced on-chain.
    let network = IntegrationTestNetwork::builder()
        .with_module_genesis(
            "orbis",
            serde_json::json!({
                "rings": [{
                    "id": RING_ID,
                    "ring_pk": "",
                    "peer_node_keys": [NODE_KEY_1, NODE_KEY_2, NODE_KEY_3],
                    "threshold": 2,
                    "pss_interval": 86400,
                    "policy_id": RING_GOVERNANCE_POLICY_ID,
                    "reporting": {
                        "demerit_config": {
                            "node_offline_demerits": 1,
                            "reset_interval_seconds": 86400
                        },
                        "backup_node_keys": [],
                        "kick_threshold": 3
                    }
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

    // Subscribe before stopping node3 so we don't miss the event.
    println!("Subscribing to report events...");
    let sub = ReportEventSubscription::connect(network.sourcehub_rpc_url())
        .await
        .expect("connect report event subscription");

    // Stop node3 — it is in the current committee; reshare will try to contact it.
    println!("Stopping node3 to simulate offline node during PSS reshare...");
    network.stop_service(IntegrationTestNetwork::NODE3_SERVICE);

    // Reshare to {node1, node2, node3} with new_threshold=3 and node3 offline.
    // Changing threshold (2→3) satisfies the chain's "must change committee or threshold"
    // check. Node3 cannot ACK any dealer's shares → no dealer ever completes → reshare
    // DKG stays stuck → ring state never updates → the offline report validates and is
    // accepted. Signing uses the CURRENT threshold (2), so node1+node2 can co-sign.
    println!("Triggering ring reshare to [node1, node2, node3] threshold=3 (node3 offline → reshare stuck)...");
    cli_tool::start_ring_reshare_by_acp_with_config(
        RING_ID.to_string(),
        vec![
            NODE_KEY_1.to_string(),
            NODE_KEY_2.to_string(),
            NODE_KEY_3.to_string(),
        ],
        Some(3u32),
        chain_config.clone(),
    )
    .await
    .expect("start ring reshare announcement");

    // Verify MsgStartRingReshareByAcp actually updated the ring state on-chain.
    let payload_bytes = cli_tool::read_bulletin_post_with_config(
        RING_ID.to_string(),
        BulletinKind::Ring,
        chain_config.clone(),
    )
    .await
    .expect("read ring payload after reshare announcement");
    let ring_payload: RingPayload =
        serde_json::from_slice(&payload_bytes).expect("parse RingPayload");
    assert!(
        ring_payload.new_peer_node_keys.is_some(),
        "MsgStartRingReshareByAcp returned success but ring's new_peer_node_keys is still None \
         — the reshare was not announced on-chain"
    );
    println!(
        "Reshare announced on-chain. Waiting for PSS reshare EventReportAccepted (up to 300s)..."
    );

    let event = sub
        .wait_for_report_accepted(RING_ID, Duration::from_secs(300))
        .await
        .expect("EventReportAccepted should be emitted after PSS reshare detects node3 offline");

    println!(
        "Reshare report accepted on chain: report_id={} accused={}",
        event.report_id, event.accused_node_key
    );

    assert_eq!(event.report_type, "node_offline", "unexpected report_type");
    assert_eq!(
        event.accused_node_key, NODE_KEY_3,
        "node3 should be the accused node"
    );
    assert_eq!(event.ring_id, RING_ID, "ring_id mismatch");
    assert!(!event.report_id.is_empty(), "report_id should be set");
    assert_ne!(
        event.reporter_node_key, NODE_KEY_3,
        "the accused (offline) node should not be the reporter"
    );

    println!("Checking node3 demerit points...");
    let demerits = controller_client
        .orbis_read_node_demerits(RING_ID, NODE_KEY_3)
        .await
        .expect("query node3 demerits");
    assert!(
        demerits >= 1,
        "node3 should have demerits after accepted offline report, got {demerits}"
    );
    println!("node3 demerit points: {demerits}");
}

/// Verifies the on-chain kick + backup-node promotion flow: node3 starts with
/// kick_threshold - 1 demerits seeded in genesis, a single accepted offline report
/// pushes it over the threshold, and the chain schedules an auto-reshare that swaps
/// node3 out for the backup node in the ring's `new_peer_node_keys`.
///
/// Reshare completion is out of scope: NODE_KEY_4 has no running node, so the test
/// asserts the announced pending committee, not the finalized one.
#[tokio::test]
#[serial_test::serial]
async fn test_report_kick_promotes_backup_node() {
    println!("Starting backup-node promotion integration test...");

    // Demerits reset once reset_interval_seconds elapse after window_started_at, so
    // anchor the seeded window at test start to keep the seed live for the whole run.
    let window_started_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_secs();

    let network = IntegrationTestNetwork::builder()
        .with_module_genesis(
            "orbis",
            serde_json::json!({
                "rings": [{
                    "id": RING_ID,
                    "ring_pk": "",
                    "peer_node_keys": [NODE_KEY_1, NODE_KEY_2, NODE_KEY_3],
                    "threshold": 2,
                    "pss_interval": 86400,
                    "policy_id": RING_GOVERNANCE_POLICY_ID,
                    "reporting": {
                        "demerit_config": {
                            "node_offline_demerits": 1,
                            "reset_interval_seconds": 86400
                        },
                        "backup_node_keys": [NODE_KEY_4],
                        "kick_threshold": 3
                    }
                }],
                // The backup node has no running container; seed its NodeInfo so the
                // chain considers it eligible for promotion (registered + whitelisted).
                "node_infos": [{
                    "node_key": NODE_KEY_4,
                    "node_info": {
                        "peer_id": "backup-node-4-peer-id",
                        "controller_key": TEST_ACCOUNT_PUBKEY_HEX,
                        "whitelisted_policy_ids": [],
                        "whitelisted_ring_ids": [RING_ID]
                    }
                }],
                // Seed node3 at kick_threshold - 1 so a single accepted report kicks it.
                "node_demerits": [{
                    "ring_id": RING_ID,
                    "node_key": NODE_KEY_3,
                    "points": 2,
                    "window_started_at": window_started_at
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

    // Sanity check: the genesis-seeded demerits for node3 are visible on-chain.
    let seeded_demerits = controller_client
        .orbis_read_node_demerits(RING_ID, NODE_KEY_3)
        .await
        .expect("query seeded node3 demerits");
    assert_eq!(
        seeded_demerits, 2,
        "genesis should seed node3 with kick_threshold - 1 demerits"
    );

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
    let did_pk_string = "backup-kick-test-did".to_string();
    let policy_id = cli_tool::add_policy_to_chain_with_config(chain_config.clone())
        .await
        .expect("add policy");

    let (reader_sk, reader_pk) = generate_keypair().expect("generate reader keypair");
    let reader_sk_hex = hex::encode(CryptoSerialize::to_bytes(&reader_sk).expect("serialize sk"));
    let reader_pk_hex = hex::encode(CryptoSerialize::to_bytes(&reader_pk).expect("serialize pk"));

    let prepared = cli_tool::prepare_secret(
        b"backup-kick-test-secret",
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

    // The kick happens in the same tx as the threshold-crossing report; poll briefly
    // for the auto-reshare announcement to land in queryable state.
    println!("Waiting for auto-reshare announcement on the ring...");
    let deadline = Instant::now() + Duration::from_secs(30);
    let ring = loop {
        let ring = controller_client
            .orbis_read_ring(RING_ID)
            .await
            .expect("read ring")
            .expect("ring should exist");
        if !ring.new_peer_node_keys.is_empty() {
            break ring;
        }
        assert!(
            Instant::now() < deadline,
            "ring never announced new_peer_node_keys after the kick-threshold report"
        );
        sleep(Duration::from_secs(1)).await;
    };

    // The chain stores the pending committee in canonical (sorted) order.
    let mut expected_committee = vec![
        NODE_KEY_1.to_string(),
        NODE_KEY_2.to_string(),
        NODE_KEY_4.to_string(),
    ];
    expected_committee.sort();
    assert_eq!(
        ring.new_peer_node_keys, expected_committee,
        "pending committee should swap node3 out for the backup node"
    );
    assert!(
        !ring.new_peer_node_keys.contains(&NODE_KEY_3.to_string()),
        "kicked node3 must not be in the pending committee"
    );
    assert!(
        ring.peer_node_keys.contains(&NODE_KEY_3.to_string()),
        "active committee is unchanged until the reshare finalizes"
    );
    assert!(
        ring.new_threshold.is_none(),
        "auto-reshare must not change the threshold"
    );
    let reporting = ring.reporting.expect("ring reporting config");
    assert!(
        !reporting.backup_node_keys.contains(&NODE_KEY_4.to_string()),
        "promoted backup key should be consumed from backup_node_keys"
    );

    println!("Checking node3 demerit points...");
    let demerits = controller_client
        .orbis_read_node_demerits(RING_ID, NODE_KEY_3)
        .await
        .expect("query node3 demerits");
    assert!(
        demerits >= 3,
        "node3 demerits should be at least kick_threshold (3), got {demerits}"
    );
    println!("node3 demerit points: {demerits} — backup promotion verified.");
}
