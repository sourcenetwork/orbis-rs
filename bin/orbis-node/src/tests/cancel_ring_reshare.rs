//! Docker-based integration test: cancel a permanently-stuck ring reshare.
//!
//! Spins up a full Docker Compose environment (SourceHub + 3 orbis-node containers),
//! runs a real DKG, announces a reshare into a committee that can never complete
//! (it includes a genesis-seeded but never-running node key), cancels it via the
//! new `CancelRingReshareByAcp` chain message, and confirms the ring reverts to its
//! original committee/threshold with the original committee still able to Sign.
//!
//! Run with:
//!   cargo test -p orbis-node --features integration-test -- test_cancel_stuck_reshare_reverts_ring_and_preserves_signing --nocapture

use bulletin::r#trait::{BulletinKind, RingPayload};
use common::{
    blockchain::{
        orbis::WhitelistTarget, ChainConfig, SourceHubClient, TxSigner, TEST_ACCOUNT_HEX_KEY,
        TEST_ACCOUNT_PUBKEY_HEX,
    },
    IntegrationTestNetwork,
};
use crypto::r#trait::ThresholdSigner;
use crypto::{CryptoDeserialize, GroupAffine, SignImpl};
use tokio::time::{sleep, Duration, Instant};

use super::constants::{
    reporting_genesis_json, NODE_KEY_1, NODE_KEY_2, NODE_KEY_3, NODE_KEY_OFFLINE,
    OFFLINE_NODE_PEER_ID, RING_GOVERNANCE_POLICY_ID,
};

const RING_ID: &str = "cancel-ring-reshare-ring";

fn sorted_node_keys(node_keys: &[String]) -> Vec<String> {
    let mut sorted = node_keys.to_vec();
    sorted.sort();
    sorted
}

async fn wait_for_node_info_on_chain(
    controller_client: &SourceHubClient,
    node_key: &str,
    timeout: Duration,
    poll_interval: Duration,
) {
    let deadline = Instant::now() + timeout;

    loop {
        let status = match controller_client.orbis_read_node_info(node_key).await {
            Ok(Some(_)) => return,
            Ok(None) => "not found".to_string(),
            Err(e) => e.to_string(),
        };

        assert!(
            Instant::now() < deadline,
            "NodeInfo for node_key {} was not visible on-chain within {:?}: {}",
            node_key,
            timeout,
            status
        );
        sleep(poll_interval).await;
    }
}

async fn read_ring_payload(chain_config: &ChainConfig, ring_id: &str) -> RingPayload {
    let payload_bytes = cli_tool::read_bulletin_post_with_config(
        ring_id.to_string(),
        BulletinKind::Ring,
        chain_config.clone(),
    )
    .await
    .expect("read ring payload from bulletin");
    serde_json::from_slice(&payload_bytes).expect("parse RingPayload")
}

async fn do_sign_expect_success(
    context: &str,
    endpoint: String,
    message: Vec<u8>,
    derivation_id: String,
    reader_did_pk: Option<String>,
) -> cli_tool::SignResult {
    let deadline = Instant::now() + Duration::from_secs(90);
    let mut attempt = 1usize;

    loop {
        match cli_tool::do_sign(
            endpoint.clone(),
            message.clone(),
            derivation_id.clone(),
            reader_did_pk.clone(),
            None,
            None,
        )
        .await
        {
            Ok(result) => return result,
            Err(e) => {
                assert!(
                    Instant::now() < deadline,
                    "{} failed after {} attempts: {}",
                    context,
                    attempt,
                    e
                );
                println!(
                    "{} attempt {} failed, retrying after transient signing race: {}",
                    context, attempt, e
                );
                attempt += 1;
                sleep(Duration::from_secs(3)).await;
            }
        }
    }
}

#[tokio::test]
#[serial_test::serial]
async fn test_cancel_stuck_reshare_reverts_ring_and_preserves_signing() {
    println!("Starting cancel-stuck-reshare integration test...");

    // NODE_KEY_OFFLINE has genesis-seeded NodeInfo but no running node behind it: a
    // dealer only completes once *every* new-committee member acks its share, so
    // including it in a reshare's target committee makes that reshare provably and
    // deterministically un-completable (see the identical mechanism documented on
    // test_reshare_bad_dkg_share_relay_triggers_on_chain_report in reporting.rs).
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
                    "reporting": reporting_genesis_json(1, &[], 3)
                }],
                "node_infos": [{
                    "node_key": NODE_KEY_OFFLINE,
                    "node_info": {
                        "peer_id": OFFLINE_NODE_PEER_ID,
                        "controller_key": TEST_ACCOUNT_PUBKEY_HEX,
                        "whitelisted_policy_ids": [],
                        "whitelisted_ring_ids": [RING_ID]
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

    let peer_addresses = [
        IntegrationTestNetwork::transform_p2p_address(
            &node1_info.p2p_address,
            IntegrationTestNetwork::NODE1_SERVICE,
        ),
        IntegrationTestNetwork::transform_p2p_address(
            &node2_info.p2p_address,
            IntegrationTestNetwork::NODE2_SERVICE,
        ),
        IntegrationTestNetwork::transform_p2p_address(
            &node3_info.p2p_address,
            IntegrationTestNetwork::NODE3_SERVICE,
        ),
    ];

    let controller_client = SourceHubClient::with_signer(
        chain_config.clone(),
        TxSigner::from_hex_key(TEST_ACCOUNT_HEX_KEY, chain_config.clone())
            .expect("test account signer"),
    )
    .await
    .expect("controller chain client");

    let original_node_keys = [NODE_KEY_1, NODE_KEY_2, NODE_KEY_3];
    let governance_policy_id = crate::helpers::test_helpers::create_ring_governance_with_ring(
        &controller_client,
        RING_ID,
        &original_node_keys,
    )
    .await;
    assert_eq!(
        governance_policy_id, RING_GOVERNANCE_POLICY_ID,
        "ACP policy ID mismatch — acp_core may have changed. \
         Update RING_GOVERNANCE_POLICY_ID to: {governance_policy_id}"
    );

    for (node_key, peer_address) in original_node_keys.iter().zip(&peer_addresses) {
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
            "update NodeInfo peer ID tx failed: {}",
            peer_update.log
        );

        let whitelist_update = controller_client
            .orbis_add_node_to_whitelist(node_key, WhitelistTarget::RingId(RING_ID.to_string()))
            .await
            .expect("add ring to NodeInfo whitelist");
        assert_eq!(
            whitelist_update.code, 0,
            "add ring to NodeInfo whitelist tx failed: {}",
            whitelist_update.log
        );
    }

    // ====================================================================
    // Step 1: Real DKG, so the ring holds genuine, mutually-consistent shares
    // before we ever try to reshare it.
    // ====================================================================
    println!("Starting DKG for ring {RING_ID}...");
    let dkg_result = cli_tool::do_dkg(endpoint.clone(), RING_ID.to_string()).await;
    assert!(
        dkg_result.is_ok(),
        "DKG should succeed: {:?}",
        dkg_result.err()
    );

    let ring_pk_hex = crate::helpers::test_helpers::wait_for_ring_finalized(
        &chain_config,
        RING_ID,
        Duration::from_secs(90),
    )
    .await;
    println!(
        "DKG finalized. Ring PK: {}...",
        &ring_pk_hex[..40.min(ring_pk_hex.len())]
    );

    // ====================================================================
    // Step 2: Baseline Sign, proving the original committee works before we
    // ever attempt (and abandon) a reshare.
    // ====================================================================
    let policy_id = cli_tool::add_policy_to_chain_with_config(chain_config.clone())
        .await
        .expect("policy_id");
    let resource = "document".to_string();
    let permission = "read".to_string();
    let sign_derivation = "cancel-reshare-test-derivation".to_string();
    let sign_did_pk = "cancel_reshare_test_did_secret".to_string();

    let (derivation_id, derived_pk_hex) = cli_tool::post_key_derivation_with_config(
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
    .expect("register_object_to_chain for derivation_id");

    cli_tool::set_relationship_on_chain_with_config(
        policy_id.clone(),
        derivation_id.clone(),
        resource.clone(),
        "reader".to_string(),
        Some(sign_did_pk.clone()),
        chain_config.clone(),
    )
    .await
    .expect("set_relationship_on_chain for derivation_id");

    let sign_message = b"hello before the aborted reshare";
    let baseline_sign = do_sign_expect_success(
        "baseline Sign",
        endpoint.clone(),
        sign_message.to_vec(),
        derivation_id.clone(),
        Some(sign_did_pk.clone()),
    )
    .await;

    let derived_pk_bytes = hex::decode(&derived_pk_hex).expect("decode derived_pk hex");
    let derived_pk = GroupAffine::from_bytes(&derived_pk_bytes).expect("deserialize derived_pk");
    let signer = SignImpl::new();
    let baseline_sig_bytes = hex::decode(&baseline_sign.signature).expect("decode baseline sig");
    let baseline_signature =
        <SignImpl as ThresholdSigner>::Signature::from_bytes(&baseline_sig_bytes)
            .expect("deserialize baseline signature");
    signer
        .verify(&derived_pk, sign_message, &baseline_signature)
        .expect("baseline signature should verify against derived public key");
    println!("Baseline Sign verified — original committee is healthy.");

    // ====================================================================
    // Step 3: Announce a reshare that can never complete (new committee
    // includes the never-running NODE_KEY_OFFLINE).
    // ====================================================================
    let stuck_new_peer_node_keys = vec![
        NODE_KEY_1.to_string(),
        NODE_KEY_2.to_string(),
        NODE_KEY_3.to_string(),
        NODE_KEY_OFFLINE.to_string(),
    ];
    let stuck_new_threshold = 2u32;

    println!("Announcing a reshare that includes the offline node (must never complete)...");
    cli_tool::start_ring_reshare_by_acp_with_config(
        RING_ID.to_string(),
        stuck_new_peer_node_keys.clone(),
        Some(stuck_new_threshold),
        chain_config.clone(),
    )
    .await
    .expect("start ring reshare announcement");

    let announced_payload = read_ring_payload(&chain_config, RING_ID).await;
    assert_eq!(
        announced_payload
            .new_peer_node_keys
            .as_ref()
            .map(|keys| sorted_node_keys(keys)),
        Some(sorted_node_keys(&stuck_new_peer_node_keys)),
        "reshare announcement should set the stuck target committee"
    );
    assert_eq!(
        announced_payload.new_threshold,
        Some(stuck_new_threshold),
        "reshare announcement should set the stuck target threshold"
    );

    // ====================================================================
    // Step 4: Confirm it's genuinely stuck, not just "not yet finished" —
    // the pending fields must still be set after a bounded wait.
    // ====================================================================
    println!("Confirming the reshare does not complete on its own...");
    sleep(Duration::from_secs(15)).await;
    let still_pending = controller_client
        .orbis_read_ring(RING_ID)
        .await
        .expect("read ring while confirming stall")
        .expect("ring must still exist");
    assert!(
        !still_pending.new_peer_node_keys.is_empty(),
        "reshare unexpectedly completed on its own; the offline-member stall fixture is broken"
    );

    // ====================================================================
    // Step 5: Cancel it, and confirm the ring reverts (not just clears).
    // ====================================================================
    println!("Cancelling the stuck reshare...");
    cli_tool::cancel_ring_reshare_by_acp_with_config(RING_ID.to_string(), chain_config.clone())
        .await
        .expect("cancel ring reshare");

    let cancel_deadline = Instant::now() + Duration::from_secs(30);
    let reverted_ring = loop {
        let ring = controller_client
            .orbis_read_ring(RING_ID)
            .await
            .expect("poll ring after cancel")
            .expect("ring must still exist after cancel");
        if ring.new_peer_node_keys.is_empty() && ring.new_threshold.is_none() {
            break ring;
        }
        assert!(
            Instant::now() < cancel_deadline,
            "reshare was not cancelled within 30 seconds"
        );
        sleep(Duration::from_secs(1)).await;
    };
    assert_eq!(
        sorted_node_keys(&reverted_ring.peer_node_keys),
        sorted_node_keys(
            &original_node_keys
                .iter()
                .map(|k| k.to_string())
                .collect::<Vec<_>>()
        ),
        "cancelling the reshare must leave the original committee in place"
    );
    assert_eq!(
        reverted_ring.threshold, 2,
        "cancelling the reshare must leave the original threshold in place"
    );
    assert_eq!(
        reverted_ring.ring_pk, ring_pk_hex,
        "cancelling the reshare must not change the ring's public key"
    );
    println!("Reshare cancelled; ring reverted to the original committee/threshold.");

    // ====================================================================
    // Step 6: Post-cancel Sign — the strongest proof available that no
    // node's share was corrupted by the aborted reshare attempt.
    // ====================================================================
    let sign_message_after = b"hello after cancelling the reshare";
    let post_cancel_sign = do_sign_expect_success(
        "post-cancel Sign",
        endpoint.clone(),
        sign_message_after.to_vec(),
        derivation_id.clone(),
        Some(sign_did_pk.clone()),
    )
    .await;
    let post_cancel_sig_bytes =
        hex::decode(&post_cancel_sign.signature).expect("decode post-cancel sig");
    let post_cancel_signature =
        <SignImpl as ThresholdSigner>::Signature::from_bytes(&post_cancel_sig_bytes)
            .expect("deserialize post-cancel signature");
    signer
        .verify(&derived_pk, sign_message_after, &post_cancel_signature)
        .expect("post-cancel signature should verify against the unchanged derived public key");

    println!("Post-cancel Sign verified — the original committee is still fully functional.");
}
