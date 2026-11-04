//! PRE succeeds when one of three nodes is down (threshold=2).
//!
//! Node 0 and node 1 are alive. Node 2's process is aborted before the PRE
//! request. With threshold=2, the two remaining shares are enough to
//! recover the plaintext, so `do_pre` should complete successfully.
//!
//! Harness-unification migration, PR 6: migrated off `fault_injection.rs`'s
//! Cosmos-only in-process bootstrap onto [`super::live_node`]'s shared one.
//! The original used `FaultNetworkController`-free node abort already
//! (`net.charlie.task.abort()`) — a straight port, no fault-controller
//! wiring needed. Fully dual-backend — no `#[ignore]` needed.

use super::live_node::setup_ring;
use tokio::time::Duration;

#[tokio::test]
#[serial_test::serial]
async fn test_pre_one_node_down_succeeds() {
    let net = super::live_node::setup_live_node_network(3, "fault_pre_1node_down").await;
    let endpoint = net.node(0).grpc_endpoint.clone();

    // Step 1: DKG -> ring (threshold=2)
    let (ring_pk_hex, ring_id) = setup_ring(&net, &endpoint, 2).await;

    // Step 2: Add policy + prepare + store secret + authz relationship
    let policy_id = net.create_document_policy().await;
    let resource = "document".to_string();
    let permission = "read".to_string();
    let secret = b"fault-pre-one-down-plaintext";

    let prepared = cli_tool::prepare_secret(
        secret,
        &ring_pk_hex,
        None,
        policy_id.clone(),
        resource.clone(),
        permission.clone(),
        None,
        None,
        None,
        None,
    )
    .expect("prepare secret");

    let obj_resp = cli_tool::store_prepared_secret(
        endpoint.clone(),
        &prepared,
        ring_id.clone(),
        None,
        true,
        None,
    )
    .await
    .expect("store prepared secret");
    let object_id = obj_resp.object_id;

    let did_seed = "fault_reader_1".to_string();
    net.register_object(&policy_id, &resource, &object_id).await;
    net.grant(&policy_id, &resource, &object_id, "reader", &did_seed)
        .await;

    // Step 4: Crash node 2 (abort its task)
    net.node(2).stop();
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Step 5: PRE request — should succeed with nodes 0+1's shares (threshold=2)
    let result = cli_tool::do_pre(
        endpoint.clone(),
        net.node(0).app_state.bulletin.chain_id(),
        ring_pk_hex.clone(),
        object_id.clone(),
        Some(did_seed.clone()),
        None,
        None,
        None,
        None,
    )
    .await
    .expect("PRE should succeed with one node down (threshold=2)");

    assert_eq!(
        result.as_slice(),
        secret.as_ref(),
        "Decrypted plaintext must match original with one node down"
    );

    println!(
        "PRE succeeded with node 2 down: {} bytes decrypted",
        result.len()
    );
}
