//! SIGN (`store_prepared_secret`) succeeds when one of three nodes is down
//! (threshold=2).
//!
//! Node 0 and node 1 are alive. Node 2's process is aborted before the SIGN
//! request. With threshold=2, the two remaining signature shares are enough
//! to recover the full signature, so `store_prepared_secret` should
//! complete successfully.
//!
//! Harness-unification migration, PR 6: migrated off `fault_injection.rs`'s
//! Cosmos-only in-process bootstrap onto [`super::live_node`]'s shared one.
//! Fully dual-backend — no `#[ignore]` needed.

use super::live_node::setup_ring;
use tokio::time::Duration;

#[tokio::test]
#[serial_test::serial]
async fn test_sign_one_node_down_succeeds() {
    let net = super::live_node::setup_live_node_network(3, "fault_sign_1node_down", 51066).await;
    let endpoint = net.node(0).grpc_endpoint.clone();

    // Step 1: DKG -> ring (threshold=2)
    let (ring_pk_hex, ring_id) = setup_ring(&net, &endpoint, 2).await;

    // Step 2: Prepare secret (local, no network needed)
    let policy_id = net.create_document_policy().await;
    let resource = "document".to_string();
    let permission = "read".to_string();
    let secret = b"fault-sign-one-down-secret";

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

    // Step 3: Crash node 2 before the SIGN operation
    net.node(2).stop();
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Step 4: store_prepared_secret triggers FROST signing — should succeed
    // with nodes 0+1's shares.
    let resp = cli_tool::store_prepared_secret(
        endpoint.clone(),
        &prepared,
        ring_id.clone(),
        None,
        true,
        None,
    )
    .await
    .expect("SIGN should succeed with one node down (threshold=2)");

    assert!(
        !resp.object_id.is_empty(),
        "store_prepared_secret must return an object_id"
    );
    assert!(
        !resp.signature.is_empty(),
        "store_prepared_secret must return a signature"
    );

    println!(
        "SIGN succeeded with node 2 down: object_id={}, sig_len={}",
        resp.object_id,
        resp.signature.len()
    );
}
