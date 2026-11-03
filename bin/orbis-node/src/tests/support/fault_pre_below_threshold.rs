//! PRE fails fast when fewer than threshold nodes are reachable.
//!
//! Nodes 1 and 2 are both aborted before the PRE request. Node 0 can
//! contribute its own local share but has no one else to collect from,
//! leaving only 1 share out of the required 2. The operation should
//! return an error quickly (not hang for `PRE_COLLECTION_TIMEOUT`).
//!
//! Harness-unification migration, PR 6: migrated off `fault_injection.rs`'s
//! Cosmos-only in-process bootstrap onto [`super::live_node`]'s shared one.
//! The original partitioned node 0 from the other two via
//! `FaultNetworkController::block_peer` — ported here as a direct abort of
//! both other nodes instead (per this migration's own PR 6 survey: the test
//! only asserts the *outcome*, insufficient reachable shares, and "node is
//! dead" is just as unreachable as "node is blocked" for that purpose).
//! This avoids needing `FaultNetwork` in the shared dual-backend bootstrap
//! at all — it stays Cosmos-only infrastructure, scoped to this migration's
//! untouched "Bucket C" tests. Fully dual-backend — no `#[ignore]` needed.

use super::live_node::setup_ring;
use tokio::time::Duration;

#[cfg(all(feature = "integration-test", feature = "cosmos"))]
use crate::constants::PRE_COLLECTION_TIMEOUT;
#[cfg(all(feature = "integration-test", feature = "native"))]
use crate::constants::PRE_COLLECTION_TIMEOUT;

#[tokio::test]
#[serial_test::serial]
async fn test_pre_below_threshold_nodes_down_fails_fast() {
    let net =
        super::live_node::setup_live_node_network(3, "fault_pre_below_threshold", 51063).await;
    let endpoint = net.node(0).grpc_endpoint.clone();

    // Step 1: DKG -> ring (threshold=2)
    let (ring_pk_hex, ring_id) = setup_ring(&net, &endpoint, 2).await;

    // Step 2: Add policy + prepare + store secret + authz relationship
    let policy_id = net.create_document_policy().await;
    let resource = "document".to_string();
    let permission = "read".to_string();
    let secret = b"fault-pre-below-threshold-plaintext";

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

    let did_seed = "fault_reader_2".to_string();
    net.register_object(&policy_id, &resource, &object_id).await;
    net.grant(&policy_id, &resource, &object_id, "reader", &did_seed)
        .await;

    // Step 4: Crash nodes 1 and 2 — node 0 has no one left to collect from.
    net.node(1).stop();
    net.node(2).stop();
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Step 5: PRE request — should fail (insufficient shares) and complete well
    //         within PRE_COLLECTION_TIMEOUT + 5s (not hang indefinitely).
    let deadline = PRE_COLLECTION_TIMEOUT + Duration::from_secs(5);
    let timed = tokio::time::timeout(
        deadline,
        cli_tool::do_pre(
            endpoint.clone(),
            net.node(0).app_state.bulletin.chain_id(),
            ring_pk_hex.clone(),
            object_id.clone(),
            Some(did_seed.clone()),
            None,
            None,
            None,
            None,
        ),
    )
    .await;

    match timed {
        Err(_) => panic!(
            "PRE with no reachable peers hung past PRE_COLLECTION_TIMEOUT + 5s — \
             JoinSet timeout not working"
        ),
        Ok(inner) => {
            assert!(
                inner.is_err(),
                "PRE should return an error when nodes 1 and 2 are unreachable, \
                 but it returned Ok"
            );
            println!("PRE failed fast as expected: {:?}", inner.unwrap_err());
        }
    }
}
