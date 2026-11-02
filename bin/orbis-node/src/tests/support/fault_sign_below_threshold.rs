//! SIGN fails fast when fewer than threshold nodes are reachable.
//!
//! Nodes 1 and 2 are both aborted before the SIGN request. Node 0 can
//! contribute its own local signing share but has no one else to collect
//! from, leaving only 1 share out of the required 2. The operation should
//! return an error quickly (not hang for `SIGN_COLLECTION_TIMEOUT`).
//!
//! Harness-unification migration, PR 6: migrated off `fault_injection.rs`'s
//! Cosmos-only in-process bootstrap onto [`super::live_node`]'s shared one
//! — same "abort instead of block_peer" port as
//! `fault_pre_below_threshold.rs`. Fully dual-backend — no `#[ignore]`
//! needed.

use super::live_node::setup_ring;
use tokio::time::Duration;

#[cfg(all(feature = "integration-test", feature = "cosmos"))]
use crate::constants::SIGN_COLLECTION_TIMEOUT;
#[cfg(all(feature = "integration-test", feature = "native"))]
use orbis_node::constants::SIGN_COLLECTION_TIMEOUT;

#[tokio::test]
#[serial_test::serial]
async fn test_sign_below_threshold_nodes_down_fails_fast() {
    let net =
        super::live_node::setup_live_node_network(3, "fault_sign_below_threshold", 51069).await;
    let endpoint = net.node(0).grpc_endpoint.clone();

    // Step 1: DKG -> ring (threshold=2)
    let (ring_pk_hex, ring_id) = setup_ring(&net, &endpoint, 2).await;

    // Step 2: Prepare secret (local)
    let policy_id = net.create_document_policy().await;
    let resource = "document".to_string();
    let permission = "read".to_string();
    let secret = b"fault-sign-below-threshold-secret";

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

    // Step 3: Crash nodes 1 and 2 — node 0 has no one left to collect from.
    net.node(1).stop();
    net.node(2).stop();
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Step 4: store_prepared_secret — should fail (insufficient shares) and complete
    //         well within SIGN_COLLECTION_TIMEOUT + 5s (not hang indefinitely).
    let deadline = SIGN_COLLECTION_TIMEOUT + Duration::from_secs(5);
    let timed = tokio::time::timeout(
        deadline,
        cli_tool::store_prepared_secret(
            endpoint.clone(),
            &prepared,
            ring_id.clone(),
            None,
            true,
            None,
        ),
    )
    .await;

    match timed {
        Err(_) => panic!(
            "SIGN with no reachable peers hung past SIGN_COLLECTION_TIMEOUT + 5s — \
             JoinSet timeout not working"
        ),
        Ok(inner) => {
            assert!(
                inner.is_err(),
                "SIGN should return an error when nodes 1 and 2 are unreachable, \
                 but it returned Ok"
            );
            println!("SIGN failed fast as expected: {:?}", inner.unwrap_err());
        }
    }
}
