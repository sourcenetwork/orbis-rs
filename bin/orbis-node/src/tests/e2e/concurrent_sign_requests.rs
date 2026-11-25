//! Three threshold-BLS signing requests on the same ring running
//! simultaneously must all complete without deadlock or nonce reuse.
//!
//! Harness-unification migration, PR 6: migrated off `concurrent.rs`'s
//! Cosmos-only in-process bootstrap onto [`super::live_node`]'s shared one.
//! Exercises `SignResponseManager`/`NonceStateManager` under concurrent
//! load — all three FROST signing sessions are in flight at the same time.
//! Fully dual-backend — no `#[ignore]` needed on either side.

use super::live_node::setup_ring;

#[tokio::test]
#[serial_test::serial]
async fn test_concurrent_sign_requests() {
    let net = super::live_node::setup_live_node_network(3, "concurrent_sign").await;
    let endpoint = net.node(0).grpc_endpoint.clone();

    // Step 1: DKG -> ring
    let (ring_pk_hex, ring_id) = setup_ring(&net, &endpoint, 2).await;

    // Step 2: Add a policy (required as payload metadata; authz enforcement is PRE-only)
    let policy_id = net.create_document_policy().await;
    let resource = "document".to_string();
    let permission = "read".to_string();

    // Prepare three distinct secrets -- each produces a separate bulletin post + signature
    let secrets: [&[u8]; 3] = [b"sign-secret-one", b"sign-secret-two", b"sign-secret-three"];
    let preps: Vec<_> = secrets
        .iter()
        .map(|s| {
            cli_tool::prepare_secret(
                s,
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
            .expect("prepare secret")
        })
        .collect();

    // Step 3: Three concurrent store_prepared_secret calls, each triggering a
    // full FROST threshold BLS signing round-trip.
    let (r1, r2, r3) = tokio::join!(
        cli_tool::store_prepared_secret(
            endpoint.clone(),
            &preps[0],
            ring_id.clone(),
            None,
            true,
            None,
        ),
        cli_tool::store_prepared_secret(
            endpoint.clone(),
            &preps[1],
            ring_id.clone(),
            None,
            true,
            None,
        ),
        cli_tool::store_prepared_secret(
            endpoint.clone(),
            &preps[2],
            ring_id.clone(),
            None,
            true,
            None,
        ),
    );

    let resp1 = r1.expect("SIGN 1 failed");
    let resp2 = r2.expect("SIGN 2 failed");
    let resp3 = r3.expect("SIGN 3 failed");

    assert!(
        !resp1.object_id.is_empty(),
        "SIGN 1 must produce an object_id"
    );
    assert!(
        !resp2.object_id.is_empty(),
        "SIGN 2 must produce an object_id"
    );
    assert!(
        !resp3.object_id.is_empty(),
        "SIGN 3 must produce an object_id"
    );
    assert!(
        !resp1.signature.is_empty(),
        "SIGN 1 must produce a signature"
    );
    assert!(
        !resp2.signature.is_empty(),
        "SIGN 2 must produce a signature"
    );
    assert!(
        !resp3.signature.is_empty(),
        "SIGN 3 must produce a signature"
    );
    assert_ne!(
        resp1.object_id, resp2.object_id,
        "distinct secrets must produce distinct bulletin posts"
    );
    assert_ne!(
        resp1.object_id, resp3.object_id,
        "distinct secrets must produce distinct bulletin posts"
    );
    assert_ne!(
        resp2.object_id, resp3.object_id,
        "distinct secrets must produce distinct bulletin posts"
    );

    println!(
        "All 3 concurrent SIGN requests completed:\n  obj1={}\n  obj2={}\n  obj3={}",
        resp1.object_id, resp2.object_id, resp3.object_id,
    );
}
