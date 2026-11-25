//! Three simultaneous PRE decryptions of the same ciphertext must all
//! complete and return the original plaintext.
//!
//! Harness-unification migration, PR 6: migrated off `concurrent.rs`'s
//! Cosmos-only in-process bootstrap onto [`super::live_node`]'s shared one.
//! Exercises `PreResponseManager` under concurrent load — all three requests
//! are in flight simultaneously, each collecting threshold re-encryption
//! shares from the responder nodes. Fully dual-backend — no `#[ignore]`
//! needed on either side.

use super::live_node::setup_ring;

#[tokio::test]
#[serial_test::serial]
async fn test_concurrent_pre_requests() {
    let net = super::live_node::setup_live_node_network(3, "concurrent_pre").await;
    let endpoint = net.node(0).grpc_endpoint.clone();

    // Step 1: DKG -> ring
    let (ring_pk_hex, ring_id) = setup_ring(&net, &endpoint, 2).await;

    // Step 2: Store one encrypted secret on the bulletin
    let policy_id = net.create_document_policy().await;
    let resource = "document".to_string();
    let permission = "read".to_string();
    let secret = b"concurrent-pre-plaintext";

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

    // Step 3: Authz -- register the object and grant read access to the test DID
    let did_seed = "pre_reader".to_string();
    net.register_object(&policy_id, &resource, &object_id).await;
    net.grant(&policy_id, &resource, &object_id, "reader", &did_seed)
        .await;

    // Step 4: Three concurrent PRE decryptions -- each generates its own
    // fresh ephemeral reader keypair internally.
    let (r1, r2, r3) = tokio::join!(
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
    );

    let d1 = r1.expect("PRE 1 failed");
    let d2 = r2.expect("PRE 2 failed");
    let d3 = r3.expect("PRE 3 failed");

    assert_eq!(d1.as_slice(), secret.as_ref(), "PRE 1 plaintext mismatch");
    assert_eq!(d2.as_slice(), secret.as_ref(), "PRE 2 plaintext mismatch");
    assert_eq!(d3.as_slice(), secret.as_ref(), "PRE 3 plaintext mismatch");

    println!("All 3 concurrent PRE requests decrypted successfully.");
}
