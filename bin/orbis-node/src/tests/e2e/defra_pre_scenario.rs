//! Docker E2E: a real 3-node ring backed by a real Defra container end to end.
//!
//! Cosmos-only (see the Defra PRE-Share Storage plan's Step 6 — native
//! doesn't carry `pre_share_endpoints` in this PR). Uses `CosmosNetwork`
//! directly rather than the backend-neutral `TestEnvironmentImpl`/
//! `BackendAdmin` fixture layer: `BackendAdmin::register_ring` is itself
//! `unimplemented!()` for Cosmos (ring creation always goes through
//! `cli_tool::create_ring` via `helpers::test_helpers`), and the
//! backend-neutral `RingSpec` deliberately has no `pre_share_endpoints`
//! field at all, so there is nothing to plug into there regardless.
//!
//! Complements (does not replace) `pre::v0::tests::
//! test_pre_with_defra_stored_delivery_end_to_end`, which exercises the same
//! Defra-backed recovery path in-process against a mocked Defra endpoint —
//! deliberately so, since that test's own harness has no real gRPC server to
//! connect to. This test is the one place in the whole feature that proves
//! the real gRPC round trip (`cli_tool::do_pre` over an actual
//! `PreServiceClient` connection) against a *real* `defra` binary.

use std::time::Duration;

use test_support::CosmosNetwork;

use crate::helpers::test_helpers::{
    create_orbis_ring_policy, create_ring_on_chain_with_pre_share_endpoints,
    wait_for_ring_finalized,
};

const THRESHOLD: u32 = 2;
const PLAINTEXT: &[u8] = b"defra-docker-e2e-plaintext";
const READER_SEED: &str = "defra-pre-scenario-reader";

#[tokio::test]
#[serial_test::serial]
async fn test_defra_backed_pre_end_to_end() {
    let network = CosmosNetwork::builder().with_defra().build();
    let defra_url = network
        .defra_url()
        .expect("with_defra() was set")
        .to_string();

    // Playing the ring operator's role: no production code provisions this
    // collection automatically (confirmed by reading every `orbis-node` call
    // site — `provision_collection` is only ever called from `pre-share`'s
    // own unit tests), standing up Defra infrastructure ahead of a ring
    // that points at it is the operator's job.
    let defra_client = pre_share::DefraClient::new(
        pre_share::Url::parse(&defra_url).expect("defra_url is a valid URL"),
        String::new(),
    )
    .expect("build Defra client");
    defra_client
        .provision_collection(pre_share::PRE_SHARE_COLLECTION_SDL)
        .await
        .expect("provision PreShare collection");

    let mut node_keys = Vec::new();
    for endpoint in network.all_endpoints() {
        let info = cli_tool::query_node_info(endpoint.to_string())
            .await
            .expect("query node info");
        node_keys.push(info.node_key);
    }

    let ring_policy_id = create_orbis_ring_policy(&network.chain_config()).await;
    // The bridge-network gateway address, reachable both by producer nodes
    // (sibling containers) and by this test's own reader-role `do_pre` call
    // below (running on the host) — unlike the `defra` Compose service name,
    // which only resolves inside the Compose network. See
    // `CosmosNetwork::defra_container_url`'s doc comment.
    let ring_id = create_ring_on_chain_with_pre_share_endpoints(
        &network.chain_config(),
        &node_keys,
        THRESHOLD,
        &ring_policy_id,
        None,
        vec![network
            .defra_container_url()
            .expect("with_defra() was set")
            .to_string()],
    )
    .await;

    // Each Dockerized node self-registers its own `NodeInfo` on startup with
    // no ring/policy whitelisted — unlike `live_node.rs`'s in-process
    // bootstrap, the test has no way to inject a custom whitelist into that
    // self-registration, so each node must be whitelisted for this specific
    // ring via its own transaction, same as `CosmosTestEnvironment::provision`
    // does for the fixture-driven path.
    for node_key in &node_keys {
        cli_tool::add_node_to_whitelist_with_config(
            node_key.clone(),
            common::blockchain::orbis::WhitelistTarget::RingId(ring_id.clone()),
            network.chain_config(),
        )
        .await
        .expect("whitelist node for ring");
    }

    cli_tool::do_dkg(network.node1_endpoint().to_string(), ring_id.clone())
        .await
        .expect("DKG initiation");
    let ring_pk_hex =
        wait_for_ring_finalized(&network.chain_config(), &ring_id, Duration::from_secs(90)).await;

    let document_policy_id = cli_tool::add_policy_to_chain_with_config(network.chain_config())
        .await
        .expect("add document policy");

    let prepared = cli_tool::prepare_secret(
        PLAINTEXT,
        &ring_pk_hex,
        None,
        document_policy_id.clone(),
        "document".to_string(),
        "read".to_string(),
        None,
        None,
        None,
        None,
    )
    .expect("prepare secret");

    let stored = cli_tool::store_prepared_secret(
        network.node1_endpoint().to_string(),
        &prepared,
        ring_id.clone(),
        None,
        true,
        None,
    )
    .await
    .expect("store prepared secret");
    let object_id = stored.object_id;

    cli_tool::register_object_to_chain_with_config(
        document_policy_id.clone(),
        object_id.clone(),
        "document".to_string(),
        network.chain_config(),
    )
    .await
    .expect("register document object");
    cli_tool::set_relationship_on_chain_with_config(
        document_policy_id,
        object_id.clone(),
        "document".to_string(),
        "reader".to_string(),
        Some(READER_SEED.to_string()),
        network.chain_config(),
    )
    .await
    .expect("grant reader relationship");

    // The real gRPC round trip: StartPre -> PreReencryptResponse::Stored ->
    // pre_share::recover_from_manifest (fetching from the real `defra`
    // container) -> decrypt. Exercises the full chain this feature promises,
    // not an in-process shortcut.
    let decrypted = cli_tool::do_pre(
        network.node1_endpoint().to_string(),
        network.chain_config().chain_id,
        ring_pk_hex,
        object_id,
        Some(READER_SEED.to_string()),
        None,
        None,
        None,
        None,
    )
    .await
    .expect("Defra-backed PRE should succeed end to end");

    assert_eq!(
        decrypted, PLAINTEXT,
        "decrypted plaintext must match the original secret"
    );
}
