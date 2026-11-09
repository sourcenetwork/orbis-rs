//! Docker E2E: a real 3-node ring backed by a real Defra container end to end.
//!
//! Runs on both backends. One test, same name, same `#[tokio::test]` — the
//! backend selector is a `#[cfg]`'d body per branch, matching `upgrade.rs`'s
//! convention, not two separate function definitions.
//!
//! Goes through `TestEnvironmentImpl::provision` (`ScenarioFixture::defra`)
//! like every other scenario, rather than building a raw `CosmosNetwork`/
//! `NativeNetworkAdapter` directly — `environment.defra_url()`/
//! `defra_container_url()` are escape hatches each concrete environment
//! exposes (not part of any shared trait: see each one's own doc comment).
//! Ring creation itself still can't go through the backend-neutral
//! `BackendAdmin::register_ring`/`RingSpec` fixture path: that trait
//! deliberately has no `pre_share_endpoints` concept, so each backend drives
//! ring creation through its own escape hatch instead — `cli_tool::create_ring`
//! (via `chain_config()`) on Cosmos, `NativeTestEnvironment::
//! create_ring_with_pre_share_endpoints` on native.
//!
//! Complements (does not replace) `pre::v0::tests::
//! test_pre_with_defra_stored_delivery_end_to_end`, which exercises the same
//! Defra-backed recovery path in-process against a mocked Defra endpoint —
//! deliberately so, since that test's own harness has no real gRPC server to
//! connect to. This test is the one place in the whole feature that proves
//! the real gRPC round trip (`cli_tool::do_pre` over an actual
//! `PreServiceClient` connection) against a *real* `defra` binary.

use super::TestEnvironmentImpl;

#[cfg(feature = "cosmos")]
use std::time::Duration;

use test_support::fixture::{
    FixtureId, NetworkTestDriver, NodeFixture, NodeRole, ScenarioFixture, TestEnvironment,
};

#[cfg(feature = "cosmos")]
use crate::helpers::test_helpers::{
    create_orbis_ring_policy, create_ring_on_chain_with_pre_share_endpoints,
    wait_for_ring_finalized,
};

#[cfg(feature = "native")]
use super::pre_scenario;
#[cfg(feature = "native")]
use test_support::fixture::AuthorizationTestDriver;

const THRESHOLD: u32 = 2;
#[cfg(feature = "cosmos")]
const PLAINTEXT: &[u8] = b"defra-docker-e2e-plaintext";
#[cfg(feature = "cosmos")]
const READER_SEED: &str = "defra-pre-scenario-reader";

#[cfg(feature = "native")]
const NATIVE_RING_POLICY_YAML: &str = r#"
name: defra-pre-scenario-ring-policy
resources:
  - name: ring_policy
    relations:
      - name: creator
    permissions:
      - name: create_ring
        expr: creator
  - name: ring
    relations:
      - name: operator
    permissions:
      - name: update_ring
        expr: operator
"#;

#[cfg(feature = "native")]
const NATIVE_DOCUMENT_POLICY_YAML: &str = r#"
name: defra-pre-scenario-document-policy
resources:
- name: document
  permissions:
  - name: read
    expr: reader
  relations:
  - name: reader
    types:
    - actor
"#;

#[tokio::test]
#[serial_test::serial]
async fn test_defra_backed_pre_end_to_end() {
    let fixture = ScenarioFixture {
        nodes: (0..3)
            .map(|_| NodeFixture {
                id: FixtureId::new("node"),
                role: NodeRole::Running,
            })
            .collect(),
        defra: true,
        ..Default::default()
    };
    let environment = TestEnvironmentImpl::provision(fixture).await;

    #[cfg(feature = "native")]
    run_native_defra_pre_scenario(&environment).await;

    #[cfg(feature = "cosmos")]
    run_defra_pre_scenario(&environment).await;
}

#[cfg(feature = "native")]
async fn run_native_defra_pre_scenario(environment: &TestEnvironmentImpl) {
    let defra_url = environment
        .defra_url()
        .expect("ScenarioFixture::defra was set")
        .to_string();

    // Playing the ring operator's role, same as the Cosmos branch — see its
    // own comment on why no production code does this automatically.
    let defra_client = pre_share::DefraClient::new(
        pre_share::Url::parse(&defra_url).expect("defra_url is a valid URL"),
        String::new(),
    )
    .expect("build Defra client");
    defra_client
        .provision_collection(pre_share::PRE_SHARE_COLLECTION_SDL)
        .await
        .expect("provision PreShare collection");

    let node_keys: Vec<String> = environment
        .nodes()
        .iter()
        .map(|node| node.node_key.clone())
        .collect();

    let ring_policy_id = environment.create_policy(NATIVE_RING_POLICY_YAML).await;
    // The statically pre-assigned bridge-network address (see
    // `NativeTestNetwork::defra_container_url`'s doc comment) — reachable
    // both by producer nodes (sibling containers) and by `pre_scenario::run`'s
    // own reader-role `cli_tool::do_pre` calls below, running on the host.
    let ring_id = environment
        .create_ring_with_pre_share_endpoints(
            &ring_policy_id,
            &node_keys,
            THRESHOLD,
            vec![environment
                .defra_container_url()
                .expect("ScenarioFixture::defra was set")],
        )
        .await;

    let document_policy_id = environment.create_policy(NATIVE_DOCUMENT_POLICY_YAML).await;

    // Runs the full standard-DKG StoreSecret/PRE conformance flow — since
    // `ring_id`'s `pre_share_endpoints` is set, every `cli_tool::do_pre` call
    // inside automatically goes through the real gRPC round trip ->
    // `PreReencryptResponse::Stored` -> `pre_share::recover_from_manifest`
    // (fetching from the real `defra` container) -> decrypt, exactly like
    // the Cosmos branch's own hand-rolled version of this below, just via
    // the shared, already-proven conformance helper instead of duplicating
    // it one more time.
    pre_scenario::run(environment, &ring_id, &document_policy_id).await;
}

#[cfg(feature = "cosmos")]
async fn run_defra_pre_scenario(environment: &TestEnvironmentImpl) {
    let defra_url = environment
        .defra_url()
        .expect("ScenarioFixture::defra was set")
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

    let node_keys: Vec<String> = environment
        .nodes()
        .iter()
        .map(|node| node.node_key.clone())
        .collect();

    let ring_policy_id = create_orbis_ring_policy(&environment.chain_config()).await;
    // The bridge-network gateway address, reachable both by producer nodes
    // (sibling containers) and by this test's own reader-role `do_pre` call
    // below (running on the host) — unlike the `defra` Compose service name,
    // which only resolves inside the Compose network. See
    // `CosmosTestEnvironment::defra_container_url`'s doc comment.
    let ring_id = create_ring_on_chain_with_pre_share_endpoints(
        &environment.chain_config(),
        &node_keys,
        THRESHOLD,
        &ring_policy_id,
        None,
        vec![environment
            .defra_container_url()
            .expect("ScenarioFixture::defra was set")
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
            environment.chain_config(),
        )
        .await
        .expect("whitelist node for ring");
    }

    let node1_endpoint = environment.nodes()[0].grpc_endpoint.clone();
    cli_tool::do_dkg(node1_endpoint.clone(), ring_id.clone())
        .await
        .expect("DKG initiation");
    let ring_pk_hex = wait_for_ring_finalized(
        &environment.chain_config(),
        &ring_id,
        Duration::from_secs(90),
    )
    .await;

    let document_policy_id = cli_tool::add_policy_to_chain_with_config(environment.chain_config())
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
        node1_endpoint.clone(),
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
        environment.chain_config(),
    )
    .await
    .expect("register document object");
    cli_tool::set_relationship_on_chain_with_config(
        document_policy_id,
        object_id.clone(),
        "document".to_string(),
        "reader".to_string(),
        Some(READER_SEED.to_string()),
        environment.chain_config(),
    )
    .await
    .expect("grant reader relationship");

    // The real gRPC round trip: StartPre -> PreReencryptResponse::Stored ->
    // pre_share::recover_from_manifest (fetching from the real `defra`
    // container) -> decrypt. Exercises the full chain this feature promises,
    // not an in-process shortcut.
    let decrypted = cli_tool::do_pre(
        node1_endpoint,
        environment.chain_config().chain_id,
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
