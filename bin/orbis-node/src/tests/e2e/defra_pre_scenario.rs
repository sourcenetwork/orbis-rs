//! Docker E2E: a real 3-node ring backed by a real Defra container end to end.
//!
//! Fully backend-neutral — one test body, no `#[cfg]` split. Ring creation
//! with `pre_share_endpoints` now goes through the shared
//! `BulletinTestDriver::register_ring`/`RingSpec` path (extended with a
//! `pre_share_endpoints` field — see that struct's own doc comment) rather
//! than a per-backend escape hatch: `CosmosAdmin::register_ring` and
//! `NativeTestEnvironment::register_ring` each hide their own backend's
//! ring-policy registration/node-authorization mechanics behind the same
//! method signature. `environment.defra_url()`/`defra_container_url()`
//! remain backend-specific escape hatches (not part of any shared trait —
//! see each one's own doc comment), since `ScenarioFixture::defra` and
//! Defra access are the only pieces this feature still needs outside the
//! trait.
//!
//! DKG uses the already-shared `pre_scenario::run_dkg` helper. The PRE
//! retrieval step, though, needs a sidecar: a reader fetching from Defra
//! needs `defra_container_url`, and on Docker Desktop (macOS/Windows) only
//! a *container* on this project's own bridge network can reach that
//! address — the host process (this test itself) cannot, confirmed
//! empirically on both backends. Producer-side writes from sibling
//! containers succeed (Defra logs real mutation commits); a host-side
//! fetch of the same address fails for every manifest entry. Not a bug in
//! this feature or in Docker Desktop — its VM-isolated networking has no
//! general host-to-container-IP path, only the narrow, purpose-built
//! tunnels `defra_url` (host-published port) and (container-side only)
//! `host.docker.internal` provide; this is a real Linux Docker host (CI)
//! only limitation to work around, not something to re-diagnose from
//! scratch if it fails here again.
//!
//! The split: `cli_tool::do_pre_and_save` runs the *request* on the host
//! (plain gRPC to a published port, the same one-hop path every other
//! `do_pre` call already uses) and stops just short of needing Defra,
//! returning a `PendingPreRetrieval` the host already has in hand. That
//! gets handed to a one-off `cli-tool` container
//! (`test_support::build_cli_tool_sidecar_image`/`run_sidecar_container`,
//! joined to `environment.sidecar_network_name()`) running `retrieve-pre`,
//! which *does* reach Defra, fine, since it's just another container on the
//! same bridge. Its stdout carries the same "Decrypted Secret: ..." line
//! `cli-tool`'s own direct `pre` command already prints.
//!
//! Complements (does not replace) `pre::v0::tests::
//! test_pre_with_defra_stored_delivery_end_to_end`, which exercises the same
//! Defra-backed recovery path in-process against a mocked Defra endpoint —
//! deliberately so, since that test's own harness has no real gRPC server to
//! connect to. This test is the one place in the whole feature that proves
//! the real gRPC round trip (`cli_tool::do_pre_and_save` over an actual
//! `PreServiceClient` connection, `retrieve-pre` over a real `defra` binary)
//! end to end.

use super::{pre_scenario, TestEnvironmentImpl};
use test_support::admin::RingSpec;
use test_support::fixture::{
    AuthorizationTestDriver, BulletinTestDriver, FixtureId, NetworkTestDriver, NodeFixture,
    NodeRole, ScenarioFixture, TestEnvironment,
};

const THRESHOLD: u32 = 2;
const PLAINTEXT: &[u8] = b"defra-docker-e2e-plaintext";
const READER_SEED: &str = "defra-pre-scenario-reader";

// `register_ring`'s own implementation (both backends) registers
// `policy_id` as a `ring_policy` ACP object and grants itself the `creator`
// relation on it — the policy supplied here must define that shape (see
// `RingSpec::pre_share_endpoints`'s doc comment).
const RING_POLICY_YAML: &str = r#"
name: defra-pre-scenario-ring-policy
resources:
- name: ring_policy
  permissions:
  - name: create_ring
    expr: creator
  relations:
  - name: creator
    types:
    - actor
- name: ring
  permissions:
  - name: update_ring
    expr: operator
  relations:
  - name: operator
    types:
    - actor
"#;

const DOCUMENT_POLICY_YAML: &str = r#"
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

    let ring_policy_id = environment.create_policy(RING_POLICY_YAML).await;
    let ring_id = environment
        .register_ring(RingSpec {
            node_keys,
            threshold: THRESHOLD,
            pss_interval: std::time::Duration::from_secs(86_400),
            policy_id: ring_policy_id,
            nonce: None,
            trusted_auth_relay_dids: Vec::new(),
            requires_pet: false,
            // The address reachable both by producer nodes (sibling
            // containers) and by `pre_scenario::run`'s own reader-role
            // `cli_tool::do_pre` calls below, running on the host — see
            // `defra_container_url`'s own doc comment on each backend.
            pre_share_endpoints: vec![environment
                .defra_container_url()
                .expect("ScenarioFixture::defra was set")],
        })
        .await;

    let (keys, _local_state) = pre_scenario::run_dkg(&environment, &ring_id).await;

    let document_policy_id = environment.create_policy(DOCUMENT_POLICY_YAML).await;

    let prepared = cli_tool::prepare_secret(
        PLAINTEXT,
        &keys.main,
        None,
        document_policy_id.0.clone(),
        "document".to_string(),
        "read".to_string(),
        None,
        None,
        None,
        None,
    )
    .expect("prepare secret");

    let node1_endpoint = environment.nodes()[0].grpc_endpoint.clone();
    let stored = cli_tool::store_prepared_secret(
        node1_endpoint.clone(),
        &prepared,
        ring_id.0.clone(),
        None,
        true,
        None,
    )
    .await
    .expect("store prepared secret");
    let object_id = stored.object_id;

    environment
        .register_object(&document_policy_id, "document", &object_id)
        .await;
    let reader_did = cli_tool::reader_did_from_seed(READER_SEED);
    environment
        .grant(
            &document_policy_id,
            "document",
            &object_id,
            "reader",
            &reader_did,
        )
        .await;

    // Host-side request only — stops just short of needing Defra access
    // (see this file's own module doc comment).
    let pending = cli_tool::do_pre_and_save(
        node1_endpoint,
        environment.chain_id(),
        keys.main.clone(),
        object_id,
        Some(READER_SEED.to_string()),
        None,
        None,
        None,
        None,
    )
    .await
    .expect("request PRE reencryption");
    let pending_json = serde_json::to_string(&pending).expect("serialize pending PRE retrieval");

    let crypto_feature =
        std::env::var("ORBIS_INTEGRATION_CRYPTO").unwrap_or_else(|_| "bls12-381".to_string());
    let image = test_support::build_cli_tool_sidecar_image(&crypto_feature)
        .expect("build cli-tool sidecar image");
    let stdout = test_support::run_sidecar_container(
        &image,
        &environment.sidecar_network_name(),
        &["retrieve-pre", "--pending-json", &pending_json],
    )
    .expect("run cli-tool sidecar for PRE retrieval");

    let decrypted = stdout
        .lines()
        .find_map(|line| line.trim().strip_prefix("Decrypted Secret:"))
        .map(str::trim)
        .expect("sidecar output must include a decrypted secret line");
    assert_eq!(
        decrypted.as_bytes(),
        PLAINTEXT,
        "decrypted plaintext must match the original secret"
    );
}
