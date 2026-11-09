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
//! The rest of the flow — DKG trigger+wait, StoreSecret, register/grant,
//! PRE, decrypt, assert — is the already-shared `pre_scenario::run`
//! conformance helper used by a dozen other scenario tests; since
//! `ring_id`'s `pre_share_endpoints` is set, every `cli_tool::do_pre` call
//! inside it automatically goes through the real gRPC round trip ->
//! `PreReencryptResponse::Stored` -> `pre_share::recover_from_manifest`
//! (fetching from the real `defra` container) -> decrypt, with no special
//! casing needed.
//!
//! Complements (does not replace) `pre::v0::tests::
//! test_pre_with_defra_stored_delivery_end_to_end`, which exercises the same
//! Defra-backed recovery path in-process against a mocked Defra endpoint —
//! deliberately so, since that test's own harness has no real gRPC server to
//! connect to. This test is the one place in the whole feature that proves
//! the real gRPC round trip (`cli_tool::do_pre` over an actual
//! `PreServiceClient` connection) against a *real* `defra` binary.

use super::{pre_scenario, TestEnvironmentImpl};
use test_support::admin::RingSpec;
use test_support::fixture::{
    AuthorizationTestDriver, BulletinTestDriver, FixtureId, NetworkTestDriver, NodeFixture,
    NodeRole, ScenarioFixture, TestEnvironment,
};

const THRESHOLD: u32 = 2;

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

    let document_policy_id = environment.create_policy(DOCUMENT_POLICY_YAML).await;

    pre_scenario::run(&environment, &ring_id, &document_policy_id).await;
}
