//! Cosmos's concrete [`TestEnvironment`]. Compiled only under this crate's
//! `cosmos` feature — native's counterpart lives in
//! `bin/orbis-node/tests/support/native_environment.rs` instead (it needs
//! `vera-client`/`vera-domain`/`k256`/`acp-light-client`, which this crate
//! deliberately excludes; see `admin/mod.rs`'s doc comment). Each backend
//! defines its own `TestEnvironmentImpl` alias at its own test-tree entry
//! point — there is no single shared module path for both, since Cosmos's
//! tests live in the `orbis-node` library's `#[cfg(test)]` tree while
//! native's live in a separate `tests/native_startup.rs` binary; the two are
//! never compiled together.

use crate::admin::{
    cosmos::create_ring_governance_with_ring, BackendAdmin, DocumentId, PolicyId, RingId, RingKeys,
    RingSpec, RingView,
};
use crate::fixture::{
    AuthorizationTestDriver, BulletinTestDriver, FixtureId, NetworkTestDriver, NodeRef, NodeRole,
    PolicyHandle, ProvisionedFixture, ReportingFixture, RingFixture, RingHandle, ScenarioFixture,
    TestEnvironment,
};
use crate::network::{CosmosNetwork, NodeInfo};
use crate::node_readiness::wait_for_nodes_ready;
use common::blockchain::{orbis::WhitelistTarget, TxSigner, VeraClient, TEST_ACCOUNT_HEX_KEY};
use std::collections::HashMap;
use std::time::Duration;

/// Deterministic secp256k1 node identities injected via `ORBIS_SIGNING_KEY`
/// in `docker/docker-compose-integration-test.yml` — fixed by the compose
/// topology itself, not chosen per test. Mirrors
/// `bin/orbis-node/src/tests/constants.rs`'s identical values; duplicated
/// rather than shared because that module lives in the `orbis-node` crate,
/// not here.
const NODE_KEYS: [&str; 4] = [
    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
    "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
    "02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13",
];

fn reporting_json(reporting: &ReportingFixture) -> serde_json::Value {
    let backup_node_keys: Vec<&str> = reporting
        .backup_node_keys
        .iter()
        .map(|node| match node {
            NodeRef::Running(index) => NODE_KEYS[*index],
            NodeRef::Offline(_) | NodeRef::Backup(_) => panic!(
                "CosmosTestEnvironment::provision: NodeRole::Offline/Backup isn't supported yet"
            ),
        })
        .collect();
    serde_json::json!({
        "demerit_config": {
            "node_offline_demerits": reporting.node_offline_demerits,
            "invalid_crypto_response_demerits": reporting.invalid_crypto_response_demerits,
            "unauthorized_request_demerits": reporting.unauthorized_request_demerits,
            "reset_interval_seconds": reporting.reset_interval.as_secs(),
        },
        "backup_node_keys": backup_node_keys,
        "kick_threshold": reporting.kick_threshold,
    })
}

fn resolve_members(members: &[NodeRef]) -> Vec<&'static str> {
    members
        .iter()
        .map(|node| match node {
            NodeRef::Running(index) => NODE_KEYS[*index],
            NodeRef::Offline(_) | NodeRef::Backup(_) => panic!(
                "CosmosTestEnvironment::provision: NodeRole::Offline/Backup isn't supported yet"
            ),
        })
        .collect()
}

fn ring_genesis_json(ring: &RingFixture) -> serde_json::Value {
    assert!(
        ring.upgrade.is_none(),
        "CosmosTestEnvironment::provision: RingFixture::upgrade isn't supported yet"
    );
    serde_json::json!({
        "id": ring.id.0,
        "ring_pk": "",
        "peer_node_keys": resolve_members(&ring.members),
        "threshold": ring.threshold,
        "pss_interval": ring.pss_interval.as_secs(),
        // Cosmos ACP policy ids are content-addressed, not caller-chosen, so
        // a ring's genesis `policy_id` can't embed a not-yet-created
        // `PolicyFixture`'s real id. Every ring gets its own governance
        // policy instead (created live, just after the chain starts, via
        // `create_ring_governance_with_ring` below) — the exact mechanism
        // every existing Cosmos DKG test already uses; `ring.policy`'s
        // `FixtureId` resolves to *that* policy afterward, not to a
        // separately-created `PolicyFixture`. This field's value is
        // overwritten on-chain by `MsgFinalizeRing`-permission bookkeeping
        // and isn't otherwise checked at genesis time — see
        // `bin/orbis-node/src/tests/pending_ring_cancellation.rs`, which uses
        // a bare placeholder string here with no backing policy at all.
        "policy_id": ring.id.0,
        "reporting": reporting_json(&ring.reporting),
    })
}

async fn wait_for_node_info_on_chain(client: &VeraClient, node_key: &str) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        match client.orbis_read_node_info(node_key).await {
            Ok(Some(_)) => return,
            _ => {
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "NodeInfo for node_key {node_key} was not visible on-chain within 60s"
                );
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        }
    }
}

pub struct CosmosTestEnvironment {
    network: CosmosNetwork,
    fixture: ProvisionedFixture,
}

#[async_trait::async_trait]
impl TestEnvironment for CosmosTestEnvironment {
    async fn provision(fixture: ScenarioFixture) -> Self {
        // Fixture-driven document/key-derivation/demerit materialization and
        // non-`Running` nodes aren't implemented yet — both need either a
        // finalized ring (live DKG, which only happens in the scenario
        // itself, after provisioning) or genesis-injection support that
        // doesn't exist in Vera today. See the harness-unification plan.
        assert!(
            fixture.documents.is_empty()
                && fixture.key_derivations.is_empty()
                && fixture.node_demerits.is_empty(),
            "CosmosTestEnvironment::provision: fixture-driven document/key-derivation/\
             demerit materialization isn't implemented yet"
        );
        assert!(
            fixture
                .nodes
                .iter()
                .all(|node| node.role == NodeRole::Running),
            "CosmosTestEnvironment::provision: only NodeRole::Running is supported today"
        );

        let node_count = fixture.nodes.len();
        let mut builder = CosmosNetwork::builder().with_node_count(node_count);
        if !fixture.rings.is_empty() {
            let rings: Vec<serde_json::Value> =
                fixture.rings.iter().map(ring_genesis_json).collect();
            builder = builder.with_module_genesis("orbis", serde_json::json!({ "rings": rings }));
        }
        let network = builder.build();

        let endpoints: Vec<String> = network
            .all_endpoints()
            .into_iter()
            .map(str::to_string)
            .collect();
        let nodes = wait_for_nodes_ready(&endpoints).await;

        let mut policies: HashMap<FixtureId, PolicyId> = HashMap::new();
        let mut rings: HashMap<FixtureId, RingHandle> = HashMap::new();

        if !fixture.rings.is_empty() {
            let controller_client = VeraClient::with_signer(
                network.chain_config(),
                TxSigner::from_hex_key(TEST_ACCOUNT_HEX_KEY, network.chain_config())
                    .expect("test account signer"),
            )
            .await
            .expect("signed chain client for ring governance");

            for ring in &fixture.rings {
                let members = resolve_members(&ring.members);
                for node_key in &members {
                    wait_for_node_info_on_chain(&controller_client, node_key).await;
                }
                let governance_policy_id =
                    create_ring_governance_with_ring(&controller_client, &ring.id.0, &members)
                        .await;
                for node_key in &members {
                    controller_client
                        .orbis_add_node_to_whitelist(
                            node_key,
                            WhitelistTarget::RingId(ring.id.0.clone()),
                        )
                        .await
                        .expect("whitelist node for ring");
                }
                policies.insert(ring.policy.clone(), PolicyId(governance_policy_id));
                rings.insert(
                    ring.id.clone(),
                    RingHandle {
                        id: RingId(ring.id.0.clone()),
                        members: members.into_iter().map(str::to_string).collect(),
                    },
                );
            }
        }

        // `fixture.policies`/`relationships` are resolved through the same
        // chain client every other admin operation uses — no genesis-timing
        // concern here, unlike rings. Calling `network.admin()` directly
        // (rather than `self.create_policy`/`self.grant`) since `Self`
        // hasn't been constructed yet at this point.
        for policy in &fixture.policies {
            if !policies.contains_key(&policy.id) {
                let id = network.admin().create_policy(&policy.definition).await;
                policies.insert(policy.id.clone(), id);
            }
        }
        let resolve = |id: &FixtureId| -> String {
            policies
                .get(id)
                .map(|policy| policy.0.clone())
                .or_else(|| rings.get(id).map(|ring| ring.id.0.clone()))
                .unwrap_or_else(|| id.0.clone())
        };
        for relationship in &fixture.relationships {
            let policy = PolicyId(resolve(&relationship.policy));
            let object_id = resolve(&relationship.object);
            network
                .admin()
                .grant(
                    &policy,
                    &relationship.resource,
                    &object_id,
                    &relationship.relation,
                    &relationship.subject_did,
                )
                .await;
        }

        Self {
            network,
            fixture: ProvisionedFixture {
                nodes,
                rings,
                policies: policies
                    .into_iter()
                    .map(|(fixture_id, id)| (fixture_id, PolicyHandle { id }))
                    .collect(),
                documents: HashMap::new(),
            },
        }
    }

    fn fixture(&self) -> &ProvisionedFixture {
        &self.fixture
    }
}

#[async_trait::async_trait]
impl NetworkTestDriver for CosmosTestEnvironment {
    fn nodes(&self) -> &[NodeInfo] {
        &self.fixture.nodes
    }

    async fn stop_node(&self, index: usize) {
        self.network
            .stop_service(CosmosNetwork::service_name_for_node(index + 1));
    }

    async fn start_node(&self, index: usize) -> String {
        self.network
            .start_service(CosmosNetwork::service_name_for_node(index + 1))
    }

    async fn restart_nodes(&self) -> Vec<String> {
        self.network.restart_nodes()
    }
}

#[async_trait::async_trait]
impl AuthorizationTestDriver for CosmosTestEnvironment {
    async fn create_policy(&self, definition: &str) -> PolicyId {
        self.network.admin().create_policy(definition).await
    }

    async fn grant(
        &self,
        policy: &PolicyId,
        resource: &str,
        object_id: &str,
        relation: &str,
        subject_did: &str,
    ) {
        self.network
            .admin()
            .grant(policy, resource, object_id, relation, subject_did)
            .await
    }

    async fn revoke(
        &self,
        policy: &PolicyId,
        resource: &str,
        object_id: &str,
        relation: &str,
        subject_did: &str,
    ) {
        self.network
            .admin()
            .revoke(policy, resource, object_id, relation, subject_did)
            .await
    }
}

#[async_trait::async_trait]
impl BulletinTestDriver for CosmosTestEnvironment {
    async fn register_ring(&self, spec: RingSpec) -> RingId {
        // Same `unimplemented!()` as `CosmosAdmin::register_ring` — not a new
        // gap, see that method's doc comment. Fixture-driven ring creation
        // (`provision()`, above) does not go through this method for Cosmos;
        // it genesis-seeds instead, since a live `register_ring` here would
        // need the same not-yet-available mechanism.
        self.network.admin().register_ring(spec).await
    }

    async fn read_ring(&self, ring: &RingId) -> Option<RingView> {
        self.network.admin().read_ring(ring).await
    }

    async fn wait_for_finalized(&self, ring: &RingId, timeout: Duration) -> RingKeys {
        self.network.admin().wait_for_finalized(ring, timeout).await
    }

    async fn store_document(
        &self,
        ring: &RingId,
        payload: &[u8],
        reader_dids: &[String],
    ) -> DocumentId {
        self.network
            .admin()
            .store_document(ring, payload, reader_dids)
            .await
    }

    async fn read_document(&self, id: &DocumentId) -> Vec<u8> {
        self.network.admin().read_document(id).await
    }
}
