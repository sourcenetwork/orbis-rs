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
    cosmos::create_ring_governance_with_ring, BackendAdmin, DocumentId, PolicyId, RingId, RingSpec,
    RingView,
};
use crate::fixture::{
    AuthorizationTestDriver, BulletinTestDriver, FixtureId, NetworkTestDriver, NodeRef, NodeRole,
    PolicyHandle, ProvisionedFixture, ReportingFixture, RingFixture, RingHandle, ScenarioFixture,
    TestEnvironment,
};
use crate::network::{CosmosNetwork, NodeInfo};
use crate::node_readiness::wait_for_nodes_ready;
use bulletin::r#trait::{Bulletin, BulletinKind, BulletinWriteKind, KeyDerivation};
use bulletin::vera::VeraBulletin;
use common::blockchain::{
    orbis::WhitelistTarget, TxSigner, VeraClient, TEST_ACCOUNT_HEX_KEY, TEST_ACCOUNT_PUBKEY_HEX,
};
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

/// Deterministic ACP policy ID `create_ring_governance_with_ring`'s
/// `ORBIS_RING_POLICY_YAML` always produces as the *first* policy
/// (counter=0) on a fresh chain — same value, same reasoning, as
/// `bin/orbis-node/src/tests/constants.rs::RING_GOVERNANCE_POLICY_ID`
/// (duplicated for the same reason `NODE_KEYS` is, above). Must be known
/// *before* that call returns so genesis can embed the ring's real
/// `policy_id` up front — Cosmos's permission checks (reshare's in
/// particular) read the ring record's own `policy_id` field, not whatever
/// `create_ring_governance_with_ring` happens to return. Only correct for a
/// fixture with exactly one ring; a second ring's governance policy would be
/// counter=1, a different id this constant doesn't cover.
const RING_GOVERNANCE_POLICY_ID: &str =
    "3199b84b4a6862c40fe2623879dfc36df281a2262898da36f7de65c376a93e05";

/// Deterministic secp256k1 key for a genesis-registered node with no
/// running process behind it — e.g. a reshare target that can never ack,
/// making the reshare provably stuck. Same value as
/// `bin/orbis-node/src/tests/constants.rs::NODE_KEY_OFFLINE` (duplicated for
/// the same reason `NODE_KEYS` is, above). Only one `NodeRole::Offline`
/// node is supported today — `resolve_members` always resolves it to this
/// one key regardless of which `FixtureId` a `NodeRef::Offline` names.
const NODE_KEY_OFFLINE: &str = "03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556";

/// P2P address seeded into `NODE_KEY_OFFLINE`'s genesis `NodeInfo` — passes
/// peer-id validation but points at a host that doesn't exist in the
/// Compose network, so every send to it fails. Same value as
/// `bin/orbis-node/src/tests/constants.rs::OFFLINE_NODE_PEER_ID`.
const OFFLINE_NODE_PEER_ID: &str =
    "5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f@node-offline:4242";

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
            // A ring's *initial* membership is always `Running` today — an
            // `Offline` node only ever becomes a *reshare target*
            // (`TestEnvironmentImpl::update_membership`), which goes through
            // `NODE_KEY_OFFLINE` directly in the scenario, not through a
            // `RingFixture.members` entry. Not exercised by any fixture yet.
            NodeRef::Offline(_) | NodeRef::Backup(_) => panic!(
                "CosmosTestEnvironment::provision: NodeRole::Offline/Backup isn't supported \
                 as a ring's *initial* member yet"
            ),
        })
        .collect()
}

/// Genesis `node_infos` entries for every `NodeRole::Offline` node in the
/// fixture — registered on-chain with no running process behind them.
/// Whitelists each for every ring in the fixture; only one offline node and
/// one ring are supported today (see `NODE_KEY_OFFLINE`'s doc comment).
fn offline_node_infos_json(fixture: &ScenarioFixture) -> Vec<serde_json::Value> {
    if !fixture
        .nodes
        .iter()
        .any(|node| node.role == NodeRole::Offline)
    {
        return Vec::new();
    }
    let whitelisted_ring_ids: Vec<&str> = fixture
        .rings
        .iter()
        .map(|ring| ring.id.0.as_str())
        .collect();
    vec![serde_json::json!({
        "node_key": NODE_KEY_OFFLINE,
        "node_info": {
            "peer_id": OFFLINE_NODE_PEER_ID,
            "controller_key": TEST_ACCOUNT_PUBKEY_HEX,
            "whitelisted_policy_ids": [],
            "whitelisted_ring_ids": whitelisted_ring_ids,
        }
    })]
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
        // separately-created `PolicyFixture`. Genesis must embed that same
        // policy's real (deterministic) id up front — permission checks
        // that read the ring record's own `policy_id` field (reshare's in
        // particular) run against *this* value, not whatever
        // `create_ring_governance_with_ring` returns afterward.
        "policy_id": RING_GOVERNANCE_POLICY_ID,
        "reporting": reporting_json(&ring.reporting),
        "requires_pet": ring.requires_pet,
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
                .all(|node| matches!(node.role, NodeRole::Running | NodeRole::Offline)),
            "CosmosTestEnvironment::provision: only NodeRole::Running/Offline is supported today"
        );

        let node_count = fixture
            .nodes
            .iter()
            .filter(|node| node.role == NodeRole::Running)
            .count();
        let mut builder = CosmosNetwork::builder().with_node_count(node_count);
        let node_infos = offline_node_infos_json(&fixture);
        if !fixture.rings.is_empty() || !node_infos.is_empty() {
            let rings: Vec<serde_json::Value> =
                fixture.rings.iter().map(ring_genesis_json).collect();
            builder = builder.with_module_genesis(
                "orbis",
                serde_json::json!({ "rings": rings, "node_infos": node_infos }),
            );
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
                assert_eq!(
                    governance_policy_id, RING_GOVERNANCE_POLICY_ID,
                    "ACP policy ID changed; update RING_GOVERNANCE_POLICY_ID and genesis's \
                     embedded policy_id to match"
                );
                for (node_ref, node_key) in ring.members.iter().zip(&members) {
                    let NodeRef::Running(index) = node_ref else {
                        panic!(
                            "CosmosTestEnvironment::provision: NodeRole::Offline/Backup isn't \
                             supported yet"
                        );
                    };
                    // Each node's self-reported `p2p_address` (from
                    // `wait_for_nodes_ready`) isn't reachable by other
                    // containers as-is — it must be rewritten to the
                    // Compose service name before other members can "prepare"
                    // with it during DKG, same as the pre-fixture adapter did.
                    let peer_address = CosmosNetwork::transform_p2p_address(
                        &nodes[*index].p2p_address,
                        CosmosNetwork::service_name_for_node(*index + 1),
                    );
                    let peer_update = controller_client
                        .orbis_update_node_peer_id(node_key, &peer_address)
                        .await
                        .expect("update NodeInfo peer ID");
                    assert_eq!(
                        peer_update.code, 0,
                        "update NodeInfo peer ID tx failed: {}",
                        peer_update.log
                    );
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

    fn chain_id(&self) -> String {
        self.network.chain_config().chain_id
    }

    fn supports_direct_document_write(&self) -> bool {
        true
    }
}

impl CosmosTestEnvironment {
    async fn signed_bulletin(&self) -> VeraBulletin {
        VeraBulletin::with_signer(
            self.network.chain_config_builder(),
            TxSigner::from_hex_key(TEST_ACCOUNT_HEX_KEY, self.network.chain_config())
                .expect("test account signer"),
            None,
        )
        .await
        .expect("signed bulletin client")
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

    async fn register_object(&self, policy: &PolicyId, resource: &str, object_id: &str) {
        let client = VeraClient::with_signer(
            self.network.chain_config(),
            TxSigner::from_hex_key(TEST_ACCOUNT_HEX_KEY, self.network.chain_config())
                .expect("test account signer"),
        )
        .await
        .expect("signed chain client for object registration");
        client
            .acp_register_object(
                &policy.0,
                common::blockchain::acp::Object {
                    resource: resource.to_string(),
                    id: object_id.to_string(),
                },
            )
            .await
            .expect("register ACP object");
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

    async fn wait_for_finalized(&self, ring: &RingId, timeout: Duration) -> RingView {
        tokio::time::timeout(timeout, async {
            loop {
                if let Some(view) = self.read_ring(ring).await {
                    if !view.ring_pk.is_empty() {
                        return view;
                    }
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("Timed out waiting for ring {} to be finalized", ring.0))
    }

    /// Unlike `CosmosAdmin::store_document` (still `unimplemented!()`), this
    /// doesn't need a new cli-tool-dependency decision — `bulletin::vera`'s
    /// `Bulletin::post`/`read` (the same generic post primitive the product
    /// itself uses for documents/key-derivations) is already reachable from
    /// this crate's `cosmos` feature. `_reader_dids` is unused: granting
    /// read access is a separate `grant` call, not part of posting.
    async fn store_document(
        &self,
        _ring: &RingId,
        payload: &[u8],
        _reader_dids: &[String],
    ) -> DocumentId {
        let id = self
            .signed_bulletin()
            .await
            .post(BulletinWriteKind::Document, payload.to_vec())
            .await
            .expect("post shared scenario document directly");
        DocumentId(id)
    }

    async fn read_document(&self, id: &DocumentId) -> Vec<u8> {
        VeraBulletin::new(self.network.chain_config_builder())
            .await
            .expect("bulletin read client")
            .read(id.0.clone(), BulletinKind::Document)
            .await
            .expect("read shared scenario document")
            .payload
    }

    async fn register_key_derivation(
        &self,
        ring: &RingId,
        derivation: &str,
        policy: &PolicyId,
        resource: &str,
        permission: &str,
    ) -> String {
        let payload = serde_json::to_vec(&KeyDerivation {
            ring_id: ring.0.clone(),
            derivation: derivation.to_string(),
            policy_id: policy.0.clone(),
            resource: resource.to_string(),
            permission: permission.to_string(),
        })
        .expect("serialize shared Sign key derivation");
        self.signed_bulletin()
            .await
            .post(BulletinWriteKind::KeyDerivation, payload)
            .await
            .expect("post shared Sign key derivation")
    }

    async fn update_membership(&self, ring: &RingId, new_members: Vec<String>, new_threshold: u32) {
        let client = VeraClient::with_signer(
            self.network.chain_config(),
            TxSigner::from_hex_key(TEST_ACCOUNT_HEX_KEY, self.network.chain_config())
                .expect("test account signer"),
        )
        .await
        .expect("signed chain client for shared reshare");
        let result = client
            .orbis_start_ring_reshare_by_acp(&ring.0, new_members, Some(new_threshold))
            .await
            .expect("announce shared Cosmos reshare");
        assert!(
            result.code == 0,
            "announce shared Cosmos reshare failed: {}",
            result.log
        );
    }

    // `force_refresh_due` keeps the default no-op: this test ring is always
    // genesis-seeded with a short `pss_interval` (see `provision`), so a
    // refresh becomes due naturally within the scenario's own wait.

    async fn cancel_reshare(&self, ring: &RingId) {
        let client = VeraClient::with_signer(
            self.network.chain_config(),
            TxSigner::from_hex_key(TEST_ACCOUNT_HEX_KEY, self.network.chain_config())
                .expect("test account signer"),
        )
        .await
        .expect("signed chain client for reshare cancellation");
        let result = client
            .orbis_cancel_ring_reshare_by_acp(&ring.0)
            .await
            .expect("cancel stuck Cosmos reshare");
        assert!(
            result.code == 0,
            "cancel stuck Cosmos reshare failed: {}",
            result.log
        );
    }
}
