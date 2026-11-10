//! Cosmos's concrete [`TestEnvironment`]. Compiled only under this crate's
//! `cosmos` feature — native's counterpart lives in
//! `bin/orbis-node/src/tests/e2e/native_environment.rs` instead (it needs
//! `vera-client`/`vera-domain`/`k256`/`acp-light-client`, which this crate
//! deliberately excludes; see `admin/mod.rs`'s doc comment). Each backend
//! defines its own `TestEnvironmentImpl` alias at the shared test-tree entry
//! point. Exactly one concrete environment is selected per backend build.

use crate::admin::{
    cosmos::create_ring_governance_with_ring, BackendAdmin, DocumentId, PolicyId, RingId, RingSpec,
    RingStateFacts, RingView,
};
use crate::fixture::{
    AuthorizationTestDriver, BulletinTestDriver, FixtureId, NetworkTestDriver, NodeRef, NodeRole,
    PolicyHandle, ProvisionedFixture, ReportingFixture, RingFixture, RingHandle, ScenarioFixture,
    TestEnvironment,
};
use crate::network::{select_publish_port, CosmosNetwork, NodeInfo};
use crate::node_readiness::wait_for_nodes_ready;
use bulletin::r#trait::{
    Bulletin, BulletinKind, BulletinWriteKind, DocumentPayload, KeyDerivation,
};
use bulletin::vera::VeraBulletin;
use common::blockchain::{
    orbis::{generate_document_id, WhitelistTarget},
    ChainConfig, TxSigner, VeraClient, TEST_ACCOUNT_HEX_KEY, TEST_ACCOUNT_PUBKEY_HEX,
};
use proto::info_service::{info_service_client::InfoServiceClient, GetNodeInfoRequest};
use std::collections::HashMap;
use std::net::Ipv4Addr;
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

/// Deterministic peer id seeded into a `NodeRole::Backup` node's genesis
/// `NodeInfo` — a loosely-shaped placeholder (unlike `OFFLINE_NODE_PEER_ID`,
/// this never needs to pass route-building validation: a backup promotion
/// test only asserts the *announced* pending committee, never the finalized
/// reshare, so nothing ever tries to route to it). Same value as the
/// pre-fixture `test_report_kick_promotes_backup_node`'s own literal.
const BACKUP_NODE_PEER_ID: &str = "backup-node-4-peer-id";

/// Resolves a `NodeRef` to its deterministic test key, for contexts (like
/// `backup_node_keys`) where only `Running`/`Backup` make sense. Only one
/// `NodeRole::Backup` node is supported today — always `NODE_KEYS[3]`
/// regardless of which `FixtureId` a `NodeRef::Backup` names (same
/// single-node limitation as `NODE_KEY_OFFLINE`).
fn resolve_backup_capable_node_ref(node: &NodeRef) -> &'static str {
    match node {
        NodeRef::Running(index) => NODE_KEYS[*index],
        NodeRef::Backup(_) => NODE_KEYS[3],
        NodeRef::Offline(_) => {
            panic!("CosmosTestEnvironment::provision: NodeRole::Offline isn't supported here yet")
        }
    }
}

fn reporting_json(reporting: &ReportingFixture) -> serde_json::Value {
    let backup_node_keys: Vec<&str> = reporting
        .backup_node_keys
        .iter()
        .map(resolve_backup_capable_node_ref)
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

/// Genesis `node_infos` entries for every `NodeRole::Backup` node in the
/// fixture — registered and whitelisted so the chain considers it eligible
/// for kick-promotion, but with no running process behind it. Same
/// single-node limitation as [`offline_node_infos_json`].
fn backup_node_infos_json(fixture: &ScenarioFixture) -> Vec<serde_json::Value> {
    if !fixture
        .nodes
        .iter()
        .any(|node| node.role == NodeRole::Backup)
    {
        return Vec::new();
    }
    let whitelisted_ring_ids: Vec<&str> = fixture
        .rings
        .iter()
        .map(|ring| ring.id.0.as_str())
        .collect();
    vec![serde_json::json!({
        "node_key": NODE_KEYS[3],
        "node_info": {
            "peer_id": BACKUP_NODE_PEER_ID,
            "controller_key": TEST_ACCOUNT_PUBKEY_HEX,
            "whitelisted_policy_ids": [],
            "whitelisted_ring_ids": whitelisted_ring_ids,
        }
    })]
}

/// Genesis `node_demerits` entries. `window_started_at` anchors to `now`
/// (captured once in `provision`, same instant `ring_genesis_json`'s
/// `upgrade_info`/`activation_time` anchors to) plus each fixture's own
/// offset — keeping the seeded window live for the whole test run, same
/// reasoning the pre-fixture `test_report_kick_promotes_backup_node` gave
/// for anchoring at test start.
fn node_demerits_genesis_json(fixture: &ScenarioFixture, now: u64) -> Vec<serde_json::Value> {
    fixture
        .node_demerits
        .iter()
        .map(|demerit| {
            serde_json::json!({
                "ring_id": demerit.ring.0,
                "node_key": resolve_backup_capable_node_ref(&demerit.node),
                "points": demerit.points,
                "window_started_at": now + demerit.window_started_offset.as_secs(),
            })
        })
        .collect()
}

fn ring_genesis_json(ring: &RingFixture, now: u64) -> serde_json::Value {
    let mut value = serde_json::json!({
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
    });
    if let Some(upgrade) = &ring.upgrade {
        value["upgrade_info"] = serde_json::json!({
            "current_version": upgrade.current_version,
            "next_version": upgrade.next_version,
            "activation_time": now + upgrade.activation_offset.as_secs(),
        });
    }
    value
}

/// Genesis `documents` entries — placeholder, never-decrypted records.
/// Unlike [`DocumentFixture`]'s general doc comment (which assumes
/// encrypting the payload against the named ring's real key), there's no
/// real key to encrypt against here: genesis happens before any ring can
/// possibly be finalized. Only useful for a ring that's deliberately never
/// finalized (e.g. `upgrade.rs`'s version-gating test, which only needs
/// these records to exist and route correctly, never to decrypt). Genesis
/// also happens before any `PolicyFixture` is live-created, so — like
/// `offline_node_infos_json`'s node keys — `policy_id` is always just the
/// declaring `FixtureId`'s own literal string, a free-form value nothing
/// here ever validates against a real ACP policy.
fn documents_genesis_json(fixture: &ScenarioFixture) -> Vec<serde_json::Value> {
    fixture
        .documents
        .iter()
        .map(|document| {
            serde_json::json!({
                "id": document.id.0,
                "ring_id": document.ring.0,
                "document": String::from_utf8_lossy(&document.payload),
                "proof": "genesis-placeholder-proof",
                "policy_id": document.policy.0,
                "resource": document.resource,
                "permission": document.permission,
            })
        })
        .collect()
}

/// Genesis `key_derivations` entries — same placeholder reasoning as
/// [`documents_genesis_json`].
fn key_derivations_genesis_json(fixture: &ScenarioFixture) -> Vec<serde_json::Value> {
    fixture
        .key_derivations
        .iter()
        .map(|derivation| {
            serde_json::json!({
                "id": derivation.id.0,
                "ring_id": derivation.ring.0,
                "derivation": derivation.derivation,
                "policy_id": derivation.policy.0,
                "resource": derivation.resource,
                "permission": derivation.permission,
            })
        })
        .collect()
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
        // `documents`/`key_derivations` are genesis-seedable as placeholder,
        // never-decrypted records (see `documents_genesis_json`'s doc
        // comment) — enough for a ring that's deliberately never finalized.
        assert!(
            fixture.nodes.iter().all(|node| matches!(
                node.role,
                NodeRole::Running | NodeRole::Offline | NodeRole::Backup
            )),
            "CosmosTestEnvironment::provision: only NodeRole::Running/Offline/Backup is \
             supported today"
        );

        let node_count = fixture
            .nodes
            .iter()
            .filter(|node| node.role == NodeRole::Running)
            .count();
        let mut builder = CosmosNetwork::builder().with_node_count(node_count);
        if fixture.defra {
            builder = builder.with_defra();
        }
        let mut node_infos = offline_node_infos_json(&fixture);
        node_infos.extend(backup_node_infos_json(&fixture));
        let documents = documents_genesis_json(&fixture);
        let key_derivations = key_derivations_genesis_json(&fixture);
        if !fixture.rings.is_empty()
            || !node_infos.is_empty()
            || !documents.is_empty()
            || !key_derivations.is_empty()
            || !fixture.node_demerits.is_empty()
        {
            // Captured once, before genesis is built (and well before the
            // cluster actually finishes starting) — an `UpgradeFixture`'s
            // `activation_offset` is relative to *this* instant, same
            // reasoning as `test_v0_services_rejected_after_ring_upgrade`'s
            // own pre-`.build()` `activation_time` capture: whatever lead
            // time the fixture asks for already accounts for however long
            // the cluster takes to actually come up afterward.
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock")
                .as_secs();
            let rings: Vec<serde_json::Value> = fixture
                .rings
                .iter()
                .map(|ring| ring_genesis_json(ring, now))
                .collect();
            let node_demerits = node_demerits_genesis_json(&fixture, now);
            builder = builder.with_module_genesis(
                "orbis",
                serde_json::json!({
                    "rings": rings,
                    "node_infos": node_infos,
                    "documents": documents,
                    "key_derivations": key_derivations,
                    "node_demerits": node_demerits,
                }),
            );
        }
        let network = builder.build();

        let endpoints: Vec<String> = network
            .all_endpoints()
            .into_iter()
            .map(str::to_string)
            .collect();
        let mut nodes = wait_for_nodes_ready(&endpoints).await;
        // Ready only means gRPC is up. iroh may advertise the STUN-mapped
        // public port. Publishing that port as `nodeN:<stun-port>` makes
        // other containers dial a port nothing is listening on.
        for (index, node) in nodes.iter_mut().enumerate() {
            node.p2p_address = publishable_p2p_address(&network, index, &node.grpc_endpoint).await;
        }

        let controller_client = VeraClient::with_signer(
            network.chain_config(),
            TxSigner::from_hex_key(TEST_ACCOUNT_HEX_KEY, network.chain_config())
                .expect("test account signer"),
        )
        .await
        .expect("signed chain client for fixture setup");

        // Publish routes for every running node, even when the fixture has
        // no genesis rings. A ring created later through `register_ring`
        // still needs these routes; startup may have registered a bare peer
        // ID or a public address that sibling containers cannot dial.
        for (index, node) in nodes.iter().enumerate() {
            wait_for_node_info_on_chain(&controller_client, &node.node_key).await;
            let peer_address = CosmosNetwork::transform_p2p_address(
                &node.p2p_address,
                CosmosNetwork::service_name_for_node(index + 1),
            );
            let peer_update = controller_client
                .orbis_update_node_peer_id(&node.node_key, &peer_address)
                .await
                .expect("update NodeInfo peer ID");
            assert_eq!(
                peer_update.code, 0,
                "update NodeInfo peer ID tx failed: {}",
                peer_update.log
            );
        }

        let mut policies: HashMap<FixtureId, PolicyId> = HashMap::new();
        let mut rings: HashMap<FixtureId, RingHandle> = HashMap::new();

        if !fixture.rings.is_empty() {
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
                    let NodeRef::Running(_) = node_ref else {
                        panic!(
                            "CosmosTestEnvironment::provision: NodeRole::Offline/Backup isn't \
                             supported yet"
                        );
                    };
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

    /// Raw chain config escape hatch for Cosmos-only test code that needs
    /// operations no backend-neutral trait covers yet (e.g. a second, live
    /// `MsgCreateRing` outside the fixture system — `register_ring` stays
    /// `unimplemented!()` on `CosmosAdmin` pending a `cli-tool` dependency
    /// decision, see that method's doc comment). Not part of any shared
    /// trait: native has no equivalent concept.
    pub fn chain_config(&self) -> ChainConfig {
        self.network.chain_config()
    }

    /// Host-reachable Defra URL, when `ScenarioFixture::defra` was set.
    /// `None` otherwise. Not part of any shared trait, but `NativeTestEnvironment`
    /// has its own mirrored method of the same name.
    pub fn defra_url(&self) -> Option<&str> {
        self.network.defra_url()
    }

    /// The Compose-bridge-network address a ring's `pre_share_endpoints`
    /// must use so both sibling node containers and this process can reach
    /// it — see `CosmosNetwork::defra_container_url`'s own doc comment for
    /// why the Compose service name alone doesn't work here. `None` unless
    /// `ScenarioFixture::defra` was set. Not part of any shared trait, but
    /// `NativeTestEnvironment` has its own mirrored method of the same name.
    pub fn defra_container_url(&self) -> Option<String> {
        self.network.defra_container_url()
    }

    /// This environment's own Docker network, for joining a one-off sidecar
    /// container to it directly (`test_support::run_sidecar_container`) —
    /// see `defra_pre_scenario.rs`'s own module doc comment. Not part of any
    /// shared trait, but `NativeTestEnvironment` has its own mirrored method
    /// of the same name.
    pub fn sidecar_network_name(&self) -> String {
        self.network.network_name()
    }

    /// Whitelists a *non-member* running node for `ring`, so it can later be
    /// announced as a pure-new reshare target. `provision` already
    /// publishes every running node's route unconditionally, regardless of
    /// ring membership — this only needs to add the whitelist entry
    /// `provision`'s own ring loop skips for a non-member. Not part of any
    /// shared trait: native's `Allow` authorization step applies to every
    /// running node regardless of ring membership, so this gap is
    /// Cosmos-only.
    pub async fn whitelist_node_for_ring(&self, ring: &RingId, node_index: usize) {
        let client = VeraClient::with_signer(
            self.network.chain_config(),
            TxSigner::from_hex_key(TEST_ACCOUNT_HEX_KEY, self.network.chain_config())
                .expect("test account signer"),
        )
        .await
        .expect("signed chain client for node whitelisting");
        let node_key = &self.fixture.nodes[node_index].node_key;
        client
            .orbis_add_node_to_whitelist(node_key, WhitelistTarget::RingId(ring.0.clone()))
            .await
            .expect("whitelist node for ring");
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
        // Fixture-driven ring creation (`provision()`, above) does not go
        // through this method for Cosmos; it genesis-seeds instead, since
        // genesis is the only place a *fixture* ring's id needs to be known
        // ahead of time. This is the live, post-provision path instead —
        // see `CosmosAdmin::register_ring`.
        self.network.admin().register_ring(spec).await
    }

    async fn read_ring(&self, ring: &RingId) -> Option<RingView> {
        self.network.admin().read_ring(ring).await
    }

    /// Same direct `VeraBulletin::read` pattern `read_document` already
    /// uses — the raw `RingPayload` this reads is exactly what a real
    /// responder hashes when verifying evidence against the ring's current
    /// state, so `ring_state_sha256` here is guaranteed to match.
    async fn read_ring_state_facts(&self, ring: &RingId) -> RingStateFacts {
        let payload_bytes = VeraBulletin::new(self.network.chain_config_builder())
            .await
            .expect("bulletin read client")
            .read(ring.0.clone(), BulletinKind::Ring)
            .await
            .expect("read ring payload")
            .payload;
        let payload: bulletin::r#trait::RingPayload =
            serde_json::from_slice(&payload_bytes).expect("parse RingPayload");
        RingStateFacts {
            ring_pk: payload.ring_pk.clone(),
            peer_node_keys: payload.peer_node_keys.clone(),
            threshold: payload.threshold,
            new_peer_node_keys: payload.new_peer_node_keys.clone(),
            new_threshold: payload.new_threshold,
            state_sha256: bulletin::reporting::ring_state_sha256(&payload),
        }
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

    async fn register_document(
        &self,
        ring: &RingId,
        document: &str,
        proof: &str,
        policy: &PolicyId,
        resource: &str,
        permission: &str,
    ) -> String {
        let payload = serde_json::to_vec(&DocumentPayload {
            ring_id: ring.0.clone(),
            document: document.to_string(),
            proof: proof.to_string(),
            policy_id: policy.0.clone(),
            resource: resource.to_string(),
            permission: permission.to_string(),
            tier: None,
            timestamp: None,
            pet_tag: None,
            pet_tag_proof: None,
        })
        .expect("serialize shared PRE document");
        self.signed_bulletin()
            .await
            .post(BulletinWriteKind::Document, payload)
            .await
            .expect("post shared PRE document")
    }

    fn predict_document_id(
        &self,
        ring: &RingId,
        document: &str,
        proof: &str,
        policy: &PolicyId,
        resource: &str,
        permission: &str,
    ) -> String {
        generate_document_id(
            &ring.0, document, proof, &policy.0, resource, permission, None, None, None, None,
        )
        .expect("predict shared PRE document id")
    }

    async fn authorize_reshare_candidate(&self, ring: &RingId, node_index: usize) {
        self.whitelist_node_for_ring(ring, node_index).await;
    }

    async fn update_membership(
        &self,
        ring: &RingId,
        mut new_members: Vec<String>,
        new_threshold: u32,
    ) {
        // The chain rejects a reshare whose member list is not strictly sorted.
        new_members.sort();
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

    async fn schedule_ring_upgrade(&self, ring: &RingId, next_version: u64, activation_time: u64) {
        let client = VeraClient::with_signer(
            self.network.chain_config(),
            TxSigner::from_hex_key(TEST_ACCOUNT_HEX_KEY, self.network.chain_config())
                .expect("test account signer"),
        )
        .await
        .expect("signed chain client for ring upgrade scheduling");
        let result = client
            .orbis_schedule_ring_upgrade_by_acp(&ring.0, next_version, activation_time)
            .await
            .expect("schedule Cosmos ring upgrade");
        assert!(
            result.code == 0,
            "schedule Cosmos ring upgrade failed: {}",
            result.log
        );
    }

    async fn read_node_demerits(&self, ring: &RingId, node_key: &str) -> u64 {
        self.network
            .admin()
            .read_node_demerits(&ring.0, node_key)
            .await
    }
}

/// Address other containers can dial. Prefer a private bind from GetNodeInfo.
/// A public address whose port is already bound is kept: on Linux that port
/// is the socket iroh is listening on. Only a NAT-mapped port (not bound
/// inside the container) is replaced with a listen port.
async fn publishable_p2p_address(network: &CosmosNetwork, index: usize, endpoint: &str) -> String {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let latest = loop {
        if let Some(address) = current_p2p_address(endpoint).await {
            if container_local_bind(&address) {
                println!("container bind for {endpoint}: {address}");
                return address;
            }
            break address;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "node at {endpoint} never returned a p2p address"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    };
    let advertised = address_port(&latest);
    let service = CosmosNetwork::service_name_for_node(index + 1);
    let listen_ports = network.container_udp_listen_ports(service);
    let Some(port) = advertised.and_then(|port| select_publish_port(port, &listen_ports)) else {
        panic!(
            "node at {endpoint} advertised {latest} and its UDP listen ports could not be read ({listen_ports:?})"
        );
    };
    if Some(port) == advertised {
        println!("container bind for {endpoint}: {latest}");
        return latest;
    }
    let rewritten = replace_port(&latest, port);
    println!("container bind for {endpoint} rewritten from {latest} to {rewritten}");
    rewritten
}

async fn current_p2p_address(endpoint: &str) -> Option<String> {
    let mut client = InfoServiceClient::connect(endpoint.to_string())
        .await
        .ok()?;
    client
        .get_node_info(GetNodeInfoRequest {})
        .await
        .ok()
        .map(|response| response.into_inner().p2p_address)
}

fn container_local_bind(address: &str) -> bool {
    let Some((_, host_port)) = address.split_once('@') else {
        return false;
    };
    let host = host_port
        .rsplit_once(':')
        .map(|(host, _)| host)
        .unwrap_or(host_port);
    let Ok(ip) = host.parse::<Ipv4Addr>() else {
        return false;
    };
    ip.is_private() || ip.is_loopback() || ip.is_link_local()
}

fn address_port(address: &str) -> Option<u16> {
    let host_port = address.split_once('@')?.1;
    host_port.rsplit_once(':')?.1.parse().ok()
}

fn replace_port(address: &str, port: u16) -> String {
    let Some((peer, host_port)) = address.split_once('@') else {
        panic!("p2p address {address} has no peer separator");
    };
    let host = host_port
        .rsplit_once(':')
        .map(|(host, _)| host)
        .unwrap_or(host_port);
    format!("{peer}@{host}:{port}")
}
