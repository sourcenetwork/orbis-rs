//! Native's concrete `test_support::fixture::TestEnvironment`. It lives here
//! rather than in `crates/test-support` because protocol-level calls need
//! `vera-client`/`vera-domain`/`alloy-primitives`/`k256`/`acp-light-client`,
//! none of which are `test-support` dependencies.
//!
//! `provision()` materializes policies, relationships, rings, and synthetic
//! offline/backup node identities through native Vera administration. Vera's
//! current genesis schema cannot seed Orbis module records, so placeholder
//! documents, key derivations, upgrades, and arbitrary demerit scores remain
//! explicit capability gaps instead of being faked in this adapter.

use super::native_confirmation::{confirmed, submit};
use alloy_primitives::B256;
use commonware_codec::Encode;
use crypto::r#trait::CryptoDeserialize;
use proto::unsafe_testing::{
    unsafe_testing_service_client::UnsafeTestingServiceClient, GetLocalStorageRequest,
    LocalStorageAccessMode, LocalStorageKey, LocalStorageKeyType, SetLocalStorageRequest,
};
use std::collections::{HashMap, HashSet};
use std::time::Duration;
use test_support::admin::{DocumentId, PolicyId, RingId, RingSpec, RingView};
use test_support::fixture::{
    AuthorizationTestDriver, BulletinTestDriver, FixtureId, NetworkTestDriver, NodeRef, NodeRole,
    PolicyHandle, ProvisionedFixture, RingHandle, ScenarioFixture, TestEnvironment,
};
use test_support::node_readiness::wait_for_nodes_ready;
use test_support::{NativeNetworkAdapter, NativeTestNetwork, NodeInfo};
use vera_client::{
    create_scoped_bearer_token,
    nodes::{
        encode_node_request, sign_node_request, NodeCommand, NodeInfo as VeraNodeInfo, NodeRequest,
        NodeTarget,
    },
    rings::{encode_ring_command, ReportingConfig, RingCommand, RingConfig, RingState, RingUpdate},
    threshold_objects::{encode_threshold_object, KeyDerivation, ObjectKind, ThresholdObject},
    BlsSigner, DelegationScope, VeraClient,
};
use vera_domain::ConsensusPublicKey;
use vera_harness::cluster::KeySet;

const DEPLOYMENT: u64 = 9000;
const OFFLINE_NODE_SECRET: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6,
];
const BACKUP_NODE_SECRET: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4,
];
/// Same placeholder as the Cosmos genesis peer (`OFFLINE_NODE_PEER_ID` in
/// `crates/test-support`). The node id is 64 hex characters, so committee
/// route resolution accepts it, and it is not an iroh public key, so a dial
/// fails before any network I/O.
const OFFLINE_NODE_PEER: &str =
    "5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f@node-offline:4242";
const BACKUP_NODE_PEER: &str = "backup-node-4-peer-id";
const RING_POLICY_YAML: &str = r#"
name: native-test-ring-policy
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

pub struct NativeTestEnvironment {
    network: NativeNetworkAdapter,
    client: VeraClient,
    trusted: ConsensusPublicKey,
    root: B256,
    controller: k256::ecdsa::SigningKey,
    actor: String,
    worker: BlsSigner,
    fixture: ProvisionedFixture,
}

impl NativeTestEnvironment {
    fn policy_bytes(policy: &PolicyId) -> B256 {
        B256::from_slice(&hex::decode(&policy.0).expect("policy id is hex-encoded"))
    }

    /// Host-reachable Defra URL, when `ScenarioFixture::defra` was set.
    /// `None` otherwise. Mirrors `CosmosTestEnvironment::defra_url`.
    pub fn defra_url(&self) -> Option<&str> {
        self.network.defra_url()
    }

    /// The address a ring's `pre_share_endpoints` must use so both sibling
    /// node containers and this process can reach it. Unlike Cosmos's
    /// equivalent, this doesn't need a bridge-network gateway-IP lookup —
    /// native's own project network pre-assigns every address statically
    /// (see `NativeTestNetwork::defra_container_url`). `None` unless
    /// `ScenarioFixture::defra` was set. Mirrors
    /// `CosmosTestEnvironment::defra_container_url`.
    pub fn defra_container_url(&self) -> Option<String> {
        self.network.defra_container_url()
    }

    /// Same ring-creation path as `register_ring`, but sets
    /// `pre_share_endpoints` directly and performs the one-time ring-policy
    /// registration/authorization that `provision()`'s fixture loop
    /// otherwise does inline. `RingSpec` deliberately carries no
    /// `pre_share_endpoints` field (see its own doc comment), so this is a
    /// dedicated escape hatch for `defra_pre_scenario.rs`, mirroring
    /// `CosmosTestEnvironment::chain_config()`'s role on the Cosmos side.
    pub async fn create_ring_with_pre_share_endpoints(
        &self,
        policy_id: &PolicyId,
        node_keys: &[String],
        threshold: u32,
        pre_share_endpoints: Vec<String>,
    ) -> RingId {
        let policy_bytes = Self::policy_bytes(policy_id);
        let registered = self
            .client
            .native_register_object(&self.worker, policy_bytes, &policy_id.0, "ring_policy")
            .await
            .unwrap();
        confirmed(&self.client, registered.transaction_hash, &self.trusted).await;
        let granted = self
            .client
            .native_set_relationship(
                &self.worker,
                policy_bytes,
                "ring_policy",
                &policy_id.0,
                "creator",
                &self.actor,
            )
            .await
            .unwrap();
        confirmed(&self.client, granted.transaction_hash, &self.trusted).await;

        let now = unix_now();
        for info in self.nodes() {
            for command in [
                NodeCommand::SetPeer(info.p2p_address.clone()),
                NodeCommand::Allow(NodeTarget::Policy(policy_id.0.clone())),
            ] {
                let current = self
                    .client
                    .read_threshold_node(&info.node_key, 1, &self.trusted)
                    .await
                    .unwrap()
                    .record
                    .unwrap();
                let signed = sign_node_request(
                    NodeRequest {
                        deployment_root: self.root.0,
                        deployment_id: DEPLOYMENT,
                        node_key: info.node_key.clone(),
                        sequence: current.sequence,
                        expires_at: now + 300,
                        command,
                    },
                    &self.controller,
                )
                .unwrap();
                submit(
                    &self.client,
                    &self.worker,
                    &self.trusted,
                    encode_node_request(&signed).unwrap(),
                    "authorize node for defra-backed ring",
                    self.network.cluster(),
                )
                .await;
            }
        }

        create_ring(
            &self.client,
            &self.worker,
            &self.trusted,
            &self.controller,
            self.network.cluster(),
            RingSpec {
                node_keys: node_keys.to_vec(),
                threshold,
                pss_interval: Duration::from_secs(86_400),
                policy_id: policy_id.clone(),
                nonce: None,
                trusted_auth_relay_dids: Vec::new(),
                requires_pet: false,
            },
            ReportingConfig::default(),
            pre_share_endpoints,
        )
        .await
    }
}

fn fixture_node(
    secret: [u8; 32],
    peer: &str,
    controller_key: &str,
    allowed_policy_ids: Vec<String>,
) -> (k256::ecdsa::SigningKey, NodeInfo, VeraNodeInfo) {
    let signing_key = k256::ecdsa::SigningKey::from_slice(&secret).unwrap();
    let node_key = hex::encode(signing_key.verifying_key().to_sec1_bytes());
    (
        signing_key,
        NodeInfo {
            grpc_endpoint: String::new(),
            node_key: node_key.clone(),
            peer_id: peer.split('@').next().unwrap_or(peer).to_string(),
            p2p_address: peer.to_string(),
            public_address: node_key.clone(),
        },
        VeraNodeInfo {
            peer_id: peer.to_string(),
            controller_key: controller_key.to_string(),
            allowed_policy_ids,
            allowed_ring_ids: Vec::new(),
        },
    )
}

/// Share index stored in a finalized bundle: 1-based rank of the node key
/// among the committee, not its position in the fixture member list.
fn share_member_id(members: &[String], node_key: &str) -> u32 {
    crate::helpers::node_routes::canonical_node_id_assignments_from_node_keys(members)
        .expect("ring member keys are unique")
        .get(node_key)
        .copied()
        .expect("node key must be a ring member")
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

async fn create_policy(
    client: &VeraClient,
    worker: &BlsSigner,
    trusted: &ConsensusPublicKey,
    definition: &[u8],
) -> PolicyId {
    let before: HashSet<String> = client.get_policy_ids().await.unwrap().into_iter().collect();
    let created = client
        .native_create_policy(worker, definition, 1)
        .await
        .unwrap();
    confirmed(client, created.transaction_hash, trusted).await;
    let mut added = client
        .get_policy_ids()
        .await
        .unwrap()
        .into_iter()
        .filter(|id| !before.contains(id));
    let id = added
        .next()
        .expect("created policy must appear in catalogue");
    assert!(
        added.next().is_none(),
        "one policy creation added multiple ids"
    );
    PolicyId(id)
}

/// Shared by `provision()` (fixture-driven rings) and
/// `BulletinTestDriver::register_ring` (a standalone, callable-after-
/// provision ring creation — unlike Cosmos, native has no genesis-timing
/// problem, so both paths can share this one real implementation).
#[allow(clippy::too_many_arguments)]
async fn create_ring(
    client: &VeraClient,
    worker: &BlsSigner,
    trusted: &ConsensusPublicKey,
    controller: &k256::ecdsa::SigningKey,
    cluster: &NativeTestNetwork,
    spec: RingSpec,
    reporting: ReportingConfig,
    pre_share_endpoints: Vec<String>,
) -> RingId {
    let mut members = spec.node_keys;
    members.sort();
    let config = RingConfig {
        policy_id: spec.policy_id.0,
        peer_node_keys: members,
        threshold: spec.threshold,
        // Native creates rings through the live production command, whose
        // validator rejects short PSS intervals. Shared fixtures may use a
        // short interval because the Cosmos adapter can seed it in genesis;
        // native's `force_refresh_due` diagnostic hook provides the same test
        // semantics without weakening the live chain configuration.
        pss_interval: spec.pss_interval.as_secs().max(86_400),
        current_version: 0,
        requires_pet: spec.requires_pet,
        // `spec.nonce` is Cosmos-shaped (a string); native's ring-id
        // derivation nonce is a fixed-size byte array and isn't threaded
        // through yet — matches the legacy native workflow's hardcoded
        // `[2; 32]`.
        nonce: [2; 32],
        trusted_auth_relay_dids: (!spec.trusted_auth_relay_dids.is_empty())
            .then_some(spec.trusted_auth_relay_dids),
        reporting,
        pre_share_endpoints,
    };
    let ring_id = config.id().unwrap();
    let now = unix_now();
    let token = create_scoped_bearer_token(
        controller,
        worker.did(),
        DEPLOYMENT,
        now,
        now + 300,
        DelegationScope::ManageRings,
    )
    .unwrap();
    submit(
        client,
        worker,
        trusted,
        encode_ring_command(&RingCommand::Create(config), &token).unwrap(),
        "create ring",
        cluster,
    )
    .await;
    RingId(ring_id)
}

#[async_trait::async_trait]
impl TestEnvironment for NativeTestEnvironment {
    async fn provision(fixture: ScenarioFixture) -> Self {
        // Fixture-driven document/key-derivation/demerit materialization
        // isn't implemented yet — those records need either a
        // finalized ring (live DKG, which only happens in the scenario
        // itself, after provisioning) or genesis-injection support that
        // doesn't exist in Vera today. See the harness-unification plan.
        assert!(
            fixture.documents.is_empty()
                && fixture.key_derivations.is_empty()
                && fixture.node_demerits.is_empty(),
            "NativeTestEnvironment::provision: fixture-driven document/key-derivation/\
             demerit materialization isn't implemented yet"
        );
        let node_count = fixture
            .nodes
            .iter()
            .filter(|node| node.role == NodeRole::Running)
            .count();

        // Deployment seed is not yet part of `ScenarioFixture` — every
        // `NativeTestEnvironment` currently gets the builder's default
        // (9000). Revisit if/when a fixture needs to run more than one
        // native environment in the same process.
        let requires_unsafe_testing = fixture.requires_unsafe_testing;
        let network = NativeNetworkAdapter::start_configured(
            DEPLOYMENT,
            node_count,
            !requires_unsafe_testing,
            requires_unsafe_testing,
            fixture.defra,
        )
        .await;

        let trusted = *KeySet::builder()
            .seed(DEPLOYMENT)
            .build()
            .unwrap()
            .epoch_info()
            .output
            .public()
            .public();
        let url = network.cluster().node(0).rpc_url();
        let client = VeraClient::new(&url);
        let first = client.read_finalized_revision(1, &trusted).await.unwrap();
        let headers = acp_light_client::header_sync::HeaderChain::connect(
            &url.replacen("http://", "ws://", 1),
            acp_light_client::ProofClient::new(&url, &hex::encode(trusted.encode())).unwrap(),
        )
        .await
        .unwrap();
        headers
            .wait_for_height(first.height + 1, Duration::from_secs(15))
            .await
            .unwrap();
        assert!(headers.fresh_state().unwrap().height > first.height);
        let root: B256 = first.parent_hash.parse().unwrap();
        let controller = k256::ecdsa::SigningKey::from_slice(&[34; 32]).unwrap();
        let actor = vera_crypto::secp256k1::did_from_secp256k1_pubkey(
            controller.verifying_key().to_sec1_bytes().as_ref(),
        )
        .unwrap();
        let worker = BlsSigner::new(7u64.into(), DEPLOYMENT).unwrap();

        // Full "http://host:port" URLs — `wait_for_nodes_ready` connects with
        // these directly (same convention `CosmosTestEnvironment` uses; it
        // builds its own `tonic::transport::Endpoint` rather than taking a
        // bare host:port the way `vera_client`'s helpers in this file do).
        let endpoints: Vec<String> = network.node_endpoints();
        let nodes = wait_for_nodes_ready(&endpoints).await;

        // `fixture.policies`/`relationships` are fully live on native — no
        // genesis-timing concern the way Cosmos has. Calling the chain
        // client directly (rather than `self.create_policy`/`self.grant`)
        // since `Self` hasn't been constructed yet at this point.
        let mut policies: HashMap<FixtureId, PolicyId> = HashMap::new();
        for policy in &fixture.policies {
            let id = create_policy(&client, &worker, &trusted, policy.definition.as_bytes()).await;
            policies.insert(policy.id.clone(), id);
        }
        // A scenario may name a ring policy without separately caring about
        // its concrete policy fixture. Cosmos materializes such governance
        // policies internally; native does the equivalent here so the
        // scenario vocabulary stays backend-neutral.
        for ring in &fixture.rings {
            if policies.contains_key(&ring.policy) {
                continue;
            }
            let id = create_policy(&client, &worker, &trusted, RING_POLICY_YAML.as_bytes()).await;
            policies.insert(ring.policy.clone(), id);
        }
        let resolve = |id: &FixtureId| -> String {
            policies
                .get(id)
                .map(|policy| policy.0.clone())
                .unwrap_or_else(|| id.0.clone())
        };
        for relationship in &fixture.relationships {
            let policy_bytes =
                NativeTestEnvironment::policy_bytes(&PolicyId(resolve(&relationship.policy)));
            let outcome = client
                .native_set_relationship(
                    &worker,
                    policy_bytes,
                    &relationship.resource,
                    &resolve(&relationship.object),
                    &relationship.relation,
                    &relationship.subject_did,
                )
                .await
                .unwrap();
            confirmed(&client, outcome.transaction_hash, &trusted).await;
        }

        let controller_key = hex::encode(controller.verifying_key().to_sec1_bytes());
        let mut allowed_policy_ids: Vec<String> = fixture
            .rings
            .iter()
            .map(|ring| resolve(&ring.policy))
            .collect();
        allowed_policy_ids.sort();
        allowed_policy_ids.dedup();
        let mut non_running_nodes: HashMap<FixtureId, NodeInfo> = HashMap::new();
        for node in &fixture.nodes {
            let (secret, peer) = match node.role {
                NodeRole::Running => continue,
                NodeRole::Offline => (OFFLINE_NODE_SECRET, OFFLINE_NODE_PEER),
                NodeRole::Backup => (BACKUP_NODE_SECRET, BACKUP_NODE_PEER),
            };
            let (signing_key, info, chain_info) =
                fixture_node(secret, peer, &controller_key, allowed_policy_ids.clone());
            let request = NodeRequest {
                deployment_root: root.0,
                deployment_id: DEPLOYMENT,
                node_key: info.node_key.clone(),
                sequence: 0,
                expires_at: unix_now() + 300,
                command: NodeCommand::Register(chain_info),
            };
            let signed = sign_node_request(request, &signing_key).unwrap();
            submit(
                &client,
                &worker,
                &trusted,
                encode_node_request(&signed).unwrap(),
                "register fixture-only node",
                network.cluster(),
            )
            .await;
            assert!(
                non_running_nodes.insert(node.id.clone(), info).is_none(),
                "fixture-only node ids must be unique"
            );
        }

        let mut ring_policy_registered: std::collections::HashSet<String> =
            std::collections::HashSet::new();
        let mut rings: HashMap<FixtureId, RingHandle> = HashMap::new();
        for ring in &fixture.rings {
            assert!(
                ring.upgrade.is_none(),
                "NativeTestEnvironment::provision: RingFixture::upgrade isn't supported yet"
            );
            let members: Vec<&NodeInfo> = ring
                .members
                .iter()
                .map(|node_ref| match node_ref {
                    NodeRef::Running(index) => &nodes[*index],
                    NodeRef::Offline(id) | NodeRef::Backup(id) => non_running_nodes
                        .get(id)
                        .unwrap_or_else(|| panic!("unknown fixture-only node {}", id.0)),
                })
                .collect();
            let policy_id = PolicyId(resolve(&ring.policy));

            // `RingCommand::Create`'s submitter (`actor`) needs the ACP
            // `creator` relation on a `ring_policy` object registered under
            // this same policy — the same registration and grant the Trust
            // gateway applies before it creates a ring. Once
            // per distinct policy, not once per ring.
            if ring_policy_registered.insert(policy_id.0.clone()) {
                let policy_bytes = NativeTestEnvironment::policy_bytes(&policy_id);
                let registered = client
                    .native_register_object(&worker, policy_bytes, &policy_id.0, "ring_policy")
                    .await
                    .unwrap();
                confirmed(&client, registered.transaction_hash, &trusted).await;
                let granted = client
                    .native_set_relationship(
                        &worker,
                        policy_bytes,
                        "ring_policy",
                        &policy_id.0,
                        "creator",
                        &actor,
                    )
                    .await
                    .unwrap();
                confirmed(&client, granted.transaction_hash, &trusted).await;
            }

            let now = unix_now();
            // Authorize every running fixture node for the policy, not only
            // the initial committee. Shared reshare scenarios deliberately
            // introduce a running non-member later; that candidate must be
            // prepared by the adapter just like a genesis-whitelisted node.
            for info in &nodes {
                for command in [
                    NodeCommand::SetPeer(info.p2p_address.clone()),
                    NodeCommand::Allow(NodeTarget::Policy(policy_id.0.clone())),
                ] {
                    let current = client
                        .read_threshold_node(&info.node_key, 1, &trusted)
                        .await
                        .unwrap()
                        .record
                        .unwrap();
                    let signed = sign_node_request(
                        NodeRequest {
                            deployment_root: root.0,
                            deployment_id: DEPLOYMENT,
                            node_key: info.node_key.clone(),
                            sequence: current.sequence,
                            expires_at: now + 300,
                            command,
                        },
                        &controller,
                    )
                    .unwrap();
                    submit(
                        &client,
                        &worker,
                        &trusted,
                        encode_node_request(&signed).unwrap(),
                        "authorize node for fixture ring",
                        network.cluster(),
                    )
                    .await;
                }
            }
            let node_keys: Vec<String> = members.iter().map(|info| info.node_key.clone()).collect();
            let id = create_ring(
                &client,
                &worker,
                &trusted,
                &controller,
                network.cluster(),
                RingSpec {
                    node_keys: node_keys.clone(),
                    threshold: ring.threshold,
                    pss_interval: ring.pss_interval,
                    policy_id: policy_id.clone(),
                    nonce: None,
                    trusted_auth_relay_dids: Vec::new(),
                    requires_pet: ring.requires_pet,
                },
                ReportingConfig {
                    node_offline_demerits: ring.reporting.node_offline_demerits,
                    invalid_crypto_response_demerits: ring
                        .reporting
                        .invalid_crypto_response_demerits,
                    unauthorized_request_demerits: ring.reporting.unauthorized_request_demerits,
                    reset_interval_seconds: ring.reporting.reset_interval.as_secs(),
                    kick_threshold: ring.reporting.kick_threshold,
                    backup_node_keys: ring
                        .reporting
                        .backup_node_keys
                        .iter()
                        .map(|node| match node {
                            NodeRef::Running(index) => nodes[*index].node_key.clone(),
                            NodeRef::Offline(id) | NodeRef::Backup(id) => non_running_nodes
                                .get(id)
                                .unwrap_or_else(|| {
                                    panic!("unknown fixture-only backup node {}", id.0)
                                })
                                .node_key
                                .clone(),
                        })
                        .collect(),
                },
                vec![],
            )
            .await;
            rings.insert(
                ring.id.clone(),
                RingHandle {
                    id,
                    members: node_keys,
                },
            );
        }

        Self {
            network,
            client,
            trusted,
            root,
            controller,
            actor,
            worker,
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
        vera_client::rings::ring_deployment_label(self.root.0, DEPLOYMENT)
    }

    fn checks_production_kdf_header() -> bool {
        true
    }
}

#[async_trait::async_trait]
impl NetworkTestDriver for NativeTestEnvironment {
    fn nodes(&self) -> &[NodeInfo] {
        &self.fixture.nodes
    }

    async fn stop_node(&self, index: usize) {
        self.network.stop_node(index);
    }

    async fn start_node(&self, index: usize) -> String {
        self.network.start_node(index)
    }

    async fn restart_nodes(&self) -> Vec<String> {
        self.network.restart_nodes()
    }

    fn persisted_kdf_params(
        &self,
        index: usize,
    ) -> Option<test_support::fixture::PersistedKdfParams> {
        let stored =
            super::stored_bundle::persisted_kdf_params(&self.network.node_directory(index));
        Some(test_support::fixture::PersistedKdfParams {
            m_cost_kib: stored.m_cost_kib,
            t_cost: stored.t_cost,
            p_cost: stored.p_cost,
            version: stored.version,
        })
    }
}

#[async_trait::async_trait]
impl AuthorizationTestDriver for NativeTestEnvironment {
    async fn create_policy(&self, definition: &str) -> PolicyId {
        create_policy(
            &self.client,
            &self.worker,
            &self.trusted,
            definition.as_bytes(),
        )
        .await
    }

    async fn register_object(&self, policy: &PolicyId, resource: &str, object_id: &str) {
        let registered = self
            .client
            .native_register_object(
                &self.worker,
                Self::policy_bytes(policy),
                object_id,
                resource,
            )
            .await
            .expect("register shared scenario object");
        confirmed(&self.client, registered.transaction_hash, &self.trusted).await;
    }

    async fn grant(
        &self,
        policy: &PolicyId,
        resource: &str,
        object_id: &str,
        relation: &str,
        subject_did: &str,
    ) {
        let outcome = self
            .client
            .native_set_relationship(
                &self.worker,
                Self::policy_bytes(policy),
                resource,
                object_id,
                relation,
                subject_did,
            )
            .await
            .unwrap();
        confirmed(&self.client, outcome.transaction_hash, &self.trusted).await;
    }

    async fn revoke(
        &self,
        policy: &PolicyId,
        resource: &str,
        object_id: &str,
        relation: &str,
        subject_did: &str,
    ) {
        let outcome = self
            .client
            .native_delete_relationship(
                &self.worker,
                Self::policy_bytes(policy),
                resource,
                object_id,
                relation,
                subject_did,
            )
            .await
            .unwrap();
        confirmed(&self.client, outcome.transaction_hash, &self.trusted).await;
    }
}

#[async_trait::async_trait]
impl BulletinTestDriver for NativeTestEnvironment {
    async fn register_ring(&self, spec: RingSpec) -> RingId {
        create_ring(
            &self.client,
            &self.worker,
            &self.trusted,
            &self.controller,
            self.network.cluster(),
            spec,
            ReportingConfig::default(),
            vec![],
        )
        .await
    }

    async fn read_ring(&self, ring: &RingId) -> Option<RingView> {
        let record = match self
            .client
            .read_threshold_ring(&ring.0, 1, &self.trusted)
            .await
        {
            Ok(response) => response.record?,
            Err(error) if error.is_throttled() => return None,
            Err(error) => panic!("certified ring read failed: {error}"),
        };
        let settings = record.current_settings();
        let (ring_pk, pet_pk) = match &record.state {
            RingState::Active { keys } => (keys.public_key.clone(), keys.pet_public_key.clone()),
            _ => (String::new(), None),
        };
        Some(RingView {
            ring_pk,
            peer_node_keys: settings.peer_node_keys.clone(),
            threshold: settings.threshold,
            requires_pet: record.config.requires_pet,
            pet_pk,
            confirmations: 0,
            new_peer_node_keys: settings
                .pending_reshare
                .as_ref()
                .map(|target| target.peer_node_keys.clone())
                .unwrap_or_default(),
            new_threshold: settings
                .pending_reshare
                .as_ref()
                .map(|target| target.threshold),
        })
    }

    async fn wait_for_finalized(&self, ring: &RingId, timeout: Duration) -> RingView {
        tokio::time::timeout(timeout, async {
            loop {
                if let Some(view) = self.read_ring(ring).await {
                    if !view.ring_pk.is_empty() {
                        return view;
                    }
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("Timed out waiting for ring {} to be finalized", ring.0))
    }

    /// Native has no equivalent of Cosmos's generic `bulletin::vera` post
    /// primitive to reuse for a direct, backend-admin-shortcut document
    /// write — the only way to store a document is the real `StoreSecret`
    /// gRPC flow this scenario already exercises. Same as before PR 4: not a
    /// regression, this was always `Capability::Unsupported` on native.
    async fn store_document(
        &self,
        _ring: &RingId,
        _payload: &[u8],
        _reader_dids: &[String],
    ) -> DocumentId {
        unimplemented!("NativeTestEnvironment::store_document: no direct-write path exists")
    }

    async fn read_document(&self, id: &DocumentId) -> Vec<u8> {
        let record = self
            .client
            .read_threshold_object(ObjectKind::Document, &id.0, 1, &self.trusted)
            .await
            .expect("read shared scenario native document")
            .record
            .expect("shared scenario native document must exist");
        let ThresholdObject::Document(document) = record.object else {
            panic!("document lookup returned a key derivation")
        };
        serde_json::to_vec(&document).expect("serialize authoritative native document")
    }

    async fn register_key_derivation(
        &self,
        ring: &RingId,
        derivation: &str,
        policy: &PolicyId,
        resource: &str,
        permission: &str,
    ) -> String {
        let derivation = KeyDerivation {
            ring_id: ring.0.clone(),
            derivation: derivation.to_string(),
            policy_id: policy.0.clone(),
            resource: resource.to_string(),
            permission: permission.to_string(),
        };
        let object = ThresholdObject::KeyDerivation(derivation);
        let derivation_id = object.id().expect("derive native key-derivation id");
        let now = unix_now();
        let token = create_scoped_bearer_token(
            &self.controller,
            self.worker.did(),
            DEPLOYMENT,
            now,
            now + 300,
            DelegationScope::StoreThresholdObject,
        )
        .expect("create native key-derivation delegation");
        submit(
            &self.client,
            &self.worker,
            &self.trusted,
            encode_threshold_object(&object, &token).expect("encode native key derivation"),
            "store shared Sign key derivation",
            self.network.cluster(),
        )
        .await;
        derivation_id
    }

    async fn update_membership(
        &self,
        ring: &RingId,
        mut new_members: Vec<String>,
        new_threshold: u32,
    ) {
        // The chain rejects a StartReshare whose member list is not strictly sorted.
        new_members.sort();
        let record = self
            .client
            .read_threshold_ring(&ring.0, 1, &self.trusted)
            .await
            .expect("read native ring before shared reshare")
            .record
            .expect("shared reshare ring must exist");
        let now = unix_now();
        let token = create_scoped_bearer_token(
            &self.controller,
            self.worker.did(),
            DEPLOYMENT,
            now,
            now + 300,
            DelegationScope::ManageRings,
        )
        .expect("create native shared-reshare delegation");
        submit(
            &self.client,
            &self.worker,
            &self.trusted,
            encode_ring_command(
                &RingCommand::Update {
                    ring_id: ring.0.clone(),
                    expected_sequence: record.sequence,
                    update: RingUpdate::StartReshare {
                        peer_node_keys: Some(new_members),
                        threshold: Some(new_threshold),
                    },
                },
                &token,
            )
            .expect("encode native shared reshare"),
            "start shared native reshare",
            self.network.cluster(),
        )
        .await;
    }

    async fn arm_refresh_for_next_start(&self, _ring: &RingId, ring_pk: &str, members: &[String]) {
        for (index, node) in self.nodes().iter().enumerate() {
            if !members.iter().any(|key| key == &node.node_key) {
                continue;
            }
            super::stored_bundle::backdate_main_ring(
                &self.network.node_directory(index),
                ring_pk,
                share_member_id(members, &node.node_key),
            );
        }
    }

    /// Native has no short-`pss_interval` escape hatch for a live-created
    /// ring (unlike Cosmos's genesis seed) — so, same as the pre-migration
    /// adapters, force a refresh due by backdating each member's persisted
    /// bundle through the `UnsafeTestingService` diagnostic hook instead of
    /// waiting out the real interval. A member whose container is already
    /// stopped is left alone: its scheduler is not running, and the live
    /// store is not reachable.
    async fn force_refresh_due(&self, ring: &RingId, ring_pk: &str, members: &[String]) {
        let main_storage_key =
            crypto::GroupAffine::from_bytes(&hex::decode(ring_pk).expect("ring public key is hex"))
                .expect("ring public key must decode")
                .to_string();
        let view = self
            .read_ring(ring)
            .await
            .expect("refresh target ring must exist");
        let mut bundles = vec![(
            LocalStorageKeyType::RingKey,
            main_storage_key,
            ring_pk.to_string(),
        )];
        if let Some(pet_pk) = view.pet_pk {
            bundles.push((LocalStorageKeyType::PetRingKey, ring.0.clone(), pet_pk));
        }
        let mut backdated = 0usize;
        for (index, node) in self.nodes().iter().enumerate() {
            if !members.iter().any(|key| key == &node.node_key) {
                continue;
            }
            if !self.network.node_is_running(index) {
                continue;
            }
            let member = share_member_id(members, &node.node_key);
            let mut control = UnsafeTestingServiceClient::connect(node.grpc_endpoint.clone())
                .await
                .expect("connect native refresh test control");
            for (key_type, storage_ring_key, public_key) in &bundles {
                let storage_key = LocalStorageKey {
                    key_type: *key_type as i32,
                    ring_key: storage_ring_key.clone(),
                };
                let stored = control
                    .get_local_storage(GetLocalStorageRequest {
                        key: Some(storage_key.clone()),
                        access_mode: LocalStorageAccessMode::Encrypted as i32,
                    })
                    .await
                    .expect("read live native refresh bundle")
                    .into_inner();
                assert!(stored.found, "native refresh bundle must exist");
                let due = super::stored_bundle::Bundle::backdated(stored.value, public_key, member);
                control
                    .set_local_storage(SetLocalStorageRequest {
                        key: Some(storage_key),
                        access_mode: LocalStorageAccessMode::Encrypted as i32,
                        value: due,
                    })
                    .await
                    .expect("backdate live native refresh bundle");
            }
            backdated += 1;
        }
        assert!(
            backdated > 0,
            "native refresh backdate requires a running member"
        );
    }

    /// Native's chain module has no reshare-cancellation command at all —
    /// `vera_client::rings::RingUpdate` has no cancel variant, only
    /// `StartReshare` (and unrelated updates) — so there's nothing to call.
    async fn cancel_reshare(&self, _ring: &RingId) {
        unimplemented!("NativeTestEnvironment::cancel_reshare: no RingUpdate variant exists")
    }

    async fn read_node_demerits(&self, ring: &RingId, node_key: &str) -> u64 {
        self.client
            .read_threshold_node_demerits(&ring.0, node_key, 1, &self.trusted)
            .await
            .expect("read node demerits")
            .record
            .map(|demerits| demerits.points)
            .unwrap_or(0)
    }
}
