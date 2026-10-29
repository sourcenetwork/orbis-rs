//! Native's concrete `test_support::fixture::TestEnvironment`. Lives here
//! (not in `crates/test-support`) for the same reason `NativeAdmin` does —
//! see `support/admin.rs`'s doc comment: protocol-level calls need
//! `vera-client`/`vera-domain`/`alloy-primitives`/`k256`/`acp-light-client`,
//! none of which are `test-support` dependencies.
//!
//! Its `provision()` bootstrap is lifted from `native_pet::dkg::NativeHarness`
//! (the earlier DKG/PRE-migration proof) verbatim, with the node-readiness
//! poll replaced by the shared `test_support::node_readiness` helper instead
//! of a hand-rolled one. `NativeHarness`/`NativeWorkflow` are untouched —
//! every other native scenario still uses them until it migrates too.
//!
//! Scope limit matching `CosmosTestEnvironment`: `provision()` only brings up
//! the network. Fixture-driven ring/policy/document/key-derivation/demerit
//! materialization is the harness-unification migration's next PR.
//!
//! Unused for now (`#![allow(dead_code)]` below): nothing constructs a
//! `NativeTestEnvironment` yet since that's a later migration PR.
#![allow(dead_code)]

use super::{confirmed, submit};
use alloy_primitives::B256;
use commonware_codec::Encode;
use std::collections::HashMap;
use std::time::Duration;
use test_support::admin::{DocumentId, PolicyId, RingId, RingKeys, RingSpec, RingView};
use test_support::fixture::{
    AuthorizationTestDriver, BulletinTestDriver, FixtureId, NetworkTestDriver, NodeRef, NodeRole,
    PolicyHandle, ProvisionedFixture, RingHandle, ScenarioFixture, TestEnvironment,
};
use test_support::node_readiness::wait_for_nodes_ready;
use test_support::{IntegrationBackend, IntegrationTestNetwork, NativeTestNetwork, NodeInfo};
use vera_client::{
    create_scoped_bearer_token,
    nodes::{encode_node_request, sign_node_request, NodeCommand, NodeRequest, NodeTarget},
    rings::{encode_ring_command, ReportingConfig, RingCommand, RingConfig, RingState},
    BlsSigner, DelegationScope, VeraClient,
};
use vera_domain::ConsensusPublicKey;
use vera_harness::cluster::KeySet;

const DEPLOYMENT: u64 = 9000;

pub struct NativeTestEnvironment {
    network: IntegrationTestNetwork,
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
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
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
    actor: &str,
    root: B256,
    cluster: &NativeTestNetwork,
    spec: RingSpec,
) -> RingId {
    let mut members = spec.node_keys;
    members.sort();
    let config = RingConfig {
        policy_id: spec.policy_id.0,
        peer_node_keys: members,
        threshold: spec.threshold,
        pss_interval: 86_400,
        current_version: 0,
        requires_pet: spec.requires_pet,
        // `spec.nonce` is Cosmos-shaped (a string); native's ring-id
        // derivation nonce is a fixed-size byte array and isn't threaded
        // through yet — matches the previous `NativeAdmin`'s own hardcoded
        // `[2; 32]`.
        nonce: [2; 32],
        trusted_auth_relay_dids: None,
        reporting: ReportingConfig::default(),
    };
    let ring_id = config.id(root.0, actor).unwrap();
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
        // Fixture-driven document/key-derivation/demerit materialization and
        // non-`Running` nodes aren't implemented yet — both need either a
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
        assert!(
            fixture
                .nodes
                .iter()
                .all(|node| node.role == NodeRole::Running),
            "NativeTestEnvironment::provision: only NodeRole::Running is supported today"
        );
        let node_count = fixture.nodes.len();

        // Deployment seed is not yet part of `ScenarioFixture` — every
        // `NativeTestEnvironment` currently gets the builder's default
        // (9000). Revisit if/when a fixture needs to run more than one
        // native environment in the same process.
        let network = IntegrationTestNetwork::builder()
            .with_backend(IntegrationBackend::NativeVera)
            .with_node_count(node_count)
            .build_async()
            .await;

        let trusted = *KeySet::builder()
            .seed(DEPLOYMENT)
            .build()
            .unwrap()
            .epoch_info()
            .output
            .public()
            .public();
        let url = network.native().cluster().node(0).rpc_url();
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
        let endpoints: Vec<String> = network.native().node_endpoints();
        let nodes = wait_for_nodes_ready(&endpoints).await;

        // `fixture.policies`/`relationships` are fully live on native — no
        // genesis-timing concern the way Cosmos has. Calling the chain
        // client directly (rather than `self.create_policy`/`self.grant`)
        // since `Self` hasn't been constructed yet at this point.
        let mut policies: HashMap<FixtureId, PolicyId> = HashMap::new();
        for policy in &fixture.policies {
            let created = client
                .native_create_policy(&worker, policy.definition.as_bytes(), 1)
                .await
                .unwrap();
            confirmed(&client, created.transaction_hash, &trusted).await;
            let id = PolicyId(client.get_policy_ids().await.unwrap().pop().unwrap());
            policies.insert(policy.id.clone(), id);
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
                    NodeRef::Offline(_) | NodeRef::Backup(_) => panic!(
                        "NativeTestEnvironment::provision: NodeRole::Offline/Backup isn't \
                         supported yet"
                    ),
                })
                .collect();
            let policy_id = PolicyId(resolve(&ring.policy));

            // `RingCommand::Create`'s submitter (`actor`) needs the ACP
            // `creator` relation on a `ring_policy` object registered under
            // this same policy — mirrors `NativeWorkflow::start_with_network`'s
            // identical registration/grant pair (native_workflow.rs). Once
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
            for info in &members {
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
                        network.native().cluster(),
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
                &actor,
                root,
                network.native().cluster(),
                RingSpec {
                    node_keys: node_keys.clone(),
                    threshold: ring.threshold,
                    policy_id: policy_id.clone(),
                    nonce: None,
                    trusted_auth_relay_dids: Vec::new(),
                    requires_pet: ring.requires_pet,
                },
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
}

#[async_trait::async_trait]
impl NetworkTestDriver for NativeTestEnvironment {
    fn nodes(&self) -> &[NodeInfo] {
        &self.fixture.nodes
    }

    async fn stop_node(&self, index: usize) {
        self.network.native().stop_node(index);
    }

    async fn start_node(&self, index: usize) -> String {
        self.network.native().start_node(index)
    }

    async fn restart_nodes(&self) -> Vec<String> {
        self.network.native().restart_nodes()
    }
}

#[async_trait::async_trait]
impl AuthorizationTestDriver for NativeTestEnvironment {
    async fn create_policy(&self, definition: &str) -> PolicyId {
        let created = self
            .client
            .native_create_policy(&self.worker, definition.as_bytes(), 1)
            .await
            .unwrap();
        confirmed(&self.client, created.transaction_hash, &self.trusted).await;
        PolicyId(self.client.get_policy_ids().await.unwrap().pop().unwrap())
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
            &self.actor,
            self.root,
            self.network.native().cluster(),
            spec,
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
        })
    }

    async fn wait_for_finalized(&self, ring: &RingId, timeout: Duration) -> RingKeys {
        tokio::time::timeout(timeout, async {
            loop {
                if let Some(view) = self.read_ring(ring).await {
                    if !view.ring_pk.is_empty() {
                        return RingKeys(view.ring_pk);
                    }
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("Timed out waiting for ring {} to be finalized", ring.0))
    }

    async fn store_document(
        &self,
        _ring: &RingId,
        _payload: &[u8],
        _reader_dids: &[String],
    ) -> DocumentId {
        unimplemented!("NativeTestEnvironment::store_document: see NativeAdmin (Phase C)")
    }

    async fn read_document(&self, _id: &DocumentId) -> Vec<u8> {
        unimplemented!("NativeTestEnvironment::read_document: see store_document")
    }
}
