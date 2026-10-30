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

use super::{confirmed, stored_bundle, submit};
use alloy_primitives::B256;
use commonware_codec::Encode;
use crypto::r#trait::CryptoDeserialize;
use proto::unsafe_testing::{
    unsafe_testing_service_client::UnsafeTestingServiceClient, GetLocalStorageRequest,
    LocalStorageAccessMode, LocalStorageKey, LocalStorageKeyType, SetLocalStorageRequest,
};
use std::collections::HashMap;
use std::time::Duration;
use test_support::admin::{DocumentId, PolicyId, RingId, RingSpec, RingView};
use test_support::fixture::{
    AuthorizationTestDriver, BulletinTestDriver, FixtureId, NetworkTestDriver, NodeRef, NodeRole,
    PolicyHandle, ProvisionedFixture, RingHandle, ScenarioFixture, TestEnvironment,
};
use test_support::node_readiness::wait_for_nodes_ready;
use test_support::{IntegrationBackend, IntegrationTestNetwork, NativeTestNetwork, NodeInfo};
use vera_client::{
    create_scoped_bearer_token,
    nodes::{encode_node_request, sign_node_request, NodeCommand, NodeRequest, NodeTarget},
    rings::{encode_ring_command, ReportingConfig, RingCommand, RingConfig, RingState, RingUpdate},
    threshold_objects::{encode_threshold_object, KeyDerivation, ObjectKind, ThresholdObject},
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
        pss_interval: spec.pss_interval.as_secs(),
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
                    pss_interval: ring.pss_interval,
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

    fn chain_id(&self) -> String {
        vera_client::rings::ring_deployment_label(self.root.0, DEPLOYMENT)
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
            self.network.native().cluster(),
        )
        .await;
        derivation_id
    }

    async fn update_membership(&self, ring: &RingId, new_members: Vec<String>, new_threshold: u32) {
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
            self.network.native().cluster(),
        )
        .await;
    }

    /// Native has no short-`pss_interval` escape hatch for a live-created
    /// ring (unlike Cosmos's genesis seed) — so, same as the pre-migration
    /// adapters, force a refresh due by backdating each member's persisted
    /// bundle through the `UnsafeTestingService` diagnostic hook instead of
    /// waiting out the real interval.
    async fn force_refresh_due(&self, _ring: &RingId, ring_pk: &str, members: &[String]) {
        let ring_key =
            crypto::GroupAffine::from_bytes(&hex::decode(ring_pk).expect("ring public key is hex"))
                .expect("ring public key must decode")
                .to_string();
        for node in self.nodes() {
            let member = members
                .iter()
                .position(|node_key| node_key == &node.node_key)
                .expect("native node must remain a ring member") as u32
                + 1;
            let storage_key = LocalStorageKey {
                key_type: LocalStorageKeyType::RingKey as i32,
                ring_key: ring_key.clone(),
            };
            let mut control = UnsafeTestingServiceClient::connect(node.grpc_endpoint.clone())
                .await
                .expect("connect native refresh test control");
            let stored = control
                .get_local_storage(GetLocalStorageRequest {
                    key: Some(storage_key.clone()),
                    access_mode: LocalStorageAccessMode::Encrypted as i32,
                })
                .await
                .expect("read live native main bundle")
                .into_inner();
            assert!(stored.found, "native main bundle must exist");
            let due = stored_bundle::Bundle::backdated(stored.value, ring_pk, member);
            control
                .set_local_storage(SetLocalStorageRequest {
                    key: Some(storage_key),
                    access_mode: LocalStorageAccessMode::Encrypted as i32,
                    value: due,
                })
                .await
                .expect("backdate live native main bundle");
        }
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
