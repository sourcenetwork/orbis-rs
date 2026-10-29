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

use crate::admin::{BackendAdmin, DocumentId, PolicyId, RingId, RingKeys, RingSpec, RingView};
use crate::fixture::{
    AuthorizationTestDriver, BulletinTestDriver, NetworkTestDriver, NodeRole, ProvisionedFixture,
    ScenarioFixture, TestEnvironment,
};
use crate::network::{CosmosNetwork, NodeInfo};
use crate::node_readiness::wait_for_nodes_ready;
use std::collections::HashMap;
use std::time::Duration;

pub struct CosmosTestEnvironment {
    network: CosmosNetwork,
    fixture: ProvisionedFixture,
}

#[async_trait::async_trait]
impl TestEnvironment for CosmosTestEnvironment {
    async fn provision(fixture: ScenarioFixture) -> Self {
        // Fixture-driven ring/policy/document/key-derivation/demerit
        // materialization is not implemented yet — translating `fixture`'s
        // declarative state into real Cosmos genesis/chain calls is the next
        // PR in the harness-unification migration. This PR only proves node
        // bring-up through the new trait shape.
        assert!(
            fixture.rings.is_empty()
                && fixture.policies.is_empty()
                && fixture.relationships.is_empty()
                && fixture.documents.is_empty()
                && fixture.key_derivations.is_empty()
                && fixture.node_demerits.is_empty(),
            "CosmosTestEnvironment::provision: fixture-driven ring/policy/document/\
             key-derivation/demerit materialization isn't implemented yet \
             (harness-unification migration PR 3) — only `fixture.nodes` is honored today"
        );
        let node_count = fixture
            .nodes
            .iter()
            .filter(|node| node.role == NodeRole::Running)
            .count();
        let network = CosmosNetwork::builder().with_node_count(node_count).build();
        let endpoints: Vec<String> = network
            .all_endpoints()
            .into_iter()
            .map(str::to_string)
            .collect();
        let nodes = wait_for_nodes_ready(&endpoints).await;
        Self {
            network,
            fixture: ProvisionedFixture {
                nodes,
                rings: HashMap::new(),
                policies: HashMap::new(),
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
        // gap, see that method's doc comment.
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
