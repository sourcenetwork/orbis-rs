//! Backend-neutral E2E scenario vocabulary: a declarative [`ScenarioFixture`]
//! describing the state a test wants ("3 running nodes, one ring, one
//! document..."), resolved by a concrete [`TestEnvironment`] implementation
//! into real backend state (a running Cosmos or native-Vera cluster) without
//! the test ever naming a Docker service, a chain RPC call, or a backend
//! enum.
//!
//! This module is purely additive: it defines the shared types and traits,
//! not a selection mechanism or a concrete implementation for either
//! backend. See the harness-unification plan for the PRs that build on top
//! of it.
//!
//! Field shapes here are drawn directly from the `with_module_genesis`
//! patches already used across `bin/orbis-node/src/tests/*` (ring config,
//! `reporting_genesis_json`, `upgrade_info`, `node_infos`, `node_demerits`)
//! — this type family exists to stop describing that same state as raw JSON
//! once per test, not to invent new scenario shapes.

use crate::admin::{DocumentId, PolicyId, RingId, RingSpec, RingView};
use crate::network::NodeInfo;
use std::collections::HashMap;
use std::time::Duration;

/// A name a test gives something inside one [`ScenarioFixture`] — never a
/// Docker service name or on-chain id itself. Resolved to a real backend id
/// only after [`TestEnvironment::provision`] returns; see
/// [`ProvisionedFixture`].
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FixtureId(pub String);

impl FixtureId {
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeRole {
    /// A real Orbis node process is launched for this entry.
    Running,
    /// Registered as a node identity with no running process — e.g. an
    /// unreachable reshare target, or a pre-authorized node that never
    /// starts. Each implementation resolves this into whatever "node exists
    /// on-chain but nothing is listening" looks like for that backend.
    Offline,
    /// Registered but not an active ring member — eligible for backup
    /// promotion.
    Backup,
}

#[derive(Clone, Debug)]
pub struct NodeFixture {
    pub id: FixtureId,
    pub role: NodeRole,
}

/// A reference to one [`ScenarioFixture::nodes`] entry, used from
/// [`RingFixture::members`], [`ReportingFixture::backup_node_keys`], and
/// [`NodeDemeritFixture::node`]. `Running(n)` is the nth `Running`-role node
/// (0-indexed, in declaration order); `Offline`/`Backup` match a
/// [`NodeFixture::id`] by name. Never a real node key or Docker service name
/// — each implementation resolves this against its own running/registered
/// nodes.
#[derive(Clone, Debug)]
pub enum NodeRef {
    Running(usize),
    Offline(FixtureId),
    Backup(FixtureId),
}

#[derive(Clone, Debug)]
pub struct ReportingFixture {
    pub node_offline_demerits: u64,
    pub invalid_crypto_response_demerits: u64,
    pub unauthorized_request_demerits: u64,
    pub reset_interval: Duration,
    pub backup_node_keys: Vec<NodeRef>,
    pub kick_threshold: u64,
}

impl Default for ReportingFixture {
    /// Mirrors `reporting_genesis_json(1, &[], 3)`'s existing baseline
    /// (`bin/orbis-node/src/tests/constants.rs`).
    fn default() -> Self {
        Self {
            node_offline_demerits: 1,
            invalid_crypto_response_demerits: 1,
            unauthorized_request_demerits: 1,
            reset_interval: Duration::from_secs(86_400),
            backup_node_keys: Vec::new(),
            kick_threshold: 3,
        }
    }
}

#[derive(Clone, Debug)]
pub struct UpgradeFixture {
    pub current_version: u32,
    pub next_version: u32,
    /// Offset from provisioning time, not an absolute timestamp — stays
    /// backend/time-neutral; each materializer adds it to "now" itself.
    pub activation_offset: Duration,
}

#[derive(Clone, Debug)]
pub struct RingFixture {
    pub id: FixtureId,
    pub members: Vec<NodeRef>,
    pub threshold: u32,
    pub pss_interval: Duration,
    pub requires_pet: bool,
    pub policy: FixtureId,
    pub reporting: ReportingFixture,
    pub upgrade: Option<UpgradeFixture>,
}

#[derive(Clone, Debug)]
pub struct PolicyFixture {
    pub id: FixtureId,
    /// Raw ACP policy source — already backend-neutral (both chains
    /// evaluate the same policy language), so no further abstraction here.
    pub definition: String,
}

#[derive(Clone, Debug)]
pub struct RelationshipFixture {
    pub policy: FixtureId,
    pub resource: String,
    pub object: FixtureId,
    pub relation: String,
    /// A did:key string, computed by the test the same way it is today
    /// (`did_key::generate`/`vera_crypto::secp256k1::did_from_secp256k1_pubkey`)
    /// — identity DIDs are already backend-neutral, no fixture type needed.
    pub subject_did: String,
}

#[derive(Clone, Debug)]
pub struct DocumentFixture {
    pub id: FixtureId,
    pub ring: FixtureId,
    pub policy: FixtureId,
    pub resource: String,
    pub permission: String,
    /// Plaintext. Each materializer encrypts against whatever key the named
    /// ring will have (for a genesis-seeded fixture, a predetermined
    /// deterministic key; for a live-provisioned one, the ring's real key).
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct KeyDerivationFixture {
    pub id: FixtureId,
    pub ring: FixtureId,
    pub policy: FixtureId,
    pub derivation: String,
    pub resource: String,
    pub permission: String,
}

#[derive(Clone, Debug)]
pub struct NodeDemeritFixture {
    pub ring: FixtureId,
    pub node: NodeRef,
    pub points: u64,
    pub window_started_offset: Duration,
}

#[derive(Clone, Debug, Default)]
pub struct ScenarioFixture {
    pub nodes: Vec<NodeFixture>,
    pub rings: Vec<RingFixture>,
    pub policies: Vec<PolicyFixture>,
    pub relationships: Vec<RelationshipFixture>,
    pub documents: Vec<DocumentFixture>,
    pub key_derivations: Vec<KeyDerivationFixture>,
    pub node_demerits: Vec<NodeDemeritFixture>,
}

/// A provisioned ring's resolved backend id plus its resolved member node
/// keys (in the order [`RingFixture::members`] declared them).
pub struct RingHandle {
    pub id: RingId,
    pub members: Vec<String>,
}

pub struct PolicyHandle {
    pub id: PolicyId,
}

pub struct DocumentHandle {
    pub id: DocumentId,
}

/// Resolved handles after [`TestEnvironment::provision`] returns. Look up by
/// the [`FixtureId`] a test declared in its [`ScenarioFixture`]; get back the
/// real backend id/endpoint.
pub struct ProvisionedFixture {
    pub nodes: Vec<NodeInfo>,
    pub rings: HashMap<FixtureId, RingHandle>,
    pub policies: HashMap<FixtureId, PolicyHandle>,
    pub documents: HashMap<FixtureId, DocumentHandle>,
}

/// A fully provisioned, backend-selected test environment. Exactly one
/// concrete implementation is compiled in per build (selected the same way
/// production `Authz`/`Bulletin` backends are), so tests never construct or
/// match on a backend enum themselves.
#[async_trait::async_trait]
pub trait TestEnvironment: Sized {
    async fn provision(fixture: ScenarioFixture) -> Self;
    fn fixture(&self) -> &ProvisionedFixture;

    /// The chain/deployment identifier scenario code needs to authenticate
    /// backend-specific requests (e.g. a JWT's issuer-chain claim) — Cosmos's
    /// chain id string, native's deployment label. Genuinely backend-specific
    /// and cheap, so a plain sync getter rather than another driver trait.
    fn chain_id(&self) -> String;

    /// Whether `BulletinTestDriver::store_document`/`read_document` are real
    /// on this backend — Cosmos: yes (`bulletin::vera`'s generic post
    /// primitive); native: no equivalent direct-write path exists. Default
    /// `false` so native needs no override. A scenario must check this
    /// before calling `store_document` rather than relying on it panicking
    /// — "never fake success, report unsupported explicitly" without a
    /// generic `Capability<T>` wrapper type, now that there's exactly one
    /// concrete environment per build to ask directly.
    fn supports_direct_document_write(&self) -> bool {
        false
    }
}

/// Node lifecycle control, backend-neutral. Replaces direct
/// `.cosmos()`/`.native()` escape hatches and Docker-service-name knowledge.
#[async_trait::async_trait]
pub trait NetworkTestDriver {
    fn nodes(&self) -> &[NodeInfo];
    async fn stop_node(&self, index: usize);
    async fn start_node(&self, index: usize) -> String;
    async fn restart_nodes(&self) -> Vec<String>;
}

/// ACP policy/relationship administration — the independently-selectable
/// authz half of [`crate::BackendAdmin`]'s surface (production permits
/// choosing an authz backend independently of a bulletin backend; so does
/// this).
#[async_trait::async_trait]
pub trait AuthorizationTestDriver {
    async fn create_policy(&self, definition: &str) -> PolicyId;

    /// Register an ACP object under `policy` so a later `grant` can target
    /// it. Both backends always did this as a required first step before
    /// granting a relationship on a new object — split out as its own
    /// method rather than folded into `grant`, since some callers (e.g. a
    /// ring's own governance object) register without ever granting.
    async fn register_object(&self, policy: &PolicyId, resource: &str, object_id: &str);

    async fn grant(
        &self,
        policy: &PolicyId,
        resource: &str,
        object_id: &str,
        relation: &str,
        subject_did: &str,
    );

    async fn revoke(
        &self,
        policy: &PolicyId,
        resource: &str,
        object_id: &str,
        relation: &str,
        subject_did: &str,
    );
}

/// Ring/document administration — the independently-selectable bulletin
/// half of [`crate::BackendAdmin`]'s surface.
#[async_trait::async_trait]
pub trait BulletinTestDriver {
    async fn register_ring(&self, spec: RingSpec) -> RingId;

    async fn read_ring(&self, ring: &RingId) -> Option<RingView>;

    /// Returns the full view (not just [`RingKeys`]) once `ring_pk` is set —
    /// callers that only need the main key still get it via `.ring_pk`, but
    /// `requires_pet`/`pet_pk`/`confirmations` no longer need a second read.
    async fn wait_for_finalized(&self, ring: &RingId, timeout: Duration) -> RingView;

    async fn store_document(
        &self,
        ring: &RingId,
        payload: &[u8],
        reader_dids: &[String],
    ) -> DocumentId;

    async fn read_document(&self, id: &DocumentId) -> Vec<u8>;

    /// Register a key-derivation object and return its id. Deriving the
    /// *public key* for it is pure curve math, identical on both backends —
    /// that stays in scenario code (which already depends on `crypto`),
    /// not here.
    async fn register_key_derivation(
        &self,
        ring: &RingId,
        derivation: &str,
        policy: &PolicyId,
        resource: &str,
        permission: &str,
    ) -> String;

    /// Announce a committee/threshold change for `ring` and return once the
    /// chain has accepted the *request* — not once the reshare completes;
    /// waiting for completion is a scenario-level concern (same as DKG
    /// finalization), using `read_ring`/`wait_for_finalized`.
    async fn update_membership(&self, ring: &RingId, new_members: Vec<String>, new_threshold: u32);

    /// Force a PSS/share-refresh ceremony to become due right now for
    /// `ring`, bypassing however long a real wait against its configured
    /// `pss_interval` would take — a test-only diagnostic hook, not a
    /// production operation. Default no-op: a backend whose ring already
    /// uses a short enough interval (Cosmos's genesis-seeded rings always
    /// do) never needs to override this.
    async fn force_refresh_due(&self, _ring: &RingId, _ring_pk: &str, _members: &[String]) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Not a real scenario run — just proves the DKG/PRE shape (3 running
    /// nodes, one ring with a policy/relationship, one document, one key
    /// derivation) composes as a plain struct literal before anything
    /// actually provisions it.
    #[test]
    fn standard_dkg_pre_shape_composes() {
        let ring = FixtureId::new("ring");
        let policy = FixtureId::new("policy");
        let document = FixtureId::new("document");
        let derivation = FixtureId::new("derivation");

        let fixture = ScenarioFixture {
            nodes: (0..3)
                .map(|_| NodeFixture {
                    id: FixtureId::new("node"),
                    role: NodeRole::Running,
                })
                .collect(),
            rings: vec![RingFixture {
                id: ring.clone(),
                members: vec![
                    NodeRef::Running(0),
                    NodeRef::Running(1),
                    NodeRef::Running(2),
                ],
                threshold: 2,
                pss_interval: Duration::from_secs(86_400),
                requires_pet: false,
                policy: policy.clone(),
                reporting: ReportingFixture::default(),
                upgrade: None,
            }],
            policies: vec![PolicyFixture {
                id: policy.clone(),
                definition: "name: standard dkg/pre policy".to_string(),
            }],
            relationships: vec![RelationshipFixture {
                policy: policy.clone(),
                resource: "document".to_string(),
                object: document.clone(),
                relation: "reader".to_string(),
                subject_did: "did:key:z6Mk...reader".to_string(),
            }],
            documents: vec![DocumentFixture {
                id: document,
                ring: ring.clone(),
                policy: policy.clone(),
                resource: "document".to_string(),
                permission: "read".to_string(),
                payload: b"shared backend StoreSecret and PRE".to_vec(),
            }],
            key_derivations: vec![KeyDerivationFixture {
                id: derivation,
                ring,
                policy,
                derivation: "native-signing".to_string(),
                resource: "key".to_string(),
                permission: "sign".to_string(),
            }],
            node_demerits: Vec::new(),
        };

        assert_eq!(fixture.nodes.len(), 3);
        assert_eq!(fixture.rings[0].members.len(), 3);
        assert!(fixture.node_demerits.is_empty());
    }
}
