//! Backend-neutral chain administration operations shared by E2E scenarios.
//!
//! One narrow trait, generalizing the pattern already proven by
//! `pet_dkg_contract::Backend` (paired-DKG verification shared across Cosmos
//! and native Vera): a shared signature, implemented once per backend.
//!
//! `CosmosAdmin` (this crate, [`cosmos`]) implements it directly against
//! `common`'s Cosmos chain client. Native's implementation does **not** live
//! here — it lives in `bin/orbis-node/tests/support/admin.rs`, alongside the
//! `vera-client`/`vera-domain`/`alloy-primitives`/`k256`/`acp-light-client`
//! dependencies its protocol-level calls need. Pulling those into this crate
//! would be a much larger, riskier dependency change than a behavior-preserving
//! move warrants; the trait boundary here is what lets the native impl live
//! elsewhere while still satisfying `&dyn BackendAdmin` callers.

use std::time::Duration;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PolicyId(pub String);

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RingId(pub String);

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DocumentId(pub String);

/// The ring's finalized key material. Single-field today (the main signing
/// key); both backends also expose a PET key via [`RingView::pet_pk`] once a
/// ring is read back.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RingKeys(pub String);

#[derive(Clone, Debug)]
pub struct RingSpec {
    pub node_keys: Vec<String>,
    pub threshold: u32,
    pub policy_id: PolicyId,
    pub nonce: Option<String>,
    pub trusted_auth_relay_dids: Vec<String>,
    pub requires_pet: bool,
}

#[derive(Clone, Debug)]
pub struct RingView {
    pub ring_pk: String,
    pub peer_node_keys: Vec<String>,
    pub threshold: u32,
    pub requires_pet: bool,
    pub pet_pk: Option<String>,
    /// Pending-finalization confirmation count. Cosmos clears this to 0 at
    /// finalization; native's reconciliation model has no equivalent list and
    /// always reports 0.
    pub confirmations: usize,
}

#[async_trait::async_trait]
pub trait BackendAdmin: Send + Sync {
    async fn create_policy(&self, definition: &str) -> PolicyId;

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

    async fn register_ring(&self, spec: RingSpec) -> RingId;

    async fn read_ring(&self, ring: &RingId) -> Option<RingView>;

    async fn wait_for_finalized(&self, ring: &RingId, timeout: Duration) -> RingKeys;

    /// Not yet backed by either backend as a standalone operation — both
    /// Cosmos and native currently do this inline inside monolithic test
    /// bodies (see Phase C of the harness-unification plan). Implementations
    /// may `unimplemented!()` until that extraction happens.
    async fn update_membership(&self, ring: &RingId, new_members: Vec<String>, new_threshold: u32);

    /// Not yet backed by either backend as a standalone operation; see
    /// [`BackendAdmin::update_membership`].
    async fn store_document(
        &self,
        ring: &RingId,
        payload: &[u8],
        reader_dids: &[String],
    ) -> DocumentId;

    /// Not yet backed by either backend as a standalone operation; see
    /// [`BackendAdmin::update_membership`].
    async fn read_document(&self, id: &DocumentId) -> Vec<u8>;
}

#[cfg(feature = "cosmos")]
pub mod cosmos;
