//! `test_support::BackendAdmin` for the native Vera chain.
//!
//! Lives here, not in `crates/test-support/src/admin/native.rs`, because its
//! calls are protocol-level (tx signing/submission, bearer-token scoping,
//! certified reads) and need `vera-client`/`vera-domain`/`alloy-primitives`/
//! `k256` — none of which are `test-support` dependencies today. Pulling them
//! in would be a much larger, riskier dependency change than a
//! behavior-preserving harness refactor warrants; see the Phase A report for
//! `iverc/native-threshold-review`'s harness-unification plan. Cosmos's
//! equivalent (`test_support::admin::cosmos::CosmosAdmin`) only needed
//! `common` (already a dependency), so it physically moved; this didn't.
//!
//! Every method here forwards to the same client calls `NativeWorkflow`/
//! `native_pet.rs` already make — nothing here is new protocol behavior.
//!
//! Unused for now (`#[allow(dead_code)]` below): nothing calls
//! `NativeWorkflow::admin()` yet since the shared E2E scenario layer it's
//! for is Phase C. Exists now so Phase C has a working facade to build on.
#![allow(dead_code)]

use super::{confirmed, submit};
use alloy_primitives::B256;
use std::time::Duration;
use test_support::admin::{
    BackendAdmin, DocumentId, PolicyId, RingId, RingKeys, RingSpec, RingView,
};
use test_support::NativeTestNetwork;
use vera_client::{
    create_scoped_bearer_token,
    rings::{encode_ring_command, ReportingConfig, RingCommand, RingConfig, RingState},
    BlsSigner, DelegationScope, VeraClient,
};
use vera_domain::ConsensusPublicKey;

pub struct NativeAdmin<'a> {
    pub client: &'a VeraClient,
    pub worker: &'a BlsSigner,
    pub trusted: &'a ConsensusPublicKey,
    pub controller: &'a k256::ecdsa::SigningKey,
    pub actor: &'a str,
    pub root: B256,
    pub deployment: u64,
    pub cluster: &'a NativeTestNetwork,
}

impl NativeAdmin<'_> {
    fn policy_bytes(policy: &PolicyId) -> B256 {
        B256::from_slice(&hex::decode(&policy.0).expect("policy id is hex-encoded"))
    }

    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }
}

#[async_trait::async_trait]
impl BackendAdmin for NativeAdmin<'_> {
    async fn create_policy(&self, definition: &str) -> PolicyId {
        // Mirrors `NativeWorkflow::start_with_network`'s policy-creation step
        // (native_workflow.rs) — grabs the last policy id rather than diffing
        // against a "before" snapshot like Cosmos's `CosmosAdmin::create_policy`
        // does; inherited behavior, not something this facade introduces.
        let created = self
            .client
            .native_create_policy(self.worker, definition.as_bytes(), 1)
            .await
            .unwrap();
        confirmed(self.client, created.transaction_hash, self.trusted).await;
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
                self.worker,
                Self::policy_bytes(policy),
                resource,
                object_id,
                relation,
                subject_did,
            )
            .await
            .unwrap();
        confirmed(self.client, outcome.transaction_hash, self.trusted).await;
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
                self.worker,
                Self::policy_bytes(policy),
                resource,
                object_id,
                relation,
                subject_did,
            )
            .await
            .unwrap();
        confirmed(self.client, outcome.transaction_hash, self.trusted).await;
    }

    async fn register_ring(&self, spec: RingSpec) -> RingId {
        let mut members = spec.node_keys;
        members.sort();
        let config = RingConfig {
            policy_id: spec.policy_id.0,
            peer_node_keys: members,
            threshold: spec.threshold,
            pss_interval: 86400,
            current_version: 0,
            requires_pet: spec.requires_pet,
            // `spec.nonce` is Cosmos-shaped (a string); native's ring-id
            // derivation nonce is a fixed-size byte array and isn't threaded
            // through yet — matches `NativeWorkflow`'s own hardcoded `[2; 32]`.
            nonce: [2; 32],
            trusted_auth_relay_dids: None,
            reporting: ReportingConfig::default(),
        };
        let ring_id = config.id(self.root.0, self.actor).unwrap();
        let now = Self::now();
        let token = create_scoped_bearer_token(
            self.controller,
            self.worker.did(),
            self.deployment,
            now,
            now + 300,
            DelegationScope::ManageRings,
        )
        .unwrap();
        submit(
            self.client,
            self.worker,
            self.trusted,
            encode_ring_command(&RingCommand::Create(config), &token).unwrap(),
            "create ring",
            self.cluster,
        )
        .await;
        RingId(ring_id)
    }

    async fn read_ring(&self, ring: &RingId) -> Option<RingView> {
        let record = match self
            .client
            .read_threshold_ring(&ring.0, 1, self.trusted)
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
            // Native's reconciliation model has no pending-confirmation list
            // the way Cosmos's `Ring.confirmations` does; always 0.
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

    async fn update_membership(
        &self,
        _ring: &RingId,
        _new_members: Vec<String>,
        _new_threshold: u32,
    ) {
        unimplemented!(
            "NativeAdmin::update_membership: not yet extracted from native_pet.rs's inline \
             reshare flow (Phase C)"
        )
    }

    async fn store_document(
        &self,
        _ring: &RingId,
        _payload: &[u8],
        _reader_dids: &[String],
    ) -> DocumentId {
        unimplemented!("NativeAdmin::store_document: see native_pet/document.rs (Phase C)")
    }

    async fn read_document(&self, _id: &DocumentId) -> Vec<u8> {
        unimplemented!("NativeAdmin::read_document: see store_document (Phase C)")
    }
}
