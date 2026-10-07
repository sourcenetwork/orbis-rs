//! Cosmos/SourceHub chain administration.
//!
//! The free functions below are a direct, behavior-preserving move out of
//! `bin/orbis-node/src/helpers/test_helpers.rs` (same bodies, same
//! signatures) — `test_helpers.rs` now re-exports them so its ~30 existing
//! call sites across `bin/orbis-node/src/tests/*` keep compiling unchanged.
//! `CosmosAdmin` is the new addition: a [`super::BackendAdmin`] impl built on
//! top of these same functions, for the shared E2E scenario layer.
//!
//! `create_ring_on_chain`/`create_ring_on_chain_with_trusted_relays` did
//! **not** move here — they call `cli_tool::create_ring`, and `cli-tool`
//! hardcodes a default crypto feature (`bls12-381`) that would conflict with
//! a jubjub build's feature unification if pulled into this crate. They stay
//! in `test_helpers.rs`, unchanged; `CosmosAdmin::register_ring` is
//! `unimplemented!()` pending a real decision on that dependency (see the
//! Phase A report).

use super::{BackendAdmin, DocumentId, PolicyId, RingId, RingKeys, RingSpec, RingView};
use common::blockchain::{
    acp::{Actor, Object, Relationship, Subject, SubjectKind},
    ChainConfig, TxSigner, VeraClient, TEST_ACCOUNT_HEX_KEY,
};
use std::time::Duration;

pub const ORBIS_RING_POLICY_YAML: &str = r#"
name: orbis ring policy
resources:
- name: ring_policy
  permissions:
  - name: create_ring
    expr: ring_creator
  relations:
  - name: ring_creator
    types:
    - actor
- name: ring
  permissions:
  - name: update_ring
    expr: operator
  relations:
  - name: operator
    types:
    - actor
"#;

/// Compute the did:key DID for a secp256k1 compressed public key (hex-encoded).
/// Format: `did:key:z{base58btc([0xe7, 0x01] + pubkey_bytes)}`
/// Matches Vera `x/acp/did/types.go` `DIDFromPubKey` for secp256k1 keys.
fn secp256k1_pubkey_to_did(compressed_pubkey_hex: &str) -> String {
    let pubkey_bytes = hex::decode(compressed_pubkey_hex).expect("invalid compressed pubkey hex");
    let mut prefixed = vec![0xe7u8, 0x01u8]; // varint(231) = secp256k1-pub multicodec
    prefixed.extend_from_slice(&pubkey_bytes);
    format!("did:key:z{}", bs58::encode(&prefixed).into_string())
}

/// Create an orbis ring governance policy as TEST_ACCOUNT_HEX_KEY, register its
/// own policy ID as a `ring_policy` ACP object, and return the policy ID.
pub async fn create_orbis_ring_policy(chain_config: &ChainConfig) -> String {
    let client = VeraClient::with_signer(
        chain_config.clone(),
        TxSigner::from_hex_key(TEST_ACCOUNT_HEX_KEY, chain_config.clone())
            .expect("test account signer"),
    )
    .await
    .expect("chain client for policy creation");

    let ids_before: std::collections::HashSet<String> = client
        .acp_list_policy_ids()
        .await
        .expect("list policy ids")
        .ids
        .into_iter()
        .collect();

    client
        .acp_create_policy(ORBIS_RING_POLICY_YAML, 1)
        .await
        .expect("create orbis ring policy");

    let policy_id = client
        .acp_list_policy_ids()
        .await
        .expect("list policy ids after create")
        .ids
        .into_iter()
        .find(|id| !ids_before.contains(id))
        .expect("new policy ID not found in list");

    client
        .acp_register_object(
            &policy_id,
            Object {
                resource: "ring_policy".to_string(),
                id: policy_id.clone(),
            },
        )
        .await
        .expect("register ring_policy object");

    policy_id
}

/// Create an orbis ring governance policy and register both the policy itself
/// and the given ring as ACP objects, all using the provided `client`.
///
/// Using an existing client avoids account-sequence conflicts when the caller
/// also uses that client for subsequent transactions.
pub async fn create_ring_governance_with_ring(
    client: &VeraClient,
    ring_id: &str,
    operator_pubkeys: &[&str],
) -> String {
    let ids_before: std::collections::HashSet<String> = client
        .acp_list_policy_ids()
        .await
        .expect("list policy ids")
        .ids
        .into_iter()
        .collect();

    client
        .acp_create_policy(ORBIS_RING_POLICY_YAML, 1)
        .await
        .expect("create orbis ring policy");

    // Poll until the new policy appears on-chain (confirms it is committed).
    let policy_id = client
        .acp_list_policy_ids()
        .await
        .expect("list policy ids after create")
        .ids
        .into_iter()
        .find(|id| !ids_before.contains(id))
        .expect("new policy ID not found");

    client
        .acp_register_object(
            &policy_id,
            Object {
                resource: "ring_policy".to_string(),
                id: policy_id.clone(),
            },
        )
        .await
        .expect("register ring_policy object");

    client
        .acp_register_object(
            &policy_id,
            Object {
                resource: "ring".to_string(),
                id: ring_id.to_string(),
            },
        )
        .await
        .expect("register ring object");

    // Grant each node's DID the `operator` relation so MsgFinalizeRing passes the
    // Vera ACP update_ring permission check (nodes sign with secp256k1 keys,
    // and Vera derives did:key from the on-chain pubkey for the permission lookup).
    for pubkey_hex in operator_pubkeys {
        let node_did = secp256k1_pubkey_to_did(pubkey_hex);
        client
            .acp_set_relationship(
                &policy_id,
                Relationship {
                    object: Some(Object {
                        resource: "ring".to_string(),
                        id: ring_id.to_string(),
                    }),
                    relation: "operator".to_string(),
                    subject: Some(Subject {
                        kind: Some(SubjectKind::Actor(Actor { id: node_did })),
                    }),
                },
            )
            .await
            .expect("grant node operator on ring");
    }

    policy_id
}

/// Poll the chain until the ring is finalized (ring_pk != "") or the timeout expires.
/// Panics on timeout.
pub async fn wait_for_ring_finalized(
    chain_config: &ChainConfig,
    ring_id: &str,
    timeout: Duration,
) -> String {
    let client = VeraClient::new(chain_config.clone())
        .await
        .expect("chain client for ring polling");

    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if let Ok(Some(ring)) = client.orbis_read_ring(ring_id).await {
            if !ring.ring_pk.is_empty() {
                return ring.ring_pk;
            }
        }
        if tokio::time::Instant::now() >= deadline {
            panic!("Timed out waiting for ring {} to be finalized", ring_id);
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

/// [`BackendAdmin`] over the Cosmos/SourceHub chain client.
pub struct CosmosAdmin {
    chain_config: ChainConfig,
}

impl CosmosAdmin {
    pub fn new(chain_config: ChainConfig) -> Self {
        Self { chain_config }
    }

    async fn signed_client(&self) -> VeraClient {
        VeraClient::with_signer(
            self.chain_config.clone(),
            TxSigner::from_hex_key(TEST_ACCOUNT_HEX_KEY, self.chain_config.clone())
                .expect("test account signer"),
        )
        .await
        .expect("signed chain client")
    }
}

#[async_trait::async_trait]
impl BackendAdmin for CosmosAdmin {
    async fn create_policy(&self, definition: &str) -> PolicyId {
        let client = self.signed_client().await;
        let ids_before: std::collections::HashSet<String> = client
            .acp_list_policy_ids()
            .await
            .expect("list policy ids")
            .ids
            .into_iter()
            .collect();
        client
            .acp_create_policy(definition, 1)
            .await
            .expect("create policy");
        let policy_id = client
            .acp_list_policy_ids()
            .await
            .expect("list policy ids after create")
            .ids
            .into_iter()
            .find(|id| !ids_before.contains(id))
            .expect("new policy ID not found in list");
        PolicyId(policy_id)
    }

    async fn grant(
        &self,
        policy: &PolicyId,
        resource: &str,
        object_id: &str,
        relation: &str,
        subject_did: &str,
    ) {
        let client = self.signed_client().await;
        client
            .acp_set_relationship(
                &policy.0,
                Relationship {
                    object: Some(Object {
                        resource: resource.to_string(),
                        id: object_id.to_string(),
                    }),
                    relation: relation.to_string(),
                    subject: Some(Subject {
                        kind: Some(SubjectKind::Actor(Actor {
                            id: subject_did.to_string(),
                        })),
                    }),
                },
            )
            .await
            .expect("grant relationship");
    }

    async fn revoke(
        &self,
        policy: &PolicyId,
        resource: &str,
        object_id: &str,
        relation: &str,
        subject_did: &str,
    ) {
        let client = self.signed_client().await;
        client
            .acp_delete_relationship(
                &policy.0,
                Relationship {
                    object: Some(Object {
                        resource: resource.to_string(),
                        id: object_id.to_string(),
                    }),
                    relation: relation.to_string(),
                    subject: Some(Subject {
                        kind: Some(SubjectKind::Actor(Actor {
                            id: subject_did.to_string(),
                        })),
                    }),
                },
            )
            .await
            .expect("revoke relationship");
    }

    async fn register_ring(&self, _spec: RingSpec) -> RingId {
        // `create_ring_on_chain_with_trusted_relays` (test_helpers.rs) does
        // this via `cli_tool::create_ring`, intentionally not moved here —
        // see this module's doc comment.
        unimplemented!(
            "CosmosAdmin::register_ring: ring creation stays in \
             bin/orbis-node/src/helpers/test_helpers.rs::create_ring_on_chain_with_trusted_relays \
             pending a cli-tool dependency decision (Phase A report)"
        )
    }

    async fn read_ring(&self, ring: &RingId) -> Option<RingView> {
        let client = VeraClient::new(self.chain_config.clone())
            .await
            .expect("chain client for ring read");
        let ring = client.orbis_read_ring(&ring.0).await.expect("read ring")?;
        Some(RingView {
            ring_pk: ring.ring_pk,
            peer_node_keys: ring.peer_node_keys,
            threshold: ring.threshold,
            requires_pet: ring.requires_pet,
            pet_pk: ring.pet_pk,
            confirmations: ring.confirmations.len(),
        })
    }

    async fn wait_for_finalized(&self, ring: &RingId, timeout: Duration) -> RingKeys {
        RingKeys(wait_for_ring_finalized(&self.chain_config, &ring.0, timeout).await)
    }

    async fn update_membership(
        &self,
        _ring: &RingId,
        _new_members: Vec<String>,
        _new_threshold: u32,
    ) {
        unimplemented!(
            "CosmosAdmin::update_membership: not yet extracted from the monolithic \
             test_pet_ring_refresh_and_reshare body (Phase C)"
        )
    }

    async fn store_document(
        &self,
        _ring: &RingId,
        _payload: &[u8],
        _reader_dids: &[String],
    ) -> DocumentId {
        unimplemented!(
            "CosmosAdmin::store_document: not yet extracted from integration.rs's \
             do_pre_expect_success/store_prepared_secret_expect_success (Phase C)"
        )
    }

    async fn read_document(&self, _id: &DocumentId) -> Vec<u8> {
        unimplemented!("CosmosAdmin::read_document: see store_document (Phase C)")
    }
}
