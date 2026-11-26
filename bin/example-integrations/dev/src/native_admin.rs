//! Native (Vera) chain admin operations this tool needs: create a policy,
//! register+authorize a ring, trigger DKG, and grant/revoke ACP
//! relationships.
//!
//! Ported from (not imported from — that code is `#[cfg(test)]`-private to
//! `orbis-node`) `bin/orbis-node/src/tests/e2e/vera_environment.rs`'s native
//! `BackendAdmin` implementation, trimmed to what an interactive dev tool
//! needs: no light-client header-sync rigor (`confirmed` here just waits for
//! a transaction receipt, the same primitive
//! `bin/orbis-node/src/tests/e2e/vera_confirmation.rs` uses), no
//! fixture/scenario machinery, one ring shape, one caller.
//!
//! The admin keys below are fixed, not derived from any genesis secret —
//! `vera_environment.rs` already proves this exact derivation works against
//! a devnet created the same way (`VeraNetworkAdapter::start`), so any
//! caller can reproduce it.

use alloy_primitives::B256;
use anyhow::{anyhow, Context, Result};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use vera_client::{
    create_scoped_bearer_token,
    nodes::{encode_node_request, sign_node_request, NodeCommand, NodeRequest, NodeTarget},
    rings::{
        encode_ring_command, ring_deployment_label, ReportingConfig, RingCommand, RingConfig,
        RingState,
    },
    threshold_objects::{encode_threshold_object, KeyDerivation, ThresholdObject},
    BlsSigner, DelegationScope, VeraClient,
};
use vera_domain::ConsensusPublicKey;
use vera_harness::cluster::KeySet;

/// Matches `VeraNetworkAdapter::start`'s deployment id — fixed so the admin
/// keys below (seeded from it) are reproducible.
pub const DEPLOYMENT: u64 = 9000;

pub struct AdminKeys {
    pub controller: k256::ecdsa::SigningKey,
    pub actor: String,
    pub worker: BlsSigner,
    pub trusted: ConsensusPublicKey,
    /// This deployment's genesis block hash, needed to sign a `NodeRequest`
    /// — fetched once, right after the cluster comes up.
    pub root: B256,
}

/// Derives the fixed admin identities a freshly-started `VeraNetworkAdapter`
/// devnet already recognizes — see this module's doc comment — and fetches
/// the deployment root `NodeRequest` signing needs.
pub async fn derive_admin_keys(client: &VeraClient) -> Result<AdminKeys> {
    let controller = k256::ecdsa::SigningKey::from_slice(&[34; 32])
        .map_err(|e| anyhow!("derive controller key: {e}"))?;
    let actor = vera_crypto::secp256k1::did_from_secp256k1_pubkey(
        controller.verifying_key().to_sec1_bytes().as_ref(),
    )
    .map_err(|e| anyhow!("derive actor did: {e}"))?;
    let worker =
        BlsSigner::new(7u64.into(), DEPLOYMENT).map_err(|e| anyhow!("derive worker key: {e}"))?;
    // `BlsSigner::new` always starts its local nonce at 0 — fine for a
    // brand-new devnet's first-ever transaction, but `grant`/`revoke`
    // target an already-running cluster where this same worker identity
    // has already submitted transactions during `up`. Sync from the
    // chain's own count, per `set_next_sequence`'s own doc comment.
    let current_nonce = client
        .get_native_nonce(worker.did())
        .await
        .map_err(|e| anyhow!("read worker nonce: {e}"))?;
    worker.set_next_sequence(current_nonce);
    let trusted = *KeySet::builder()
        .seed(DEPLOYMENT)
        .build()
        .map_err(|e| anyhow!("derive consensus trust: {e}"))?
        .epoch_info()
        .output
        .public()
        .public();
    let first = client
        .read_finalized_revision(1, &trusted)
        .await
        .map_err(|e| anyhow!("read first finalized revision: {e}"))?;
    let root: B256 = first
        .parent_hash
        .parse()
        .map_err(|e| anyhow!("parse deployment root: {e}"))?;
    Ok(AdminKeys {
        controller,
        actor,
        worker,
        trusted,
        root,
    })
}

/// The chain id a client's PRE reader-key proof-of-possession transcript
/// must bind to — *not* the bare `DEPLOYMENT` number. A client that passes
/// the wrong value here still passes every other check (ACP included) but
/// fails with a signature-verification error specifically, since the
/// transcript's `chain_id` field just won't match what the server
/// independently reconstructs. Sign has no equivalent concern — nothing in
/// its own request binds `chain_id` at all.
pub fn chain_id(keys: &AdminKeys) -> String {
    ring_deployment_label(keys.root.0, DEPLOYMENT)
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before epoch")
        .as_secs()
}

fn policy_bytes(policy_id: &str) -> Result<B256> {
    let bytes = hex::decode(policy_id).context("policy id is hex-encoded")?;
    Ok(B256::from_slice(&bytes))
}

/// Waits (up to 30s) for a submitted native transaction's receipt, the same
/// primitive `vera_confirmation::confirmed` uses — no light-client proof,
/// just the chain's own receipt lookup.
async fn confirmed(
    client: &VeraClient,
    id: B256,
    trusted: &ConsensusPublicKey,
    phase: &str,
) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let Some(proof) = client
                .read_receipt(id, trusted)
                .await
                .map_err(|e| anyhow!("{phase}: read receipt: {e}"))?
            {
                let receipt = proof
                    .verify(id, trusted)
                    .map_err(|e| anyhow!("{phase}: verify receipt: {e}"))?;
                if !receipt.success() {
                    return Err(anyhow!(
                        "{phase}: native transaction {id} failed on-chain: refusal={:?}",
                        receipt.refusal
                    ));
                }
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .map_err(|_| anyhow!("{phase}: native transaction {id} receipt timed out after 30s"))?
}

/// Signs `worker`'s native BLS transaction and submits+confirms it.
async fn submit(
    client: &VeraClient,
    worker: &BlsSigner,
    trusted: &ConsensusPublicKey,
    call: alloy_primitives::Bytes,
    phase: &str,
) -> Result<()> {
    let wire = worker
        .sign_native_tx(vera_client::VERA_ADDRESS, call)
        .map_err(|e| anyhow!("{phase}: sign native tx: {e}"))?;
    let id = client
        .send_native_tx(&wire)
        .await
        .map_err(|e| anyhow!("{phase}: send native tx: {e}"))?;
    eprintln!("submission phase={phase:?} id={id}");
    confirmed(client, id, trusted, phase).await
}

/// Creates a new ACP policy from `definition` and returns its id, predicted
/// from the definition, the worker and the nonce.
pub async fn create_policy(
    client: &VeraClient,
    worker: &BlsSigner,
    trusted: &ConsensusPublicKey,
    definition: &str,
) -> Result<String> {
    let nonce = vera_client::random_policy_nonce();
    let id = vera_client::predict_policy_id(
        definition,
        &vera_client::PolicyMarshalingType::ShortYaml,
        &nonce,
        worker.did(),
    )
    .map_err(|e| anyhow!("predict policy id: {e}"))?;
    let created = client
        .native_create_policy(worker, definition.as_bytes(), 1, nonce)
        .await
        .map_err(|e| anyhow!("create policy: {e}"))?;
    confirmed(client, created.transaction_hash, trusted, "create policy").await?;
    if !client
        .get_policy_ids()
        .await
        .map_err(|e| anyhow!("list policy ids: {e}"))?
        .contains(&id)
    {
        return Err(anyhow!("created policy did not appear in catalogue"));
    }
    Ok(id)
}

/// One running node's identity, as reported by its own `InfoService` —
/// exactly `test_support::NodeInfo`, named locally to keep this module's
/// signatures self-describing.
pub use test_support::NodeInfo;

/// Registers `policy_id` as a `ring_policy` ACP object, grants `creator` to
/// the admin actor, authorizes every node in `nodes` for that policy, then
/// creates the ring. Returns the new ring's id.
#[allow(clippy::too_many_arguments)]
pub async fn register_and_create_ring(
    client: &VeraClient,
    keys: &AdminKeys,
    policy_id: &str,
    nodes: &[NodeInfo],
    threshold: u32,
) -> Result<String> {
    let policy = policy_bytes(policy_id)?;
    let registered = client
        .native_register_object(&keys.worker, policy, policy_id, "ring_policy")
        .await
        .map_err(|e| anyhow!("register ring_policy object: {e}"))?;
    confirmed(
        client,
        registered.transaction_hash,
        &keys.trusted,
        "register ring_policy object",
    )
    .await?;
    let granted = client
        .native_set_relationship(
            &keys.worker,
            policy,
            "ring_policy",
            policy_id,
            "creator",
            &keys.actor,
        )
        .await
        .map_err(|e| anyhow!("grant creator on ring_policy: {e}"))?;
    confirmed(
        client,
        granted.transaction_hash,
        &keys.trusted,
        "grant creator on ring_policy",
    )
    .await?;

    let now = unix_now();
    for node in nodes {
        for (label, command) in [
            ("set peer", NodeCommand::SetPeer(node.p2p_address.clone())),
            (
                "authorize for policy",
                NodeCommand::Allow(NodeTarget::Policy(policy_id.to_string())),
            ),
        ] {
            let phase = format!("{label} (node {})", node.node_key);
            let current = client
                .read_threshold_node(&node.node_key, 1, &keys.trusted)
                .await
                .map_err(|e| anyhow!("{phase}: read node record: {e}"))?
                .record
                .ok_or_else(|| anyhow!("{phase}: node has no record yet"))?;
            let signed = sign_node_request(
                NodeRequest {
                    deployment_root: keys.root.0,
                    deployment_id: DEPLOYMENT,
                    node_key: node.node_key.clone(),
                    sequence: current.sequence,
                    expires_at: now + 300,
                    command,
                },
                &keys.controller,
            )
            .map_err(|e| anyhow!("{phase}: sign node request: {e}"))?;
            submit(
                client,
                &keys.worker,
                &keys.trusted,
                encode_node_request(&signed)
                    .map_err(|e| anyhow!("{phase}: encode node request: {e}"))?,
                &phase,
            )
            .await?;
        }
    }

    let mut peer_node_keys: Vec<String> = nodes.iter().map(|node| node.node_key.clone()).collect();
    peer_node_keys.sort();
    let config = RingConfig {
        policy_id: policy_id.to_string(),
        peer_node_keys,
        threshold,
        pss_interval: 86_400,
        current_version: 0,
        requires_pet: false,
        nonce: [2; 32],
        trusted_auth_relay_dids: None,
        reporting: ReportingConfig::default(),
        pre_share_endpoints: Vec::new(),
    };
    let ring_id = config.id().map_err(|e| anyhow!("predict ring id: {e}"))?;
    let token = create_scoped_bearer_token(
        &keys.controller,
        keys.worker.did(),
        DEPLOYMENT,
        now,
        now + 300,
        DelegationScope::ManageRings,
    )
    .map_err(|e| anyhow!("create ring-management token: {e}"))?;
    submit(
        client,
        &keys.worker,
        &keys.trusted,
        encode_ring_command(&RingCommand::Create(config), &token)
            .map_err(|e| anyhow!("encode create-ring command: {e}"))?,
        "create ring",
    )
    .await?;

    Ok(ring_id)
}

/// Registers `object_id` under `resource` in `policy_id` — needed before
/// `grant_relationship` can set any relation on it:
/// `native_set_relationship` refuses a relation on an object that was never
/// registered, same as `register_and_create_ring`'s own `ring_policy`
/// object needed registering before granting `creator` on it worked.
pub async fn register_object(
    client: &VeraClient,
    keys: &AdminKeys,
    policy_id: &str,
    resource: &str,
    object_id: &str,
) -> Result<()> {
    let policy = policy_bytes(policy_id)?;
    let registered = client
        .native_register_object(&keys.worker, policy, object_id, resource)
        .await
        .map_err(|e| anyhow!("register object: {e}"))?;
    confirmed(
        client,
        registered.transaction_hash,
        &keys.trusted,
        "register object",
    )
    .await
}

/// Creates a named Sign key derivation on `ring_id` and returns its own
/// object id — the object Sign's permission checks actually key on, *not*
/// the ring id itself (ring-level ACP only governs `update_ring`, via the
/// `ring_policy`/`ring` resources `register_and_create_ring` already
/// handles). Must be `register_object`'d (under the `key` resource) before
/// `grant_relationship` can set a `signer` relation on it.
pub async fn register_key_derivation(
    client: &VeraClient,
    keys: &AdminKeys,
    ring_id: &str,
    derivation: &str,
    policy_id: &str,
    resource: &str,
    permission: &str,
) -> Result<String> {
    let object = ThresholdObject::KeyDerivation(KeyDerivation {
        ring_id: ring_id.to_string(),
        derivation: derivation.to_string(),
        policy_id: policy_id.to_string(),
        resource: resource.to_string(),
        permission: permission.to_string(),
    });
    let derivation_id = object
        .id()
        .map_err(|e| anyhow!("derive key-derivation id: {e}"))?;
    let now = unix_now();
    let token = create_scoped_bearer_token(
        &keys.controller,
        keys.worker.did(),
        DEPLOYMENT,
        now,
        now + 300,
        DelegationScope::StoreThresholdObject,
    )
    .map_err(|e| anyhow!("create key-derivation delegation token: {e}"))?;
    submit(
        client,
        &keys.worker,
        &keys.trusted,
        encode_threshold_object(&object, &token)
            .map_err(|e| anyhow!("encode key derivation: {e}"))?,
        "store key derivation",
    )
    .await?;
    Ok(derivation_id)
}

/// Grants (or revokes) `relation` on `resource`/`object_id` under
/// `policy_id` to/from `subject_did`.
pub async fn grant_relationship(
    client: &VeraClient,
    keys: &AdminKeys,
    policy_id: &str,
    resource: &str,
    object_id: &str,
    relation: &str,
    subject_did: &str,
) -> Result<()> {
    let policy = policy_bytes(policy_id)?;
    let outcome = client
        .native_set_relationship(
            &keys.worker,
            policy,
            resource,
            object_id,
            relation,
            subject_did,
        )
        .await
        .map_err(|e| anyhow!("set relationship: {e}"))?;
    confirmed(
        client,
        outcome.transaction_hash,
        &keys.trusted,
        "grant relationship",
    )
    .await
}

/// The grant/revoke asymmetry is real on native, not an oversight: setting a
/// relationship and deleting one are two different precompile calls
/// (`native_set_relationship`/`native_delete_relationship`), unlike a
/// "set the same relation to false" pattern.
pub async fn revoke_relationship(
    client: &VeraClient,
    keys: &AdminKeys,
    policy_id: &str,
    resource: &str,
    object_id: &str,
    relation: &str,
    subject_did: &str,
) -> Result<()> {
    let policy = policy_bytes(policy_id)?;
    let outcome = client
        .native_delete_relationship(
            &keys.worker,
            policy,
            resource,
            object_id,
            relation,
            subject_did,
        )
        .await
        .map_err(|e| anyhow!("delete relationship: {e}"))?;
    confirmed(
        client,
        outcome.transaction_hash,
        &keys.trusted,
        "revoke relationship",
    )
    .await
}

/// Polls until `ring_id`'s key is finalized (its `RingState` becomes
/// `Active`), returning the hex-encoded ring public key.
pub async fn wait_for_ring_pk(
    client: &VeraClient,
    ring_id: &str,
    trusted: &ConsensusPublicKey,
    timeout: Duration,
) -> Result<String> {
    tokio::time::timeout(timeout, async {
        loop {
            let read = client.read_threshold_ring(ring_id, 1, trusted).await;
            if let Ok(response) = read {
                if let Some(record) = response.record {
                    if let RingState::Active { keys } = &record.state {
                        return keys.public_key.clone();
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await
    .map_err(|_| anyhow!("ring {ring_id} did not finalize before the timeout"))
}
