//! Cross-revision upgrade scenario shared by the revision-local upgrade driver.
//!
//! The baseline driver writes [`UpgradeFixtureManifestV1`]. The target driver
//! reads that same stable document using its own generated protobuf clients and
//! crypto implementation. Keeping this code in `orbis-bench` lets the upgrade
//! gate reuse the production-topology setup and protocol correctness helpers
//! without coupling the public shell orchestrator to a particular RPC shape.

use crate::compose::{RingDefinition, CONTROLLER_PUBLIC_KEY, RING_GOVERNANCE_POLICY_ID};
use crate::config::CryptoFeature;
use crate::protocol::{
    discover_node_identity, wait_nodes_ready, DirectClients, NodeEndpoint, NodeIdentity,
    PreFixture, SignFixture,
};
use crate::setup::{
    create_ring_governance_policy, create_rings_on_chain, fund_nodes, register_ring_governance,
    update_peer_addresses,
};
use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use common::blockchain::{ChainConfig, SourceHubClient, TxSigner, TEST_ACCOUNT_HEX_KEY};
use crypto::helpers::generate_keypair;
use crypto::{CryptoDeserialize, CryptoSerialize, ScalarField};
use proto::info_service::{
    info_service_client::InfoServiceClient, GetRingStateRequest, GetRingStateResponse,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::time::{sleep, timeout};
use tonic::Code;

pub const UPGRADE_MANIFEST_VERSION: u32 = 1;
pub const NODE_COUNT: usize = 4;
pub const THRESHOLD: usize = 2;
pub const INITIAL_MEMBERS: [usize; 3] = [1, 2, 3];
pub const RESHARED_MEMBERS: [usize; 3] = [1, 2, 4];
const PSS_INTERVAL_SECS: u64 = 86_400;
const SETUP_TIMEOUT: Duration = Duration::from_secs(300);
const DKG_TIMEOUT: Duration = Duration::from_secs(180);
const RESHARE_TIMEOUT: Duration = Duration::from_secs(300);
const SETUP_BATCH_SIZE: usize = 16;
const RING_PROTOCOL_VERSION: u64 = 0;
const RESOURCE: &str = "document";
const PERMISSION: &str = "read";

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct UpgradeFixtureManifestV1 {
    pub format_version: u32,
    pub baseline_sha: String,
    pub crypto: String,
    pub sourcehub_ref: String,
    pub ring: RingFixtureV1,
    pub nodes: Vec<NodeFixtureV1>,
    pub legacy_pre: PreFixtureV1,
    pub legacy_sign: SignFixtureV1,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct RingFixtureV1 {
    pub ring_id: String,
    pub ring_pk: String,
    pub threshold: usize,
    pub initial_members: Vec<usize>,
    pub policy_id: String,
    pub resource: String,
    pub permission: String,
    pub node_states: Vec<RingStateFixtureV1>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct NodeFixtureV1 {
    pub index: usize,
    pub node_key: String,
    pub peer_id: String,
    pub public_address: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct RingStateFixtureV1 {
    pub node_index: usize,
    pub public_polynomial: String,
    pub last_pss: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct PreFixtureV1 {
    pub object_id: String,
    pub ring_pk: String,
    pub reader_pk_hex: String,
    pub reader_sk_hex: String,
    pub reader_identity: String,
    pub derivation_hex: Option<String>,
    pub salt: Option<String>,
    pub expected_plaintext_hex: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct SignFixtureV1 {
    pub derivation_id: String,
    pub derived_public_key: String,
    pub reader_identity: String,
    pub message_hex: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UpgradeVerificationResultV1 {
    pub format_version: u32,
    pub target_sha: String,
    pub crypto: String,
    pub identity_continuity_verified: bool,
    pub storage_continuity_verified: bool,
    pub reshare_verified: bool,
    pub departed_share_deleted: bool,
    pub target_pre_reshare: OnlineFixturesV1,
    pub target_post_reshare: OnlineFixturesV1,
    pub final_states: Vec<RingStateFixtureV1>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OnlineFixturesV1 {
    pub pre: PreFixtureV1,
    pub sign: SignFixtureV1,
}

pub fn internal_node_endpoints() -> Vec<NodeEndpoint> {
    (1..=NODE_COUNT)
        .map(|index| NodeEndpoint {
            index,
            service: format!("node-{index:03}"),
            grpc_url: format!("http://node-{index:03}:50051"),
            metrics_url: format!("http://node-{index:03}:9090/metrics"),
        })
        .collect()
}

pub fn internal_chain_config() -> ChainConfig {
    ChainConfig::builder()
        .rpc_url(Some("http://sourcehub:26657".to_string()))
        .rest_url(Some("http://sourcehub:1317".to_string()))
        .grpc_url(Some("http://sourcehub:9090".to_string()))
        .build()
}

pub fn stable_node_arguments(index: usize) -> Result<Vec<String>> {
    if !(1..=NODE_COUNT).contains(&index) {
        bail!("upgrade node index must be in 1..={NODE_COUNT}, got {index}");
    }
    Ok(vec![
        "orbis-node".to_string(),
        "--addr".to_string(),
        "0.0.0.0:50051".to_string(),
        "--log-level".to_string(),
        "info".to_string(),
        "--authz-grpc".to_string(),
        "http://sourcehub:9090".to_string(),
        "--bulletin-grpc".to_string(),
        "http://sourcehub:9090".to_string(),
        "--chain-rpc".to_string(),
        "http://sourcehub:26657".to_string(),
        "--chain-rest".to_string(),
        "http://sourcehub:1317".to_string(),
        "--chain-gas-multiplier".to_string(),
        "3".to_string(),
        "--metrics-addr".to_string(),
        "0.0.0.0:9090".to_string(),
        "--runtime-base-path".to_string(),
        "/data".to_string(),
        "--reshare-interval-secs".to_string(),
        "1".to_string(),
        "--node-controller-key".to_string(),
        CONTROLLER_PUBLIC_KEY.to_string(),
        "--node-whitelisted-policy-id".to_string(),
        RING_GOVERNANCE_POLICY_ID.to_string(),
    ])
}

pub async fn run_upgrade_node(index: usize) -> Result<()> {
    let args = orbis_node::Args::try_parse_from(stable_node_arguments(index)?)
        .context("translate stable upgrade-node contract into current node arguments")?;
    orbis_node::run(args)
        .await
        .map_err(|error| anyhow!(error.to_string()))
}

pub async fn prepare_upgrade_fixture(
    manifest_path: &Path,
    baseline_sha: String,
    crypto: String,
    sourcehub_ref: String,
) -> Result<UpgradeFixtureManifestV1> {
    validate_compiled_crypto(&crypto)?;
    let endpoints = internal_node_endpoints();
    let chain_config = internal_chain_config();
    let controller = controller_client(chain_config.clone()).await?;

    let bootstrap_identities = discover_identities(&endpoints, SETUP_TIMEOUT).await?;
    fund_nodes(&controller, &bootstrap_identities, SETUP_BATCH_SIZE)
        .await
        .context("fund baseline nodes")?;
    let identities = wait_nodes_ready(&endpoints, SETUP_TIMEOUT)
        .await
        .context("wait for funded baseline nodes")?;
    assert_identity_continuity(&bootstrap_identities, &identities)?;
    update_changed_peer_addresses(&controller, &identities, SETUP_BATCH_SIZE)
        .await
        .context("publish baseline peer routes")?;

    let policy_id = create_ring_governance_policy(&controller).await?;
    let mut operator_node_keys: Vec<String> = identities
        .iter()
        .map(|identity| identity.node_key.clone())
        .collect();
    operator_node_keys.push(CONTROLLER_PUBLIC_KEY.to_string());
    let mut ring = RingDefinition {
        id: String::new(),
        peer_node_keys: INITIAL_MEMBERS
            .iter()
            .map(|member| identities[*member - 1].node_key.clone())
            .collect(),
        operator_node_keys,
        threshold: THRESHOLD,
        pss_interval_secs: PSS_INTERVAL_SECS,
        policy_id: policy_id.clone(),
    };
    create_rings_on_chain(
        &controller,
        std::iter::once(&mut ring),
        RING_PROTOCOL_VERSION,
    )
    .await?;
    register_ring_governance(&controller, &[ring.clone()], SETUP_BATCH_SIZE).await?;

    let mut clients = DirectClients::connect(&endpoints).await?;
    clients.start_dkg(0, &ring.id).await?;
    let ring_pk = clients
        .wait_ring_finalized_everywhere(&controller, &ring.id, &INITIAL_MEMBERS, DKG_TIMEOUT)
        .await?;
    let initial_states = clients.ring_states(&INITIAL_MEMBERS, &ring_pk).await?;
    let state_fixtures = state_fixtures(&INITIAL_MEMBERS, &initial_states)?;

    let legacy =
        prepare_online_fixtures(&endpoints[0], &ring.id, &ring_pk, chain_config, "legacy").await?;
    run_fixture_set(&endpoints, &INITIAL_MEMBERS, &legacy).await?;

    let manifest = UpgradeFixtureManifestV1 {
        format_version: UPGRADE_MANIFEST_VERSION,
        baseline_sha,
        crypto,
        sourcehub_ref,
        ring: RingFixtureV1 {
            ring_id: ring.id,
            ring_pk,
            threshold: THRESHOLD,
            initial_members: INITIAL_MEMBERS.to_vec(),
            policy_id,
            resource: RESOURCE.to_string(),
            permission: PERMISSION.to_string(),
            node_states: state_fixtures,
        },
        nodes: identities.iter().map(NodeFixtureV1::from).collect(),
        legacy_pre: legacy.pre,
        legacy_sign: legacy.sign,
    };
    write_json(manifest_path, &manifest)?;
    Ok(manifest)
}

pub async fn verify_upgrade_fixture(
    manifest_path: &Path,
    result_path: &Path,
    target_sha: String,
) -> Result<UpgradeVerificationResultV1> {
    let manifest: UpgradeFixtureManifestV1 = read_json(manifest_path)?;
    validate_manifest(&manifest)?;
    validate_compiled_crypto(&manifest.crypto)?;

    let endpoints = internal_node_endpoints();
    let chain_config = internal_chain_config();
    let controller = controller_client(chain_config.clone()).await?;
    let identities = wait_nodes_ready(&endpoints, SETUP_TIMEOUT)
        .await
        .context("target nodes did not reopen their persisted databases")?;
    assert_manifest_identities(&manifest.nodes, &identities)?;

    // The Iroh peer identity is persisted, while its bound UDP port belongs to
    // the recreated container. Publish the new routes before exercising MPC.
    update_changed_peer_addresses(&controller, &identities, SETUP_BATCH_SIZE)
        .await
        .context("publish target peer routes")?;

    let clients = DirectClients::connect(&endpoints).await?;
    let reopened_states = clients
        .ring_states(&manifest.ring.initial_members, &manifest.ring.ring_pk)
        .await
        .context("read reopened ring state")?;
    assert_reopened_states(&manifest.ring.node_states, &reopened_states)?;

    let legacy = OnlineFixturesV1 {
        pre: manifest.legacy_pre.clone(),
        sign: manifest.legacy_sign.clone(),
    };
    run_fixture_set(&endpoints, &manifest.ring.initial_members, &legacy).await?;

    let target_pre_reshare = prepare_online_fixtures(
        &endpoints[0],
        &manifest.ring.ring_id,
        &manifest.ring.ring_pk,
        chain_config.clone(),
        "target-before-reshare",
    )
    .await?;
    run_fixture_set(
        &endpoints,
        &manifest.ring.initial_members,
        &target_pre_reshare,
    )
    .await?;

    wait_until_timestamp_can_advance(&manifest.ring.node_states).await;
    let next_node_keys: Vec<String> = RESHARED_MEMBERS
        .iter()
        .map(|member| identities[*member - 1].node_key.clone())
        .collect();
    // Fixture setup uses independently constructed controller clients and
    // advances the same account sequence. Refresh it before the reshare tx.
    let controller = controller_client(chain_config.clone()).await?;
    let reshare = controller
        .orbis_start_ring_reshare_by_acp(
            &manifest.ring.ring_id,
            next_node_keys.clone(),
            Some(THRESHOLD as u32),
        )
        .await
        .context("announce target reshare")?;
    if reshare.code != 0 {
        bail!("announce target reshare failed: {}", reshare.log);
    }

    let final_states = wait_for_reshare(
        &controller,
        &endpoints,
        &manifest,
        &next_node_keys,
        RESHARE_TIMEOUT,
    )
    .await?;
    let departed_members = INITIAL_MEMBERS
        .iter()
        .copied()
        .filter(|member| !RESHARED_MEMBERS.contains(member))
        .collect::<Vec<_>>();
    let [departed_member] = departed_members.as_slice() else {
        bail!("reshare committee must remove exactly one initial member");
    };
    wait_for_departed_share_deletion(
        &endpoints[*departed_member - 1],
        &manifest.ring.ring_pk,
        RESHARE_TIMEOUT,
    )
    .await?;

    run_fixture_set(&endpoints, &RESHARED_MEMBERS, &legacy).await?;
    run_fixture_set(&endpoints, &RESHARED_MEMBERS, &target_pre_reshare).await?;

    let added_member = RESHARED_MEMBERS
        .iter()
        .copied()
        .find(|member| !INITIAL_MEMBERS.contains(member))
        .context("reshare committee must add one new member")?;
    let target_post_reshare = prepare_online_fixtures(
        &endpoints[added_member - 1],
        &manifest.ring.ring_id,
        &manifest.ring.ring_pk,
        chain_config,
        "target-after-reshare",
    )
    .await?;
    run_fixture_set(&endpoints, &RESHARED_MEMBERS, &target_post_reshare).await?;

    let result = UpgradeVerificationResultV1 {
        format_version: UPGRADE_MANIFEST_VERSION,
        target_sha,
        crypto: manifest.crypto,
        identity_continuity_verified: true,
        storage_continuity_verified: true,
        reshare_verified: true,
        departed_share_deleted: true,
        target_pre_reshare,
        target_post_reshare,
        final_states,
    };
    write_json(result_path, &result)?;
    Ok(result)
}

async fn prepare_online_fixtures(
    endpoint: &NodeEndpoint,
    ring_id: &str,
    ring_pk: &str,
    chain_config: ChainConfig,
    label: &str,
) -> Result<OnlineFixturesV1> {
    let policy_id = cli_tool::add_policy_to_chain_with_config(chain_config.clone()).await?;
    let reader_identity = format!("orbis-upgrade-{label}-reader");
    let (reader_sk, reader_pk) = generate_keypair()?;
    let plaintext = format!("orbis upgrade plaintext: {label}").into_bytes();
    let prepared = cli_tool::prepare_secret(
        &plaintext,
        ring_pk,
        None,
        policy_id.clone(),
        RESOURCE.to_string(),
        PERMISSION.to_string(),
        None,
        None,
        None,
    )?;
    let stored = cli_tool::store_prepared_secret(
        endpoint.grpc_url.clone(),
        &prepared,
        ring_id.to_string(),
        policy_id.clone(),
        RESOURCE.to_string(),
        PERMISSION.to_string(),
        Some(reader_identity.clone()),
        true,
        None,
        None,
    )
    .await?;
    cli_tool::register_object_to_chain_with_config(
        policy_id.clone(),
        stored.object_id.clone(),
        RESOURCE.to_string(),
        chain_config.clone(),
    )
    .await?;
    cli_tool::set_relationship_on_chain_with_config(
        policy_id.clone(),
        stored.object_id.clone(),
        RESOURCE.to_string(),
        "reader".to_string(),
        Some(reader_identity.clone()),
        chain_config.clone(),
    )
    .await?;

    let sign_identity = format!("orbis-upgrade-{label}-signer");
    let (derivation_id, derived_public_key) = cli_tool::post_key_derivation_with_config(
        ring_id.to_string(),
        format!("orbis-upgrade-{label}-derivation"),
        policy_id.clone(),
        RESOURCE.to_string(),
        PERMISSION.to_string(),
        chain_config.clone(),
    )
    .await?;
    cli_tool::register_object_to_chain_with_config(
        policy_id.clone(),
        derivation_id.clone(),
        RESOURCE.to_string(),
        chain_config.clone(),
    )
    .await?;
    cli_tool::set_relationship_on_chain_with_config(
        policy_id,
        derivation_id.clone(),
        RESOURCE.to_string(),
        "reader".to_string(),
        Some(sign_identity.clone()),
        chain_config,
    )
    .await?;

    Ok(OnlineFixturesV1 {
        pre: PreFixtureV1 {
            object_id: stored.object_id,
            ring_pk: ring_pk.to_string(),
            reader_pk_hex: hex::encode(CryptoSerialize::to_bytes(&reader_pk)?),
            reader_sk_hex: hex::encode(CryptoSerialize::to_bytes(&reader_sk)?),
            reader_identity,
            derivation_hex: None,
            salt: None,
            expected_plaintext_hex: hex::encode(plaintext),
        },
        sign: SignFixtureV1 {
            derivation_id,
            derived_public_key,
            reader_identity: sign_identity,
            message_hex: hex::encode(format!("orbis upgrade sign message: {label}")),
        },
    })
}

async fn run_fixture_set(
    endpoints: &[NodeEndpoint],
    members: &[usize],
    fixtures: &OnlineFixturesV1,
) -> Result<()> {
    let pre = fixtures.pre.to_runtime()?;
    let sign = fixtures.sign.to_runtime();
    let message = fixtures.sign.message()?;
    let mut clients = DirectClients::connect(endpoints).await?;
    for member in members {
        let initiator = member
            .checked_sub(1)
            .context("committee indices are one-based")?;
        clients
            .pre(initiator, &pre)
            .await
            .with_context(|| format!("PRE fixture failed from node {member}"))?;
        clients
            .sign(initiator, &sign, message.clone())
            .await
            .with_context(|| format!("SIGN fixture failed from node {member}"))?;
    }
    Ok(())
}

async fn discover_identities(
    endpoints: &[NodeEndpoint],
    deadline: Duration,
) -> Result<Vec<NodeIdentity>> {
    let futures = endpoints
        .iter()
        .cloned()
        .map(|endpoint| discover_node_identity(endpoint, deadline));
    futures::future::join_all(futures)
        .await
        .into_iter()
        .collect()
}

async fn controller_client(config: ChainConfig) -> Result<SourceHubClient> {
    let signer = TxSigner::from_hex_key(TEST_ACCOUNT_HEX_KEY, config.clone())?;
    Ok(SourceHubClient::with_signer(config, signer).await?)
}

async fn update_changed_peer_addresses(
    controller: &SourceHubClient,
    identities: &[NodeIdentity],
    maximum_batch_size: usize,
) -> Result<()> {
    let mut changed = Vec::new();
    for identity in identities {
        let expected = identity.docker_p2p_address()?;
        let existing = controller
            .orbis_read_node_info(&identity.node_key)
            .await
            .with_context(|| format!("read NodeInfo for node {}", identity.endpoint.index))?;
        if existing.as_ref().map(|info| info.peer_id.as_str()) != Some(expected.as_str()) {
            changed.push(identity.clone());
        }
    }
    if !changed.is_empty() {
        update_peer_addresses(controller, &changed, maximum_batch_size).await?;
    }
    Ok(())
}

async fn wait_for_reshare(
    controller: &SourceHubClient,
    endpoints: &[NodeEndpoint],
    manifest: &UpgradeFixtureManifestV1,
    expected_node_keys: &[String],
    deadline: Duration,
) -> Result<Vec<RingStateFixtureV1>> {
    let clients = DirectClients::connect(endpoints).await?;
    let baseline: BTreeMap<usize, &RingStateFixtureV1> = manifest
        .ring
        .node_states
        .iter()
        .map(|state| (state.node_index, state))
        .collect();
    let mut expected_keys = expected_node_keys.to_vec();
    expected_keys.sort();

    timeout(deadline, async {
        loop {
            let ring = match controller.orbis_read_ring(&manifest.ring.ring_id).await {
                Ok(Some(ring)) => ring,
                Ok(None) | Err(_) => {
                    sleep(Duration::from_millis(500)).await;
                    continue;
                }
            };
            if !reshare_chain_complete(
                &ring.ring_pk,
                &ring.peer_node_keys,
                ring.threshold,
                &ring.new_peer_node_keys,
                ring.new_threshold,
                &manifest.ring.ring_pk,
                &expected_keys,
                THRESHOLD as u32,
            ) {
                sleep(Duration::from_millis(500)).await;
                continue;
            }

            if let Ok(states) = clients
                .ring_states(&RESHARED_MEMBERS, &manifest.ring.ring_pk)
                .await
            {
                if reshare_local_states_converged(&RESHARED_MEMBERS, &states, &baseline) {
                    return state_fixtures(&RESHARED_MEMBERS, &states);
                }
            }
            sleep(Duration::from_millis(500)).await;
        }
    })
    .await
    .context("reshare did not converge before timeout")?
}

fn reshare_local_states_converged(
    members: &[usize],
    states: &[GetRingStateResponse],
    baseline: &BTreeMap<usize, &RingStateFixtureV1>,
) -> bool {
    if members.len() != states.len() {
        return false;
    }
    let Some(polynomial) = states
        .first()
        .map(|state| state.public_polynomial.as_str())
        .filter(|value| !value.is_empty())
    else {
        return false;
    };
    let baseline_last_pss = baseline
        .values()
        .map(|state| state.last_pss)
        .max()
        .unwrap_or(0);

    members.iter().zip(states).all(|(member, state)| {
        state.public_polynomial == polynomial
            && state.last_pss > baseline_last_pss
            && baseline
                .get(member)
                .is_none_or(|old| state.public_polynomial != old.public_polynomial)
    })
}

#[allow(clippy::too_many_arguments)]
fn reshare_chain_complete(
    ring_pk: &str,
    peer_node_keys: &[String],
    threshold: u32,
    new_peer_node_keys: &[String],
    new_threshold: Option<u32>,
    expected_ring_pk: &str,
    expected_node_keys: &[String],
    expected_threshold: u32,
) -> bool {
    let mut actual = peer_node_keys.to_vec();
    actual.sort();
    ring_pk == expected_ring_pk
        && actual == expected_node_keys
        && threshold == expected_threshold
        && new_peer_node_keys.is_empty()
        && new_threshold.is_none()
}

async fn wait_for_departed_share_deletion(
    endpoint: &NodeEndpoint,
    ring_pk: &str,
    deadline: Duration,
) -> Result<()> {
    timeout(deadline, async {
        loop {
            let Ok(mut client) = InfoServiceClient::connect(endpoint.grpc_url.clone()).await else {
                sleep(Duration::from_millis(500)).await;
                continue;
            };
            match client
                .get_ring_state(GetRingStateRequest {
                    ring_pk_hex: ring_pk.to_string(),
                })
                .await
            {
                Err(status) if is_departed_share_not_found(status.code()) => return Ok(()),
                _ => sleep(Duration::from_millis(500)).await,
            }
        }
    })
    .await
    .context("departed node retained ring material after reshare")?
}

fn is_departed_share_not_found(code: Code) -> bool {
    code == Code::NotFound
}

fn validate_manifest(manifest: &UpgradeFixtureManifestV1) -> Result<()> {
    if manifest.format_version != UPGRADE_MANIFEST_VERSION {
        bail!(
            "unsupported upgrade fixture version {}; this driver supports {}",
            manifest.format_version,
            UPGRADE_MANIFEST_VERSION
        );
    }
    if manifest.nodes.len() != NODE_COUNT {
        bail!("upgrade fixture must contain exactly {NODE_COUNT} nodes");
    }
    if manifest.ring.initial_members != INITIAL_MEMBERS {
        bail!("upgrade fixture initial committee does not match v1 contract");
    }
    if manifest.ring.threshold != THRESHOLD {
        bail!("upgrade fixture threshold does not match v1 contract");
    }
    Ok(())
}

fn validate_compiled_crypto(expected: &str) -> Result<()> {
    let compiled = CryptoFeature::compiled().feature_name();
    if expected != compiled {
        bail!("driver was compiled for {compiled}, fixture requested {expected}");
    }
    Ok(())
}

fn assert_identity_continuity(before: &[NodeIdentity], after: &[NodeIdentity]) -> Result<()> {
    if before.len() != after.len() {
        bail!("node count changed while baseline nodes were being funded");
    }
    for (before, after) in before.iter().zip(after) {
        if before.node_key != after.node_key
            || before.peer_id != after.peer_id
            || before.public_address != after.public_address
        {
            bail!(
                "node {} identity changed during baseline setup",
                before.endpoint.index
            );
        }
    }
    Ok(())
}

fn assert_manifest_identities(expected: &[NodeFixtureV1], actual: &[NodeIdentity]) -> Result<()> {
    if expected.len() != actual.len() {
        bail!("target node count differs from baseline manifest");
    }
    for (expected, actual) in expected.iter().zip(actual) {
        if expected.index != actual.endpoint.index
            || expected.node_key != actual.node_key
            || expected.peer_id != actual.peer_id
            || expected.public_address != actual.public_address
        {
            bail!(
                "node {} identity did not reopen from its baseline database",
                expected.index
            );
        }
    }
    Ok(())
}

fn assert_reopened_states(
    expected: &[RingStateFixtureV1],
    actual: &[GetRingStateResponse],
) -> Result<()> {
    if expected.len() != actual.len() {
        bail!("target ring-state count differs from baseline manifest");
    }
    for (expected, actual) in expected.iter().zip(actual) {
        if expected.public_polynomial != actual.public_polynomial
            || expected.last_pss != actual.last_pss
        {
            bail!(
                "node {} ring state changed while nodes were stopped",
                expected.node_index
            );
        }
    }
    Ok(())
}

fn state_fixtures(
    members: &[usize],
    states: &[GetRingStateResponse],
) -> Result<Vec<RingStateFixtureV1>> {
    if members.len() != states.len() {
        bail!("ring-state response count did not match committee size");
    }
    Ok(members
        .iter()
        .zip(states)
        .map(|(node_index, state)| RingStateFixtureV1 {
            node_index: *node_index,
            public_polynomial: state.public_polynomial.clone(),
            last_pss: state.last_pss,
        })
        .collect())
}

async fn wait_until_timestamp_can_advance(states: &[RingStateFixtureV1]) {
    let baseline = states.iter().map(|state| state.last_pss).max().unwrap_or(0);
    let now = unix_now();
    if baseline >= now {
        sleep(Duration::from_secs(baseline - now + 1)).await;
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create artifact directory {}", parent.display()))?;
    }
    let bytes = serde_json::to_vec_pretty(value)?;
    std::fs::write(path, bytes).with_context(|| format!("write {}", path.display()))
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    let bytes = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("parse {}", path.display()))
}

impl NodeFixtureV1 {
    fn from(identity: &NodeIdentity) -> Self {
        Self {
            index: identity.endpoint.index,
            node_key: identity.node_key.clone(),
            peer_id: identity.peer_id.clone(),
            public_address: identity.public_address.clone(),
        }
    }
}

impl PreFixtureV1 {
    fn to_runtime(&self) -> Result<PreFixture> {
        Ok(PreFixture {
            ring_pk: self.ring_pk.clone(),
            reader_pk: hex::decode(&self.reader_pk_hex)?,
            reader_sk: <ScalarField as CryptoDeserialize>::from_bytes(&hex::decode(
                &self.reader_sk_hex,
            )?)?,
            object_id: self.object_id.clone(),
            reader_identity: self.reader_identity.clone(),
            derivation: self.derivation_hex.as_ref().map(hex::decode).transpose()?,
            salt: self.salt.clone(),
            expected_plaintext: hex::decode(&self.expected_plaintext_hex)?,
        })
    }
}

impl SignFixtureV1 {
    fn to_runtime(&self) -> SignFixture {
        SignFixture {
            derivation_id: self.derivation_id.clone(),
            derived_public_key: self.derived_public_key.clone(),
            reader_identity: self.reader_identity.clone(),
        }
    }

    fn message(&self) -> Result<Vec<u8>> {
        Ok(hex::decode(&self.message_hex)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_manifest() -> UpgradeFixtureManifestV1 {
        UpgradeFixtureManifestV1 {
            format_version: UPGRADE_MANIFEST_VERSION,
            baseline_sha: "abc123".to_string(),
            crypto: CryptoFeature::compiled().feature_name().to_string(),
            sourcehub_ref: "sourcehub-ref".to_string(),
            ring: RingFixtureV1 {
                ring_id: "ring".to_string(),
                ring_pk: "ring-pk".to_string(),
                threshold: THRESHOLD,
                initial_members: INITIAL_MEMBERS.to_vec(),
                policy_id: "policy".to_string(),
                resource: RESOURCE.to_string(),
                permission: PERMISSION.to_string(),
                node_states: INITIAL_MEMBERS
                    .iter()
                    .map(|index| RingStateFixtureV1 {
                        node_index: *index,
                        public_polynomial: "polynomial".to_string(),
                        last_pss: 1,
                    })
                    .collect(),
            },
            nodes: (1..=NODE_COUNT)
                .map(|index| NodeFixtureV1 {
                    index,
                    node_key: format!("node-key-{index}"),
                    peer_id: format!("peer-{index}"),
                    public_address: format!("address-{index}"),
                })
                .collect(),
            legacy_pre: PreFixtureV1 {
                object_id: "object".to_string(),
                ring_pk: "ring-pk".to_string(),
                reader_pk_hex: "00".to_string(),
                reader_sk_hex: "00".to_string(),
                reader_identity: "reader".to_string(),
                derivation_hex: None,
                salt: None,
                expected_plaintext_hex: "00".to_string(),
            },
            legacy_sign: SignFixtureV1 {
                derivation_id: "derivation".to_string(),
                derived_public_key: "derived-pk".to_string(),
                reader_identity: "signer".to_string(),
                message_hex: "00".to_string(),
            },
        }
    }

    #[test]
    fn manifest_v1_round_trips_and_ignores_additive_fields() {
        let expected = sample_manifest();
        let mut value = serde_json::to_value(&expected).unwrap();
        value["future_optional_field"] = serde_json::json!({"enabled": true});
        let decoded: UpgradeFixtureManifestV1 = serde_json::from_value(value).unwrap();
        assert_eq!(decoded, expected);
        validate_manifest(&decoded).unwrap();
    }

    #[test]
    fn stable_node_contract_persists_only_database_directory() {
        let arguments = stable_node_arguments(1).unwrap();
        assert!(arguments
            .windows(2)
            .any(|pair| pair == ["--runtime-base-path", "/data"]));
        assert!(!arguments
            .iter()
            .any(|argument| argument.contains("secret-key")));

        let compose = include_str!("../../../docker/docker-compose-upgrade-test.yml");
        assert_eq!(compose.matches(":/data/dbs").count(), NODE_COUNT);
        assert!(!compose.contains(":/data\n"));
        assert!(!compose.contains("ORBIS_SECRET_KEY"));
        assert!(!compose.contains("ORBIS_SIGNING_KEY"));
    }

    #[test]
    fn detects_reopened_state_changes() {
        let expected = vec![RingStateFixtureV1 {
            node_index: 1,
            public_polynomial: "before".to_string(),
            last_pss: 7,
        }];
        let actual = vec![GetRingStateResponse {
            public_polynomial: "after".to_string(),
            last_pss: 7,
        }];
        assert!(assert_reopened_states(&expected, &actual).is_err());
    }

    #[test]
    fn reshare_completion_requires_stable_key_and_cleared_announcement() {
        let expected = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        assert!(reshare_chain_complete(
            "pk",
            &["c".to_string(), "a".to_string(), "b".to_string()],
            2,
            &[],
            None,
            "pk",
            &expected,
            2,
        ));
        assert!(!reshare_chain_complete(
            "pk",
            &expected,
            2,
            &["pending".to_string()],
            Some(2),
            "pk",
            &expected,
            2,
        ));
    }

    #[test]
    fn reshare_local_convergence_requires_every_members_timestamp_to_advance() {
        let baseline_states = [
            RingStateFixtureV1 {
                node_index: 1,
                public_polynomial: "old-1".to_string(),
                last_pss: 10,
            },
            RingStateFixtureV1 {
                node_index: 2,
                public_polynomial: "old-2".to_string(),
                last_pss: 10,
            },
            RingStateFixtureV1 {
                node_index: 3,
                public_polynomial: "old-3".to_string(),
                last_pss: 10,
            },
        ];
        let baseline = baseline_states
            .iter()
            .map(|state| (state.node_index, state))
            .collect();
        let mut states = RESHARED_MEMBERS
            .iter()
            .map(|_| GetRingStateResponse {
                public_polynomial: "new".to_string(),
                last_pss: 11,
            })
            .collect::<Vec<_>>();

        assert!(reshare_local_states_converged(
            &RESHARED_MEMBERS,
            &states,
            &baseline
        ));
        states[2].last_pss = 10;
        assert!(!reshare_local_states_converged(
            &RESHARED_MEMBERS,
            &states,
            &baseline
        ));
    }

    #[test]
    fn departed_share_requires_not_found() {
        assert!(is_departed_share_not_found(Code::NotFound));
        assert!(!is_departed_share_not_found(Code::Internal));
    }
}
