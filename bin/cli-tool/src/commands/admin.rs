//! Chain administration: ACP policies/objects/relationships, ring lifecycle
//! (create/reshare/PSS interval/upgrade), node registration (peer ID/controller/
//! whitelist), account queries, and funding.

use anyhow::{anyhow, Result};
use common::blockchain::{
    acp::{Actor, Object, Relationship, Subject, SubjectKind},
    orbis::WhitelistTarget,
    ChainConfig, TEST_ACCOUNT_HEX_KEY,
};

use super::chain::{ensure_tx_success, signed_vera_client, vera_client};
use super::crypto::reader_did_from_seed;

const TEST_POLICY_YAML: &str = r#"
name: test-policy
resources:
  - name: document
    relations:
      - name: creator
        types:
          - actor
      - name: reader
        types:
          - actor
    permissions:
      - name: read
        expr: creator + reader
      - name: write
        expr: creator
"#;

async fn add_policy_to_chain_impl(config: ChainConfig, signing_key_hex: &str) -> Result<String> {
    let client = signed_vera_client(config, signing_key_hex).await?;

    let ids_before: std::collections::HashSet<String> = client
        .acp_list_policy_ids()
        .await
        .map_err(|e| anyhow!("Failed to list policy IDs: {}", e))?
        .ids
        .into_iter()
        .collect();

    let create_result = client
        .acp_create_policy(TEST_POLICY_YAML, 1)
        .await
        .map_err(|e| anyhow!("Failed to create policy: {}", e))?;
    println!(
        "[ACP] create_policy: code={} hash={} log={}",
        create_result.code, create_result.tx_hash, create_result.log
    );
    ensure_tx_success("Failed to create policy", &create_result)?;

    let policy_id = client
        .acp_list_policy_ids()
        .await
        .map_err(|e| anyhow!("Failed to list policy IDs: {}", e))?
        .ids
        .into_iter()
        .find(|id| !ids_before.contains(id))
        .ok_or_else(|| anyhow!("Newly created policy ID not found in list"))?;
    println!("[ACP] policy_id from list: {}", policy_id);
    Ok(policy_id)
}

pub async fn add_policy_to_chain(config: ChainConfig, signing_key_hex: &str) -> Result<String> {
    add_policy_to_chain_impl(config, signing_key_hex).await
}

// Only called via the `cli-tool` lib target (orbis-node integration tests); unused from the bin target.
#[allow(dead_code)]
pub async fn add_policy_to_chain_with_config(config: ChainConfig) -> Result<String> {
    add_policy_to_chain_impl(config, TEST_ACCOUNT_HEX_KEY).await
}

async fn register_object_to_chain_impl(
    policy_id: String,
    object_id: String,
    resource: String,
    config: ChainConfig,
    signing_key_hex: &str,
) -> Result<()> {
    let client = signed_vera_client(config, signing_key_hex).await?;

    let document = Object {
        resource,
        id: object_id,
    };
    let result = client
        .acp_register_object(&policy_id, document)
        .await
        .map_err(|e| anyhow!("Failed to register object: {}", e))?;

    println!(
        "[ACP] register_object: code={} hash={} log={}",
        result.code, result.tx_hash, result.log
    );

    ensure_tx_success("Failed to register object", &result)?;

    Ok(())
}

pub async fn register_object_to_chain(
    policy_id: String,
    object_id: String,
    resource: String,
    config: ChainConfig,
    signing_key_hex: &str,
) -> Result<()> {
    register_object_to_chain_impl(policy_id, object_id, resource, config, signing_key_hex).await
}

// Only called via the `cli-tool` lib target (orbis-node integration tests); unused from the bin target.
#[allow(dead_code)]
pub async fn register_object_to_chain_with_config(
    policy_id: String,
    object_id: String,
    resource: String,
    config: ChainConfig,
) -> Result<()> {
    register_object_to_chain_impl(policy_id, object_id, resource, config, TEST_ACCOUNT_HEX_KEY)
        .await
}

async fn set_relationship_on_chain_impl(
    policy_id: String,
    object_id: String,
    resource: String,
    relation: String,
    did_uri: String,
    config: ChainConfig,
    signing_key_hex: &str,
) -> Result<()> {
    let client = signed_vera_client(config, signing_key_hex).await?;

    let document = Object {
        resource,
        id: object_id,
    };

    let reader_relationship = Relationship {
        object: Some(document),
        relation,
        subject: Some(Subject {
            kind: Some(SubjectKind::Actor(Actor {
                id: did_uri.clone(),
            })),
        }),
    };

    let result = client
        .acp_set_relationship(&policy_id, reader_relationship)
        .await
        .map_err(|e| anyhow!("Failed to set reader relationship: {}", e))?;

    println!(
        "[ACP] set_relationship({}): code={} hash={} log={}",
        did_uri, result.code, result.tx_hash, result.log
    );

    ensure_tx_success("Failed to set relationship", &result)?;

    Ok(())
}

pub async fn set_relationship_on_chain(
    policy_id: String,
    object_id: String,
    resource: String,
    relation: String,
    did_uri: String,
    config: ChainConfig,
    signing_key_hex: &str,
) -> Result<()> {
    set_relationship_on_chain_impl(
        policy_id,
        object_id,
        resource,
        relation,
        did_uri,
        config,
        signing_key_hex,
    )
    .await
}

// Only called via the `cli-tool` lib target (orbis-node integration tests); unused from the bin target.
#[allow(dead_code)]
pub async fn set_relationship_on_chain_with_config(
    policy_id: String,
    object_id: String,
    resource: String,
    relation: String,
    reader_did_pk: Option<String>,
    config: ChainConfig,
) -> Result<()> {
    let did_uri = reader_did_from_seed(&reader_did_pk.unwrap_or("test_jwt".to_string()));
    set_relationship_on_chain_impl(
        policy_id,
        object_id,
        resource,
        relation,
        did_uri,
        config,
        TEST_ACCOUNT_HEX_KEY,
    )
    .await
}

/// Create a blank ring on-chain, to be targeted by a subsequent `dkg` session.
///
/// Returns the chain-assigned `ring_id`.
#[allow(clippy::too_many_arguments)]
pub async fn create_ring(
    peer_node_keys: Vec<String>,
    threshold: u32,
    pss_interval: u64,
    policy_id: String,
    nonce: Option<String>,
    current_version: u64,
    trusted_auth_relay_dids: Vec<String>,
    config: ChainConfig,
    signing_key_hex: &str,
) -> Result<String> {
    let client = signed_vera_client(config, signing_key_hex).await?;

    let trusted_auth_relay_dids =
        (!trusted_auth_relay_dids.is_empty()).then_some(trusted_auth_relay_dids);

    let (result, ring_id) = client
        .orbis_create_ring_get_id(
            peer_node_keys,
            threshold,
            pss_interval,
            &policy_id,
            nonce,
            current_version,
            None,
            trusted_auth_relay_dids,
        )
        .await
        .map_err(|e| anyhow!("Failed to create ring: {}", e))?;

    println!(
        "[Orbis] create_ring: hash={} ring_id={}",
        result.tx_hash, ring_id
    );
    Ok(ring_id)
}

async fn start_ring_reshare_by_acp_impl(
    ring_id: String,
    new_peer_node_keys: Vec<String>,
    new_threshold: Option<u32>,
    config: ChainConfig,
    signing_key_hex: &str,
) -> Result<()> {
    let client = signed_vera_client(config, signing_key_hex).await?;
    let result = client
        .orbis_start_ring_reshare_by_acp(&ring_id, new_peer_node_keys, new_threshold)
        .await
        .map_err(|e| anyhow!("Failed to start ring reshare: {}", e))?;
    ensure_tx_success("Failed to start ring reshare", &result)?;
    println!("Started reshare for ring: {}", ring_id);
    Ok(())
}

async fn cancel_ring_reshare_by_acp_impl(
    ring_id: String,
    config: ChainConfig,
    signing_key_hex: &str,
) -> Result<()> {
    let client = signed_vera_client(config, signing_key_hex).await?;
    let result = client
        .orbis_cancel_ring_reshare_by_acp(&ring_id)
        .await
        .map_err(|e| anyhow!("Failed to cancel ring reshare: {}", e))?;
    ensure_tx_success("Failed to cancel ring reshare", &result)?;
    println!("Cancelled reshare for ring: {}", ring_id);
    Ok(())
}

pub async fn cancel_ring_reshare_by_acp(
    ring_id: String,
    config: ChainConfig,
    signing_key_hex: &str,
) -> Result<()> {
    cancel_ring_reshare_by_acp_impl(ring_id, config, signing_key_hex).await
}

// Only called via the `cli-tool` lib target (orbis-node integration tests); unused from the bin target.
#[allow(dead_code)]
pub async fn cancel_ring_reshare_by_acp_with_config(
    ring_id: String,
    config: ChainConfig,
) -> Result<()> {
    cancel_ring_reshare_by_acp_impl(ring_id, config, TEST_ACCOUNT_HEX_KEY).await
}

pub async fn start_ring_reshare_by_acp(
    ring_id: String,
    new_peer_node_keys: Vec<String>,
    new_threshold: Option<u32>,
    config: ChainConfig,
    signing_key_hex: &str,
) -> Result<()> {
    start_ring_reshare_by_acp_impl(
        ring_id,
        new_peer_node_keys,
        new_threshold,
        config,
        signing_key_hex,
    )
    .await
}

// Only called via the `cli-tool` lib target (orbis-node integration tests); unused from the bin target.
#[allow(dead_code)]
pub async fn start_ring_reshare_by_acp_with_config(
    ring_id: String,
    new_peer_node_keys: Vec<String>,
    new_threshold: Option<u32>,
    config: ChainConfig,
) -> Result<()> {
    start_ring_reshare_by_acp_impl(
        ring_id,
        new_peer_node_keys,
        new_threshold,
        config,
        TEST_ACCOUNT_HEX_KEY,
    )
    .await
}

async fn set_ring_pss_interval_by_acp_impl(
    ring_id: String,
    pss_interval: u64,
    config: ChainConfig,
    signing_key_hex: &str,
) -> Result<()> {
    let client = signed_vera_client(config, signing_key_hex).await?;
    let result = client
        .orbis_set_ring_pss_interval_by_acp(&ring_id, pss_interval)
        .await
        .map_err(|e| anyhow!("Failed to set PSS interval: {}", e))?;
    ensure_tx_success("Failed to set PSS interval", &result)?;
    println!("Set PSS interval for ring: {}", ring_id);
    Ok(())
}

pub async fn set_ring_pss_interval_by_acp(
    ring_id: String,
    pss_interval: u64,
    config: ChainConfig,
    signing_key_hex: &str,
) -> Result<()> {
    set_ring_pss_interval_by_acp_impl(ring_id, pss_interval, config, signing_key_hex).await
}

// Only called via the `cli-tool` lib target (orbis-node integration tests); unused from the bin target.
#[allow(dead_code)]
pub async fn set_ring_pss_interval_by_acp_with_config(
    ring_id: String,
    pss_interval: u64,
    config: ChainConfig,
) -> Result<()> {
    set_ring_pss_interval_by_acp_impl(ring_id, pss_interval, config, TEST_ACCOUNT_HEX_KEY).await
}

async fn schedule_ring_upgrade_by_acp_impl(
    ring_id: String,
    next_version: u64,
    activation_time: u64,
    config: ChainConfig,
    signing_key_hex: &str,
) -> Result<()> {
    let client = signed_vera_client(config, signing_key_hex).await?;
    let result = client
        .orbis_schedule_ring_upgrade_by_acp(&ring_id, next_version, activation_time)
        .await
        .map_err(|e| anyhow!("Failed to schedule ring upgrade: {}", e))?;
    ensure_tx_success("Failed to schedule ring upgrade", &result)?;
    println!("Scheduled upgrade for ring: {}", ring_id);
    Ok(())
}

pub async fn schedule_ring_upgrade_by_acp(
    ring_id: String,
    next_version: u64,
    activation_time: u64,
    config: ChainConfig,
    signing_key_hex: &str,
) -> Result<()> {
    schedule_ring_upgrade_by_acp_impl(
        ring_id,
        next_version,
        activation_time,
        config,
        signing_key_hex,
    )
    .await
}

// Only called via the `cli-tool` lib target (orbis-node integration tests); unused from the bin target.
#[allow(dead_code)]
pub async fn schedule_ring_upgrade_by_acp_with_config(
    ring_id: String,
    next_version: u64,
    activation_time: u64,
    config: ChainConfig,
) -> Result<()> {
    schedule_ring_upgrade_by_acp_impl(
        ring_id,
        next_version,
        activation_time,
        config,
        TEST_ACCOUNT_HEX_KEY,
    )
    .await
}

async fn cancel_ring_upgrade_by_acp_impl(
    ring_id: String,
    config: ChainConfig,
    signing_key_hex: &str,
) -> Result<()> {
    let client = signed_vera_client(config, signing_key_hex).await?;
    let result = client
        .orbis_cancel_ring_upgrade_by_acp(&ring_id)
        .await
        .map_err(|e| anyhow!("Failed to cancel ring upgrade: {}", e))?;
    ensure_tx_success("Failed to cancel ring upgrade", &result)?;
    println!("Cancelled upgrade for ring: {}", ring_id);
    Ok(())
}

pub async fn cancel_ring_upgrade_by_acp(
    ring_id: String,
    config: ChainConfig,
    signing_key_hex: &str,
) -> Result<()> {
    cancel_ring_upgrade_by_acp_impl(ring_id, config, signing_key_hex).await
}

// Only called via the `cli-tool` lib target (orbis-node integration tests); unused from the bin target.
#[allow(dead_code)]
pub async fn cancel_ring_upgrade_by_acp_with_config(
    ring_id: String,
    config: ChainConfig,
) -> Result<()> {
    cancel_ring_upgrade_by_acp_impl(ring_id, config, TEST_ACCOUNT_HEX_KEY).await
}

async fn update_node_peer_id_impl(
    node_key: String,
    peer_id: String,
    config: ChainConfig,
    signing_key_hex: &str,
) -> Result<()> {
    let client = signed_vera_client(config, signing_key_hex).await?;
    let result = client
        .orbis_update_node_peer_id(&node_key, &peer_id)
        .await
        .map_err(|e| anyhow!("Failed to update node peer ID: {}", e))?;
    ensure_tx_success("Failed to update node peer ID", &result)?;
    println!("Updated peer ID for node: {}", node_key);
    Ok(())
}

pub async fn update_node_peer_id(
    node_key: String,
    peer_id: String,
    config: ChainConfig,
    signing_key_hex: &str,
) -> Result<()> {
    update_node_peer_id_impl(node_key, peer_id, config, signing_key_hex).await
}

// Only called via the `cli-tool` lib target (orbis-node integration tests); unused from the bin target.
#[allow(dead_code)]
pub async fn update_node_peer_id_with_config(
    node_key: String,
    peer_id: String,
    config: ChainConfig,
) -> Result<()> {
    update_node_peer_id_impl(node_key, peer_id, config, TEST_ACCOUNT_HEX_KEY).await
}

async fn transfer_node_controller_impl(
    node_key: String,
    controller_key: String,
    config: ChainConfig,
    signing_key_hex: &str,
) -> Result<()> {
    let client = signed_vera_client(config, signing_key_hex).await?;
    let result = client
        .orbis_transfer_node_controller(&node_key, &controller_key)
        .await
        .map_err(|e| anyhow!("Failed to transfer node controller: {}", e))?;
    ensure_tx_success("Failed to transfer node controller", &result)?;
    println!("Transferred controller for node: {}", node_key);
    Ok(())
}

pub async fn transfer_node_controller(
    node_key: String,
    controller_key: String,
    config: ChainConfig,
    signing_key_hex: &str,
) -> Result<()> {
    transfer_node_controller_impl(node_key, controller_key, config, signing_key_hex).await
}

// Only called via the `cli-tool` lib target (orbis-node integration tests); unused from the bin target.
#[allow(dead_code)]
pub async fn transfer_node_controller_with_config(
    node_key: String,
    controller_key: String,
    config: ChainConfig,
) -> Result<()> {
    transfer_node_controller_impl(node_key, controller_key, config, TEST_ACCOUNT_HEX_KEY).await
}

async fn add_node_to_whitelist_impl(
    node_key: String,
    target: WhitelistTarget,
    config: ChainConfig,
    signing_key_hex: &str,
) -> Result<()> {
    let client = signed_vera_client(config, signing_key_hex).await?;
    let result = client
        .orbis_add_node_to_whitelist(&node_key, target)
        .await
        .map_err(|e| anyhow!("Failed to add node to whitelist: {}", e))?;
    ensure_tx_success("Failed to add node to whitelist", &result)?;
    println!("Added node {} to whitelist", node_key);
    Ok(())
}

pub async fn add_node_to_whitelist(
    node_key: String,
    target: WhitelistTarget,
    config: ChainConfig,
    signing_key_hex: &str,
) -> Result<()> {
    add_node_to_whitelist_impl(node_key, target, config, signing_key_hex).await
}

// Only called via the `cli-tool` lib target (orbis-node integration tests); unused from the bin target.
#[allow(dead_code)]
pub async fn add_node_to_whitelist_with_config(
    node_key: String,
    target: WhitelistTarget,
    config: ChainConfig,
) -> Result<()> {
    add_node_to_whitelist_impl(node_key, target, config, TEST_ACCOUNT_HEX_KEY).await
}

async fn remove_node_from_whitelist_impl(
    node_key: String,
    target: WhitelistTarget,
    config: ChainConfig,
    signing_key_hex: &str,
) -> Result<()> {
    let client = signed_vera_client(config, signing_key_hex).await?;
    let result = client
        .orbis_remove_node_from_whitelist(&node_key, target)
        .await
        .map_err(|e| anyhow!("Failed to remove node from whitelist: {}", e))?;
    ensure_tx_success("Failed to remove node from whitelist", &result)?;
    println!("Removed node {} from whitelist", node_key);
    Ok(())
}

pub async fn remove_node_from_whitelist(
    node_key: String,
    target: WhitelistTarget,
    config: ChainConfig,
    signing_key_hex: &str,
) -> Result<()> {
    remove_node_from_whitelist_impl(node_key, target, config, signing_key_hex).await
}

// Only called via the `cli-tool` lib target (orbis-node integration tests); unused from the bin target.
#[allow(dead_code)]
pub async fn remove_node_from_whitelist_with_config(
    node_key: String,
    target: WhitelistTarget,
    config: ChainConfig,
) -> Result<()> {
    remove_node_from_whitelist_impl(node_key, target, config, TEST_ACCOUNT_HEX_KEY).await
}

/// Fetch a ring from the orbis module by ring_id.
/// Returns (ring_id, ring_pk_hex).
pub async fn get_latest_ring(ring_id: String, config: ChainConfig) -> Result<(String, String)> {
    let client = vera_client(config).await?;

    let ring = client
        .orbis_read_ring(&ring_id)
        .await
        .map_err(|e| anyhow!("Failed to read ring {}: {}", ring_id, e))?
        .ok_or_else(|| anyhow!("Ring {} not found", ring_id))?;

    Ok((ring_id, ring.ring_pk))
}

/// Get the current sequence number for an account address.
/// Useful for verifying if a transaction was broadcast (sequence increments after each tx).
pub async fn get_account_sequence(address: &str) -> Result<u64> {
    get_account_sequence_with_config(address, ChainConfig::local()).await
}

pub async fn get_account_sequence_with_config(address: &str, config: ChainConfig) -> Result<u64> {
    let client = vera_client(config).await?;

    let account_info = client
        .get_account(address)
        .await
        .map_err(|e| anyhow!("Failed to get account info: {}", e))?;

    Ok(account_info.sequence)
}

async fn fund_impl(address: String, config: ChainConfig, signing_key_hex: &str) -> Result<()> {
    println!("Funding address: {}", address);

    // Transfer a reasonable amount (e.g., 1000000 uopen = 1 OPEN)
    // This should be enough for multiple transactions
    let amount = 1_000_000u64;
    let denom = "uopen";

    println!("Transferring {} {} to {}", amount, denom, address);

    // Retry logic for timing issues (REST API might not be ready immediately)
    // and sequence mismatch issues (multiple nodes starting simultaneously)
    // This is dumb but fine for testing
    let max_retries = 15;
    let mut last_error = None;

    // Create the client (with signer) once
    let client = signed_vera_client(config, signing_key_hex).await?;

    for attempt in 1..=max_retries {
        match client.transfer(&address, amount, denom).await {
            Ok(result) => {
                println!(
                    "Transfer successful! Tx hash: {}, Height: {:?}",
                    result.tx_hash, result.height
                );
                return Ok(());
            }
            Err(e) => {
                let err_str = e.to_string();
                println!(
                    "Transfer attempt {}/{} failed: {}",
                    attempt, max_retries, err_str
                );
                last_error = Some(anyhow!("{}", e));
                if attempt < max_retries {
                    // Use pseudo-random delay (1-4 seconds) to desynchronize competing nodes
                    // Based on current time nanos to add jitter between nodes
                    let nanos = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_nanos() as u64)
                        .unwrap_or(0);
                    let delay_ms = 1000 + (nanos % 3000);
                    println!("Retrying in {}ms...", delay_ms);
                    tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;
                }
            }
        }
    }

    Err(anyhow!(
        "Failed to transfer funds after {} attempts: {}",
        max_retries,
        last_error.map(|e| e.to_string()).unwrap_or_default()
    ))
}

// Only called via the `cli-tool` lib target (orbis-node integration tests); unused from the bin target.
#[allow(dead_code)]
pub async fn fund(address: String, config: ChainConfig) -> Result<()> {
    fund_impl(address, config, TEST_ACCOUNT_HEX_KEY).await
}

pub async fn fund_with_signer(
    address: String,
    config: ChainConfig,
    signing_key_hex: &str,
) -> Result<()> {
    fund_impl(address, config, signing_key_hex).await
}
