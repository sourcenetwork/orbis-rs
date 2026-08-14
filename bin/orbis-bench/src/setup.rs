use crate::compose::{RingDefinition, RING_GOVERNANCE_POLICY_ID};
use crate::protocol::NodeIdentity;
use anyhow::{anyhow, bail, Context, Result};
use common::blockchain::{
    acp::{
        Actor, MsgDirectPolicyCmd, Object, PolicyCmd, PolicyCmdKind, RegisterObjectCmd,
        Relationship, SetRelationshipCmd, Subject, SubjectKind,
    },
    bank::{Coin, MsgSend},
    orbis::{DemeritConfig, MsgUpdateNodePeerId, ReportingConfig},
    SourceHubClient,
};
use cosmrs::Any;
use prost::Message;
use serde::{Deserialize, Serialize};
use std::collections::{HashSet, VecDeque};
use std::future::Future;

pub const RING_POLICY_YAML: &str = r#"
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

#[derive(Clone, Debug)]
pub struct SetupMessage {
    pub label: String,
    pub any: Any,
}

impl SetupMessage {
    pub fn new<T: Message>(label: impl Into<String>, type_url: &str, message: &T) -> Self {
        Self {
            label: label.into(),
            any: Any {
                type_url: type_url.to_string(),
                value: message.encode_to_vec(),
            },
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct BatchOutcome {
    pub transactions: usize,
    pub messages: usize,
    pub split_batches: usize,
    pub failed_attempts: Vec<BatchFailure>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BatchFailure {
    pub labels: Vec<String>,
    pub error: String,
}

pub async fn broadcast_bounded(
    client: &SourceHubClient,
    messages: Vec<SetupMessage>,
    maximum_batch_size: usize,
) -> Result<BatchOutcome> {
    broadcast_bounded_with(messages, maximum_batch_size, |messages| async move {
        match client
            .broadcast_proto_msgs_with_gas(messages, client.config().gas_multiplier)
            .await
        {
            Ok(result) if result.code == 0 => Ok(()),
            Ok(result) => Err(format!("chain code {}: {}", result.code, result.log)),
            Err(error) => Err(error.to_string()),
        }
    })
    .await
}

async fn broadcast_bounded_with<F, Fut>(
    messages: Vec<SetupMessage>,
    maximum_batch_size: usize,
    mut broadcast: F,
) -> Result<BatchOutcome>
where
    F: FnMut(Vec<Any>) -> Fut,
    Fut: Future<Output = std::result::Result<(), String>>,
{
    if maximum_batch_size == 0 {
        bail!("maximum batch size must be at least one");
    }
    let total_messages = messages.len();
    let mut queue: VecDeque<Vec<SetupMessage>> = messages
        .chunks(maximum_batch_size)
        .map(<[SetupMessage]>::to_vec)
        .collect();
    let mut outcome = BatchOutcome {
        messages: total_messages,
        ..BatchOutcome::default()
    };

    while let Some(batch) = queue.pop_front() {
        let messages = batch.iter().map(|message| message.any.clone()).collect();
        let failure = match broadcast(messages).await {
            Ok(()) => {
                outcome.transactions += 1;
                continue;
            }
            Err(error) => error,
        };
        if batch.len() == 1 {
            return Err(anyhow!(
                "setup item '{}' failed after batch isolation: {failure}",
                batch[0].label
            ));
        }
        outcome.failed_attempts.push(BatchFailure {
            labels: batch.iter().map(|message| message.label.clone()).collect(),
            error: failure,
        });
        let midpoint = batch.len() / 2;
        let mut left = batch;
        let right = left.split_off(midpoint);
        queue.push_front(right);
        queue.push_front(left);
        outcome.split_batches += 1;
    }
    Ok(outcome)
}

pub async fn fund_nodes(
    client: &SourceHubClient,
    nodes: &[NodeIdentity],
    maximum_batch_size: usize,
) -> Result<BatchOutcome> {
    let from_address = client
        .signer()
        .ok_or_else(|| anyhow!("funding client has no signer"))?
        .address();
    let messages = nodes
        .iter()
        .map(|node| {
            let message = MsgSend {
                from_address: from_address.clone(),
                to_address: node.public_address.clone(),
                amount: vec![Coin {
                    denom: "uopen".to_string(),
                    amount: "100000000".to_string(),
                }],
            };
            SetupMessage::new(
                format!("fund node {}", node.endpoint.index),
                MsgSend::TYPE_URL,
                &message,
            )
        })
        .collect();
    broadcast_bounded(client, messages, maximum_batch_size).await
}

pub async fn update_peer_addresses(
    client: &SourceHubClient,
    nodes: &[NodeIdentity],
    maximum_batch_size: usize,
) -> Result<BatchOutcome> {
    let creator = client
        .signer()
        .ok_or_else(|| anyhow!("controller client has no signer"))?
        .address();
    let messages = nodes
        .iter()
        .map(|node| {
            let peer_address = node.docker_p2p_address()?;
            let message = MsgUpdateNodePeerId::new(&creator, &node.node_key, &peer_address);
            Ok(SetupMessage::new(
                format!("update peer address for node {}", node.endpoint.index),
                MsgUpdateNodePeerId::TYPE_URL,
                &message,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    broadcast_bounded(client, messages, maximum_batch_size).await
}

/// Create every planned ring on-chain via `MsgCreateRing`, writing the
/// chain-assigned ring ID back into each `RingDefinition`. Rings are created
/// one transaction at a time (each needs its own decoded response to learn
/// its ID, so unlike `fund_nodes`/`update_peer_addresses` these can't be
/// folded into `broadcast_bounded`'s batching).
pub async fn create_rings_on_chain<'a>(
    client: &SourceHubClient,
    rings: impl Iterator<Item = &'a mut RingDefinition>,
    protocol_version: u64,
) -> Result<()> {
    for ring in rings {
        let reporting = ReportingConfig {
            demerit_config: Some(DemeritConfig {
                node_offline_demerits: 1,
                invalid_crypto_response_demerits: 1,
                unauthorized_request_demerits: 1,
                reset_interval_seconds: 86400,
            }),
            backup_node_keys: Vec::new(),
            kick_threshold: ring.peer_node_keys.len().max(1) as u64,
        };
        // A ring's chain identity is derived from creator + these parameters
        // + nonce. When ring_size == network_size, every trial's ring has
        // identical members/threshold/pss_interval/policy_id, so a constant
        // nonce (e.g. always None) collides as "ring already exists" from
        // the second otherwise-identical ring onward. A fresh UUID per ring
        // keeps every creation unique regardless of how many trials share
        // the same membership.
        let nonce = uuid::Uuid::new_v4().to_string();
        let (_, ring_id) = client
            .orbis_create_ring_get_id(
                ring.peer_node_keys.clone(),
                ring.threshold as u32,
                ring.pss_interval_secs,
                &ring.policy_id,
                Some(nonce),
                protocol_version,
                Some(reporting),
                None,
            )
            .await
            .with_context(|| {
                format!(
                    "create ring on-chain (threshold {}, {} members)",
                    ring.threshold,
                    ring.peer_node_keys.len()
                )
            })?;
        ring.id = ring_id;
    }
    Ok(())
}

/// Create the ACP governance policy that rings are tied to. Must run before
/// any `MsgCreateRing` — the chain rejects a ring whose `policy_id` doesn't
/// already exist. Returns the chain-assigned policy ID, which is expected to
/// equal `RING_GOVERNANCE_POLICY_ID` since this is always the first policy
/// created on a fresh chain (see that constant's doc comment).
pub async fn create_ring_governance_policy(client: &SourceHubClient) -> Result<String> {
    let existing: HashSet<String> = client
        .acp_list_policy_ids()
        .await?
        .ids
        .into_iter()
        .collect();
    let result = client.acp_create_policy(RING_POLICY_YAML, 1).await?;
    if result.code != 0 {
        bail!("create ring governance policy failed: {}", result.log);
    }
    let policy_id = client
        .acp_list_policy_ids()
        .await?
        .ids
        .into_iter()
        .find(|id| !existing.contains(id))
        .context("created policy did not appear in policy list")?;
    if policy_id != RING_GOVERNANCE_POLICY_ID {
        bail!(
            "ring policy ID changed: expected {}, chain returned {}",
            RING_GOVERNANCE_POLICY_ID,
            policy_id
        );
    }

    let creator = client
        .signer()
        .ok_or_else(|| anyhow!("governance client has no signer"))?
        .address();
    let message = register_object_message(&creator, &policy_id, "ring_policy", &policy_id);
    let result = broadcast_bounded(client, vec![message], 1).await?;
    if !result.failed_attempts.is_empty() {
        bail!(
            "register ring_policy ACP object failed: {:?}",
            result.failed_attempts
        );
    }
    Ok(policy_id)
}

/// Grant each ring's committee `operator` so ring-governance transactions
/// (reshare, pss interval changes, etc.) are authorized. Does *not* register
/// the ring as an ACP object — `MsgCreateRing`'s chain-side handler already
/// does that itself as part of ring creation
/// (`Keeper.registerRingACPObject` in SourceHub's `x/orbis/keeper/msg_server.go`);
/// registering it again here fails with "object already registered". Rings
/// must already exist on-chain (via `create_rings_on_chain`) and the
/// governance policy must already exist (via
/// `create_ring_governance_policy`) before calling this.
pub async fn register_ring_governance(
    client: &SourceHubClient,
    rings: &[RingDefinition],
    maximum_batch_size: usize,
) -> Result<BatchOutcome> {
    let creator = client
        .signer()
        .ok_or_else(|| anyhow!("governance client has no signer"))?
        .address();
    let policy_id = RING_GOVERNANCE_POLICY_ID.to_string();
    let mut messages = Vec::new();
    for ring in rings {
        let operator_node_keys = if ring.operator_node_keys.is_empty() {
            &ring.peer_node_keys
        } else {
            &ring.operator_node_keys
        };
        for node_key in operator_node_keys {
            let relationship = Relationship {
                object: Some(Object {
                    resource: "ring".to_string(),
                    id: ring.id.clone(),
                }),
                relation: "operator".to_string(),
                subject: Some(Subject {
                    kind: Some(SubjectKind::Actor(Actor {
                        id: secp256k1_pubkey_to_did(node_key)?,
                    })),
                }),
            };
            let message = MsgDirectPolicyCmd {
                creator: creator.clone(),
                policy_id: policy_id.clone(),
                cmd: Some(PolicyCmd {
                    kind: Some(PolicyCmdKind::SetRelationshipCmd(SetRelationshipCmd {
                        relationship: Some(relationship),
                    })),
                }),
            };
            messages.push(SetupMessage::new(
                format!("grant {} operator on {}", node_key, ring.id),
                MsgDirectPolicyCmd::TYPE_URL,
                &message,
            ));
        }
    }
    broadcast_bounded(client, messages, maximum_batch_size).await
}

fn register_object_message(
    creator: &str,
    policy_id: &str,
    resource: &str,
    object_id: &str,
) -> SetupMessage {
    let message = MsgDirectPolicyCmd {
        creator: creator.to_string(),
        policy_id: policy_id.to_string(),
        cmd: Some(PolicyCmd {
            kind: Some(PolicyCmdKind::RegisterObjectCmd(RegisterObjectCmd {
                object: Some(Object {
                    resource: resource.to_string(),
                    id: object_id.to_string(),
                }),
            })),
        }),
    };
    SetupMessage::new(
        format!("register {resource}/{object_id}"),
        MsgDirectPolicyCmd::TYPE_URL,
        &message,
    )
}

pub fn secp256k1_pubkey_to_did(compressed_pubkey_hex: &str) -> Result<String> {
    let public_key = hex::decode(compressed_pubkey_hex).context("decode node public key")?;
    if public_key.len() != 33 {
        bail!("compressed secp256k1 public key must contain 33 bytes");
    }
    let mut prefixed = vec![0xe7u8, 0x01u8];
    prefixed.extend_from_slice(&public_key);
    Ok(format!("did:key:z{}", bs58::encode(prefixed).into_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sourcehub_did_matches_known_test_controller() {
        let did = secp256k1_pubkey_to_did(
            "024f4e2ad99c34d60b9ba6283c9431a8418af8673212961f97a77b6377fcd05b62",
        )
        .unwrap();
        assert!(did.starts_with("did:key:zQ3sh"));
    }

    #[test]
    fn bounded_batches_preserve_every_item_when_partitioned() {
        let messages: Vec<SetupMessage> = (0..51)
            .map(|index| {
                SetupMessage::new(
                    index.to_string(),
                    MsgSend::TYPE_URL,
                    &MsgSend {
                        from_address: "a".into(),
                        to_address: "b".into(),
                        amount: Vec::new(),
                    },
                )
            })
            .collect();
        let batches: Vec<Vec<SetupMessage>> =
            messages.chunks(25).map(<[SetupMessage]>::to_vec).collect();
        assert_eq!(batches.iter().map(Vec::len).sum::<usize>(), 51);
        assert_eq!(batches.len(), 3);
    }

    #[tokio::test]
    async fn failed_batches_are_bisected_and_retried() {
        let messages: Vec<_> = (0..4)
            .map(|index| SetupMessage {
                label: format!("item-{index}"),
                any: Any {
                    type_url: "/test.Message".into(),
                    value: vec![index],
                },
            })
            .collect();
        let outcome = broadcast_bounded_with(messages, 4, |batch| async move {
            if batch.len() > 2 {
                Err("simulated oversized transaction".into())
            } else {
                Ok(())
            }
        })
        .await
        .unwrap();
        assert_eq!(outcome.messages, 4);
        assert_eq!(outcome.transactions, 2);
        assert_eq!(outcome.split_batches, 1);
        assert_eq!(outcome.failed_attempts.len(), 1);
        assert_eq!(outcome.failed_attempts[0].labels.len(), 4);
    }

    #[tokio::test]
    async fn a_bad_item_is_named_after_recursive_isolation() {
        let messages: Vec<_> = (0..4)
            .map(|index| SetupMessage {
                label: format!("item-{index}"),
                any: Any {
                    type_url: "/test.Message".into(),
                    value: vec![index],
                },
            })
            .collect();
        let error = broadcast_bounded_with(messages, 4, |batch| async move {
            if batch.iter().any(|message| message.value == [2]) {
                Err("simulated invalid message".into())
            } else {
                Ok(())
            }
        })
        .await
        .unwrap_err();
        assert!(error.to_string().contains("item-2"));
    }
}
