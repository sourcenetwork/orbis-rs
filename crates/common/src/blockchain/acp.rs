//! Access Control Policy (ACP) module types and operations.
//!
//! This module provides types and methods for interacting with SourceHub's ACP module,
//! which manages access control policies for applications.

use crate::blockchain::{BlockchainError, BroadcastResult, Result, SourceHubClient};
use cosmrs::Any;
use prost::Message;
use serde::{Deserialize, Serialize};

// ============================================================================
// Message Types (for transactions)
// ============================================================================

/// Create a new access control policy.
/// Proto field numbers match sourcehub/acp/tx.proto:
/// - 1: creator (string)
/// - 2: policy (string)
/// - 3: marshal_type (PolicyMarshalingType enum)
#[derive(Clone, Serialize, Deserialize, Message)]
pub struct MsgCreatePolicy {
    /// Creator's address
    #[prost(string, tag = "1")]
    pub creator: String,
    /// Policy definition (YAML or JSON format)
    #[prost(string, tag = "2")]
    pub policy: String,
    /// Marshal type: 0 = Unknown, 1 = YAML, 2 = JSON
    #[prost(int32, tag = "3")]
    #[serde(default)]
    pub marshal_type: i32,
}

impl MsgCreatePolicy {
    pub const TYPE_URL: &'static str = "/sourcehub.acp.MsgCreatePolicy";

    /// Create a new policy message with YAML format.
    pub fn new_yaml(creator: &str, policy: &str) -> Self {
        Self {
            creator: creator.to_string(),
            policy: policy.to_string(),
            marshal_type: 1, // YAML
        }
    }

    /// Create a new policy message with JSON format.
    pub fn new_json(creator: &str, policy: &str) -> Self {
        Self {
            creator: creator.to_string(),
            policy: policy.to_string(),
            marshal_type: 2, // JSON
        }
    }
}

/// Check access for a request and store the result on-chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MsgCheckAccess {
    /// Creator's address
    pub creator: String,
    /// Policy ID
    pub policy_id: String,
    /// Access request details
    pub access_request: AccessRequest,
}

impl MsgCheckAccess {
    pub const TYPE_URL: &'static str = "/sourcehub.acp.MsgCheckAccess";
}

/// Direct policy command message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MsgDirectPolicyCmd {
    /// Creator's address
    pub creator: String,
    /// Policy ID
    pub policy_id: String,
    /// Command to execute
    pub cmd: PolicyCmd,
}

impl MsgDirectPolicyCmd {
    pub const TYPE_URL: &'static str = "/sourcehub.acp.MsgDirectPolicyCmd";
}

// ============================================================================
// Supporting Types
// ============================================================================

/// Access request for checking permissions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessRequest {
    /// Operations to check
    pub operations: Vec<Operation>,
}

/// A single operation to check access for.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Operation {
    /// Object being accessed
    pub object: Object,
    /// Relation being checked (e.g., "reader", "writer", "owner")
    pub relation: String,
    /// Actor requesting access
    pub actor: Actor,
}

/// An object in the access control system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Object {
    /// Resource type (e.g., "document", "file")
    pub resource: String,
    /// Object identifier
    pub id: String,
}

/// An actor in the access control system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Actor {
    /// Actor identifier (typically a DID)
    pub id: String,
}

/// A relationship between actors and objects.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Relationship {
    /// Object
    pub object: Object,
    /// Relation name
    pub relation: String,
    /// Subject (can be an actor or object reference)
    pub subject: Subject,
}

/// Subject of a relationship (either an actor or an object).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Subject {
    Actor { actor: Actor },
    Object { object: Object },
}

/// Policy command (oneof in proto).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyCmd {
    SetRelationshipCmd(SetRelationshipCmd),
    DeleteRelationshipCmd(DeleteRelationshipCmd),
    RegisterObjectCmd(RegisterObjectCmd),
    ArchiveObjectCmd(ArchiveObjectCmd),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetRelationshipCmd {
    pub relationship: Relationship,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteRelationshipCmd {
    pub relationship: Relationship,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterObjectCmd {
    pub object: Object,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveObjectCmd {
    pub object: Object,
}

// ============================================================================
// Query Response Types
// ============================================================================

/// Response from querying a policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryPolicyResponse {
    pub record: Option<PolicyRecord>,
}

/// Policy record stored on-chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRecord {
    pub policy: Option<Policy>,
    pub creation_time: Option<String>,
}

/// Policy definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub id: String,
    pub name: String,
    pub resources: Vec<Resource>,
    pub actor_resource: Option<ActorResource>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Resource {
    pub name: String,
    pub relations: Vec<Relation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Relation {
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActorResource {
    pub name: String,
}

/// Response from listing policy IDs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryPolicyIdsResponse {
    pub ids: Vec<String>,
    pub pagination: Option<Pagination>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pagination {
    pub next_key: Option<String>,
    pub total: Option<String>,
}

/// Response from verifying access.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryVerifyAccessResponse {
    pub valid: bool,
}

/// Access decision stored on-chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessDecision {
    pub id: String,
    pub policy_id: String,
    pub creator: String,
    pub operations: Vec<OperationResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationResult {
    pub operation: Operation,
    pub is_authorized: bool,
}

// ============================================================================
// Client Extension Methods
// ============================================================================

impl SourceHubClient {
    // ========================================================================
    // ACP Queries
    // ========================================================================

    /// Query a policy by ID.
    pub async fn acp_query_policy(&self, policy_id: &str) -> Result<QueryPolicyResponse> {
        let url = format!(
            "{}/sourcenetwork/sourcehub/acp/policy/{}",
            self.config().rest_url,
            policy_id
        );
        self.rest_get(&url).await
    }

    /// List all policy IDs.
    pub async fn acp_list_policy_ids(&self) -> Result<QueryPolicyIdsResponse> {
        let url = format!(
            "{}/sourcenetwork/sourcehub/acp/policy_ids",
            self.config().rest_url
        );
        self.rest_get(&url).await
    }

    /// Verify an access request without storing the result.
    pub async fn acp_verify_access(
        &self,
        policy_id: &str,
        access_request: &AccessRequest,
    ) -> Result<bool> {
        // Build query parameters
        let url = format!(
            "{}/sourcenetwork/sourcehub/acp/verify_access_request/{}",
            self.config().rest_url,
            policy_id
        );

        // POST the access request
        let response: QueryVerifyAccessResponse = self.rest_post(&url, access_request).await?;
        Ok(response.valid)
    }

    // ========================================================================
    // ACP Transactions
    // ========================================================================

    /// Create a new policy.
    ///
    /// Requires a signer to be configured on the client.
    pub async fn acp_create_policy(
        &self,
        policy: &str,
        marshal_type: i32,
    ) -> Result<BroadcastResult> {
        let signer = self
            .signer()
            .ok_or_else(|| BlockchainError::Signing("No signer configured".to_string()))?;

        let msg = MsgCreatePolicy {
            creator: signer.address(),
            policy: policy.to_string(),
            marshal_type,
        };

        self.broadcast_proto_msg(MsgCreatePolicy::TYPE_URL, &msg)
            .await
    }

    /// Check access and store the decision on-chain.
    pub async fn acp_check_access(
        &self,
        policy_id: &str,
        access_request: AccessRequest,
    ) -> Result<BroadcastResult> {
        let signer = self
            .signer()
            .ok_or_else(|| BlockchainError::Signing("No signer configured".to_string()))?;

        let msg = MsgCheckAccess {
            creator: signer.address(),
            policy_id: policy_id.to_string(),
            access_request,
        };

        self.broadcast_json_msg(MsgCheckAccess::TYPE_URL, &msg)
            .await
    }

    /// Register an object in a policy.
    pub async fn acp_register_object(
        &self,
        policy_id: &str,
        object: Object,
    ) -> Result<BroadcastResult> {
        let signer = self
            .signer()
            .ok_or_else(|| BlockchainError::Signing("No signer configured".to_string()))?;

        let msg = MsgDirectPolicyCmd {
            creator: signer.address(),
            policy_id: policy_id.to_string(),
            cmd: PolicyCmd::RegisterObjectCmd(RegisterObjectCmd { object }),
        };

        self.broadcast_json_msg(MsgDirectPolicyCmd::TYPE_URL, &msg)
            .await
    }

    /// Set a relationship in a policy.
    pub async fn acp_set_relationship(
        &self,
        policy_id: &str,
        relationship: Relationship,
    ) -> Result<BroadcastResult> {
        let signer = self
            .signer()
            .ok_or_else(|| BlockchainError::Signing("No signer configured".to_string()))?;

        let msg = MsgDirectPolicyCmd {
            creator: signer.address(),
            policy_id: policy_id.to_string(),
            cmd: PolicyCmd::SetRelationshipCmd(SetRelationshipCmd { relationship }),
        };

        self.broadcast_json_msg(MsgDirectPolicyCmd::TYPE_URL, &msg)
            .await
    }

    /// Delete a relationship from a policy.
    pub async fn acp_delete_relationship(
        &self,
        policy_id: &str,
        relationship: Relationship,
    ) -> Result<BroadcastResult> {
        let signer = self
            .signer()
            .ok_or_else(|| BlockchainError::Signing("No signer configured".to_string()))?;

        let msg = MsgDirectPolicyCmd {
            creator: signer.address(),
            policy_id: policy_id.to_string(),
            cmd: PolicyCmd::DeleteRelationshipCmd(DeleteRelationshipCmd { relationship }),
        };

        self.broadcast_json_msg(MsgDirectPolicyCmd::TYPE_URL, &msg)
            .await
    }

    /// Archive an object (remove all relationships).
    pub async fn acp_archive_object(
        &self,
        policy_id: &str,
        object: Object,
    ) -> Result<BroadcastResult> {
        let signer = self
            .signer()
            .ok_or_else(|| BlockchainError::Signing("No signer configured".to_string()))?;

        let msg = MsgDirectPolicyCmd {
            creator: signer.address(),
            policy_id: policy_id.to_string(),
            cmd: PolicyCmd::ArchiveObjectCmd(ArchiveObjectCmd { object }),
        };

        self.broadcast_json_msg(MsgDirectPolicyCmd::TYPE_URL, &msg)
            .await
    }

    // ========================================================================
    // Helper Methods
    // ========================================================================

    /// Broadcast a protobuf-encoded message as a transaction.
    async fn broadcast_proto_msg<T: Message>(
        &self,
        type_url: &str,
        msg: &T,
    ) -> Result<BroadcastResult> {
        let signer = self
            .signer()
            .ok_or_else(|| BlockchainError::Signing("No signer configured".to_string()))?;

        // Get account info for sequence number
        let account_info = self.get_account(&signer.address()).await?;

        // Encode message as protobuf
        let msg_bytes = msg.encode_to_vec();

        let any_msg = Any {
            type_url: type_url.to_string(),
            value: msg_bytes,
        };

        // Sign the transaction
        let tx_bytes = signer.sign_tx(
            vec![any_msg],
            account_info.account_number,
            account_info.sequence,
            None, // Use default gas
            None, // No memo
        )?;

        // Broadcast
        self.broadcast_tx_commit(tx_bytes).await
    }

    /// Broadcast a JSON-encoded message as a transaction (for messages not yet migrated to prost).
    #[allow(dead_code)]
    async fn broadcast_json_msg<T: Serialize>(
        &self,
        type_url: &str,
        msg: &T,
    ) -> Result<BroadcastResult> {
        let signer = self
            .signer()
            .ok_or_else(|| BlockchainError::Signing("No signer configured".to_string()))?;

        // Get account info for sequence number
        let account_info = self.get_account(&signer.address()).await?;

        // Encode message as JSON bytes
        let msg_bytes = serde_json::to_vec(msg)?;

        let any_msg = Any {
            type_url: type_url.to_string(),
            value: msg_bytes,
        };

        // Sign the transaction
        let tx_bytes = signer.sign_tx(
            vec![any_msg],
            account_info.account_number,
            account_info.sequence,
            None, // Use default gas
            None, // No memo
        )?;

        // Broadcast
        self.broadcast_tx_commit(tx_bytes).await
    }
}
