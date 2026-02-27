//! Access Control Policy (ACP) module types and operations.
//!
//! This module provides types and methods for interacting with SourceHub's ACP module,
//! which manages access control policies for applications.

use crate::blockchain::{BlockchainError, BroadcastResult, Result, SourceHubClient};
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
/// Proto field numbers match sourcehub/acp/tx.proto:
/// - 1: creator (string)
/// - 2: policy_id (string)
/// - 3: access_request (AccessRequest)
#[derive(Clone, Serialize, Deserialize, Message)]
pub struct MsgCheckAccess {
    /// Creator's address
    #[prost(string, tag = "1")]
    pub creator: String,
    /// Policy ID
    #[prost(string, tag = "2")]
    pub policy_id: String,
    /// Access request details
    #[prost(message, optional, tag = "3")]
    pub access_request: Option<AccessRequest>,
}

impl MsgCheckAccess {
    pub const TYPE_URL: &'static str = "/sourcehub.acp.MsgCheckAccess";
}

/// Direct policy command message.
/// Proto field numbers match sourcehub/acp/tx.proto:
/// - 1: creator (string)
/// - 2: policy_id (string)
/// - 3: cmd (PolicyCmd)
#[derive(Clone, Serialize, Deserialize, Message)]
pub struct MsgDirectPolicyCmd {
    /// Creator's address
    #[prost(string, tag = "1")]
    pub creator: String,
    /// Policy ID
    #[prost(string, tag = "2")]
    pub policy_id: String,
    /// Command to execute
    #[prost(message, optional, tag = "3")]
    pub cmd: Option<PolicyCmd>,
}

impl MsgDirectPolicyCmd {
    pub const TYPE_URL: &'static str = "/sourcehub.acp.MsgDirectPolicyCmd";
}

// ============================================================================
// Supporting Types
// ============================================================================

/// Access request for checking permissions.
/// Proto field numbers match acp_core/request.proto:
/// - 1: operations (repeated Operation)
/// - 2: actor (Actor)
#[derive(Clone, Serialize, Deserialize, Message)]
pub struct AccessRequest {
    /// Operations to check
    #[prost(message, repeated, tag = "1")]
    pub operations: Vec<Operation>,
    /// Actor requesting access
    #[prost(message, optional, tag = "2")]
    pub actor: Option<Actor>,
}

/// A single operation to check access for.
/// Proto field numbers match acp_core/request.proto:
/// - 1: object (Object)
/// - 2: permission (string)
#[derive(Clone, Serialize, Deserialize, Message)]
pub struct Operation {
    /// Object being accessed
    #[prost(message, optional, tag = "1")]
    pub object: Option<Object>,
    /// Permission being checked (e.g., "read", "write")
    #[prost(string, tag = "2")]
    pub permission: String,
}

/// An object in the access control system.
/// Proto field numbers match acp_core/relationship.proto:
/// - 1: resource (string)
/// - 2: id (string)
#[derive(Clone, Serialize, Deserialize, Message)]
pub struct Object {
    /// Resource type (e.g., "document", "file")
    #[prost(string, tag = "1")]
    pub resource: String,
    /// Object identifier
    #[prost(string, tag = "2")]
    pub id: String,
}

/// An actor in the access control system.
/// Proto field numbers match acp_core/relationship.proto:
/// - 1: id (string)
#[derive(Clone, Serialize, Deserialize, Message)]
pub struct Actor {
    /// Actor identifier (typically a DID)
    #[prost(string, tag = "1")]
    pub id: String,
}

/// A relationship between actors and objects.
/// Proto field numbers match acp_core/relationship.proto:
/// - 1: object (Object)
/// - 2: relation (string)
/// - 3: subject (Subject)
#[derive(Clone, Serialize, Deserialize, Message)]
pub struct Relationship {
    /// Object
    #[prost(message, optional, tag = "1")]
    pub object: Option<Object>,
    /// Relation name
    #[prost(string, tag = "2")]
    pub relation: String,
    /// Subject (can be an actor or object reference)
    #[prost(message, optional, tag = "3")]
    pub subject: Option<Subject>,
}

/// Subject of a relationship (either an actor or an object).
/// Proto field numbers match acp_core/relationship.proto (oneof):
/// - 1: actor (Actor)
/// - 4: object (Object)
#[derive(Clone, Serialize, Deserialize, Message)]
pub struct Subject {
    #[prost(oneof = "SubjectKind", tags = "1, 4")]
    #[serde(flatten)]
    pub kind: Option<SubjectKind>,
}

/// Subject oneof variants
#[derive(Clone, Serialize, Deserialize, prost::Oneof)]
pub enum SubjectKind {
    #[prost(message, tag = "1")]
    Actor(Actor),
    #[prost(message, tag = "4")]
    Object(Object),
}

/// Policy command (oneof in proto).
/// Proto field numbers match sourcehub/acp/policy_cmd.proto:
/// - 1: set_relationship_cmd
/// - 2: delete_relationship_cmd
/// - 3: register_object_cmd
/// - 4: archive_object_cmd
#[derive(Clone, Serialize, Deserialize, Message)]
pub struct PolicyCmd {
    #[prost(oneof = "PolicyCmdKind", tags = "1, 2, 3, 4")]
    #[serde(flatten)]
    pub kind: Option<PolicyCmdKind>,
}

/// PolicyCmd oneof variants
#[derive(Clone, Serialize, Deserialize, prost::Oneof)]
pub enum PolicyCmdKind {
    #[prost(message, tag = "1")]
    SetRelationshipCmd(SetRelationshipCmd),
    #[prost(message, tag = "2")]
    DeleteRelationshipCmd(DeleteRelationshipCmd),
    #[prost(message, tag = "3")]
    RegisterObjectCmd(RegisterObjectCmd),
    #[prost(message, tag = "4")]
    ArchiveObjectCmd(ArchiveObjectCmd),
}

#[derive(Clone, Serialize, Deserialize, Message)]
pub struct SetRelationshipCmd {
    #[prost(message, optional, tag = "1")]
    pub relationship: Option<Relationship>,
}

#[derive(Clone, Serialize, Deserialize, Message)]
pub struct DeleteRelationshipCmd {
    #[prost(message, optional, tag = "1")]
    pub relationship: Option<Relationship>,
}

#[derive(Clone, Serialize, Deserialize, Message)]
pub struct RegisterObjectCmd {
    #[prost(message, optional, tag = "1")]
    pub object: Option<Object>,
}

#[derive(Clone, Serialize, Deserialize, Message)]
pub struct ArchiveObjectCmd {
    #[prost(message, optional, tag = "1")]
    pub object: Option<Object>,
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
    #[serde(default)]
    pub metadata: Option<PolicyMetadata>,
    #[serde(default)]
    pub raw_policy: String,
    #[serde(default)]
    pub marshal_type: String,
}

/// Metadata for a policy record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyMetadata {
    #[serde(default)]
    pub creation_ts: Option<CreationTimestamp>,
    #[serde(default)]
    pub tx_hash: String,
    #[serde(default)]
    pub tx_signer: String,
    #[serde(default)]
    pub owner_did: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreationTimestamp {
    #[serde(default)]
    pub proto_ts: String,
    #[serde(default)]
    pub block_height: String,
}

/// Policy definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub resources: Vec<Resource>,
    pub actor_resource: Option<ActorResource>,
    #[serde(default)]
    pub specification_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Resource {
    pub name: String,
    #[serde(default)]
    pub doc: String,
    pub relations: Vec<Relation>,
    #[serde(default)]
    pub permissions: Vec<Permission>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Relation {
    pub name: String,
    #[serde(default)]
    pub doc: String,
    #[serde(default)]
    pub manages: Vec<String>,
    #[serde(default)]
    pub vr_types: Vec<VrType>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VrType {
    pub resource_name: String,
    #[serde(default)]
    pub relation_name: String,
}

/// Permission definition within a resource.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Permission {
    pub name: String,
    #[serde(default)]
    pub doc: String,
    /// Expression defining which relations grant this permission.
    /// Examples: "owner", "(owner + reader)", "owner->member"
    /// The REST API may return this field as "expr" (proto field name).
    #[serde(default, alias = "expr")]
    pub expression: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActorResource {
    pub name: String,
    #[serde(default)]
    pub doc: String,
    #[serde(default)]
    pub relations: Vec<Relation>,
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
// Verify Access Request Types (prost, for ABCI query)
// ============================================================================

/// ABCI request for the VerifyAccessRequest query.
/// Proto: sourcehub.acp.QueryVerifyAccessRequestRequest
#[derive(Clone, Message)]
pub struct QueryVerifyAccessRequestRequest {
    #[prost(string, tag = "1")]
    pub policy_id: String,
    #[prost(message, optional, tag = "2")]
    pub access_request: Option<AccessRequest>,
}

/// ABCI response for the VerifyAccessRequest query.
/// Proto: sourcehub.acp.QueryVerifyAccessRequestResponse
#[derive(Clone, Message)]
pub struct QueryVerifyAccessRequestResponse {
    #[prost(bool, tag = "1")]
    pub valid: bool,
}

// ============================================================================
// Filter Relationships Types (with prost for gRPC)
// ============================================================================

/// Selector for filtering relationships.
/// Proto field numbers match sourcehub/acp/query.proto
#[derive(Clone, Serialize, Deserialize, Message)]
pub struct RelationshipSelector {
    #[prost(message, optional, tag = "1")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object_selector: Option<ObjectSelector>,
    #[prost(message, optional, tag = "2")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relation_selector: Option<RelationSelector>,
    #[prost(message, optional, tag = "3")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_selector: Option<SubjectSelector>,
}

/// Wildcard selector - matches anything.
/// Proto: sourcenetwork.acp_core.WildcardSelector (empty message)
#[derive(Clone, Serialize, Deserialize, Message)]
pub struct WildcardSelector {}

/// Object selector - uses oneof with object at tag 1.
/// Proto: sourcenetwork.acp_core.ObjectSelector
#[derive(Clone, Serialize, Deserialize, Message)]
pub struct ObjectSelector {
    #[prost(oneof = "ObjectSelectorKind", tags = "1, 2")]
    #[serde(flatten)]
    pub selector: Option<ObjectSelectorKind>,
}

#[derive(Clone, Serialize, Deserialize, prost::Oneof)]
pub enum ObjectSelectorKind {
    #[prost(message, tag = "1")]
    Object(Object),
    #[prost(message, tag = "2")]
    Wildcard(WildcardSelector),
}

/// Relation selector - uses oneof with relation at tag 1.
/// Proto: sourcenetwork.acp_core.RelationSelector
#[derive(Clone, Serialize, Deserialize, Message)]
pub struct RelationSelector {
    #[prost(oneof = "RelationSelectorKind", tags = "1, 2")]
    #[serde(flatten)]
    pub selector: Option<RelationSelectorKind>,
}

#[derive(Clone, Serialize, Deserialize, prost::Oneof)]
pub enum RelationSelectorKind {
    #[prost(string, tag = "1")]
    Relation(String),
    #[prost(message, tag = "2")]
    Wildcard(WildcardSelector),
}

/// Subject selector - uses oneof with subject at tag 1.
/// Proto: sourcenetwork.acp_core.SubjectSelector
#[derive(Clone, Serialize, Deserialize, Message)]
pub struct SubjectSelector {
    #[prost(oneof = "SubjectSelectorKind", tags = "1, 2")]
    #[serde(flatten)]
    pub selector: Option<SubjectSelectorKind>,
}

#[derive(Clone, Serialize, Deserialize, prost::Oneof)]
pub enum SubjectSelectorKind {
    #[prost(message, tag = "1")]
    Subject(Subject),
    #[prost(message, tag = "2")]
    Wildcard(WildcardSelector),
}

/// gRPC request for FilterRelationships query.
/// Proto: sourcehub.acp.QueryFilterRelationshipsRequest
#[derive(Clone, Message)]
pub struct QueryFilterRelationshipsRequest {
    #[prost(string, tag = "1")]
    pub policy_id: String,
    #[prost(message, optional, tag = "2")]
    pub selector: Option<RelationshipSelector>,
}

/// Response from filtering relationships (gRPC).
/// Proto: sourcehub.acp.QueryFilterRelationshipsResponse
#[derive(Clone, Message)]
pub struct QueryFilterRelationshipsResponse {
    #[prost(message, repeated, tag = "1")]
    pub records: Vec<RelationshipRecord>,
}

/// A relationship record stored on-chain.
/// Proto: sourcehub.acp.RelationshipRecord
#[derive(Clone, Message)]
pub struct RelationshipRecord {
    #[prost(string, tag = "1")]
    pub policy_id: String,
    #[prost(message, optional, tag = "2")]
    pub relationship: Option<Relationship>,
    #[prost(bool, tag = "3")]
    pub archived: bool,
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

    /// Verify an access request via the SourceHub VerifyAccessRequest ABCI query.
    ///
    /// Sends the actor + permission directly to the chain; returns `true` if the
    /// actor holds the required permission on the object, `false` otherwise.
    pub async fn acp_verify_access(
        &self,
        policy_id: &str,
        access_request: &AccessRequest,
    ) -> Result<bool> {
        let request = QueryVerifyAccessRequestRequest {
            policy_id: policy_id.to_string(),
            access_request: Some(access_request.clone()),
        };

        let request_bytes = request.encode_to_vec();

        let response_bytes = self
            .abci_query(
                "/sourcehub.acp.Query/VerifyAccessRequest",
                request_bytes,
                None,
                false,
            )
            .await?;

        let response = QueryVerifyAccessRequestResponse::decode(response_bytes.as_slice())
            .map_err(|e| {
                BlockchainError::Serialization(format!(
                    "Failed to decode VerifyAccessRequest response: {}",
                    e
                ))
            })?;

        Ok(response.valid)
    }

    /// Filter relationships in a policy.
    /// Returns relationships matching the given selector criteria.
    /// Uses ABCI query with protobuf encoding (gRPC-compatible).
    pub async fn acp_filter_relationships(
        &self,
        policy_id: &str,
        selector: &RelationshipSelector,
    ) -> Result<QueryFilterRelationshipsResponse> {
        // Build the protobuf request
        let request = QueryFilterRelationshipsRequest {
            policy_id: policy_id.to_string(),
            selector: Some(selector.clone()),
        };

        // Encode request as protobuf
        let request_bytes = request.encode_to_vec();

        // Query path for gRPC-style ABCI query
        let path = "/sourcehub.acp.Query/FilterRelationships";

        // Execute ABCI query
        let response_bytes = self.abci_query(path, request_bytes, None, false).await?;

        // Decode the protobuf response
        let response = QueryFilterRelationshipsResponse::decode(response_bytes.as_slice())
            .map_err(|e| {
                BlockchainError::Serialization(format!("Failed to decode response: {}", e))
            })?;

        Ok(response)
    }

    /// List all relationships for a given object, regardless of relation or subject.
    /// Uses wildcard selectors for relation and subject to avoid nil-pointer panics in SourceHub.
    /// Useful for diagnostics: if this returns results but `acp_has_relationship` doesn't,
    /// the issue is with how the subject selector is encoded.
    pub async fn acp_list_all_relationships_for_object(
        &self,
        policy_id: &str,
        resource: &str,
        object_id: &str,
    ) -> Result<QueryFilterRelationshipsResponse> {
        let selector = RelationshipSelector {
            object_selector: Some(ObjectSelector {
                selector: Some(ObjectSelectorKind::Object(Object {
                    resource: resource.to_string(),
                    id: object_id.to_string(),
                })),
            }),
            relation_selector: Some(RelationSelector {
                selector: Some(RelationSelectorKind::Wildcard(WildcardSelector {})),
            }),
            subject_selector: Some(SubjectSelector {
                selector: Some(SubjectSelectorKind::Wildcard(WildcardSelector {})),
            }),
        };
        self.acp_filter_relationships(policy_id, &selector).await
    }

    /// Check if an actor has a specific relation to an object.
    /// Returns true if the relationship exists.
    pub async fn acp_has_relationship(
        &self,
        policy_id: &str,
        actor_id: &str,
        resource: &str,
        object_id: &str,
        relation: &str,
    ) -> Result<bool> {
        let selector = RelationshipSelector {
            object_selector: Some(ObjectSelector {
                selector: Some(ObjectSelectorKind::Object(Object {
                    resource: resource.to_string(),
                    id: object_id.to_string(),
                })),
            }),
            relation_selector: Some(RelationSelector {
                selector: Some(RelationSelectorKind::Relation(relation.to_string())),
            }),
            subject_selector: Some(SubjectSelector {
                selector: Some(SubjectSelectorKind::Subject(Subject {
                    kind: Some(SubjectKind::Actor(Actor {
                        id: actor_id.to_string(),
                    })),
                })),
            }),
        };

        let response = self.acp_filter_relationships(policy_id, &selector).await?;
        Ok(!response.records.is_empty())
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

        self.broadcast_proto_msg_with_gas(
            MsgCreatePolicy::TYPE_URL,
            &msg,
            self.config().gas_multiplier,
        )
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
            access_request: Some(access_request),
        };

        self.broadcast_proto_msg_with_gas(
            MsgCheckAccess::TYPE_URL,
            &msg,
            self.config().gas_multiplier,
        )
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
            cmd: Some(PolicyCmd {
                kind: Some(PolicyCmdKind::RegisterObjectCmd(RegisterObjectCmd {
                    object: Some(object),
                })),
            }),
        };

        self.broadcast_proto_msg_with_gas(
            MsgDirectPolicyCmd::TYPE_URL,
            &msg,
            self.config().gas_multiplier,
        )
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
            cmd: Some(PolicyCmd {
                kind: Some(PolicyCmdKind::SetRelationshipCmd(SetRelationshipCmd {
                    relationship: Some(relationship),
                })),
            }),
        };

        self.broadcast_proto_msg_with_gas(
            MsgDirectPolicyCmd::TYPE_URL,
            &msg,
            self.config().gas_multiplier,
        )
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
            cmd: Some(PolicyCmd {
                kind: Some(PolicyCmdKind::DeleteRelationshipCmd(
                    DeleteRelationshipCmd {
                        relationship: Some(relationship),
                    },
                )),
            }),
        };

        self.broadcast_proto_msg_with_gas(
            MsgDirectPolicyCmd::TYPE_URL,
            &msg,
            self.config().gas_multiplier,
        )
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
            cmd: Some(PolicyCmd {
                kind: Some(PolicyCmdKind::ArchiveObjectCmd(ArchiveObjectCmd {
                    object: Some(object),
                })),
            }),
        };

        self.broadcast_proto_msg_with_gas(
            MsgDirectPolicyCmd::TYPE_URL,
            &msg,
            self.config().gas_multiplier,
        )
        .await
    }
}
