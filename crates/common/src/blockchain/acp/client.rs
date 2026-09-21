//! `VeraClient` extension methods for x/acp: policy transactions and queries.

use super::types::*;
use crate::blockchain::{BlockchainError, BroadcastResult, Result, VeraClient};
use prost::Message;

impl VeraClient {
    // ========================================================================
    // ACP Queries
    // ========================================================================

    /// Query a policy by ID.
    pub async fn acp_query_policy(&self, policy_id: &str) -> Result<QueryPolicyResponse> {
        let url = format!(
            "{}/sourcenetwork/vera/acp/policy/{}",
            self.config().rest_url,
            policy_id
        );
        self.rest_get(&url).await
    }

    /// List all policy IDs.
    pub async fn acp_list_policy_ids(&self) -> Result<QueryPolicyIdsResponse> {
        let url = format!(
            "{}/sourcenetwork/vera/acp/policy_ids",
            self.config().rest_url
        );
        self.rest_get(&url).await
    }

    /// Verify an access request via Vera's VerifyAccessRequest ABCI query.
    ///
    /// Sends the actor + permission directly to the chain; returns `true` if the
    /// actor holds the required permission on the object, `false` otherwise.
    pub async fn acp_verify_access(
        &self,
        policy_id: &str,
        access_request: &AccessRequest,
        height: Option<u64>,
    ) -> Result<bool> {
        let request = QueryVerifyAccessRequestRequest {
            policy_id: policy_id.to_string(),
            access_request: Some(access_request.clone()),
        };

        let request_bytes = request.encode_to_vec();

        let response_bytes = self
            .abci_query(
                "/vera.acp.Query/VerifyAccessRequest",
                request_bytes,
                height,
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
        let path = "/vera.acp.Query/FilterRelationships";

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
    /// Uses wildcard selectors for relation and subject to avoid nil-pointer panics in Vera.
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
        let signer = self.require_signer()?;

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
        let signer = self.require_signer()?;

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
        let signer = self.require_signer()?;
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
        let signer = self.require_signer()?;

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
        let signer = self.require_signer()?;

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
        let signer = self.require_signer()?;

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
