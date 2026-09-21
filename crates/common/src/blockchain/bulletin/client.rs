//! `VeraClient` extension methods for x/bulletin: post/namespace transactions and queries.

use super::types::*;
use crate::blockchain::{BlockchainError, BroadcastResult, Result, VeraClient};
use prost::Message;

impl VeraClient {
    // ========================================================================
    // Bulletin Queries (ABCI/gRPC)
    // ========================================================================

    /// Read a post by namespace and ID using ABCI query.
    /// Returns `Ok(None)` if the post does not exist.
    pub async fn bulletin_read_post(&self, namespace: &str, id: &str) -> Result<Option<Post>> {
        let request = QueryPostRequest {
            namespace: namespace.to_string(),
            id: id.to_string(),
        };

        let request_bytes = request.encode_to_vec();
        let path = "/vera.bulletin.Query/Post";

        let Some(response_bytes) = self
            .abci_query_optional(path, request_bytes, None, false)
            .await?
        else {
            return Ok(None);
        };

        let response = QueryPostResponse::decode(response_bytes.as_slice()).map_err(|e| {
            BlockchainError::Serialization(format!("Failed to decode post response: {}", e))
        })?;

        Ok(response.post)
    }

    /// Get namespace information using ABCI query.
    pub async fn bulletin_get_namespace(&self, namespace: &str) -> Result<Namespace> {
        let request = QueryNamespaceRequest {
            namespace: namespace.to_string(),
        };

        let request_bytes = request.encode_to_vec();
        let path = "/vera.bulletin.Query/Namespace";

        let response_bytes = self.abci_query(path, request_bytes, None, false).await?;

        let response = QueryNamespaceResponse::decode(response_bytes.as_slice()).map_err(|e| {
            BlockchainError::Serialization(format!("Failed to decode namespace response: {}", e))
        })?;

        response
            .namespace
            .ok_or_else(|| BlockchainError::NotFound(format!("Namespace {} not found", namespace)))
    }

    /// List posts in a namespace using ABCI query.
    pub async fn bulletin_list_posts(&self, namespace: &str) -> Result<Vec<Post>> {
        let request = QueryNamespacePostsRequest {
            namespace: namespace.to_string(),
            pagination: None,
        };

        let request_bytes = request.encode_to_vec();
        let path = "/vera.bulletin.Query/NamespacePosts";

        let response_bytes = self.abci_query(path, request_bytes, None, false).await?;

        let response =
            QueryNamespacePostsResponse::decode(response_bytes.as_slice()).map_err(|e| {
                BlockchainError::Serialization(format!("Failed to decode posts response: {}", e))
            })?;

        Ok(response.posts)
    }

    /// Query posts matching a glob pattern using ABCI query.
    pub async fn bulletin_query_glob(&self, namespace: &str, pattern: &str) -> Result<Vec<Post>> {
        let request = QueryIterateGlobRequest {
            namespace: namespace.to_string(),
            pattern: pattern.to_string(),
        };

        let request_bytes = request.encode_to_vec();
        let path = "/vera.bulletin.Query/IterateGlob";

        let response_bytes = self.abci_query(path, request_bytes, None, false).await?;

        let response =
            QueryIterateGlobResponse::decode(response_bytes.as_slice()).map_err(|e| {
                BlockchainError::Serialization(format!("Failed to decode glob response: {}", e))
            })?;

        Ok(response.posts)
    }

    // ========================================================================
    // Bulletin Transactions
    // ========================================================================

    /// Register a new namespace.
    /// The creator becomes the namespace owner.
    pub async fn bulletin_register_namespace(&self, namespace: &str) -> Result<BroadcastResult> {
        let signer = self.require_signer()?;

        let msg = MsgRegisterNamespace::new(&signer.address(), namespace);

        self.broadcast_proto_msg_with_gas(
            MsgRegisterNamespace::TYPE_URL,
            &msg,
            self.config().gas_multiplier,
        )
        .await
    }

    /// Create a post with in a namespace.
    pub async fn bulletin_create_post(
        &self,
        namespace: &str,
        payload: Vec<u8>,
        artifact: Option<String>,
    ) -> Result<BroadcastResult> {
        let signer = self.require_signer()?;

        let msg = MsgCreatePost::new(&signer.address(), namespace, payload, artifact);

        self.broadcast_proto_msg_with_gas(
            MsgCreatePost::TYPE_URL,
            &msg,
            self.config().gas_multiplier,
        )
        .await
    }

    /// Update a ring post via ACP authorization.
    pub async fn bulletin_update_ring_post_by_acp(
        &self,
        namespace: &str,
        post_id: &str,
        artifact: Option<String>,
        new_peer_ids: Vec<String>,
        new_threshold: Option<u32>,
        pss_interval: Option<u64>,
    ) -> Result<BroadcastResult> {
        let signer = self.require_signer()?;

        let msg = MsgUpdateRingPostByAcp::new(
            &signer.address(),
            namespace,
            post_id,
            artifact,
            new_peer_ids,
            new_threshold,
            pss_interval,
        );

        self.broadcast_proto_msg_with_gas(
            MsgUpdateRingPostByAcp::TYPE_URL,
            &msg,
            self.config().gas_multiplier,
        )
        .await
    }

    /// Finalize a ring reshare using a threshold signature.
    pub async fn bulletin_update_ring_post_by_threshold_signature(
        &self,
        namespace: &str,
        post_id: &str,
        artifact: Option<String>,
        signature_scheme: &str,
        signature: Vec<u8>,
    ) -> Result<BroadcastResult> {
        let signer = self.require_signer()?;

        let msg = MsgUpdateRingPostByThresholdSignature::new(
            &signer.address(),
            namespace,
            post_id,
            artifact,
            signature_scheme,
            signature,
        );

        self.broadcast_proto_msg_with_gas(
            MsgUpdateRingPostByThresholdSignature::TYPE_URL,
            &msg,
            self.config().gas_multiplier,
        )
        .await
    }

    /// Add a collaborator to a namespace.
    /// Only the namespace owner can add collaborators.
    pub async fn bulletin_add_collaborator(
        &self,
        namespace: &str,
        collaborator: &str,
    ) -> Result<BroadcastResult> {
        let signer = self.require_signer()?;

        let msg = MsgAddCollaborator::new(&signer.address(), namespace, collaborator);

        self.broadcast_proto_msg_with_gas(
            MsgAddCollaborator::TYPE_URL,
            &msg,
            self.config().gas_multiplier,
        )
        .await
    }

    /// Remove a collaborator from a namespace.
    /// Only the namespace owner can remove collaborators.
    pub async fn bulletin_remove_collaborator(
        &self,
        namespace: &str,
        collaborator: &str,
    ) -> Result<BroadcastResult> {
        let signer = self.require_signer()?;

        let msg = MsgRemoveCollaborator::new(&signer.address(), namespace, collaborator);

        self.broadcast_proto_msg_with_gas(
            MsgRemoveCollaborator::TYPE_URL,
            &msg,
            self.config().gas_multiplier,
        )
        .await
    }
}
