//! Bulletin module types and operations.
//!
//! This module provides types and methods for interacting with Vera's bulletin module,
//! which manages namespaced message posting and retrieval.

use crate::blockchain::{BlockchainError, BroadcastResult, Result, SourceHubClient};
use prost::Message;

pub const RING_RESHARE_FINALIZE_SIGN_DOC_DOMAIN: &str = "orbis-ring-reshare-finalize";

// ============================================================================
// Message Types (for transactions)
// ============================================================================

/// Create a new post in a namespace.
/// Proto field numbers match vera/bulletin/tx.proto:
/// - 1: creator (string)
/// - 2: namespace (string)
/// - 3: payload (bytes)
/// - 5: artifact (string)  [tag 4 was proof, removed; tag 5 preserved]
#[derive(Clone, Message)]
pub struct MsgCreatePost {
    /// Creator's address
    #[prost(string, tag = "1")]
    pub creator: String,
    /// Namespace identifier (combined with post ID)
    #[prost(string, tag = "2")]
    pub namespace: String,
    /// Post payload data
    #[prost(bytes = "vec", tag = "3")]
    pub payload: Vec<u8>,
    /// Artifact for finding post (optional)
    #[prost(string, tag = "5")]
    pub artifact: String,
}

impl MsgCreatePost {
    pub const TYPE_URL: &'static str = "/vera.bulletin.MsgCreatePost";

    /// Create a new post message.
    pub fn new(creator: &str, namespace: &str, payload: Vec<u8>, artifact: Option<String>) -> Self {
        Self {
            creator: creator.to_string(),
            namespace: namespace.to_string(),
            payload,
            artifact: artifact.unwrap_or("".to_string()),
        }
    }
}

/// Update a ring post in a namespace via ACP authorization.
/// Proto field numbers match vera/bulletin/tx.proto:
/// - 1: creator (string)
/// - 2: namespace (string)
/// - 3: post_id (string)
/// - 4: artifact (string)
/// - 5: new_peer_ids (repeated string)
/// - 6: new_threshold (optional uint32)
/// - 7: pss_interval (optional uint64)
#[derive(Clone, Message)]
pub struct MsgUpdateRingPostByAcp {
    /// Creator/updater's address
    #[prost(string, tag = "1")]
    pub creator: String,
    /// Namespace identifier
    #[prost(string, tag = "2")]
    pub namespace: String,
    /// Existing post identifier to update
    #[prost(string, tag = "3")]
    pub post_id: String,
    /// Artifact for finding/tracking update (optional)
    #[prost(string, tag = "4")]
    pub artifact: String,
    /// New peer IDs to reshare into
    #[prost(string, repeated, tag = "5")]
    pub new_peer_ids: Vec<String>,
    /// New threshold for the reshare committee
    #[prost(uint32, optional, tag = "6")]
    pub new_threshold: Option<u32>,
    /// Seconds between automatic PSS refresh ceremonies
    #[prost(uint64, optional, tag = "7")]
    pub pss_interval: Option<u64>,
}

impl MsgUpdateRingPostByAcp {
    pub const TYPE_URL: &'static str = "/vera.bulletin.MsgUpdateRingPostByAcp";

    pub fn new(
        creator: &str,
        namespace: &str,
        post_id: &str,
        artifact: Option<String>,
        new_peer_ids: Vec<String>,
        new_threshold: Option<u32>,
        pss_interval: Option<u64>,
    ) -> Self {
        Self {
            creator: creator.to_string(),
            namespace: namespace.to_string(),
            post_id: post_id.to_string(),
            artifact: artifact.unwrap_or_default(),
            new_peer_ids,
            new_threshold,
            pss_interval,
        }
    }
}

/// Finalize a ring reshare by threshold signature.
/// Proto field numbers match vera/bulletin/tx.proto:
/// - 1: creator (string)
/// - 2: namespace (string)
/// - 3: post_id (string)
/// - 4: artifact (string)
/// - 5: signature_scheme (string)
/// - 6: signature (bytes)
#[derive(Clone, Message)]
pub struct MsgUpdateRingPostByThresholdSignature {
    /// Creator/updater's address
    #[prost(string, tag = "1")]
    pub creator: String,
    /// Namespace identifier
    #[prost(string, tag = "2")]
    pub namespace: String,
    /// Existing post identifier to update
    #[prost(string, tag = "3")]
    pub post_id: String,
    /// Artifact for finding/tracking update (optional)
    #[prost(string, tag = "4")]
    pub artifact: String,
    /// Threshold signature scheme identifier
    #[prost(string, tag = "5")]
    pub signature_scheme: String,
    /// Threshold signature bytes
    #[prost(bytes = "vec", tag = "6")]
    pub signature: Vec<u8>,
}

/// Canonical sign document for finalizing a ring reshare.
/// Canonical sign-doc field numbers:
/// - 1: domain (string)
/// - 2: chain_id (string)
/// - 3: namespace (string)
/// - 4: post_id (string)
/// - 5: ring_pk (string)
/// - 6: current_payload_sha256 (bytes)
/// - 7: finalized_payload_sha256 (bytes)
/// - 8: block_number_nonce (uint64)
#[derive(Clone, Message)]
pub struct RingReshareFinalizeSignDoc {
    #[prost(string, tag = "1")]
    pub domain: String,
    #[prost(string, tag = "2")]
    pub chain_id: String,
    #[prost(string, tag = "3")]
    pub namespace: String,
    #[prost(string, tag = "4")]
    pub post_id: String,
    #[prost(string, tag = "5")]
    pub ring_pk: String,
    #[prost(bytes = "vec", tag = "6")]
    pub current_payload_sha256: Vec<u8>,
    #[prost(bytes = "vec", tag = "7")]
    pub finalized_payload_sha256: Vec<u8>,
    #[prost(uint64, tag = "8")]
    pub block_number_nonce: u64,
}

/// Build Vera-compatible sign bytes for a ring reshare finalization.
pub fn ring_reshare_finalize_sign_bytes_from_hashes(
    chain_id: &str,
    namespace: &str,
    post_id: &str,
    ring_pk: &str,
    current_payload_sha256: Vec<u8>,
    finalized_payload_sha256: Vec<u8>,
    block_number_nonce: u64,
) -> Result<Vec<u8>> {
    if current_payload_sha256.len() != 32 {
        return Err(BlockchainError::Serialization(format!(
            "current_payload_sha256 must be 32 bytes, got {}",
            current_payload_sha256.len()
        )));
    }
    if finalized_payload_sha256.len() != 32 {
        return Err(BlockchainError::Serialization(format!(
            "finalized_payload_sha256 must be 32 bytes, got {}",
            finalized_payload_sha256.len()
        )));
    }

    Ok(RingReshareFinalizeSignDoc {
        domain: RING_RESHARE_FINALIZE_SIGN_DOC_DOMAIN.to_string(),
        chain_id: chain_id.to_string(),
        namespace: namespace.to_string(),
        post_id: post_id.to_string(),
        ring_pk: ring_pk.to_string(),
        current_payload_sha256,
        finalized_payload_sha256,
        block_number_nonce,
    }
    .encode_to_vec())
}

impl MsgUpdateRingPostByThresholdSignature {
    pub const TYPE_URL: &'static str = "/vera.bulletin.MsgUpdateRingPostByThresholdSignature";

    pub fn new(
        creator: &str,
        namespace: &str,
        post_id: &str,
        artifact: Option<String>,
        signature_scheme: &str,
        signature: Vec<u8>,
    ) -> Self {
        Self {
            creator: creator.to_string(),
            namespace: namespace.to_string(),
            post_id: post_id.to_string(),
            artifact: artifact.unwrap_or_default(),
            signature_scheme: signature_scheme.to_string(),
            signature,
        }
    }
}

/// Register a new namespace.
/// Proto field numbers match vera/bulletin/tx.proto:
/// - 1: creator (string)
/// - 2: namespace (string)
#[derive(Clone, Message)]
pub struct MsgRegisterNamespace {
    /// Creator's address (becomes namespace owner)
    #[prost(string, tag = "1")]
    pub creator: String,
    /// Namespace identifier to register
    #[prost(string, tag = "2")]
    pub namespace: String,
}

impl MsgRegisterNamespace {
    pub const TYPE_URL: &'static str = "/vera.bulletin.MsgRegisterNamespace";

    pub fn new(creator: &str, namespace: &str) -> Self {
        Self {
            creator: creator.to_string(),
            namespace: namespace.to_string(),
        }
    }
}

/// Add a collaborator to a namespace.
/// Proto field numbers match vera/bulletin/tx.proto:
/// - 1: creator (string)
/// - 2: namespace (string)
/// - 3: collaborator (string)
#[derive(Clone, Message)]
pub struct MsgAddCollaborator {
    /// Namespace owner's address
    #[prost(string, tag = "1")]
    pub creator: String,
    /// Namespace identifier
    #[prost(string, tag = "2")]
    pub namespace: String,
    /// Collaborator's address to add
    #[prost(string, tag = "3")]
    pub collaborator: String,
}

impl MsgAddCollaborator {
    pub const TYPE_URL: &'static str = "/vera.bulletin.MsgAddCollaborator";

    pub fn new(creator: &str, namespace: &str, collaborator: &str) -> Self {
        Self {
            creator: creator.to_string(),
            namespace: namespace.to_string(),
            collaborator: collaborator.to_string(),
        }
    }
}

/// Remove a collaborator from a namespace.
/// Proto field numbers match vera/bulletin/tx.proto:
/// - 1: creator (string)
/// - 2: namespace (string)
/// - 3: collaborator (string)
#[derive(Clone, Message)]
pub struct MsgRemoveCollaborator {
    /// Namespace owner's address
    #[prost(string, tag = "1")]
    pub creator: String,
    /// Namespace identifier
    #[prost(string, tag = "2")]
    pub namespace: String,
    /// Collaborator's address to remove
    #[prost(string, tag = "3")]
    pub collaborator: String,
}

impl MsgRemoveCollaborator {
    pub const TYPE_URL: &'static str = "/vera.bulletin.MsgRemoveCollaborator";

    pub fn new(creator: &str, namespace: &str, collaborator: &str) -> Self {
        Self {
            creator: creator.to_string(),
            namespace: namespace.to_string(),
            collaborator: collaborator.to_string(),
        }
    }
}

// ============================================================================
// Query Request Types (protobuf-encoded for ABCI queries)
// ============================================================================

/// Request to read a single post.
/// Proto: vera.bulletin.QueryPostRequest
#[derive(Clone, Message)]
pub struct QueryPostRequest {
    /// Namespace identifier
    #[prost(string, tag = "1")]
    pub namespace: String,
    /// Post identifier within the namespace
    #[prost(string, tag = "2")]
    pub id: String,
}

/// Request to get namespace information.
/// Proto: vera.bulletin.QueryNamespaceRequest
#[derive(Clone, Message)]
pub struct QueryNamespaceRequest {
    /// Namespace identifier
    #[prost(string, tag = "1")]
    pub namespace: String,
}

/// Request to list posts in a namespace.
/// Proto: vera.bulletin.QueryNamespacePostsRequest
#[derive(Clone, Message)]
pub struct QueryNamespacePostsRequest {
    /// Namespace identifier
    #[prost(string, tag = "1")]
    pub namespace: String,
    /// Pagination (optional)
    #[prost(message, optional, tag = "2")]
    pub pagination: Option<PageRequest>,
}

/// Request to iterate posts matching a glob pattern.
/// Proto: vera.bulletin.QueryIterateGlobRequest
#[derive(Clone, Message)]
pub struct QueryIterateGlobRequest {
    /// Namespace identifier
    #[prost(string, tag = "1")]
    pub namespace: String,
    /// Glob pattern to match post IDs
    #[prost(string, tag = "2")]
    pub pattern: String,
}

/// Cosmos SDK pagination request.
#[derive(Clone, Message)]
pub struct PageRequest {
    /// Key to start from (for cursor-based pagination)
    #[prost(bytes = "vec", tag = "1")]
    pub key: Vec<u8>,
    /// Offset (for offset-based pagination)
    #[prost(uint64, tag = "2")]
    pub offset: u64,
    /// Maximum number of results
    #[prost(uint64, tag = "3")]
    pub limit: u64,
    /// Count total results (expensive)
    #[prost(bool, tag = "4")]
    pub count_total: bool,
    /// Reverse order
    #[prost(bool, tag = "5")]
    pub reverse: bool,
}

// ============================================================================
// Query Response Types (protobuf-encoded)
// ============================================================================

/// Response containing a single post.
/// Proto: vera.bulletin.QueryPostResponse
#[derive(Clone, Message)]
pub struct QueryPostResponse {
    /// The post data
    #[prost(message, optional, tag = "1")]
    pub post: Option<Post>,
}

/// Response containing namespace information.
/// Proto: vera.bulletin.QueryNamespaceResponse
#[derive(Clone, Message)]
pub struct QueryNamespaceResponse {
    /// The namespace data
    #[prost(message, optional, tag = "1")]
    pub namespace: Option<Namespace>,
}

/// Response containing posts in a namespace.
/// Proto: vera.bulletin.QueryNamespacePostsResponse
#[derive(Clone, Message)]
pub struct QueryNamespacePostsResponse {
    /// List of posts
    #[prost(message, repeated, tag = "1")]
    pub posts: Vec<Post>,
    /// Pagination info
    #[prost(message, optional, tag = "2")]
    pub pagination: Option<PageResponse>,
}

/// Response from glob iteration.
/// Proto: vera.bulletin.QueryIterateGlobResponse
#[derive(Clone, Message)]
pub struct QueryIterateGlobResponse {
    /// Matching posts
    #[prost(message, repeated, tag = "1")]
    pub posts: Vec<Post>,
}

/// Cosmos SDK pagination response.
#[derive(Clone, Message)]
pub struct PageResponse {
    /// Next key for pagination
    #[prost(bytes = "vec", tag = "1")]
    pub next_key: Vec<u8>,
    /// Total count (if requested)
    #[prost(uint64, tag = "2")]
    pub total: u64,
}

// ============================================================================
// Domain Types
// ============================================================================

/// A post stored on the bulletin board.
/// Proto: vera.bulletin.Post
#[derive(Clone, Message)]
pub struct Post {
    /// Post identifier
    #[prost(string, tag = "1")]
    pub id: String,
    /// Namespace this post belongs to
    #[prost(string, tag = "2")]
    pub namespace: String,
    /// Creator's DID
    #[prost(string, tag = "3")]
    pub creator: String,
    /// Post payload data
    #[prost(bytes = "vec", tag = "4")]
    pub payload: Vec<u8>,
    /// Cryptographic proof
    #[prost(bytes = "vec", tag = "5")]
    pub proof: Vec<u8>,
}

/// A namespace in the bulletin module.
/// Proto: vera.bulletin.Namespace
#[derive(Clone, Message)]
pub struct Namespace {
    /// Namespace identifier
    #[prost(string, tag = "1")]
    pub id: String,
    /// Owner's address
    #[prost(string, tag = "2")]
    pub owner: String,
}

/// A collaborator record.
/// Proto: vera.bulletin.Collaborator
#[derive(Clone, Message)]
pub struct Collaborator {
    /// Namespace identifier
    #[prost(string, tag = "1")]
    pub namespace: String,
    /// Collaborator's DID or address
    #[prost(string, tag = "2")]
    pub collaborator_did: String,
}

// ============================================================================
// Client Extension Methods
// ============================================================================

impl SourceHubClient {
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
        let signer = self
            .signer()
            .ok_or_else(|| BlockchainError::Signing("No signer configured".to_string()))?;

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
        let signer = self
            .signer()
            .ok_or_else(|| BlockchainError::Signing("No signer configured".to_string()))?;

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
        let signer = self
            .signer()
            .ok_or_else(|| BlockchainError::Signing("No signer configured".to_string()))?;

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
        let signer = self
            .signer()
            .ok_or_else(|| BlockchainError::Signing("No signer configured".to_string()))?;

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
        let signer = self
            .signer()
            .ok_or_else(|| BlockchainError::Signing("No signer configured".to_string()))?;

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
        let signer = self
            .signer()
            .ok_or_else(|| BlockchainError::Signing("No signer configured".to_string()))?;

        let msg = MsgRemoveCollaborator::new(&signer.address(), namespace, collaborator);

        self.broadcast_proto_msg_with_gas(
            MsgRemoveCollaborator::TYPE_URL,
            &msg,
            self.config().gas_multiplier,
        )
        .await
    }
}
