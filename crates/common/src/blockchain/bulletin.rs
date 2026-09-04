//! Bulletin module types and operations.
//!
//! This module provides types and methods for interacting with SourceHub's bulletin module,
//! which manages namespaced message posting and retrieval.

use crate::blockchain::{BlockchainError, BroadcastResult, Result, SourceHubClient};
use prost::Message;

// ============================================================================
// Message Types (for transactions)
// ============================================================================

/// Create a new post in a namespace.
/// Proto field numbers match sourcehub/bulletin/tx.proto:
/// - 1: creator (string)
/// - 2: namespace (string)
/// - 3: payload (bytes)
/// - 4: proof (bytes)
/// - 5: artifact (string)
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
    ///
    /// Tag 4 was a `proof` field that Vera's `MsgCreatePost` does not have.
    /// Sending it makes the chain reject the transaction at decode time with
    /// `errUnknownField "*types.MsgCreatePost": {TagNum: 4}`.
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

/// Register a new namespace.
/// Proto field numbers match sourcehub/bulletin/tx.proto:
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
/// Proto field numbers match sourcehub/bulletin/tx.proto:
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
/// Proto field numbers match sourcehub/bulletin/tx.proto:
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

        let response_bytes = match self.abci_query(path, request_bytes, None, false).await {
            Ok(bytes) => bytes,
            Err(BlockchainError::NotFound(_)) => return Ok(None),
            Err(e) => return Err(e),
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

    /// Create a post in a namespace.
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

    /// Create a post in a namespace, given a proof the caller holds.
    ///
    /// Vera's `MsgCreatePost` carries no proof field, so the proof is not
    /// persisted on chain. A caller passing a non-empty proof is warned rather
    /// than silently ignored, because a dropped proof is not visible in the
    /// result.
    pub async fn bulletin_create_post_with_proof(
        &self,
        namespace: &str,
        payload: Vec<u8>,
        proof: Vec<u8>,
        artifact: Option<String>,
    ) -> Result<BroadcastResult> {
        let signer = self
            .signer()
            .ok_or_else(|| BlockchainError::Signing("No signer configured".to_string()))?;

        if !proof.is_empty() {
            eprintln!(
                "bulletin_create_post_with_proof: dropping a {}-byte proof for namespace {}: \
                 Vera's MsgCreatePost has no proof field",
                proof.len(),
                namespace
            );
        }
        let msg = MsgCreatePost::new(&signer.address(), namespace, payload, artifact);

        self.broadcast_proto_msg_with_gas(
            MsgCreatePost::TYPE_URL,
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

#[cfg(test)]
mod message_shape_tests {
    use super::{MsgCreatePost, MsgRegisterNamespace};
    use prost::Message;

    /// A permissive view of `MsgCreatePost` that keeps the removed field 4, so
    /// a test can prove the encoder never writes it.
    #[derive(Clone, PartialEq, Message)]
    struct PostWithLegacyProof {
        #[prost(string, tag = "1")]
        creator: String,
        #[prost(string, tag = "2")]
        namespace: String,
        #[prost(bytes = "vec", tag = "3")]
        payload: Vec<u8>,
        #[prost(bytes = "vec", tag = "4")]
        legacy_proof: Vec<u8>,
        #[prost(string, tag = "5")]
        artifact: String,
    }

    /// Vera's `MsgCreatePost` has no field 4. Sending one makes the chain
    /// reject the whole transaction at decode time with
    /// `errUnknownField "*types.MsgCreatePost": {TagNum: 4}`, which surfaces as
    /// a failed DKG rather than as a bulletin error, so it is worth pinning.
    #[test]
    fn create_post_never_encodes_the_removed_proof_field() {
        let msg = MsgCreatePost::new(
            "vera1creator",
            "orbis",
            b"ring payload".to_vec(),
            Some("session-1".to_string()),
        );
        let encoded = msg.encode_to_vec();

        let decoded = PostWithLegacyProof::decode(encoded.as_slice()).expect("decode");
        assert!(
            decoded.legacy_proof.is_empty(),
            "field 4 must not be on the wire"
        );
        assert_eq!(decoded.creator, "vera1creator");
        assert_eq!(decoded.namespace, "orbis");
        assert_eq!(decoded.payload, b"ring payload");
        assert_eq!(decoded.artifact, "session-1");
    }

    /// The type URLs name Vera's proto package. The chain routes on these
    /// exactly, so a stale `sourcehub.` prefix is an unroutable transaction.
    #[test]
    fn type_urls_are_vera_qualified() {
        assert_eq!(MsgCreatePost::TYPE_URL, "/vera.bulletin.MsgCreatePost");
        assert_eq!(
            MsgRegisterNamespace::TYPE_URL,
            "/vera.bulletin.MsgRegisterNamespace"
        );
    }
}
