//! Wire types for x/bulletin: transaction messages, query request/response types,
//! and domain types.

use prost::Message;

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
