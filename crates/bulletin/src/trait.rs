use crate::error::{BulletinError, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

// Fallbacks used when the chain returns a ring without reporting config. They must mirror
// the sourcehub orbis module's default reporting params: the substituted values feed the
// canonical ring-state hash, so a divergence would have nodes reporting against config the
// chain never stored.
pub const DEFAULT_NODE_OFFLINE_DEMERITS: u64 = 1;
pub const DEFAULT_INVALID_CRYPTO_RESPONSE_DEMERITS: u64 = 1;
pub const DEFAULT_UNAUTHORIZED_REQUEST_DEMERITS: u64 = 1;
pub const DEFAULT_DEMERIT_RESET_INTERVAL_SECONDS: u64 = 86_400;
pub const DEFAULT_REPORTING_KICK_THRESHOLD: u64 = 3;

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct DemeritConfig {
    pub node_offline_demerits: u64,
    pub reset_interval_seconds: u64,
    #[serde(default = "default_invalid_crypto_response_demerits")]
    pub invalid_crypto_response_demerits: u64,
    #[serde(default = "default_unauthorized_request_demerits")]
    pub unauthorized_request_demerits: u64,
}

impl Default for DemeritConfig {
    fn default() -> Self {
        Self {
            node_offline_demerits: DEFAULT_NODE_OFFLINE_DEMERITS,
            reset_interval_seconds: DEFAULT_DEMERIT_RESET_INTERVAL_SECONDS,
            invalid_crypto_response_demerits: DEFAULT_INVALID_CRYPTO_RESPONSE_DEMERITS,
            unauthorized_request_demerits: DEFAULT_UNAUTHORIZED_REQUEST_DEMERITS,
        }
    }
}

fn default_invalid_crypto_response_demerits() -> u64 {
    DEFAULT_INVALID_CRYPTO_RESPONSE_DEMERITS
}

fn default_unauthorized_request_demerits() -> u64 {
    DEFAULT_UNAUTHORIZED_REQUEST_DEMERITS
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct ReportingConfig {
    #[serde(default)]
    pub demerit_config: DemeritConfig,
    #[serde(default)]
    pub backup_node_keys: Vec<String>,
    #[serde(default = "default_reporting_kick_threshold")]
    pub kick_threshold: u64,
}

impl Default for ReportingConfig {
    fn default() -> Self {
        Self {
            demerit_config: DemeritConfig::default(),
            backup_node_keys: Vec::new(),
            kick_threshold: DEFAULT_REPORTING_KICK_THRESHOLD,
        }
    }
}

fn default_reporting_kick_threshold() -> u64 {
    DEFAULT_REPORTING_KICK_THRESHOLD
}

#[derive(Clone, Default, Serialize, Deserialize, Debug, PartialEq)]
pub struct UpgradeInfo {
    pub current_version: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_version: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Unix timestamp in seconds when `next_version` becomes effective.
    pub activation_time: Option<u64>,
}

impl UpgradeInfo {
    /// Resolve the effective protocol version at a captured Unix timestamp.
    pub fn effective_version(&self, current_time: u64) -> Result<u64> {
        match (self.next_version, self.activation_time) {
            (None, None) => Ok(self.current_version),
            (Some(next_version), Some(activation_time)) => {
                if next_version <= self.current_version {
                    return Err(BulletinError::ParseError(format!(
                        "next_version {} must be greater than current_version {}",
                        next_version, self.current_version
                    )));
                }
                if activation_time == 0 {
                    return Err(BulletinError::ParseError(
                        "activation_time must be positive".to_string(),
                    ));
                }
                Ok(if current_time >= activation_time {
                    next_version
                } else {
                    self.current_version
                })
            }
            _ => Err(BulletinError::ParseError(
                "next_version and activation_time must both be set or both be absent".to_string(),
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BulletinKind {
    Ring,
    Document,
    KeyDerivation,
    NodeInfo,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BulletinWriteKind {
    Finalize,
    CancelPendingRing,
    Document,
    KeyDerivation,
    NodeInfo,
}

/// Struct for posting to the Bulletin
#[derive(Clone, Default, Serialize, Deserialize, Debug)]
pub struct BulletinPost {
    pub id: String,
    pub payload: Vec<u8>,
}

/// Payload for storing a secret on bulletin document_id => payload
#[derive(Clone, Default, Serialize, Deserialize, Debug, PartialEq)]
pub struct DocumentPayload {
    /// Id of the Ring to find other information about the ring
    pub ring_id: String,
    /// Encrypted document
    pub document: String,
    /// Chaum-Pedersen NIZK proof of correct encryption (binds policy info to encryption)
    pub proof: String,
    /// Id of the policy associated with document
    pub policy_id: String,
    /// Resource type on said policy
    pub resource: String,
    /// Does the DID have this permission on the policy (the policy expected with this document)
    pub permission: String,
    /// Optional tier for acp check
    pub tier: Option<String>,
    /// Optional timestamp for acp check
    pub timestamp: Option<u64>,
}
/// Payload for ring information ring_id => payload
#[derive(Clone, Default, Serialize, Deserialize, Debug, PartialEq)]
pub struct RingPayload {
    /// Public key of ring
    pub ring_pk: String,
    /// New peer ids to reshare into.
    /// When set, a reshare `SessionInit` is only accepted if its proposed peers match
    /// this field (order-independent).  `None` means the bulletin does not constrain the next
    /// committee — **nodes may still require this field** (e.g. orbis-node enforces a
    /// pre-announced committee for reshare).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_peer_node_keys: Option<Vec<String>>,
    /// Threshold for the new committee announced by `new_peer_node_keys`.
    /// Validated against `SessionKind::Reshare::new_threshold` when present.
    /// `None` means the bulletin does not constrain the new threshold — **nodes may still
    /// require this field** (e.g. orbis-node enforces a pre-announced threshold for reshare).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_threshold: Option<u32>,
    /// Network ids of peers in ring
    pub peer_node_keys: Vec<String>,
    /// Threshold of ring
    pub threshold: u32,
    /// Seconds between automatic PSS refresh ceremonies.
    #[serde(default)]
    pub pss_interval: u64,
    /// Block number of the last threshold-signature update.
    /// Each threshold signature uses this as a nonce. The chain updates it to
    /// the current block number after accepting the signature.
    #[serde(default)]
    pub block_number_nonce: u64,
    /// If set, the ring is updated externally governed by this policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_id: Option<String>,
    /// Relays allowed to authenticate requests for another actor.
    /// `None` permanently disables relays; `Some` enables relay updates.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trusted_auth_relay_dids: Option<Vec<String>>,
    /// Protocol epoch used by this ring and its optional scheduled successor.
    pub upgrade_info: UpgradeInfo,
    /// Fault-report policy and automatic replacement settings for this ring.
    #[serde(default)]
    pub reporting: ReportingConfig,
}

/// Payload for confirming a completed fresh DKG ring.
#[derive(Clone, Default, Serialize, Deserialize, Debug, PartialEq)]
pub struct RingFinalizationPayload {
    /// Id of the pending ring to finalize.
    pub ring_id: String,
    /// Aggregate public key computed by DKG participants.
    pub ring_pk: String,
}

/// Chain-observed state for a fresh-DKG finalization.
///
/// Backends that expose individual confirmations return `Some`; older or
/// non-chain backends may return `None`, in which case a successful `post` is
/// the strongest acknowledgement available.
#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub struct RingFinalizationStatus {
    pub ring_pk: String,
    pub confirmation_node_keys: Option<Vec<String>>,
}

/// Payload for cancelling an unfinished fresh DKG ring.
#[derive(Clone, Default, Serialize, Deserialize, Debug, PartialEq)]
pub struct RingCancellationPayload {
    /// Id of the pending ring to delete.
    pub ring_id: String,
}

/// Payload for derivation information derivation_id => payload
#[derive(Clone, Default, Serialize, Deserialize, Debug, PartialEq)]
pub struct KeyDerivation {
    /// Id of the Ring to find other information about the ring
    pub ring_id: String,
    /// Derivation to be added with policy infomratio to create derivation
    pub derivation: String,
    /// Id of the policy associated with document
    pub policy_id: String,
    /// Resource type on said policy
    pub resource: String,
    /// Does the DID have this permission on the policy (the policy expected with this document)
    pub permission: String,
}

#[derive(Clone, Default, Serialize, Deserialize, Debug, PartialEq)]
pub struct NodeInfo {
    /// Network id of peers in ring
    pub peer_id: String,
    /// Key stored externally from node to control ring participants
    pub controller_key: String,
    /// whitelisted policy IDs that will complete DKG with
    pub whitelisted_policy_ids: Vec<String>,
    /// whitelisted ring_ids to complete DKG with
    pub whitelisted_ring_ids: Vec<String>,
}

impl TryFrom<BulletinPost> for DocumentPayload {
    type Error = BulletinError;

    fn try_from(post: BulletinPost) -> Result<Self> {
        serde_json::from_slice(&post.payload).map_err(|e| BulletinError::ParseError(e.to_string()))
    }
}

impl TryFrom<Vec<u8>> for BulletinPost {
    type Error = BulletinError;

    fn try_from(bytes: Vec<u8>) -> Result<Self> {
        serde_json::from_slice(&bytes).map_err(|e| BulletinError::ParseError(e.to_string()))
    }
}

impl TryFrom<BulletinPost> for Vec<u8> {
    type Error = BulletinError;

    fn try_from(post: BulletinPost) -> Result<Self> {
        serde_json::to_vec(&post).map_err(|e| BulletinError::ParseError(e.to_string()))
    }
}

impl TryFrom<DocumentPayload> for Vec<u8> {
    type Error = BulletinError;

    fn try_from(payload: DocumentPayload) -> Result<Self> {
        serde_json::to_vec(&payload).map_err(|e| BulletinError::ParseError(e.to_string()))
    }
}

impl TryFrom<BulletinPost> for RingPayload {
    type Error = BulletinError;

    fn try_from(post: BulletinPost) -> Result<Self> {
        serde_json::from_slice(&post.payload).map_err(|e| BulletinError::ParseError(e.to_string()))
    }
}

impl TryFrom<RingPayload> for Vec<u8> {
    type Error = BulletinError;

    fn try_from(payload: RingPayload) -> Result<Self> {
        serde_json::to_vec(&payload).map_err(|e| BulletinError::ParseError(e.to_string()))
    }
}

impl TryFrom<BulletinPost> for RingFinalizationPayload {
    type Error = BulletinError;

    fn try_from(post: BulletinPost) -> Result<Self> {
        serde_json::from_slice(&post.payload).map_err(|e| BulletinError::ParseError(e.to_string()))
    }
}

impl TryFrom<RingFinalizationPayload> for Vec<u8> {
    type Error = BulletinError;

    fn try_from(payload: RingFinalizationPayload) -> Result<Self> {
        serde_json::to_vec(&payload).map_err(|e| BulletinError::ParseError(e.to_string()))
    }
}

impl TryFrom<RingCancellationPayload> for Vec<u8> {
    type Error = BulletinError;

    fn try_from(payload: RingCancellationPayload) -> Result<Self> {
        serde_json::to_vec(&payload).map_err(|e| BulletinError::ParseError(e.to_string()))
    }
}

impl TryFrom<BulletinPost> for KeyDerivation {
    type Error = BulletinError;

    fn try_from(post: BulletinPost) -> Result<Self> {
        serde_json::from_slice(&post.payload).map_err(|e| BulletinError::ParseError(e.to_string()))
    }
}

impl TryFrom<KeyDerivation> for Vec<u8> {
    type Error = BulletinError;

    fn try_from(payload: KeyDerivation) -> Result<Self> {
        serde_json::to_vec(&payload).map_err(|e| BulletinError::ParseError(e.to_string()))
    }
}

impl TryFrom<BulletinPost> for NodeInfo {
    type Error = BulletinError;

    fn try_from(post: BulletinPost) -> Result<Self> {
        serde_json::from_slice(&post.payload).map_err(|e| BulletinError::ParseError(e.to_string()))
    }
}

impl TryFrom<NodeInfo> for Vec<u8> {
    type Error = BulletinError;

    fn try_from(payload: NodeInfo) -> Result<Self> {
        serde_json::to_vec(&payload).map_err(|e| BulletinError::ParseError(e.to_string()))
    }
}

/// All fields required to submit a threshold-signed MPC fault report to the chain.
/// Signature must be raw bytes (hex-decoded by the caller before constructing this).
#[derive(Clone, Debug)]
pub struct BulletinReportSubmission {
    pub domain: String,
    pub report_type: String,
    pub chain_id: String,
    pub ring_id: String,
    pub ring_pk: String,
    pub ring_state_sha256: String,
    pub reporter_node_key: String,
    pub accused_node_key: String,
    pub accused_peer_id: String,
    pub observed_at: u64,
    pub expires_at: u64,
    pub payload: Vec<u8>,
    pub session_id: String,
    pub report_id: String,
    pub signature_scheme: String,
    pub signature: Vec<u8>,
}

#[async_trait]
pub trait Bulletin {
    /// Post a typed Orbis object.
    async fn post(&self, kind: BulletinWriteKind, payload: Vec<u8>) -> Result<String>;
    /// Finalize an existing typed Orbis object update while preserving its ID.
    async fn update(&self, id: String, signature_scheme: String, signature: Vec<u8>) -> Result<()>;
    /// Read a typed Orbis object.
    async fn read(&self, id: String, kind: BulletinKind) -> Result<BulletinPost>;
    /// Read fresh-DKG finalization progress. SourceHub overrides this to expose
    /// the exact persisted confirmation set, allowing a node to detect a
    /// successful transaction response whose concurrent state write was lost.
    async fn ring_finalization_status(&self, id: String) -> Result<RingFinalizationStatus> {
        let post = self.read(id, BulletinKind::Ring).await?;
        let ring = RingPayload::try_from(post)?;
        Ok(RingFinalizationStatus {
            ring_pk: ring.ring_pk,
            confirmation_node_keys: None,
        })
    }
    /// Submit a threshold-signed MPC fault report to the chain.
    async fn submit_report(&self, submission: BulletinReportSubmission) -> Result<()>;
    /// Chain ID used when building chain-bound signing statements.
    fn chain_id(&self) -> String;
    /// Serialize the canonical sign bytes for a ring reshare finalization sign doc.
    fn ring_reshare_finalize_sign_bytes(
        &self,
        chain_id: &str,
        ring_id: &str,
        ring_pk: &str,
        current_ring_sha256: Vec<u8>,
        finalized_ring_sha256: Vec<u8>,
        block_number_nonce: u64,
    ) -> Result<Vec<u8>>;
}
