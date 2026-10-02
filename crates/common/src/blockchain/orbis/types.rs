//! Wire types for x/orbis: on-chain domain state, transaction messages, and query
//! request/response pairs.

use crate::blockchain::bulletin::{PageRequest, PageResponse};
use prost::Message;

// ============================================================================
// Domain Types (on-chain state)
// ============================================================================

/// Ring state stored in x/orbis.
#[derive(Clone, Message)]
pub struct Ring {
    #[prost(string, tag = "1")]
    pub id: String,
    #[prost(string, tag = "2")]
    pub creator_did: String,
    #[prost(string, tag = "3")]
    pub ring_pk: String,
    #[prost(string, repeated, tag = "4")]
    pub peer_node_keys: Vec<String>,
    #[prost(uint32, tag = "5")]
    pub threshold: u32,
    #[prost(string, repeated, tag = "6")]
    pub new_peer_node_keys: Vec<String>,
    #[prost(uint32, optional, tag = "7")]
    pub new_threshold: Option<u32>,
    #[prost(uint64, tag = "8")]
    pub pss_interval: u64,
    #[prost(uint64, tag = "9")]
    pub block_number_nonce: u64,
    #[prost(string, tag = "10")]
    pub policy_id: String,
    /// One entry per peer that has submitted a finalize confirmation. On a
    /// `requires_pet` ring, each entry's `pet_pk` is populated too — a peer
    /// submits both keys together in one `MsgFinalizeRing`, not as two
    /// separate rounds.
    #[prost(message, repeated, tag = "11")]
    pub confirmations: Vec<RingConfirmation>,
    #[prost(message, optional, tag = "12")]
    pub upgrade_info: Option<UpgradeInfo>,
    #[prost(message, optional, tag = "13")]
    pub reporting: Option<ReportingConfig>,
    #[prost(string, repeated, tag = "14")]
    pub trusted_auth_relay_dids: Vec<String>,
    #[prost(bool, tag = "15")]
    pub allow_trusted_auth_relays: bool,
    /// Set at creation; true means this ring requires a PET check before PRE
    /// release, applying to every document in the ring. Immutable for the
    /// ring's lifetime.
    #[prost(bool, tag = "16")]
    pub requires_pet: bool,
    /// The ring's independently-generated PET public key. Absent until its own
    /// fresh-DKG ceremony finalizes (mirrors `ring_pk`, but is a distinct key —
    /// never used for signing).
    #[prost(string, optional, tag = "17")]
    pub pet_pk: Option<String>,
    // tag 18 formerly pet_confirmations; folded into RingConfirmation::pet_pk instead.
}

#[derive(Clone, Message)]
pub struct UpgradeInfo {
    #[prost(uint64, tag = "1")]
    pub current_version: u64,
    #[prost(uint64, optional, tag = "2")]
    pub next_version: Option<u64>,
    #[prost(uint64, optional, tag = "3")]
    pub activation_time: Option<u64>,
}

/// Demerit penalty configuration stored on a ring.
#[derive(Clone, Message)]
pub struct DemeritConfig {
    #[prost(uint64, tag = "1")]
    pub node_offline_demerits: u64,
    #[prost(uint64, tag = "2")]
    pub reset_interval_seconds: u64,
    #[prost(uint64, tag = "3")]
    pub invalid_crypto_response_demerits: u64,
    #[prost(uint64, tag = "4")]
    pub unauthorized_request_demerits: u64,
}

/// Fault-report policy and automatic replacement settings stored on a ring.
#[derive(Clone, Message)]
pub struct ReportingConfig {
    #[prost(message, optional, tag = "1")]
    pub demerit_config: Option<DemeritConfig>,
    #[prost(string, repeated, tag = "2")]
    pub backup_node_keys: Vec<String>,
    #[prost(uint64, tag = "3")]
    pub kick_threshold: u64,
}

/// Fresh-DKG confirmation stored on an unfinalized ring.
#[derive(Clone, Message)]
pub struct RingConfirmation {
    #[prost(string, tag = "1")]
    pub node_key: String,
    #[prost(string, tag = "2")]
    pub ring_pk: String,
    /// Present only when finalizing a `requires_pet` ring — the peer's claimed
    /// PET public key, submitted together with `ring_pk` in the same finalize
    /// message (not an independent confirmation round).
    #[prost(string, optional, tag = "3")]
    pub pet_pk: Option<String>,
}

/// Document state stored in x/orbis.
#[derive(Clone, Message)]
pub struct Document {
    #[prost(string, tag = "1")]
    pub id: String,
    #[prost(string, tag = "2")]
    pub creator_did: String,
    #[prost(string, tag = "3")]
    pub ring_id: String,
    #[prost(string, tag = "4")]
    pub document: String,
    #[prost(string, tag = "5")]
    pub proof: String,
    #[prost(string, tag = "6")]
    pub policy_id: String,
    #[prost(string, tag = "7")]
    pub resource: String,
    #[prost(string, tag = "8")]
    pub permission: String,
    #[prost(string, optional, tag = "9")]
    pub tier: Option<String>,
    #[prost(uint64, optional, tag = "10")]
    pub timestamp: Option<u64>,
    /// PET tag ciphertext, present only when the ring requires PET. JSON of
    /// `{ephemeral_point, masked_fingerprint}`. Present and absent together
    /// with `pet_tag_proof`.
    #[prost(string, optional, tag = "11")]
    pub pet_tag: Option<String>,
    /// Public knowledge proof for `pet_tag`'s `r_tag`, present only alongside
    /// `pet_tag`. JSON of `{challenge, response}`.
    #[prost(string, optional, tag = "12")]
    pub pet_tag_proof: Option<String>,
}

/// Key derivation state stored in x/orbis.
#[derive(Clone, Message)]
pub struct KeyDerivation {
    #[prost(string, tag = "1")]
    pub id: String,
    #[prost(string, tag = "2")]
    pub creator_did: String,
    #[prost(string, tag = "3")]
    pub ring_id: String,
    #[prost(string, tag = "4")]
    pub derivation: String,
    #[prost(string, tag = "5")]
    pub policy_id: String,
    #[prost(string, tag = "6")]
    pub resource: String,
    #[prost(string, tag = "7")]
    pub permission: String,
}

/// Node info stored in x/orbis.
#[derive(Clone, Message)]
pub struct NodeInfo {
    #[prost(string, tag = "1")]
    pub peer_id: String,
    #[prost(string, tag = "2")]
    pub controller_key: String,
    #[prost(string, repeated, tag = "3")]
    pub whitelisted_policy_ids: Vec<String>,
    #[prost(string, repeated, tag = "4")]
    pub whitelisted_ring_ids: Vec<String>,
}

// ============================================================================
// Transaction Message Types
// ============================================================================

#[derive(Clone, Message)]
pub struct MsgCreateRing {
    #[prost(string, tag = "1")]
    pub creator: String,
    #[prost(string, repeated, tag = "2")]
    pub peer_node_keys: Vec<String>,
    #[prost(uint32, tag = "3")]
    pub threshold: u32,
    #[prost(uint64, tag = "4")]
    pub pss_interval: u64,
    #[prost(string, tag = "5")]
    pub policy_id: String,
    #[prost(string, optional, tag = "6")]
    pub nonce: Option<String>,
    #[prost(uint64, tag = "7")]
    pub current_version: u64,
    #[prost(message, optional, tag = "8")]
    pub reporting: Option<ReportingConfig>,
    #[prost(string, repeated, tag = "9")]
    pub trusted_auth_relay_dids: Vec<String>,
    #[prost(bool, tag = "10")]
    pub allow_trusted_auth_relays: bool,
    /// Opt this ring into requiring a PET check before PRE release, applying
    /// to every document in the ring (no per-document opt-out). Immutable
    /// once set. Not yet supported: rejected until the PET checking-key
    /// lifecycle ships.
    #[prost(bool, tag = "11")]
    pub requires_pet: bool,
}

impl MsgCreateRing {
    pub const TYPE_URL: &'static str = "/vera.orbis.MsgCreateRing";

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        creator: &str,
        peer_node_keys: Vec<String>,
        threshold: u32,
        pss_interval: u64,
        policy_id: &str,
        nonce: Option<String>,
        current_version: u64,
        reporting: Option<ReportingConfig>,
        trusted_auth_relay_dids: Option<Vec<String>>,
        requires_pet: bool,
    ) -> Self {
        let allow_trusted_auth_relays = trusted_auth_relay_dids.is_some();
        Self {
            creator: creator.to_string(),
            peer_node_keys,
            threshold,
            pss_interval,
            policy_id: policy_id.to_string(),
            nonce,
            current_version,
            reporting,
            trusted_auth_relay_dids: trusted_auth_relay_dids.unwrap_or_default(),
            allow_trusted_auth_relays,
            requires_pet,
        }
    }
}

#[derive(Clone, Message)]
pub struct MsgCreateRingResponse {
    #[prost(string, tag = "1")]
    pub ring_id: String,
}

#[derive(Clone, Message)]
pub struct MsgStartRingReshareByAcp {
    #[prost(string, tag = "1")]
    pub creator: String,
    #[prost(string, tag = "2")]
    pub ring_id: String,
    #[prost(string, repeated, tag = "3")]
    pub new_peer_node_keys: Vec<String>,
    #[prost(uint32, optional, tag = "4")]
    pub new_threshold: Option<u32>,
}

impl MsgStartRingReshareByAcp {
    pub const TYPE_URL: &'static str = "/vera.orbis.MsgStartRingReshareByAcp";

    pub fn new(
        creator: &str,
        ring_id: &str,
        new_peer_node_keys: Vec<String>,
        new_threshold: Option<u32>,
    ) -> Self {
        Self {
            creator: creator.to_string(),
            ring_id: ring_id.to_string(),
            new_peer_node_keys,
            new_threshold,
        }
    }
}

#[derive(Clone, Message)]
pub struct MsgStartRingReshareByAcpResponse {}

#[derive(Clone, Message)]
pub struct MsgCancelRingReshareByAcp {
    #[prost(string, tag = "1")]
    pub creator: String,
    #[prost(string, tag = "2")]
    pub ring_id: String,
}

impl MsgCancelRingReshareByAcp {
    pub const TYPE_URL: &'static str = "/vera.orbis.MsgCancelRingReshareByAcp";

    pub fn new(creator: &str, ring_id: &str) -> Self {
        Self {
            creator: creator.to_string(),
            ring_id: ring_id.to_string(),
        }
    }
}

#[derive(Clone, Message)]
pub struct MsgCancelRingReshareByAcpResponse {}

#[derive(Clone, Message)]
pub struct MsgSetRingPssIntervalByAcp {
    #[prost(string, tag = "1")]
    pub creator: String,
    #[prost(string, tag = "2")]
    pub ring_id: String,
    #[prost(uint64, tag = "3")]
    pub pss_interval: u64,
}

impl MsgSetRingPssIntervalByAcp {
    pub const TYPE_URL: &'static str = "/vera.orbis.MsgSetRingPssIntervalByAcp";

    pub fn new(creator: &str, ring_id: &str, pss_interval: u64) -> Self {
        Self {
            creator: creator.to_string(),
            ring_id: ring_id.to_string(),
            pss_interval,
        }
    }
}

#[derive(Clone, Message)]
pub struct MsgSetRingPssIntervalByAcpResponse {}

#[derive(Clone, Message)]
pub struct MsgSetRingReportingByAcp {
    #[prost(string, tag = "1")]
    pub creator: String,
    #[prost(string, tag = "2")]
    pub ring_id: String,
    #[prost(message, optional, tag = "3")]
    pub reporting: Option<ReportingConfig>,
}

impl MsgSetRingReportingByAcp {
    pub const TYPE_URL: &'static str = "/vera.orbis.MsgSetRingReportingByAcp";

    pub fn new(creator: &str, ring_id: &str, reporting: ReportingConfig) -> Self {
        Self {
            creator: creator.to_string(),
            ring_id: ring_id.to_string(),
            reporting: Some(reporting),
        }
    }
}

#[derive(Clone, Message)]
pub struct MsgSetRingReportingByAcpResponse {}

#[derive(Clone, Message)]
pub struct MsgAddRingTrustedAuthRelayByAcp {
    #[prost(string, tag = "1")]
    pub creator: String,
    #[prost(string, tag = "2")]
    pub ring_id: String,
    #[prost(string, tag = "3")]
    pub relay_did: String,
}

impl MsgAddRingTrustedAuthRelayByAcp {
    pub const TYPE_URL: &'static str = "/vera.orbis.MsgAddRingTrustedAuthRelayByAcp";

    pub fn new(creator: &str, ring_id: &str, relay_did: &str) -> Self {
        Self {
            creator: creator.to_string(),
            ring_id: ring_id.to_string(),
            relay_did: relay_did.to_string(),
        }
    }
}

#[derive(Clone, Message)]
pub struct MsgAddRingTrustedAuthRelayByAcpResponse {}

#[derive(Clone, Message)]
pub struct MsgRemoveRingTrustedAuthRelayByAcp {
    #[prost(string, tag = "1")]
    pub creator: String,
    #[prost(string, tag = "2")]
    pub ring_id: String,
    #[prost(string, tag = "3")]
    pub relay_did: String,
}

impl MsgRemoveRingTrustedAuthRelayByAcp {
    pub const TYPE_URL: &'static str = "/vera.orbis.MsgRemoveRingTrustedAuthRelayByAcp";

    pub fn new(creator: &str, ring_id: &str, relay_did: &str) -> Self {
        Self {
            creator: creator.to_string(),
            ring_id: ring_id.to_string(),
            relay_did: relay_did.to_string(),
        }
    }
}

#[derive(Clone, Message)]
pub struct MsgRemoveRingTrustedAuthRelayByAcpResponse {}

#[derive(Clone, Message)]
pub struct MsgScheduleRingUpgradeByAcp {
    #[prost(string, tag = "1")]
    pub creator: String,
    #[prost(string, tag = "2")]
    pub ring_id: String,
    #[prost(uint64, tag = "3")]
    pub next_version: u64,
    #[prost(uint64, tag = "4")]
    pub activation_time: u64,
}

impl MsgScheduleRingUpgradeByAcp {
    pub const TYPE_URL: &'static str = "/vera.orbis.MsgScheduleRingUpgradeByAcp";

    pub fn new(creator: &str, ring_id: &str, next_version: u64, activation_time: u64) -> Self {
        Self {
            creator: creator.to_string(),
            ring_id: ring_id.to_string(),
            next_version,
            activation_time,
        }
    }
}

#[derive(Clone, Message)]
pub struct MsgScheduleRingUpgradeByAcpResponse {}

#[derive(Clone, Message)]
pub struct MsgCancelRingUpgradeByAcp {
    #[prost(string, tag = "1")]
    pub creator: String,
    #[prost(string, tag = "2")]
    pub ring_id: String,
}

impl MsgCancelRingUpgradeByAcp {
    pub const TYPE_URL: &'static str = "/vera.orbis.MsgCancelRingUpgradeByAcp";

    pub fn new(creator: &str, ring_id: &str) -> Self {
        Self {
            creator: creator.to_string(),
            ring_id: ring_id.to_string(),
        }
    }
}

#[derive(Clone, Message)]
pub struct MsgCancelRingUpgradeByAcpResponse {}

#[derive(Clone, Message)]
pub struct MsgCancelPendingRing {
    #[prost(string, tag = "1")]
    pub creator: String,
    #[prost(string, tag = "2")]
    pub ring_id: String,
}

impl MsgCancelPendingRing {
    pub const TYPE_URL: &'static str = "/vera.orbis.MsgCancelPendingRing";

    pub fn new(creator: &str, ring_id: &str) -> Self {
        Self {
            creator: creator.to_string(),
            ring_id: ring_id.to_string(),
        }
    }
}

#[derive(Clone, Message)]
pub struct MsgCancelPendingRingResponse {}

#[derive(Clone, Message)]
pub struct MsgFinalizeRing {
    #[prost(string, tag = "1")]
    pub creator: String,
    #[prost(string, tag = "2")]
    pub ring_id: String,
    #[prost(string, tag = "3")]
    pub ring_pk: String,
    /// Required, and only accepted, when the ring's `requires_pet` is true:
    /// the signer's local fresh-DKG PET key ceremony completed alongside the
    /// main one, and both are submitted together in this one finalize message.
    #[prost(string, optional, tag = "4")]
    pub pet_pk: Option<String>,
}

impl MsgFinalizeRing {
    pub const TYPE_URL: &'static str = "/vera.orbis.MsgFinalizeRing";

    pub fn new(creator: &str, ring_id: &str, ring_pk: &str, pet_pk: Option<String>) -> Self {
        Self {
            creator: creator.to_string(),
            ring_id: ring_id.to_string(),
            ring_pk: ring_pk.to_string(),
            pet_pk,
        }
    }
}

#[derive(Clone, Message)]
pub struct MsgFinalizeRingResponse {}

#[derive(Clone, Message)]
pub struct MsgFinalizeRingReshareByThresholdSignature {
    #[prost(string, tag = "1")]
    pub creator: String,
    #[prost(string, tag = "2")]
    pub ring_id: String,
    #[prost(string, tag = "3")]
    pub signature_scheme: String,
    #[prost(bytes = "vec", tag = "4")]
    pub signature: Vec<u8>,
}

impl MsgFinalizeRingReshareByThresholdSignature {
    pub const TYPE_URL: &'static str = "/vera.orbis.MsgFinalizeRingReshareByThresholdSignature";

    pub fn new(creator: &str, ring_id: &str, signature_scheme: &str, signature: Vec<u8>) -> Self {
        Self {
            creator: creator.to_string(),
            ring_id: ring_id.to_string(),
            signature_scheme: signature_scheme.to_string(),
            signature,
        }
    }
}

#[derive(Clone, Message)]
pub struct MsgStoreDocument {
    #[prost(string, tag = "1")]
    pub creator: String,
    #[prost(string, tag = "2")]
    pub ring_id: String,
    #[prost(string, tag = "3")]
    pub document: String,
    #[prost(string, tag = "4")]
    pub proof: String,
    #[prost(string, tag = "5")]
    pub policy_id: String,
    #[prost(string, tag = "6")]
    pub resource: String,
    #[prost(string, tag = "7")]
    pub permission: String,
    #[prost(string, optional, tag = "8")]
    pub tier: Option<String>,
    #[prost(uint64, optional, tag = "9")]
    pub timestamp: Option<u64>,
    /// PET tag ciphertext, present only when the ring requires PET. JSON of
    /// `{ephemeral_point, masked_fingerprint}`. Present and absent together
    /// with `pet_tag_proof`.
    #[prost(string, optional, tag = "10")]
    pub pet_tag: Option<String>,
    /// Public knowledge proof for `pet_tag`'s `r_tag`, present only alongside
    /// `pet_tag`. JSON of `{challenge, response}`.
    #[prost(string, optional, tag = "11")]
    pub pet_tag_proof: Option<String>,
}

impl MsgStoreDocument {
    pub const TYPE_URL: &'static str = "/vera.orbis.MsgStoreDocument";
}

#[derive(Clone, Message)]
pub struct MsgStoreDocumentResponse {
    #[prost(string, tag = "1")]
    pub document_id: String,
}

#[derive(Clone, Message)]
pub struct MsgStoreKeyDerivation {
    #[prost(string, tag = "1")]
    pub creator: String,
    #[prost(string, tag = "2")]
    pub ring_id: String,
    #[prost(string, tag = "3")]
    pub derivation: String,
    #[prost(string, tag = "4")]
    pub policy_id: String,
    #[prost(string, tag = "5")]
    pub resource: String,
    #[prost(string, tag = "6")]
    pub permission: String,
}

impl MsgStoreKeyDerivation {
    pub const TYPE_URL: &'static str = "/vera.orbis.MsgStoreKeyDerivation";
}

#[derive(Clone, Message)]
pub struct MsgStoreKeyDerivationResponse {
    #[prost(string, tag = "1")]
    pub key_derivation_id: String,
}

#[derive(Clone, Message)]
pub struct MsgCreateNodeInfo {
    #[prost(string, tag = "1")]
    pub creator: String,
    #[prost(string, tag = "2")]
    pub peer_id: String,
    #[prost(string, tag = "3")]
    pub controller_key: String,
    #[prost(string, repeated, tag = "4")]
    pub whitelisted_policy_ids: Vec<String>,
    #[prost(string, repeated, tag = "5")]
    pub whitelisted_ring_ids: Vec<String>,
}

impl MsgCreateNodeInfo {
    pub const TYPE_URL: &'static str = "/vera.orbis.MsgCreateNodeInfo";
}

#[derive(Clone, Message)]
pub struct MsgCreateNodeInfoResponse {}

#[derive(Clone, Message)]
pub struct MsgUpdateNodePeerId {
    #[prost(string, tag = "1")]
    pub creator: String,
    #[prost(string, tag = "2")]
    pub node_key: String,
    #[prost(string, tag = "3")]
    pub peer_id: String,
}

impl MsgUpdateNodePeerId {
    pub const TYPE_URL: &'static str = "/vera.orbis.MsgUpdateNodePeerId";

    pub fn new(creator: &str, node_key: &str, peer_id: &str) -> Self {
        Self {
            creator: creator.to_string(),
            node_key: node_key.to_string(),
            peer_id: peer_id.to_string(),
        }
    }
}

#[derive(Clone, Message)]
pub struct MsgUpdateNodePeerIdResponse {}

#[derive(Clone, Message)]
pub struct MsgTransferNodeController {
    #[prost(string, tag = "1")]
    pub creator: String,
    #[prost(string, tag = "2")]
    pub node_key: String,
    #[prost(string, tag = "3")]
    pub controller_key: String,
}

impl MsgTransferNodeController {
    pub const TYPE_URL: &'static str = "/vera.orbis.MsgTransferNodeController";

    pub fn new(creator: &str, node_key: &str, controller_key: &str) -> Self {
        Self {
            creator: creator.to_string(),
            node_key: node_key.to_string(),
            controller_key: controller_key.to_string(),
        }
    }
}

#[derive(Clone, Message)]
pub struct MsgTransferNodeControllerResponse {}

/// For `MsgAddNodeToWhitelist` and `MsgRemoveNodeFromWhitelist` oneof target.
pub enum WhitelistTarget {
    PolicyId(String),
    RingId(String),
}

#[derive(Clone, Message)]
pub struct MsgAddNodeToWhitelist {
    #[prost(string, tag = "1")]
    pub creator: String,
    #[prost(string, tag = "2")]
    pub node_key: String,
    #[prost(string, optional, tag = "3")]
    pub policy_id: Option<String>,
    #[prost(string, optional, tag = "4")]
    pub ring_id: Option<String>,
}

impl MsgAddNodeToWhitelist {
    pub const TYPE_URL: &'static str = "/vera.orbis.MsgAddNodeToWhitelist";

    pub fn new(creator: &str, node_key: &str, target: WhitelistTarget) -> Self {
        let (policy_id, ring_id) = match target {
            WhitelistTarget::PolicyId(id) => (Some(id), None),
            WhitelistTarget::RingId(id) => (None, Some(id)),
        };
        Self {
            creator: creator.to_string(),
            node_key: node_key.to_string(),
            policy_id,
            ring_id,
        }
    }
}

#[derive(Clone, Message)]
pub struct MsgAddNodeToWhitelistResponse {}

#[derive(Clone, Message)]
pub struct MsgRemoveNodeFromWhitelist {
    #[prost(string, tag = "1")]
    pub creator: String,
    #[prost(string, tag = "2")]
    pub node_key: String,
    #[prost(string, optional, tag = "3")]
    pub policy_id: Option<String>,
    #[prost(string, optional, tag = "4")]
    pub ring_id: Option<String>,
}

impl MsgRemoveNodeFromWhitelist {
    pub const TYPE_URL: &'static str = "/vera.orbis.MsgRemoveNodeFromWhitelist";

    pub fn new(creator: &str, node_key: &str, target: WhitelistTarget) -> Self {
        let (policy_id, ring_id) = match target {
            WhitelistTarget::PolicyId(id) => (Some(id), None),
            WhitelistTarget::RingId(id) => (None, Some(id)),
        };
        Self {
            creator: creator.to_string(),
            node_key: node_key.to_string(),
            policy_id,
            ring_id,
        }
    }
}

#[derive(Clone, Message)]
pub struct MsgRemoveNodeFromWhitelistResponse {}

#[derive(Clone, Message)]
pub struct ReportEnvelopeProto {
    #[prost(string, tag = "1")]
    pub domain: String,
    #[prost(string, tag = "2")]
    pub report_type: String,
    #[prost(string, tag = "3")]
    pub chain_id: String,
    #[prost(string, tag = "4")]
    pub ring_id: String,
    #[prost(string, tag = "5")]
    pub ring_pk: String,
    #[prost(string, tag = "6")]
    pub ring_state_sha256: String,
    #[prost(string, tag = "7")]
    pub reporter_node_key: String,
    #[prost(string, tag = "8")]
    pub accused_node_key: String,
    #[prost(string, tag = "9")]
    pub accused_peer_id: String,
    #[prost(uint64, tag = "10")]
    pub observed_at: u64,
    #[prost(uint64, tag = "11")]
    pub expires_at: u64,
    #[prost(bytes = "vec", tag = "12")]
    pub payload: Vec<u8>,
    #[prost(string, tag = "13")]
    pub session_id: String,
}

#[derive(Clone, Message)]
pub struct MsgSubmitReport {
    #[prost(string, tag = "1")]
    pub creator: String,
    #[prost(message, optional, tag = "2")]
    pub report: Option<ReportEnvelopeProto>,
    #[prost(string, tag = "3")]
    pub report_id: String,
    #[prost(string, tag = "4")]
    pub signature_scheme: String,
    #[prost(bytes = "vec", tag = "5")]
    pub signature: Vec<u8>,
}

impl MsgSubmitReport {
    pub const TYPE_URL: &'static str = "/vera.orbis.MsgSubmitReport";
}

#[derive(Clone, Message)]
pub struct MsgSubmitReportResponse {}

/// Typed request for [`OrbisChainClient::orbis_submit_report`].
///
/// Using a struct prevents silent swaps between the several adjacent `String`
/// fields (`session_id`, `report_id`, `signature_scheme`) that would not be
/// caught by the compiler with positional arguments.
pub struct SubmitReportRequest {
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

// ============================================================================
// Query Request/Response Types
// ============================================================================

#[derive(Clone, Message)]
pub struct QueryRingRequest {
    #[prost(string, tag = "1")]
    pub id: String,
}

#[derive(Clone, Message)]
pub struct QueryRingResponse {
    #[prost(message, optional, tag = "1")]
    pub ring: Option<Ring>,
}

#[derive(Clone, Message)]
pub struct QueryRingsRequest {
    #[prost(message, optional, tag = "1")]
    pub pagination: Option<PageRequest>,
}

#[derive(Clone, Message)]
pub struct QueryRingsResponse {
    #[prost(message, repeated, tag = "1")]
    pub rings: Vec<Ring>,
    #[prost(message, optional, tag = "2")]
    pub pagination: Option<PageResponse>,
}

#[derive(Clone, Message)]
pub struct QueryDocumentRequest {
    #[prost(string, tag = "1")]
    pub id: String,
}

#[derive(Clone, Message)]
pub struct QueryDocumentResponse {
    #[prost(message, optional, tag = "1")]
    pub document: Option<Document>,
}

#[derive(Clone, Message)]
pub struct QueryDocumentsRequest {
    #[prost(message, optional, tag = "1")]
    pub pagination: Option<PageRequest>,
}

#[derive(Clone, Message)]
pub struct QueryDocumentsResponse {
    #[prost(message, repeated, tag = "1")]
    pub documents: Vec<Document>,
    #[prost(message, optional, tag = "2")]
    pub pagination: Option<PageResponse>,
}

#[derive(Clone, Message)]
pub struct QueryKeyDerivationRequest {
    #[prost(string, tag = "1")]
    pub id: String,
}

#[derive(Clone, Message)]
pub struct QueryKeyDerivationResponse {
    #[prost(message, optional, tag = "1")]
    pub key_derivation: Option<KeyDerivation>,
}

#[derive(Clone, Message)]
pub struct QueryKeyDerivationsRequest {
    #[prost(message, optional, tag = "1")]
    pub pagination: Option<PageRequest>,
}

#[derive(Clone, Message)]
pub struct QueryKeyDerivationsResponse {
    #[prost(message, repeated, tag = "1")]
    pub key_derivations: Vec<KeyDerivation>,
    #[prost(message, optional, tag = "2")]
    pub pagination: Option<PageResponse>,
}

#[derive(Clone, Message)]
pub struct QueryNodeInfoRequest {
    #[prost(string, tag = "1")]
    pub node_key: String,
}

#[derive(Clone, Message)]
pub struct QueryNodeInfoResponse {
    #[prost(message, optional, tag = "1")]
    pub node_info: Option<NodeInfo>,
}

#[derive(Clone, Message)]
pub struct QueryNodeDemeritsRequest {
    #[prost(string, tag = "1")]
    pub ring_id: String,
    #[prost(string, tag = "2")]
    pub node_key: String,
}

#[derive(Clone, Message)]
pub struct QueryNodeDemeritsResponse {
    #[prost(uint64, tag = "1")]
    pub points: u64,
}

#[derive(Clone, Message)]
pub struct QueryAcceptedReportSessionRequest {
    #[prost(string, tag = "1")]
    pub ring_id: String,
    #[prost(string, tag = "2")]
    pub report_type: String,
    #[prost(string, tag = "3")]
    pub origin_protocol: String,
    #[prost(string, tag = "4")]
    pub accused_node_key: String,
    #[prost(string, tag = "5")]
    pub session_id: String,
    /// Leave empty for ceremony-scoped report kinds (node_offline,
    /// unauthorized_request); only attempt-scoped kinds need this set.
    #[prost(bytes = "vec", tag = "6")]
    pub attempt_id: Vec<u8>,
}

#[derive(Clone, Message)]
pub struct QueryAcceptedReportSessionResponse {
    #[prost(bool, tag = "1")]
    pub accepted: bool,
}
