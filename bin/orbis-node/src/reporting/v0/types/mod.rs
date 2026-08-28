use bulletin::r#trait::RingPayload;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::reporting::v0::error::{ReportingError, Result};

mod codec;
mod dkg;
mod envelope;
mod invalid_crypto;
mod pre_sign;
mod relay;

pub use dkg::*;
pub use envelope::*;
pub use invalid_crypto::*;
pub use pre_sign::*;
pub use relay::*;

use codec::{
    write_bool, write_optional_string, write_optional_string_vec, write_optional_u32,
    write_optional_u64, write_reporting_config, write_string, write_string_vec, write_u32,
    write_u64, Decoder,
};

pub const REPORT_DOMAIN: &str = "orbis-mpc-fault-report";
pub const NODE_OFFLINE_REPORT_TYPE: &str = "node_offline";
pub const INVALID_CRYPTO_RESPONSE_REPORT_TYPE: &str = "invalid_crypto_response";
pub const UNAUTHORIZED_REQUEST_REPORT_TYPE: &str = "unauthorized_request";
pub const PRE_REENCRYPT_RESPONSE_DOMAIN: &str = "orbis-pre-reencrypt-response-v1";
pub const SIGN_RESPONSE_DOMAIN: &str = "orbis-sign-response-v1";
pub const DKG_COMMITMENT_DOMAIN: &str = "orbis-dkg-commitment-v1";
pub const DKG_SHARE_DOMAIN: &str = "orbis-dkg-share-v1";
pub const DKG_PUBLIC_ORIGIN_FAULT_DOMAIN: &str = "orbis-dkg-public-origin-fault-v1";
pub const DKG_LEADER_EQUIVOCATION_DOMAIN: &str = "orbis-dkg-leader-equivocation-v1";
pub const DKG_LEADER_PUBLIC_FAULT_DOMAIN: &str = "orbis-dkg-leader-public-fault-v1";
pub const DKG_LEADER_BATCH_MISMATCH_DOMAIN: &str = "orbis-dkg-leader-batch-mismatch-v1";
pub const DKG_CONTROL_MESSAGE_FAULT_DOMAIN: &str = "orbis-dkg-control-message-fault-v1";
pub const RELAY_REQUEST_DOMAIN: &str = "orbis-relay-request-v1";
pub const REPORT_TTL_SECS: u64 = 120;
/// Reporters backdate `observed_at` by this so the `observed_at <= block_time`
/// check passes gas simulation against ~5s blocks. invalid_crypto_response
/// envelopes are pinned to their evidence via
/// `observed_at == signed_at - CHAIN_BLOCK_GRACE_SECS`, which makes the
/// envelope's fixed `observed_at + REPORT_TTL_SECS` expiry double as the
/// evidence expiry — a plain TTL dedupe record on chain then always outlives
/// any resubmission of the same evidence.
pub const CHAIN_BLOCK_GRACE_SECS: u64 = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitteeScope {
    Current,
    PendingNew,
}

impl CommitteeScope {
    fn tag(self) -> u8 {
        match self {
            Self::Current => 1,
            Self::PendingNew => 2,
        }
    }

    fn from_tag(tag: u8) -> Result<Self> {
        match tag {
            1 => Ok(Self::Current),
            2 => Ok(Self::PendingNew),
            value => Err(ReportingError::InvalidReport(format!(
                "unknown committee scope {value}"
            ))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeOffline {
    pub origin_protocol: String,
    pub origin_protocol_version: u64,
    pub accused_committee_scope: CommitteeScope,
    pub signing_committee_scope: CommitteeScope,
}

impl NodeOffline {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        write_string(&mut out, &self.origin_protocol);
        write_u64(&mut out, self.origin_protocol_version);
        out.push(self.accused_committee_scope.tag());
        out.push(self.signing_committee_scope.tag());
        out
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self> {
        let mut decoder = Decoder::new(bytes);
        let origin_protocol = decoder.read_string("origin_protocol")?;
        let origin_protocol_version = decoder.read_u64("origin_protocol_version")?;
        let accused_committee_scope =
            CommitteeScope::from_tag(decoder.read_u8("accused_committee_scope")?)?;
        let signing_committee_scope =
            CommitteeScope::from_tag(decoder.read_u8("signing_committee_scope")?)?;
        decoder.finish()?;
        Ok(Self {
            origin_protocol,
            origin_protocol_version,
            accused_committee_scope,
            signing_committee_scope,
        })
    }
}

pub fn ring_state_sha256(payload: &RingPayload) -> String {
    hex::encode(Sha256::digest(canonical_ring_state_bytes(payload)))
}

pub fn canonical_ring_state_bytes(payload: &RingPayload) -> Vec<u8> {
    let mut out = Vec::new();
    write_string(&mut out, &payload.ring_pk);
    write_string_vec(&mut out, &payload.peer_node_keys);
    write_u32(&mut out, payload.threshold);

    write_optional_string_vec(&mut out, payload.new_peer_node_keys.as_deref());
    write_optional_u32(&mut out, payload.new_threshold);
    write_u64(&mut out, payload.pss_interval);
    write_u64(&mut out, payload.block_number_nonce);
    write_optional_string(&mut out, payload.policy_id.as_deref());
    write_bool(&mut out, payload.trusted_auth_relay_dids.is_some());
    write_string_vec(
        &mut out,
        payload
            .trusted_auth_relay_dids
            .as_deref()
            .unwrap_or_default(),
    );
    write_u64(&mut out, payload.upgrade_info.current_version);
    write_optional_u64(&mut out, payload.upgrade_info.next_version);
    write_optional_u64(&mut out, payload.upgrade_info.activation_time);
    write_reporting_config(&mut out, &payload.reporting);
    out
}

#[cfg(test)]
mod tests;
