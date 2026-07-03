use crate::dkg::v0::error::DkgError;
use crate::helpers::identity::extract_node_part;
use crate::helpers::ring::RingConfig;
use crate::pre::v0::error::PreError;
use crate::reporting::v0::types::{
    CommitteeScope, PreInvalidReencryptionProof, NODE_OFFLINE_REPORT_TYPE,
    PRE_INVALID_REENCRYPTION_PROOF_REPORT_TYPE,
};
use crate::sign::v0::error::SignError;

#[derive(Debug, Clone)]
pub struct OfflineObservation {
    pub ring_id: String,
    pub accused_node_key: String,
    pub accused_peer_id: String,
    pub origin_protocol: String,
    pub origin_protocol_version: u64,
    pub accused_committee_scope: CommitteeScope,
    pub signing_committee_scope: CommitteeScope,
    pub observed_at: u64,
    pub session_id: String,
}

#[derive(Debug, Clone)]
pub struct PreInvalidReencryptionProofObservation {
    pub ring_id: String,
    pub accused_node_key: String,
    pub accused_peer_id: String,
    pub observed_at: u64,
    pub evidence: PreInvalidReencryptionProof,
}

#[derive(Debug, Clone)]
pub enum ReportObservation {
    NodeOffline(OfflineObservation),
    PreInvalidReencryptionProof(Box<PreInvalidReencryptionProofObservation>),
}

impl ReportObservation {
    pub fn report_type(&self) -> &'static str {
        match self {
            Self::NodeOffline(_) => NODE_OFFLINE_REPORT_TYPE,
            Self::PreInvalidReencryptionProof(_) => PRE_INVALID_REENCRYPTION_PROOF_REPORT_TYPE,
        }
    }
}

pub fn offline_observation_from_pre_error(
    ring: &RingConfig,
    peer_id: &str,
    error: &PreError,
    protocol_version: u64,
    session_id: &str,
) -> Option<OfflineObservation> {
    if !is_reportable_pre_offline_error(error) {
        return None;
    }

    offline_observation_from_ring_config(
        ring,
        peer_id,
        "pre",
        protocol_version,
        CommitteeScope::Current,
        CommitteeScope::Current,
        session_id,
    )
}

#[cfg(test)]
pub fn offline_observation_from_sign_error(
    ring: &RingConfig,
    peer_id: &str,
    error: &SignError,
    protocol_version: u64,
    session_id: &str,
) -> Option<OfflineObservation> {
    if !is_reportable_sign_offline_error(error) {
        return None;
    }

    offline_observation_from_ring_config(
        ring,
        peer_id,
        "sign",
        protocol_version,
        CommitteeScope::Current,
        CommitteeScope::Current,
        session_id,
    )
}

pub fn offline_observation_from_sign_error_scoped(
    ring: &RingConfig,
    peer_id: &str,
    error: &SignError,
    origin_protocol: &str,
    protocol_version: u64,
    accused_committee_scope: CommitteeScope,
    signing_committee_scope: CommitteeScope,
    session_id: &str,
) -> Option<OfflineObservation> {
    if !is_reportable_sign_offline_error(error) {
        return None;
    }

    offline_observation_from_ring_config(
        ring,
        peer_id,
        origin_protocol,
        protocol_version,
        accused_committee_scope,
        signing_committee_scope,
        session_id,
    )
}

pub fn is_reportable_dkg_offline_error(error: &DkgError) -> bool {
    match error {
        DkgError::NetworkConnection(_) => true,
        DkgError::NetworkCommunication(message) if message.starts_with("Failed to send") => true,
        _ => false,
    }
}

fn is_reportable_pre_offline_error(error: &PreError) -> bool {
    match error {
        PreError::NetworkConnection(_) => true,
        PreError::NetworkCommunication(message) if message.starts_with("Failed to send") => true,
        PreError::NetworkCommunication(message) if message.starts_with("Failed to receive") => true,
        PreError::Timeout(_) => true,
        _ => false,
    }
}

fn is_reportable_sign_offline_error(error: &SignError) -> bool {
    match error {
        SignError::NetworkConnection(_) => true,
        SignError::NetworkCommunication(message) if message.starts_with("Failed to send") => true,
        SignError::NetworkCommunication(message) if message.starts_with("Failed to receive") => {
            true
        }
        SignError::Timeout(_) => true,
        _ => false,
    }
}

pub fn offline_observation_from_peer_routes(
    ring_id: &str,
    peer_ids: &[String],
    peer_node_keys: &[String],
    peer_id: &str,
    origin_protocol: &str,
    protocol_version: u64,
    accused_committee_scope: CommitteeScope,
    signing_committee_scope: CommitteeScope,
    session_id: &str,
) -> Option<OfflineObservation> {
    let peer_part = extract_node_part(peer_id);
    let accused_node_key = peer_node_keys
        .iter()
        .zip(peer_ids.iter())
        .find(|(_, route)| extract_node_part(route) == peer_part)
        .map(|(node_key, _)| node_key.clone())?;

    // Subtract a grace period so observed_at is behind the chain's latest block time.
    // Gas simulation checks observed_at <= block_time; blocks are ~5s apart, so without
    // this buffer the check fails when the report is submitted before the next block.
    const CHAIN_BLOCK_GRACE_SECS: u64 = 10;
    let observed_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs()
        .saturating_sub(CHAIN_BLOCK_GRACE_SECS);

    Some(OfflineObservation {
        ring_id: ring_id.to_string(),
        accused_node_key,
        accused_peer_id: peer_id.to_string(),
        origin_protocol: origin_protocol.to_string(),
        origin_protocol_version: protocol_version,
        accused_committee_scope,
        signing_committee_scope,
        observed_at,
        session_id: session_id.to_string(),
    })
}

fn offline_observation_from_ring_config(
    ring: &RingConfig,
    peer_id: &str,
    origin_protocol: &str,
    protocol_version: u64,
    accused_committee_scope: CommitteeScope,
    signing_committee_scope: CommitteeScope,
    session_id: &str,
) -> Option<OfflineObservation> {
    offline_observation_from_peer_routes(
        &ring.ring_id,
        &ring.peer_ids,
        &ring.peer_node_keys,
        peer_id,
        origin_protocol,
        protocol_version,
        accused_committee_scope,
        signing_committee_scope,
        session_id,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ring() -> RingConfig {
        RingConfig {
            ring_id: "ring".to_string(),
            ring_pk_bytes: vec![],
            peer_ids: vec!["aa".repeat(32)],
            peer_node_keys: vec!["node-a".to_string()],
            threshold: 1,
            total_participants: 1,
            public_polynomial_hex: String::new(),
        }
    }

    #[test]
    fn peer_not_in_ring_returns_none() {
        let ring = ring();
        let unknown_peer = "bb".repeat(32);
        assert!(offline_observation_from_pre_error(
            &ring,
            &unknown_peer,
            &PreError::NetworkConnection("down".into()),
            0,
            "pre-request-1",
        )
        .is_none());
    }

    #[test]
    fn classifies_only_transport_failures() {
        let ring = ring();
        let pre_observation = offline_observation_from_pre_error(
            &ring,
            &ring.peer_ids[0],
            &PreError::Timeout("timeout".into()),
            0,
            "pre-request-1",
        )
        .unwrap();
        assert_eq!(pre_observation.session_id, "pre-request-1");
        assert!(offline_observation_from_pre_error(
            &ring,
            &ring.peer_ids[0],
            &PreError::VerificationFailed("bad share".into()),
            0,
            "pre-request-1",
        )
        .is_none());
        let sign_observation = offline_observation_from_sign_error(
            &ring,
            &ring.peer_ids[0],
            &SignError::NetworkCommunication("Failed to receive response".into()),
            0,
            "sign-request-1",
        )
        .unwrap();
        assert_eq!(sign_observation.origin_protocol, "sign");
        assert_eq!(sign_observation.session_id, "sign-request-1");
        assert_eq!(
            sign_observation.accused_committee_scope,
            CommitteeScope::Current
        );
        assert_eq!(
            sign_observation.signing_committee_scope,
            CommitteeScope::Current
        );
        assert!(offline_observation_from_sign_error(
            &ring,
            &ring.peer_ids[0],
            &SignError::VerificationFailed("bad share".into()),
            0,
            "sign-request-1",
        )
        .is_none());
        assert!(is_reportable_dkg_offline_error(
            &DkgError::NetworkConnection("down".into())
        ));
        assert!(is_reportable_dkg_offline_error(
            &DkgError::NetworkCommunication("Failed to send to peer".into())
        ));
        assert!(!is_reportable_dkg_offline_error(&DkgError::ProtocolError(
            "bad".into()
        )));
    }

    #[test]
    fn peer_route_observation_preserves_session_id() {
        let ring = ring();
        let observation = offline_observation_from_peer_routes(
            &ring.ring_id,
            &ring.peer_ids,
            &ring.peer_node_keys,
            &ring.peer_ids[0],
            "pss_refresh",
            7,
            CommitteeScope::Current,
            CommitteeScope::Current,
            "pss-session-1",
        )
        .unwrap();

        assert_eq!(observation.origin_protocol, "pss_refresh");
        assert_eq!(observation.session_id, "pss-session-1");
    }
}
