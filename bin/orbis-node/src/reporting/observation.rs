use crate::dkg::v0::error::DkgError;
use crate::helpers::identity::extract_node_part;
use crate::helpers::ring::RingConfig;
use crate::pre::v0::error::PreError;
use crate::reporting::types::{
    CommitteeScope, OfflineFailureStage, NODE_OFFLINE_REPORT_TYPE, NODE_OFFLINE_REPORT_VERSION,
};
use crate::sign::v0::error::SignError;

#[derive(Debug, Clone)]
pub struct OfflineObservation {
    pub ring_id: String,
    pub accused_node_key: String,
    pub accused_peer_id: String,
    pub origin_protocol: String,
    pub origin_protocol_version: u64,
    pub failure_stage: OfflineFailureStage,
    pub accused_committee_scope: CommitteeScope,
    pub signing_committee_scope: CommitteeScope,
    pub observed_at: u64,
}

#[derive(Debug, Clone)]
pub enum ReportObservation {
    NodeOffline(OfflineObservation),
}

impl ReportObservation {
    pub fn report_type(&self) -> &'static str {
        match self {
            Self::NodeOffline(_) => NODE_OFFLINE_REPORT_TYPE,
        }
    }

    pub fn report_version(&self) -> u16 {
        match self {
            Self::NodeOffline(_) => NODE_OFFLINE_REPORT_VERSION,
        }
    }
}

pub fn offline_observation_from_pre_error(
    ring: &RingConfig,
    peer_id: &str,
    error: &PreError,
    protocol_version: u64,
) -> Option<OfflineObservation> {
    let failure_stage = match error {
        PreError::NetworkConnection(_) => OfflineFailureStage::OpenStream,
        PreError::NetworkCommunication(message) if message.starts_with("Failed to send") => {
            OfflineFailureStage::Send
        }
        PreError::NetworkCommunication(message) if message.starts_with("Failed to receive") => {
            OfflineFailureStage::Receive
        }
        PreError::Timeout(_) => OfflineFailureStage::ResponseTimeout,
        _ => return None,
    };

    offline_observation_from_ring_config(
        ring,
        peer_id,
        "pre",
        protocol_version,
        failure_stage,
        CommitteeScope::Current,
        CommitteeScope::Current,
    )
}

#[cfg(test)]
pub fn offline_observation_from_sign_error(
    ring: &RingConfig,
    peer_id: &str,
    error: &SignError,
    protocol_version: u64,
) -> Option<OfflineObservation> {
    let failure_stage = match error {
        SignError::NetworkConnection(_) => OfflineFailureStage::OpenStream,
        SignError::NetworkCommunication(message) if message.starts_with("Failed to send") => {
            OfflineFailureStage::Send
        }
        SignError::NetworkCommunication(message) if message.starts_with("Failed to receive") => {
            OfflineFailureStage::Receive
        }
        SignError::Timeout(_) => OfflineFailureStage::ResponseTimeout,
        _ => return None,
    };

    offline_observation_from_ring_config(
        ring,
        peer_id,
        "sign",
        protocol_version,
        failure_stage,
        CommitteeScope::Current,
        CommitteeScope::Current,
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
) -> Option<OfflineObservation> {
    let failure_stage = match error {
        SignError::NetworkConnection(_) => OfflineFailureStage::OpenStream,
        SignError::NetworkCommunication(message) if message.starts_with("Failed to send") => {
            OfflineFailureStage::Send
        }
        SignError::NetworkCommunication(message) if message.starts_with("Failed to receive") => {
            OfflineFailureStage::Receive
        }
        SignError::Timeout(_) => OfflineFailureStage::ResponseTimeout,
        _ => return None,
    };

    offline_observation_from_ring_config(
        ring,
        peer_id,
        origin_protocol,
        protocol_version,
        failure_stage,
        accused_committee_scope,
        signing_committee_scope,
    )
}

pub fn offline_failure_stage_from_dkg_error(error: &DkgError) -> Option<OfflineFailureStage> {
    match error {
        DkgError::NetworkConnection(_) => Some(OfflineFailureStage::OpenStream),
        DkgError::NetworkCommunication(message) if message.starts_with("Failed to send") => {
            Some(OfflineFailureStage::Send)
        }
        _ => None,
    }
}

pub fn offline_observation_from_peer_routes(
    ring_id: &str,
    peer_ids: &[String],
    peer_node_keys: &[String],
    peer_id: &str,
    origin_protocol: &str,
    protocol_version: u64,
    failure_stage: OfflineFailureStage,
    accused_committee_scope: CommitteeScope,
    signing_committee_scope: CommitteeScope,
) -> Option<OfflineObservation> {
    let peer_part = extract_node_part(peer_id);
    let accused_node_key = peer_node_keys
        .iter()
        .zip(peer_ids.iter())
        .find(|(_, route)| extract_node_part(route) == peer_part)
        .map(|(node_key, _)| node_key.clone())?;

    let observed_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs();

    Some(OfflineObservation {
        ring_id: ring_id.to_string(),
        accused_node_key,
        accused_peer_id: peer_id.to_string(),
        origin_protocol: origin_protocol.to_string(),
        origin_protocol_version: protocol_version,
        failure_stage,
        accused_committee_scope,
        signing_committee_scope,
        observed_at,
    })
}

fn offline_observation_from_ring_config(
    ring: &RingConfig,
    peer_id: &str,
    origin_protocol: &str,
    protocol_version: u64,
    failure_stage: OfflineFailureStage,
    accused_committee_scope: CommitteeScope,
    signing_committee_scope: CommitteeScope,
) -> Option<OfflineObservation> {
    offline_observation_from_peer_routes(
        &ring.ring_id,
        &ring.peer_ids,
        &ring.peer_node_keys,
        peer_id,
        origin_protocol,
        protocol_version,
        failure_stage,
        accused_committee_scope,
        signing_committee_scope,
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
    fn classifies_only_transport_failures() {
        let ring = ring();
        assert_eq!(
            offline_observation_from_pre_error(
                &ring,
                &ring.peer_ids[0],
                &PreError::Timeout("timeout".into()),
                0,
            )
            .unwrap()
            .failure_stage,
            OfflineFailureStage::ResponseTimeout
        );
        assert!(offline_observation_from_pre_error(
            &ring,
            &ring.peer_ids[0],
            &PreError::VerificationFailed("bad share".into()),
            0,
        )
        .is_none());
        let sign_observation = offline_observation_from_sign_error(
            &ring,
            &ring.peer_ids[0],
            &SignError::NetworkCommunication("Failed to receive response".into()),
            0,
        )
        .unwrap();
        assert_eq!(sign_observation.origin_protocol, "sign");
        assert_eq!(sign_observation.failure_stage, OfflineFailureStage::Receive);
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
        )
        .is_none());
        assert_eq!(
            offline_failure_stage_from_dkg_error(&DkgError::NetworkConnection("down".into())),
            Some(OfflineFailureStage::OpenStream)
        );
        assert_eq!(
            offline_failure_stage_from_dkg_error(&DkgError::NetworkCommunication(
                "Failed to send to peer".into()
            )),
            Some(OfflineFailureStage::Send)
        );
        assert_eq!(
            offline_failure_stage_from_dkg_error(&DkgError::ProtocolError("bad".into())),
            None
        );
    }
}
