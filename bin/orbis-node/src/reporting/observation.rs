use crate::helpers::identity::extract_node_part;
use crate::helpers::ring::RingConfig;
use crate::pre::v0::error::PreError;
use crate::reporting::types::{OfflineFailureStage, OfflineObservation};

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

    let peer_part = extract_node_part(peer_id);
    let accused_node_key = ring
        .peer_node_keys
        .iter()
        .zip(ring.peer_ids.iter())
        .find(|(_, route)| extract_node_part(route) == peer_part)
        .map(|(node_key, _)| node_key.clone())?;

    let observed_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs();

    Some(OfflineObservation {
        ring_id: ring.ring_id.clone(),
        accused_node_key,
        accused_peer_id: peer_id.to_string(),
        origin_protocol: "pre".to_string(),
        origin_protocol_version: protocol_version,
        failure_stage,
        observed_at,
    })
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
    }
}
