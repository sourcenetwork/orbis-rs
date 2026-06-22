use crate::dkg::v0::error::{DkgError, Result};
use crate::dkg::v0::helpers::session_not_found;
use crate::dkg::v0::messages::DkgMessage;
use crate::dkg::v0::session_state::DkgMessageType;
use crate::helpers::identity::extract_node_part;
use network::PeerId;

use super::{message_handlers, refresh_health_check, types::CoordinatorDkg, DkgCoordinator};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::dkg::v0::coordinator) enum CommitteeScope {
    None,
    Current,
    ReshareNew,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::dkg::v0::coordinator) struct DkgMessageMeta {
    pub message_type: DkgMessageType,
    pub sender_node_id: Option<u32>,
    pub dedup_node_id: Option<u32>,
    pub committee_scope: CommitteeScope,
    pub metric_label: &'static str,
}

impl DkgMessageMeta {
    pub fn from_message(message: &DkgMessage) -> Self {
        match message {
            DkgMessage::Commitment { from_node_id, .. } => Self::from_sender(
                DkgMessageType::Commitment,
                *from_node_id,
                CommitteeScope::Current,
                "commitment",
            ),
            DkgMessage::Share { from_node_id, .. } => Self::from_sender(
                DkgMessageType::Share,
                *from_node_id,
                CommitteeScope::Current,
                "share",
            ),
            DkgMessage::Complaint { from_node_id, .. } => Self::from_sender(
                DkgMessageType::Complaint,
                *from_node_id,
                CommitteeScope::Current,
                "complaint",
            ),
            DkgMessage::ReshareShareAck {
                receiver_node_id, ..
            } => Self {
                message_type: DkgMessageType::ReshareShareAck,
                sender_node_id: Some(*receiver_node_id),
                // A receiver sends one acknowledgement per dealer. The current
                // dedup key has no dealer component, so deduplicating only by
                // receiver would discard every acknowledgement after the first.
                dedup_node_id: None,
                committee_scope: CommitteeScope::ReshareNew,
                metric_label: "reshare_share_ack",
            },
            DkgMessage::ReshareParticipantSet { from_node_id, .. } => Self::from_sender(
                DkgMessageType::ReshareParticipantSet,
                *from_node_id,
                CommitteeScope::ReshareNew,
                "reshare_participant_set",
            ),
            DkgMessage::RefreshHealthCheckResult { from_node_id, .. } => Self::from_sender(
                DkgMessageType::RefreshHealthCheckResult,
                *from_node_id,
                CommitteeScope::Current,
                "refresh_health_check_result",
            ),
            DkgMessage::SessionInit { .. } => Self {
                message_type: DkgMessageType::SessionInit,
                sender_node_id: None,
                dedup_node_id: None,
                committee_scope: CommitteeScope::None,
                metric_label: "session_init",
            },
            DkgMessage::Error { .. } => Self {
                message_type: DkgMessageType::Error,
                sender_node_id: None,
                dedup_node_id: None,
                committee_scope: CommitteeScope::None,
                metric_label: "error",
            },
        }
    }

    fn from_sender(
        message_type: DkgMessageType,
        sender_node_id: u32,
        committee_scope: CommitteeScope,
        metric_label: &'static str,
    ) -> Self {
        Self {
            message_type,
            sender_node_id: Some(sender_node_id),
            dedup_node_id: Some(sender_node_id),
            committee_scope,
            metric_label,
        }
    }
}

pub(in crate::dkg::v0::coordinator) async fn wait_for_session<D>(
    coord: &DkgCoordinator<D>,
    session_id: u128,
) -> Result<()>
where
    D: CoordinatorDkg,
{
    if coord
        .app_state
        .dkg_session_state
        .session_exists(&session_id)
        .await
    {
        return Ok(());
    }

    let session_state = coord.app_state.dkg_session_state.clone();
    let found = tokio::time::timeout(
        crate::constants::DKG_UNKNOWN_SESSION_MESSAGE_WAIT_TIMEOUT,
        async move {
            loop {
                tokio::time::sleep(crate::constants::DKG_SESSION_WAIT_POLL_INTERVAL).await;
                if session_state.session_exists(&session_id).await {
                    return;
                }
            }
        },
    )
    .await;

    found.map_err(|_| session_not_found(session_id))
}

pub(in crate::dkg::v0::coordinator) async fn validate_sender<D>(
    coord: &DkgCoordinator<D>,
    session_id: u128,
    meta: DkgMessageMeta,
    sender_peer_id: &PeerId,
) -> Result<()>
where
    D: CoordinatorDkg,
{
    let Some(claimed_node_id) = meta.sender_node_id else {
        return Ok(());
    };

    let sender_hex = hex::encode(sender_peer_id.as_bytes());
    let expected_node_id = coord
        .app_state
        .dkg_session_state
        .with_state(&session_id, |state| {
            let map = match meta.committee_scope {
                CommitteeScope::Current => &state.routing.peer_id_to_node_id,
                CommitteeScope::ReshareNew => &state.routing.reshare_new_peer_id_to_node_id,
                CommitteeScope::None => return None,
            };
            map.iter()
                .find(|(peer_id, _)| extract_node_part(peer_id) == sender_hex)
                .map(|(_, node_id)| *node_id)
        })
        .await
        .flatten();

    match expected_node_id {
        Some(expected) if expected == claimed_node_id => Ok(()),
        Some(expected) => {
            tracing::warn!(
                claimed_node_id,
                expected_node_id = expected,
                sender_peer = %sender_hex,
                session_id,
                committee_scope = ?meta.committee_scope,
                "DKG Coordinator: Rejecting message - sender identity mismatch"
            );
            Err(DkgError::Unauthorized(format!(
                "Sender identity mismatch: peer claims node_id={claimed_node_id}, but authenticated peer maps to node_id={expected}"
            )))
        }
        None => {
            tracing::warn!(
                sender_peer = %sender_hex,
                session_id,
                committee_scope = ?meta.committee_scope,
                "DKG Coordinator: Rejecting message - sender peer not found in session"
            );
            Err(DkgError::Unauthorized(format!(
                "Sender peer {sender_hex} not found in session peer mappings"
            )))
        }
    }
}

pub(in crate::dkg::v0::coordinator) async fn dispatch<D>(
    coord: &DkgCoordinator<D>,
    session_id: u128,
    message: DkgMessage,
) -> Result<Option<DkgMessage>>
where
    D: CoordinatorDkg,
{
    match message {
        DkgMessage::Commitment {
            from_node_id,
            commitment,
            ..
        } => {
            message_handlers::handle_commitment_message(coord, session_id, from_node_id, commitment)
                .await
        }
        DkgMessage::Share {
            from_node_id,
            to_node_id,
            share_value,
            nonce,
            ..
        } => {
            message_handlers::handle_share_message(
                coord,
                session_id,
                from_node_id,
                to_node_id,
                share_value,
                nonce,
            )
            .await
        }
        DkgMessage::Complaint {
            from_node_id,
            accused_node_id,
            reason,
            ..
        } => {
            tracing::warn!(
                from_node_id,
                accused_node_id,
                reason = %reason,
                "DKG Coordinator: Received complaint"
            );
            Ok(None)
        }
        DkgMessage::ReshareShareAck {
            receiver_node_id,
            dealer_id,
            ..
        } => {
            message_handlers::handle_reshare_share_ack(
                coord,
                session_id,
                receiver_node_id,
                dealer_id,
            )
            .await
        }
        DkgMessage::ReshareParticipantSet {
            from_node_id,
            selected_dealer_ids,
            ..
        } => {
            message_handlers::handle_reshare_participant_set(
                coord,
                session_id,
                from_node_id,
                selected_dealer_ids,
            )
            .await
        }
        DkgMessage::RefreshHealthCheckResult {
            from_node_id,
            statement,
            signature,
            ..
        } => {
            refresh_health_check::handle_result(
                coord,
                session_id,
                from_node_id,
                statement,
                signature,
            )
            .await
        }
        DkgMessage::Error { error, .. } => {
            tracing::error!(
                session_id,
                error = %error,
                "DKG Coordinator: Received error"
            );
            Ok(None)
        }
        DkgMessage::SessionInit { .. } => {
            unreachable!("SessionInit is handled before inbound dispatch")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dkg::v0::messages::SessionKind;
    use crate::sign::v0::messages::RefreshHealthCheckStatement;
    use std::collections::HashMap;

    fn assert_meta(
        message: DkgMessage,
        message_type: DkgMessageType,
        sender_node_id: Option<u32>,
        dedup_node_id: Option<u32>,
        committee_scope: CommitteeScope,
        metric_label: &'static str,
    ) {
        assert_eq!(
            DkgMessageMeta::from_message(&message),
            DkgMessageMeta {
                message_type,
                sender_node_id,
                dedup_node_id,
                committee_scope,
                metric_label,
            }
        );
    }

    #[test]
    fn metadata_covers_every_message_variant() {
        assert_meta(
            DkgMessage::Commitment {
                session_id: 1,
                from_node_id: 2,
                commitment: vec![],
            },
            DkgMessageType::Commitment,
            Some(2),
            Some(2),
            CommitteeScope::Current,
            "commitment",
        );
        assert_meta(
            DkgMessage::Share {
                session_id: 1,
                from_node_id: 2,
                to_node_id: 3,
                share_value: vec![],
                nonce: [0; 16],
            },
            DkgMessageType::Share,
            Some(2),
            Some(2),
            CommitteeScope::Current,
            "share",
        );
        assert_meta(
            DkgMessage::Complaint {
                session_id: 1,
                from_node_id: 2,
                accused_node_id: 3,
                reason: "test".into(),
            },
            DkgMessageType::Complaint,
            Some(2),
            Some(2),
            CommitteeScope::Current,
            "complaint",
        );
        assert_meta(
            DkgMessage::ReshareShareAck {
                session_id: 1,
                receiver_node_id: 4,
                dealer_id: 2,
            },
            DkgMessageType::ReshareShareAck,
            Some(4),
            None,
            CommitteeScope::ReshareNew,
            "reshare_share_ack",
        );
        assert_meta(
            DkgMessage::ReshareParticipantSet {
                session_id: 1,
                from_node_id: 1,
                selected_dealer_ids: vec![2],
            },
            DkgMessageType::ReshareParticipantSet,
            Some(1),
            Some(1),
            CommitteeScope::ReshareNew,
            "reshare_participant_set",
        );
        assert_meta(
            DkgMessage::RefreshHealthCheckResult {
                session_id: 1,
                from_node_id: 1,
                statement: RefreshHealthCheckStatement {
                    domain: "test".into(),
                    session_id: 1,
                    ring_pk: "ring".into(),
                    public_polynomial_sha256: "00".repeat(32),
                    peer_node_keys_sha256: "00".repeat(32),
                    threshold: 2,
                    total_participants: 3,
                },
                signature: None,
            },
            DkgMessageType::RefreshHealthCheckResult,
            Some(1),
            Some(1),
            CommitteeScope::Current,
            "refresh_health_check_result",
        );
        assert_meta(
            DkgMessage::SessionInit {
                session_id: 1,
                threshold: 2,
                total_participants: 3,
                peer_ids: vec![],
                peer_node_keys: vec![],
                node_id_assignments: HashMap::new(),
                token_string: String::new(),
                kind: SessionKind::Fresh,
                pss_interval: 0,
                policy_id: None,
                ring_id: "ring".into(),
            },
            DkgMessageType::SessionInit,
            None,
            None,
            CommitteeScope::None,
            "session_init",
        );
        assert_meta(
            DkgMessage::Error {
                session_id: 1,
                error: "test".into(),
            },
            DkgMessageType::Error,
            None,
            None,
            CommitteeScope::None,
            "error",
        );
    }
}
