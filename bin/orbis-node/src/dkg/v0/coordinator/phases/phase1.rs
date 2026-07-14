use super::*;
use crate::dkg::v0::coordinator::evidence::build_and_store_commitment_evidence;

pub async fn initiate_phase1_commitments<D>(
    coord: &DkgCoordinator<D>,
    session_id: u128,
    peer_ids: &[String],
) -> Result<()>
where
    D: CoordinatorDkg,
{
    let already_started = coord
        .app_state
        .dkg_session_state
        .with_state(&session_id, |state| {
            matches!(
                state.phase,
                DkgPhase::Phase2Shares | DkgPhase::Phase4Completing | DkgPhase::Phase4Complete
            )
        })
        .await
        .ok_or_else(|| session_not_found(session_id))?;

    if already_started {
        tracing::debug!(
            session_id = session_id,
            "Phase 1 start requested after shares/completion; ignoring duplicate request"
        );
        return Ok(());
    }

    let is_reshare_receiver = coord
        .app_state
        .dkg_session_state
        .with_state(&session_id, |state| {
            matches!(state.kind, SessionKind::Reshare { .. })
                && state.node.role() == DkgRole::Receiver
        })
        .await
        .ok_or_else(|| session_not_found(session_id))?;

    if is_reshare_receiver {
        tracing::debug!(
            session_id = session_id,
            "Reshare receiver does not generate Phase 1 commitments; ignoring start request"
        );
        return Ok(());
    }

    let fresh_phase = coord
        .app_state
        .dkg_session_state
        .with_state(&session_id, |state| {
            matches!(state.kind, SessionKind::Fresh).then_some(state.phase)
        })
        .await
        .ok_or_else(|| session_not_found(session_id))?;
    if matches!(
        fresh_phase,
        Some(DkgPhase::Initializing | DkgPhase::Phase0CommitmentHashes)
    ) {
        return Err(DkgError::ProtocolError(
            "Fresh DKG commitments can only be revealed after commitment hashes are complete"
                .to_string(),
        ));
    }

    let (commitment_bytes, node_id, threshold, is_reshare, role) = coord
        .app_state
        .dkg_session_state
        .with_state_mut(&session_id, |state| {
            if state.node.commitment().coefficients.is_empty() {
                state.generate_polynomial()?;
            }
            let bytes = serialize_commitment_coefficients(&state.node.commitment().coefficients)?;
            Ok::<_, DkgError>((
                bytes,
                state.node.node_id(),
                state.node.threshold(),
                matches!(state.kind, SessionKind::Reshare { .. }),
                state.node.role(),
            ))
        })
        .await
        .ok_or_else(|| session_not_found(session_id))??;

    coord
        .app_state
        .dkg_session_state
        .update_phase(&session_id, DkgPhase::Phase1Commitments)
        .await;
    let report_evidence =
        build_and_store_commitment_evidence(coord, session_id, node_id, commitment_bytes.clone())
            .await?;

    let mut peers_sent = 0;
    let mut expected_peers = 0;
    for peer_id_str in peer_ids {
        if is_self_peer_id(&coord.app_state.network, peer_id_str) {
            tracing::debug!(peer_id = %peer_id_str, "Skipping self when broadcasting commitment");
            continue;
        }
        expected_peers += 1;

        let commitment_msg = DkgMessage::Commitment {
            session_id,
            from_node_id: node_id,
            commitment: commitment_bytes.clone(),
            report_evidence: report_evidence.clone(),
        };

        if coord
            .send_message_to_peer(peer_id_str, commitment_msg, Some(session_id))
            .await
            .inspect_err(|error| {
                tracing::error!(
                    peer_id = %peer_id_str,
                    error = %error,
                    "Failed to send commitment to peer"
                );
            })
            .is_ok()
        {
            peers_sent += 1;
        }
    }

    tracing::info!(
        peers_sent = peers_sent,
        expected_peers = expected_peers,
        "Phase 1: Broadcasted commitment to peers"
    );

    if peers_sent < expected_peers && !is_reshare {
        tracing::error!(
            sent = peers_sent,
            expected = expected_peers,
            session_id = session_id,
            "DKG Coordinator: Could not broadcast commitment to all peers - failing DKG to preserve expected redundancy"
        );
        coord.remove_session(session_id).await;
        tracing::debug!(
            session_id = session_id,
            "Cleaned up session after Phase 1 broadcast failure"
        );
        return Err(DkgError::InsufficientPeers {
            successful: peers_sent,
            total: expected_peers,
            threshold,
        });
    }

    if peers_sent < expected_peers {
        tracing::warn!(
            sent = peers_sent,
            expected = expected_peers,
            session_id = session_id,
            "Reshare: commitment broadcast did not reach every new-committee peer; continuing until threshold selection or timeout"
        );
    }

    if is_reshare && role != DkgRole::Receiver {
        initiate_phase2_shares(coord, session_id, peer_ids).await?;
    }

    Ok(())
}

/// Check if Phase 1 is complete and trigger Phase 2 if so.
///
/// Called after each incoming commitment message.
pub async fn check_and_trigger_phase2<D>(
    coord: &DkgCoordinator<D>,
    session_id: u128,
    peer_ids: &[String],
) -> Result<()>
where
    D: CoordinatorDkg,
{
    drive_event(
        coord,
        session_id,
        DkgEvent::CommitmentRecorded,
        Some(peer_ids),
    )
    .await
}
