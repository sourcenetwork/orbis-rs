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

    let (commitment_bytes, node_id, is_reshare, role) = coord
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

    if coord
        .app_state
        .dkg_session_state
        .transport_attempt(&session_id)
        .await
        .is_none()
    {
        return Err(DkgError::InvalidState(
            "DKG commitment phase has no typed transport attempt".into(),
        ));
    }

    if coord
        .app_state
        .dkg_session_state
        .transport_attempt(&session_id)
        .await
        .is_some()
    {
        crate::dkg::v0::network::submit_public_contribution(
            coord,
            session_id,
            crate::dkg::v0::transport::DkgPublicPayload::Commitment {
                commitment: commitment_bytes,
                report_evidence,
            },
        )
        .await?;

        if is_reshare && role != DkgRole::Receiver {
            return initiate_phase2_shares(coord, session_id, peer_ids).await;
        }

        // Gossip delivery is not phase-ordered. Remote commitments may have
        // arrived and been validated while this fresh session was still in the
        // hash-reveal phase. Re-evaluate Phase 1 after publishing our own
        // commitment so those already-recorded contributions can advance the
        // session without requiring another network message.
        return check_and_trigger_phase2(coord, session_id, peer_ids).await;
    }

    Err(DkgError::InvalidState(
        "typed commitment submission returned without completing".into(),
    ))
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
