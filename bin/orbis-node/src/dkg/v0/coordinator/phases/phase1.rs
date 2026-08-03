use super::*;
use crate::dkg::v0::coordinator::evidence::build_and_store_commitment_evidence;

pub async fn initiate_phase1_commitments<D>(
    coord: &DkgCoordinator<D>,
    attempt: AttemptKey,
    peer_ids: &[String],
) -> Result<()>
where
    D: CoordinatorDkg,
{
    let session_id = attempt.session_id();
    let already_started = coord
        .app_state
        .dkg_session_state
        .with_attempt_state(attempt, |state| {
            matches!(
                state.phase,
                DkgPhase::Phase2Shares | DkgPhase::Phase4Completing | DkgPhase::Phase4Complete
            )
        })
        .await
        .map_err(|error| attempt_state_error(attempt, error))?;

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
        .with_attempt_state(attempt, |state| {
            matches!(state.kind, SessionKind::Reshare { .. })
                && state.node.role() == DkgRole::Receiver
        })
        .await
        .map_err(|error| attempt_state_error(attempt, error))?;

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
        .with_attempt_state(attempt, |state| {
            matches!(state.kind, SessionKind::Fresh).then_some(state.phase)
        })
        .await
        .map_err(|error| attempt_state_error(attempt, error))?;
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
        .with_attempt_state_mut(attempt, |state| {
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
        .map_err(|error| attempt_state_error(attempt, error))??;

    coord
        .app_state
        .dkg_session_state
        .update_phase_for_attempt(attempt, DkgPhase::Phase1Commitments)
        .await
        .map_err(|error| attempt_state_error(attempt, error))?;
    let report_evidence =
        build_and_store_commitment_evidence(coord, attempt, node_id, commitment_bytes.clone())
            .await?;

    submit_public_contribution(
        coord,
        attempt,
        DkgPublicPayload::Commitment {
            commitment: commitment_bytes,
            report_evidence,
        },
    )
    .await?;

    if is_reshare && role != DkgRole::Receiver {
        return initiate_phase2_shares(coord, attempt, peer_ids).await;
    }

    // Gossip delivery is not phase-ordered. Remote commitments may have
    // arrived and been validated while this fresh session was still in the
    // hash-reveal phase. Re-evaluate Phase 1 after publishing our own
    // commitment so those already-recorded contributions can advance the
    // session without requiring another network message.
    check_and_trigger_phase2(coord, attempt, peer_ids).await
}

/// Check if Phase 1 is complete and trigger Phase 2 if so.
///
/// Called after each incoming commitment message.
pub async fn check_and_trigger_phase2<D>(
    coord: &DkgCoordinator<D>,
    attempt: AttemptKey,
    peer_ids: &[String],
) -> Result<()>
where
    D: CoordinatorDkg,
{
    drive_event(coord, attempt, DkgEvent::CommitmentRecorded, Some(peer_ids)).await
}
