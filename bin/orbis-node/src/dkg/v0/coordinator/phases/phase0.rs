use super::*;

pub async fn initiate_phase0_commitment_hashes<D>(
    coord: &DkgCoordinator<D>,
    attempt: AttemptKey,
    peer_ids: &[String],
) -> Result<()>
where
    D: CoordinatorDkg,
{
    let session_id = attempt.session_id();
    let commitment_hash = coord
        .app_state
        .dkg_session_state
        .with_attempt_state_mut(attempt, |state| {
            if !matches!(state.kind, SessionKind::Fresh) {
                return Err(DkgError::ProtocolError(
                    "Commitment hash pre-round is only valid for Fresh DKG".to_string(),
                ));
            }
            if state.node.role() == DkgRole::Receiver {
                return Err(DkgError::ProtocolError(
                    "Fresh DKG receiver cannot broadcast a commitment hash".to_string(),
                ));
            }
            if state.node.commitment().coefficients.is_empty() {
                state.generate_polynomial()?;
            }
            let commitment_bytes =
                serialize_commitment_coefficients(&state.node.commitment().coefficients)?;
            let node_id = state.node.node_id();
            Ok::<_, DkgError>(fresh_commitment_hash(
                session_id,
                node_id,
                &commitment_bytes,
            ))
        })
        .await
        .map_err(|error| attempt_state_error(attempt, error))??;

    coord
        .app_state
        .dkg_session_state
        .update_phase_for_attempt(attempt, DkgPhase::Phase0CommitmentHashes)
        .await
        .map_err(|error| attempt_state_error(attempt, error))?;

    submit_public_contribution(
        coord,
        attempt,
        DkgPublicPayload::CommitmentHash { commitment_hash },
    )
    .await?;
    coord
        .app_state
        .dkg_session_state
        .mark_commitment_hash_broadcast_complete_for_attempt(attempt)
        .await
        .map_err(|error| attempt_state_error(attempt, error))?;
    drive_event(
        coord,
        attempt,
        DkgEvent::CommitmentHashRecorded,
        Some(peer_ids),
    )
    .await
}
