use super::*;
use crate::dkg::v0::session_state::CommitmentHashRecordOutcome;
use crypto::SignImpl;

pub(crate) async fn preflight_commitment_hash_message<D>(
    coord: &DkgCoordinator<D>,
    attempt: AttemptKey,
    from_node_id: u32,
    commitment_hash: [u8; 32],
) -> Result<()>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    let (existing, pending) = coord
        .app_state
        .dkg_session_state
        .with_attempt_state(attempt, |state| -> Result<_> {
            if !matches!(state.kind, SessionKind::Fresh) {
                return Err(DkgError::ProtocolError(
                    "CommitmentHash is only valid for Fresh DKG sessions".to_string(),
                ));
            }
            Ok((
                state
                    .commit_reveal
                    .received_hashes
                    .get(&from_node_id)
                    .copied(),
                state
                    .pending
                    .pending_commitments_waiting_for_hash
                    .get(&from_node_id)
                    .cloned(),
            ))
        })
        .await
        .map_err(|error| attempt_state_error(attempt, error))??;
    if existing.is_some_and(|existing| existing != commitment_hash) {
        return Err(DkgError::CommitmentVerificationFailed(format!(
            "Fresh commitment hash mismatch from node {}",
            from_node_id
        )));
    }
    if let Some(pending) = pending {
        super::commitment::preflight_commitment_message_with_hash(
            coord,
            attempt,
            from_node_id,
            &pending.commitment,
            pending.report_evidence.as_ref(),
            commitment_hash,
        )
        .await?;
    }
    Ok(())
}

pub async fn handle_commitment_hash_message<D>(
    coord: &DkgCoordinator<D>,
    attempt: AttemptKey,
    from_node_id: u32,
    commitment_hash: [u8; 32],
) -> Result<()>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    let session_id = attempt.session_id();
    preflight_commitment_hash_message(coord, attempt, from_node_id, commitment_hash).await?;
    let outcome = coord
        .app_state
        .dkg_session_state
        .with_attempt_state_mut(attempt, |state| {
            if !matches!(state.kind, SessionKind::Fresh) {
                return Err(DkgError::ProtocolError(
                    "CommitmentHash is only valid for Fresh DKG sessions".to_string(),
                ));
            }
            Ok(
                match state.commit_reveal.received_hashes.get(&from_node_id) {
                    Some(existing) if existing == &commitment_hash => {
                        CommitmentHashRecordOutcome::DuplicateSame
                    }
                    Some(existing) => CommitmentHashRecordOutcome::Mismatch {
                        existing: *existing,
                    },
                    None => {
                        state
                            .commit_reveal
                            .received_hashes
                            .insert(from_node_id, commitment_hash);
                        CommitmentHashRecordOutcome::Recorded
                    }
                },
            )
        })
        .await
        .map_err(|error| attempt_state_error(attempt, error))??;

    match outcome {
        CommitmentHashRecordOutcome::Recorded => {
            tracing::debug!(
                session_id = session_id,
                from_node_id = from_node_id,
                commitment_hash = %hex::encode(commitment_hash),
                "DKG Coordinator: Recorded Fresh commitment hash"
            );
        }
        CommitmentHashRecordOutcome::DuplicateSame => {
            tracing::debug!(
                session_id = session_id,
                from_node_id = from_node_id,
                "DKG Coordinator: Ignoring duplicate Fresh commitment hash"
            );
        }
        CommitmentHashRecordOutcome::Mismatch { existing } => {
            tracing::warn!(
                session_id = session_id,
                from_node_id = from_node_id,
                existing_hash = %hex::encode(existing),
                new_hash = %hex::encode(commitment_hash),
                "DKG Coordinator: Fresh commitment hash equivocation detected"
            );
            return Err(DkgError::CommitmentVerificationFailed(format!(
                "Fresh commitment hash mismatch from node {}",
                from_node_id
            )));
        }
    }

    // Peek rather than remove: if the replay below fails, the entry must
    // survive so a later retry can still replay it. Removing it up front
    // would otherwise lose the commitment and its evidence for good on any
    // transient replay failure.
    let pending = coord
        .app_state
        .dkg_session_state
        .with_attempt_state(attempt, |state| {
            state
                .pending
                .pending_commitments_waiting_for_hash
                .get(&from_node_id)
                .cloned()
        })
        .await
        .map_err(|error| attempt_state_error(attempt, error))?;
    if let Some(pending) = pending {
        tracing::debug!(
            session_id = session_id,
            from_node_id = from_node_id,
            "DKG Coordinator: Replaying commitment that was waiting for its hash"
        );
        handle_commitment_message(
            coord,
            attempt,
            from_node_id,
            pending.commitment,
            pending.report_evidence,
        )
        .await?;
        coord
            .app_state
            .dkg_session_state
            .with_attempt_state_mut(attempt, |state| {
                state
                    .pending
                    .pending_commitments_waiting_for_hash
                    .remove(&from_node_id)
            })
            .await
            .map_err(|error| attempt_state_error(attempt, error))?;
    }

    let peer_ids = coord
        .app_state
        .dkg_session_state
        .with_attempt_state(attempt, |state| state.routing.peer_ids.clone())
        .await
        .map_err(|error| attempt_state_error(attempt, error))?;
    phases::drive_event(
        coord,
        attempt,
        DkgEvent::CommitmentHashRecorded,
        Some(&peer_ids),
    )
    .await?;

    Ok(())
}
