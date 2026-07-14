use super::*;
use crate::dkg::v0::session_state::CommitmentHashRecordOutcome;
use crypto::SignImpl;

pub async fn handle_commitment_hash_message<D>(
    coord: &DkgCoordinator<D>,
    session_id: u128,
    from_node_id: u32,
    commitment_hash: [u8; 32],
) -> Result<Option<DkgMessage>>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    let is_fresh = coord
        .app_state
        .dkg_session_state
        .with_state(&session_id, |state| {
            matches!(state.kind, SessionKind::Fresh)
        })
        .await
        .ok_or_else(|| session_not_found(session_id))?;

    if !is_fresh {
        return Err(DkgError::ProtocolError(
            "CommitmentHash is only valid for Fresh DKG sessions".to_string(),
        ));
    }

    match coord
        .app_state
        .dkg_session_state
        .record_commitment_hash(&session_id, from_node_id, commitment_hash)
        .await
        .ok_or_else(|| session_not_found(session_id))?
    {
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

    if let Some(pending) = coord
        .app_state
        .dkg_session_state
        .take_pending_commitment_waiting_for_hash(&session_id, from_node_id)
        .await
    {
        tracing::debug!(
            session_id = session_id,
            from_node_id = from_node_id,
            "DKG Coordinator: Replaying commitment that was waiting for its hash"
        );
        handle_commitment_message(
            coord,
            session_id,
            from_node_id,
            pending.commitment,
            pending.report_evidence,
        )
        .await?;
    }

    let peer_ids = coord
        .app_state
        .dkg_session_state
        .get_peer_ids(&session_id)
        .await
        .unwrap_or_default();
    phases::drive_event(
        coord,
        session_id,
        DkgEvent::CommitmentHashRecorded,
        Some(&peer_ids),
    )
    .await?;

    Ok(None)
}
