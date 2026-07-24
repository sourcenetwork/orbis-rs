use super::*;

pub async fn initiate_phase0_commitment_hashes<D>(
    coord: &DkgCoordinator<D>,
    session_id: u128,
    peer_ids: &[String],
) -> Result<()>
where
    D: CoordinatorDkg,
{
    let commitment_hash = coord
        .app_state
        .dkg_session_state
        .with_state_mut(&session_id, |state| {
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
        .ok_or_else(|| session_not_found(session_id))??;

    coord
        .app_state
        .dkg_session_state
        .update_phase(&session_id, DkgPhase::Phase0CommitmentHashes)
        .await;

    if coord
        .app_state
        .dkg_session_state
        .transport_attempt(&session_id)
        .await
        .is_none()
    {
        return Err(DkgError::InvalidState(
            "fresh DKG session has no typed transport attempt".into(),
        ));
    }

    if coord
        .app_state
        .dkg_session_state
        .transport_attempt(&session_id)
        .await
        .is_some()
    {
        submit_public_contribution(
            coord,
            session_id,
            DkgPublicPayload::CommitmentHash { commitment_hash },
        )
        .await?;
        coord
            .app_state
            .dkg_session_state
            .mark_commitment_hash_broadcast_complete(&session_id)
            .await;
        return drive_event(
            coord,
            session_id,
            DkgEvent::CommitmentHashRecorded,
            Some(peer_ids),
        )
        .await;
    }

    Err(DkgError::InvalidState(
        "typed commitment-hash submission returned without completing".into(),
    ))
}
