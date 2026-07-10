use super::*;

pub async fn initiate_phase0_commitment_hashes<D>(
    coord: &DkgCoordinator<D>,
    session_id: u128,
    peer_ids: &[String],
) -> Result<()>
where
    D: CoordinatorDkg,
{
    let (commitment_hash, node_id, threshold) = coord
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
            Ok::<_, DkgError>((
                fresh_commitment_hash(session_id, node_id, &commitment_bytes),
                node_id,
                state.node.threshold(),
            ))
        })
        .await
        .ok_or_else(|| session_not_found(session_id))??;

    coord
        .app_state
        .dkg_session_state
        .update_phase(&session_id, DkgPhase::Phase0CommitmentHashes)
        .await;

    let mut peers_sent = 0;
    let mut expected_peers = 0;
    for peer_id_str in peer_ids {
        if is_self_peer_id(&coord.app_state.network, peer_id_str) {
            tracing::debug!(peer_id = %peer_id_str, "Skipping self when broadcasting commitment hash");
            continue;
        }
        expected_peers += 1;

        let msg = DkgMessage::CommitmentHash {
            session_id,
            from_node_id: node_id,
            commitment_hash,
        };

        if coord
            .send_message_to_peer(peer_id_str, msg, Some(session_id))
            .await
            .inspect_err(|error| {
                tracing::error!(
                    peer_id = %peer_id_str,
                    error = %error,
                    "Failed to send commitment hash to peer"
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
        "Phase 0: Broadcasted commitment hash to peers"
    );

    if peers_sent < expected_peers {
        tracing::error!(
            sent = peers_sent,
            expected = expected_peers,
            session_id = session_id,
            "DKG Coordinator: Could not broadcast commitment hash to all peers - failing Fresh DKG"
        );
        coord.remove_session(session_id).await;
        return Err(DkgError::InsufficientPeers {
            successful: peers_sent,
            total: expected_peers,
            threshold,
        });
    }

    coord
        .app_state
        .dkg_session_state
        .mark_commitment_hash_broadcast_complete(&session_id)
        .await;

    drive_event(
        coord,
        session_id,
        DkgEvent::CommitmentHashRecorded,
        Some(peer_ids),
    )
    .await
}
