use super::*;

/// Handle a `DkgMessage::Share`.
///
/// Validates the share is addressed to this node, deserializes it, passes it to the
/// crypto layer for verification against the sender's commitment, then checks whether
/// Phase 2 is complete.
pub(in crate::dkg::coordinator) async fn handle_share_message<D>(
    coord: &DkgCoordinator<D>,
    session_id: u64,
    from_node_id: u32,
    to_node_id: u32,
    share_value: Vec<u8>,
    nonce: [u8; 16],
) -> Result<Option<DkgMessage>>
where
    D: CoordinatorDkg,
{
    if share_value.is_empty() {
        return Err(DkgError::ShareVerificationFailed(
            "Share value cannot be empty".to_string(),
        ));
    }

    if share_value.len() != FR_COMPRESSED_SIZE {
        return Err(DkgError::ShareVerificationFailed(format!(
            "Invalid share value length: {} bytes, expected {}",
            share_value.len(),
            FR_COMPRESSED_SIZE
        )));
    }

    // Validate this share is intended for us.
    // For reshare, incoming shares are addressed by new-committee index;
    // for fresh/refresh, shares are addressed by the session node_id.
    let our_node_id = coord
        .app_state
        .dkg_session_state
        .with_state(&session_id, |state| {
            state
                .reshare_params
                .as_ref()
                .and_then(|p| p.new_node_id)
                .unwrap_or_else(|| state.node.node_id())
        })
        .await
        .ok_or_else(|| session_not_found(session_id))?;

    if to_node_id != our_node_id {
        return Err(DkgError::ShareVerificationFailed(format!(
            "Share intended for node {}, but we are node {}",
            to_node_id, our_node_id
        )));
    }

    let ignore_unselected_reshare_share = coord
        .app_state
        .dkg_session_state
        .with_state(&session_id, |state| {
            matches!(state.kind, SessionKind::Reshare { .. })
                && state
                    .reshare_selected_dealers
                    .as_ref()
                    .is_some_and(|selected| !selected.contains(&from_node_id))
        })
        .await
        .ok_or_else(|| session_not_found(session_id))?;

    if ignore_unselected_reshare_share {
        tracing::debug!(
            session_id = session_id,
            from_node_id = from_node_id,
            "Reshare: ignoring straggler share from unselected dealer"
        );
        return Ok(None);
    }

    // Commitment and share are delivered over the same persistent QUIC stream
    // (one stream per connection, opened lazily on first send).  QUIC guarantees
    // in-order delivery within a stream, so the commitment always arrives before
    // the share — no retry needed.
    let share_val = <D::ShareValue>::from_bytes(share_value.as_slice()).map_err(|e| {
        DkgError::Deserialization(format!("Failed to deserialize share value: {}", e))
    })?;
    let share = DistributedShare {
        from_id: from_node_id,
        to_id: to_node_id,
        value: share_val,
        nonce,
        session_id,
    };

    coord
        .app_state
        .dkg_session_state
        .with_state_mut(&session_id, |state| {
            state.node.receive_share(share).map_err(|e| {
                DkgError::ShareVerificationFailed(format!("Failed to receive share: {}", e))
            })
        })
        .await
        .ok_or_else(|| session_not_found(session_id))??;

    tracing::debug!(
        from_node_id = from_node_id,
        to_node_id = to_node_id,
        session_id = session_id,
        "DKG Coordinator: Received and verified share"
    );

    coord
        .app_state
        .dkg_session_state
        .increment_shares(&session_id)
        .await;

    phases::drive_event(
        coord,
        session_id,
        DkgEvent::ShareRecorded { from_node_id },
        None,
    )
    .await?;

    Ok(None)
}
