use super::*;
use crypto::error::CryptoError;

/// Handle a `DkgMessage::Share`.
///
/// Validates the share is addressed to this node, deserializes it, passes it to the
/// crypto layer for verification against the sender's commitment, then checks whether
/// Phase 2 is complete.
pub(in crate::dkg::v0::coordinator) async fn handle_share_message<D>(
    coord: &DkgCoordinator<D>,
    session_id: u128,
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
    // Pure Dealers (reshare_params present but new_node_id is None) are not in
    // the new committee and must never accept incoming shares.
    let our_node_id = coord
        .app_state
        .dkg_session_state
        .with_state(&session_id, |state| -> Result<u32> {
            if let Some(params) = state.reshare_params.as_ref() {
                params.new_node_id.ok_or_else(|| {
                    DkgError::ShareVerificationFailed(
                        "Reshare share received but this node is a pure Dealer with no new-committee assignment".to_string(),
                    )
                })
            } else {
                Ok(state.node.node_id())
            }
        })
        .await
        .ok_or_else(|| session_not_found(session_id))??;

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

    match try_receive_share(coord, session_id, share.clone()).await? {
        Ok(()) => {
            record_accepted_share(coord, session_id, from_node_id, to_node_id).await?;
        }
        Err(CryptoError::CommitmentMissing(missing_node_id)) if missing_node_id == from_node_id => {
            let inserted = coord
                .app_state
                .dkg_session_state
                .store_pending_share_waiting_for_commitment(&session_id, share)
                .await
                .ok_or_else(|| session_not_found(session_id))?;

            tracing::debug!(
                from_node_id = from_node_id,
                to_node_id = to_node_id,
                session_id = session_id,
                inserted = inserted,
                "DKG Coordinator: Share arrived before commitment; queued for replay"
            );
        }
        Err(e) => {
            return Err(DkgError::ShareVerificationFailed(format!(
                "Failed to receive share: {}",
                e
            )));
        }
    }

    Ok(None)
}

pub(super) async fn receive_and_record_share<D>(
    coord: &DkgCoordinator<D>,
    session_id: u128,
    share: DistributedShare<D::ShareValue>,
) -> Result<()>
where
    D: CoordinatorDkg,
{
    let from_node_id = share.from_id;
    let to_node_id = share.to_id;

    match try_receive_share(coord, session_id, share).await? {
        Ok(()) => record_accepted_share(coord, session_id, from_node_id, to_node_id).await,
        Err(e) => Err(DkgError::ShareVerificationFailed(format!(
            "Failed to receive share: {}",
            e
        ))),
    }
}

async fn try_receive_share<D>(
    coord: &DkgCoordinator<D>,
    session_id: u128,
    share: DistributedShare<D::ShareValue>,
) -> Result<std::result::Result<(), CryptoError>>
where
    D: CoordinatorDkg,
{
    coord
        .app_state
        .dkg_session_state
        .with_state_mut(&session_id, |state| state.node.receive_share(share))
        .await
        .ok_or_else(|| session_not_found(session_id))
}

async fn record_accepted_share<D>(
    coord: &DkgCoordinator<D>,
    session_id: u128,
    from_node_id: u32,
    to_node_id: u32,
) -> Result<()>
where
    D: CoordinatorDkg,
{
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

    Ok(())
}
