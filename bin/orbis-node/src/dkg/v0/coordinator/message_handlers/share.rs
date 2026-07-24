use super::*;
use crate::dkg::v0::coordinator::evidence::{
    queue_or_relay_invalid_share, share_evidence_proves_failure, verify_share_evidence,
};
use crypto::error::CryptoError;
use crypto::SignImpl;

/// Apply a typed private share delivery.
///
/// Validates the share is addressed to this node, deserializes it, passes it to the
/// crypto layer for verification against the sender's commitment, then checks whether
/// Phase 2 is complete.
#[cfg(test)]
pub async fn handle_share_message<D>(
    coord: &DkgCoordinator<D>,
    session_id: u128,
    from_node_id: u32,
    to_node_id: u32,
    share_value: Vec<u8>,
    nonce: [u8; 16],
    report_evidence: Option<SignedDkgShare>,
) -> Result<()>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    if accept_share_message(
        coord,
        session_id,
        from_node_id,
        to_node_id,
        share_value,
        nonce,
        report_evidence,
    )
    .await?
    {
        drive_accepted_share(coord, session_id, from_node_id).await?;
    }

    Ok(())
}

/// Validate and durably record a private share without advancing the ceremony.
///
/// The private pair transport uses this before emitting its digest ACK. Phase
/// advancement is deliberately separate because the final share can enter
/// phase 4 and wait on SourceHub; transport acknowledgement must only cover
/// crypto validation and local state acceptance, not the rest of the ceremony.
pub(crate) async fn accept_share_message<D>(
    coord: &DkgCoordinator<D>,
    session_id: u128,
    from_node_id: u32,
    to_node_id: u32,
    share_value: Vec<u8>,
    nonce: [u8; 16],
    report_evidence: Option<SignedDkgShare>,
) -> Result<bool>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
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
            if let Some(params) = state.reshare.params.as_ref() {
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
                    .reshare
                    .selected_dealers
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
        return Ok(false);
    }

    let share_val = match <D::ShareValue>::from_bytes(share_value.as_slice()) {
        Ok(value) => value,
        Err(e) => {
            // A signed but undeserializable share is still attributable bad crypto
            // (the length was already checked above, so this is a right-sized but
            // invalid encoding). Authenticate the evidence and, if it proves
            // failure, report the share instead of silently dropping it.
            let report_evidence = verify_share_evidence(
                coord,
                session_id,
                from_node_id,
                to_node_id,
                &share_value,
                nonce,
                report_evidence,
            )
            .await?;
            if let Some(report_evidence) = report_evidence {
                if share_evidence_proves_failure(&report_evidence) {
                    queue_or_relay_invalid_share(coord, session_id, report_evidence).await?;
                    tracing::warn!(
                        from_node_id = from_node_id,
                        to_node_id = to_node_id,
                        session_id = session_id,
                        error = %e,
                        "DKG Coordinator: queued invalid_crypto_response report for undeserializable DKG share"
                    );
                    return Ok(false);
                }
            }
            return Err(DkgError::Deserialization(format!(
                "Failed to deserialize share value: {}",
                e
            )));
        }
    };
    let share = DistributedShare {
        from_id: from_node_id,
        to_id: to_node_id,
        value: share_val,
        nonce,
        session_id,
    };
    let report_evidence = verify_share_evidence(
        coord,
        session_id,
        from_node_id,
        to_node_id,
        &share_value,
        nonce,
        report_evidence,
    )
    .await?;

    let accepted = match try_receive_share(coord, session_id, share.clone()).await? {
        Ok(()) => {
            record_accepted_share_state(coord, session_id, from_node_id, to_node_id).await?;
            true
        }
        Err(CryptoError::CommitmentMissing(missing_node_id)) if missing_node_id == from_node_id => {
            let inserted = coord
                .app_state
                .dkg_session_state
                .store_pending_share_waiting_for_commitment(&session_id, share, report_evidence)
                .await
                .ok_or_else(|| session_not_found(session_id))?;

            tracing::debug!(
                from_node_id = from_node_id,
                to_node_id = to_node_id,
                session_id = session_id,
                inserted = inserted,
                "DKG Coordinator: Share arrived before commitment; queued for replay"
            );
            false
        }
        Err(e) => {
            if let Some(report_evidence) = report_evidence {
                if share_evidence_proves_failure(&report_evidence) {
                    queue_or_relay_invalid_share(coord, session_id, report_evidence).await?;
                    tracing::warn!(
                        from_node_id = from_node_id,
                        to_node_id = to_node_id,
                        session_id = session_id,
                        error = %e,
                        "DKG Coordinator: queued invalid_crypto_response report for bad DKG share"
                    );
                    return Ok(false);
                }
            }
            return Err(DkgError::ShareVerificationFailed(format!(
                "Failed to receive share: {}",
                e
            )));
        }
    };

    Ok(accepted)
}

pub(super) async fn receive_and_record_share<D>(
    coord: &DkgCoordinator<D>,
    session_id: u128,
    share: DistributedShare<D::ShareValue>,
    report_evidence: Option<SignedDkgShare>,
) -> Result<()>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    let from_node_id = share.from_id;
    let to_node_id = share.to_id;

    match try_receive_share(coord, session_id, share).await? {
        Ok(()) => record_accepted_share(coord, session_id, from_node_id, to_node_id).await,
        Err(e) => {
            if let Some(report_evidence) = report_evidence {
                if share_evidence_proves_failure(&report_evidence) {
                    queue_or_relay_invalid_share(coord, session_id, report_evidence).await?;
                    tracing::warn!(
                        from_node_id = from_node_id,
                        to_node_id = to_node_id,
                        session_id = session_id,
                        error = %e,
                        "DKG Coordinator: queued invalid_crypto_response report for pending bad DKG share"
                    );
                    return Ok(());
                }
            }
            Err(DkgError::ShareVerificationFailed(format!(
                "Failed to receive share: {}",
                e
            )))
        }
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
    record_accepted_share_state(coord, session_id, from_node_id, to_node_id).await?;
    drive_accepted_share(coord, session_id, from_node_id).await
}

async fn record_accepted_share_state<D>(
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
        .record_received_share(&session_id, from_node_id)
        .await;

    Ok(())
}

pub(crate) async fn drive_accepted_share<D>(
    coord: &DkgCoordinator<D>,
    session_id: u128,
    from_node_id: u32,
) -> Result<()>
where
    D: CoordinatorDkg,
{
    phases::drive_event(
        coord,
        session_id,
        DkgEvent::ShareRecorded { from_node_id },
        None,
    )
    .await
}
