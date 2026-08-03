use super::*;
use crate::dkg::v0::coordinator::evidence::{
    build_and_store_commitment_evidence_with_context, build_share_evidence_with_context,
    evidence_build_context,
};

pub async fn initiate_phase2_shares<D>(
    coord: &DkgCoordinator<D>,
    attempt: AttemptKey,
    peer_ids: &[String],
) -> Result<()>
where
    D: CoordinatorDkg,
{
    let session_id = attempt.session_id();
    let (
        shares,
        node_id,
        threshold,
        is_reshare,
        reshare_new_node_id,
        reshare_new_node_id_to_peer_id,
        current_node_id_to_peer_id,
        commitment_bytes,
        stored_commitment_evidence,
        activated,
    ) = coord
        .app_state
        .dkg_session_state
        .with_attempt_state_mut(attempt, |state| {
            if state.node.commitment().coefficients.is_empty() {
                tracing::debug!(
                    node_id = state.node.node_id(),
                    "DKG Coordinator: Generating polynomial before Phase 2"
                );
                state.generate_polynomial()?;
            }

            tracing::debug!(
                node_id = state.node.node_id(),
                session_id = session_id,
                "DKG Coordinator: Generating shares"
            );
            let shares = state
                .node
                .generate_shares()
                .map_err(|e| DkgError::Crypto(format!("Failed to generate shares: {}", e)))?;

            tracing::debug!(
                share_count = shares.len(),
                "DKG Coordinator: Generated shares"
            );

            let reshare_peer_ids = state
                .reshare
                .params
                .as_ref()
                .map(|_| state.routing.reshare_new_node_id_to_peer_id.clone());
            let reshare_new_node_id = state
                .reshare
                .params
                .as_ref()
                .and_then(|params| params.new_node_id);
            Ok::<_, DkgError>((
                shares,
                state.node.node_id(),
                state.node.threshold(),
                matches!(state.kind, SessionKind::Reshare { .. }),
                reshare_new_node_id,
                reshare_peer_ids,
                state.routing.node_id_to_peer_id.clone(),
                serialize_commitment_coefficients(&state.node.commitment().coefficients)?,
                state.local_signed_commitment.clone(),
                state.transport.activated,
            ))
        })
        .await
        .map_err(|error| attempt_state_error(attempt, error))??;

    coord
        .app_state
        .dkg_session_state
        .update_phase_for_attempt(attempt, DkgPhase::Phase2Shares)
        .await
        .map_err(|error| attempt_state_error(attempt, error))?;
    let evidence_context = evidence_build_context(coord, attempt).await?;
    let commitment_evidence = match stored_commitment_evidence {
        Some(evidence) => Some(evidence),
        None => match &evidence_context {
            Some(context) => Some(
                build_and_store_commitment_evidence_with_context(
                    coord,
                    attempt,
                    context,
                    node_id,
                    commitment_bytes,
                )
                .await?,
            ),
            None => None,
        },
    };

    if peer_ids.is_empty() {
        tracing::error!("DKG Coordinator: No peer_ids available to send shares to");
        coord.abort_attempt(attempt).await;
        tracing::debug!(
            session_id = session_id,
            "Cleaned up session - no peer_ids available"
        );
        return Err(DkgError::InsufficientPeers {
            successful: 0,
            total: 0,
            threshold,
        });
    }

    tracing::debug!(
        share_count = shares.len(),
        node_id = node_id,
        "DKG Coordinator: Sending shares to peers"
    );

    if !activated {
        return Err(DkgError::ProtocolError(
            "private shares generated before transport attempt activation".to_string(),
        ));
    }
    let ceremony_id = attempt.ceremony_id;
    let attempt_id = attempt.attempt_id;
    let mut outgoing = Vec::with_capacity(shares.len().saturating_sub(1));
    for share in &shares {
        if !is_reshare && share.to_id == node_id {
            continue;
        }
        if is_reshare && Some(share.to_id) == reshare_new_node_id {
            // A DealerReceiver's own reshare contribution is evaluated from
            // its retained polynomial by the crypto implementation. Feeding
            // it back through `receive_share` would be both redundant and
            // invalid (`from_id == self`). The post-distribution state-machine
            // event records this dealer as locally valid for selection.
            //
            // Checked by node ID here, before resolving a route: a receiver
            // that continues into the new committee has no reason to hold a
            // route to itself, so resolving `target_peer_id` first could fail
            // with a spurious "missing peer mapping" error for this exact
            // self-delivery case.
            continue;
        }
        let target_peer_id = if is_reshare {
            reshare_new_node_id_to_peer_id
                .as_ref()
                .and_then(|routes| routes.get(&share.to_id))
                .cloned()
        } else {
            current_node_id_to_peer_id.get(&share.to_id).cloned()
        }
        .ok_or_else(|| {
            DkgError::ProtocolError(format!(
                "Missing peer mapping for node_id {}; refusing to route private share",
                share.to_id
            ))
        })?;
        let share_value = CryptoSerialize::to_bytes(&share.value).map_err(|error| {
            DkgError::Serialization(format!("Failed to serialize private share value: {error}"))
        })?;
        let report_evidence = match (&evidence_context, &commitment_evidence) {
            (Some(context), Some(commitment_evidence)) => Some(build_share_evidence_with_context(
                coord,
                context,
                node_id,
                share.to_id,
                share_value.clone(),
                share.nonce,
                commitment_evidence,
            )?),
            _ => None,
        };
        let message_id = derive_private_message_id(
            ceremony_id,
            attempt_id,
            ParticipantRef::current(node_id),
            if is_reshare {
                ParticipantRef::next(share.to_id)
            } else {
                ParticipantRef::current(share.to_id)
            },
            &share_value,
            &share.nonce,
        );
        let private = DkgPrivateMessage::ShareDelivery {
            ceremony_id,
            attempt_id,
            message_id,
            from: ParticipantRef::current(node_id),
            to: if is_reshare {
                ParticipantRef::next(share.to_id)
            } else {
                ParticipantRef::current(share.to_id)
            },
            share_value,
            nonce: share.nonce,
            report_evidence: report_evidence.map(Box::new),
        };
        let exact_bytes = encode(&private).map_err(DkgError::Serialization)?;
        if !coord
            .app_state
            .dkg_session_state
            .cache_private_message_for_attempt(attempt, message_id, exact_bytes.clone())
            .await
            .map_err(|error| attempt_state_error(attempt, error))?
        {
            return Err(DkgError::ProtocolError(
                "private share retransmission bytes changed".to_string(),
            ));
        }
        outgoing.push((share.to_id, target_peer_id, message_id, exact_bytes));
    }
    tracing::info!(
        session_id,
        node_id,
        pair_count = outgoing.len(),
        "Phase 2: cached exact private shares; starting bounded pair exchanges"
    );
    exchange_private_shares(coord, attempt, outgoing).await?;
    drive_post_phase2_event(
        coord,
        attempt,
        DkgEvent::Phase2SharesDistributed {
            local_node_id: node_id,
        },
    )
    .await
}
