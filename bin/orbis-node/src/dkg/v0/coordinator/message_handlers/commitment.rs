use super::*;
use crate::dkg::v0::coordinator::evidence::{
    build_and_store_commitment_evidence, verify_commitment_evidence,
};
use crypto::SignImpl;
/// Handle a `DkgMessage::Commitment`.
///
/// Deserializes and stores the commitment, optionally triggers polynomial generation
/// for this node (if this is the first commitment received and we haven't yet
/// generated ours), then checks whether Phase 1 is complete.
pub async fn handle_commitment_message<D>(
    coord: &DkgCoordinator<D>,
    session_id: u128,
    from_node_id: u32,
    commitment: Vec<u8>,
    report_evidence: Option<SignedDkgCommitment>,
) -> Result<Option<DkgMessage>>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    tracing::debug!(
        from_node_id = from_node_id,
        session_id = session_id,
        commitment_bytes = commitment.len(),
        "DKG Coordinator: Received commitment"
    );

    if commitment.is_empty() {
        return Err(DkgError::CommitmentVerificationFailed(
            "Commitment cannot be empty".to_string(),
        ));
    }

    if !commitment.len().is_multiple_of(G1_COMPRESSED_SIZE) {
        return Err(DkgError::CommitmentVerificationFailed(format!(
            "Invalid commitment length: {} bytes is not a multiple of {} (G1 compressed size)",
            commitment.len(),
            G1_COMPRESSED_SIZE
        )));
    }

    let num_coefficients = commitment.len() / G1_COMPRESSED_SIZE;

    if num_coefficients > MAX_COMMITMENT_COEFFICIENTS {
        return Err(DkgError::CommitmentVerificationFailed(format!(
            "Too many commitment coefficients: {} exceeds maximum {}",
            num_coefficients, MAX_COMMITMENT_COEFFICIENTS
        )));
    }

    // Get expected commitment size from session (= new_threshold for Reshare,
    // = old threshold for Fresh/Refresh), plus the session kind we need for
    // kind-specific commitment validation below.
    let (expected_coeff_count, is_refresh, is_fresh) = coord
        .app_state
        .dkg_session_state
        .with_state(&session_id, |state| {
            (
                state.expected_commitment_size(),
                matches!(state.kind, SessionKind::Refresh { .. }),
                matches!(state.kind, SessionKind::Fresh),
            )
        })
        .await
        .ok_or_else(|| session_not_found(session_id))?;

    if num_coefficients != expected_coeff_count {
        return Err(DkgError::CommitmentVerificationFailed(format!(
            "Invalid number of commitment coefficients: got {}, expected {}",
            num_coefficients, expected_coeff_count
        )));
    }

    if is_fresh {
        match coord
            .app_state
            .dkg_session_state
            .get_commitment_hash(&session_id, from_node_id)
            .await
        {
            Some(expected_hash) => {
                let actual_hash = fresh_commitment_hash(session_id, from_node_id, &commitment);
                if actual_hash != expected_hash {
                    tracing::warn!(
                        session_id = session_id,
                        from_node_id = from_node_id,
                        expected_hash = %hex::encode(expected_hash),
                        actual_hash = %hex::encode(actual_hash),
                        "DKG Coordinator: Fresh commitment reveal does not match prior hash"
                    );
                    return Err(DkgError::CommitmentVerificationFailed(format!(
                        "Fresh commitment from node {} does not match its commitment hash",
                        from_node_id
                    )));
                }
            }
            None => {
                let inserted = coord
                    .app_state
                    .dkg_session_state
                    .store_pending_commitment_waiting_for_hash(
                        &session_id,
                        from_node_id,
                        commitment,
                        report_evidence,
                    )
                    .await
                    .ok_or_else(|| session_not_found(session_id))?;
                tracing::debug!(
                    session_id = session_id,
                    from_node_id = from_node_id,
                    inserted = inserted,
                    "DKG Coordinator: Fresh commitment arrived before hash; queued for replay"
                );
                return Ok(None);
            }
        }
    }

    verify_commitment_evidence(
        coord,
        session_id,
        from_node_id,
        &commitment,
        report_evidence,
    )
    .await?;

    let mut commitment_coeffs = Vec::with_capacity(num_coefficients);
    for i in 0..num_coefficients {
        let start = i * G1_COMPRESSED_SIZE;
        let end = start + G1_COMPRESSED_SIZE;
        let coeff = <D::PublicKey>::from_bytes(&commitment[start..end]).map_err(|e| {
            DkgError::Deserialization(format!(
                "Failed to deserialize commitment coefficient {}: {}",
                i, e
            ))
        })?;
        commitment_coeffs.push(coeff);
    }

    let polynomial_commitment = PolynomialCommitment {
        coefficients: commitment_coeffs,
    };

    // Refresh delta polynomials must have an identity constant term (P(0) = O) so the
    // aggregate secret is unchanged. A non-identity constant would silently shift the
    // ring key and permanently brick decryption of existing ciphertexts. Reject before
    // the crypto layer stores it; abort-only (the session stalls to its phase timeout).
    if is_refresh && !polynomial_commitment.constant_term_is_identity() {
        return Err(DkgError::CommitmentVerificationFailed(format!(
            "Refresh commitment from node {} has a non-identity constant term \
             (a nonzero delta at x=0 would shift the ring key)",
            from_node_id
        )));
    }

    let need_to_generate_polynomial = coord
        .app_state
        .dkg_session_state
        .with_state_mut(&session_id, |state| {
            let generates_polynomial = state.node.role() != DkgRole::Receiver;
            let local_commitment_empty = state.node.commitment().coefficients.is_empty();
            if is_fresh && generates_polynomial && local_commitment_empty {
                return Err(DkgError::ProtocolError(
                    "Fresh commitment arrived before local commitment hash was prepared"
                        .to_string(),
                ));
            }

            state
                .node
                .receive_commitment(from_node_id, polynomial_commitment)
                .map_err(|e| DkgError::Crypto(format!("Failed to receive commitment: {}", e)))?;

            // Receiver nodes never generate a polynomial — they only accumulate
            // commitments to verify the shares they will receive.
            Ok::<_, DkgError>(!is_fresh && generates_polynomial && local_commitment_empty)
        })
        .await
        .ok_or_else(|| session_not_found(session_id))??;

    coord
        .app_state
        .dkg_session_state
        .increment_commitments(&session_id)
        .await;

    // If this is the first commitment received and we haven't yet generated our
    // polynomial, generate it now and broadcast our commitment.
    if need_to_generate_polynomial {
        tracing::info!(
            "DKG Coordinator: First commitment received, generating our polynomial and sending commitment"
        );

        let generated_polynomial = coord
            .app_state
            .dkg_session_state
            .with_state_mut(&session_id, |state| {
                if !state.node.commitment().coefficients.is_empty() {
                    return Ok::<_, DkgError>(false);
                }
                state.generate_polynomial()?;
                Ok(true)
            })
            .await
            .ok_or_else(|| session_not_found(session_id))??;

        if !generated_polynomial {
            tracing::debug!(
                session_id = session_id,
                "Polynomial was already generated by a concurrent first-commitment path"
            );
        } else if let Some(peer_ids) = coord
            .app_state
            .dkg_session_state
            .get_peer_ids(&session_id)
            .await
        {
            let (commitment_bytes, node_id, is_reshare, role) = coord
                .app_state
                .dkg_session_state
                .with_state(&session_id, |state| {
                    let bytes =
                        serialize_commitment_coefficients(&state.node.commitment().coefficients)?;
                    Ok::<_, DkgError>((
                        bytes,
                        state.node.node_id(),
                        matches!(state.kind, SessionKind::Reshare { .. }),
                        state.node.role(),
                    ))
                })
                .await
                .ok_or_else(|| session_not_found(session_id))??;
            let report_evidence = build_and_store_commitment_evidence(
                coord,
                session_id,
                node_id,
                commitment_bytes.clone(),
            )
            .await?;

            let mut sent_count = 0;
            let mut expected_count = 0;
            for peer_id_str in &peer_ids {
                if is_self_peer_id(&coord.app_state.network, peer_id_str) {
                    continue;
                }
                expected_count += 1;

                let commitment_msg = DkgMessage::Commitment {
                    session_id,
                    from_node_id: node_id,
                    commitment: commitment_bytes.clone(),
                    report_evidence: report_evidence.clone(),
                };

                if coord
                    .send_message_to_peer(peer_id_str, commitment_msg, Some(session_id))
                    .await
                    .inspect_err(|error| {
                        tracing::error!(
                            peer_id = %peer_id_str,
                            error = %error,
                            "Failed to send commitment to peer"
                        );
                    })
                    .is_ok()
                {
                    sent_count += 1;
                }
            }

            tracing::info!(
                sent = sent_count,
                expected = expected_count,
                "DKG Coordinator: Sent our commitment to peers"
            );

            if sent_count < expected_count && !is_reshare {
                tracing::error!(
                    sent = sent_count,
                    expected = expected_count,
                    session_id = session_id,
                    "DKG Coordinator: Could not send commitment to all peers - failing DKG to preserve expected redundancy"
                );
                coord.remove_session(session_id).await;
                tracing::debug!(
                    session_id = session_id,
                    "Cleaned up session after commitment send failure"
                );
                return Err(DkgError::NetworkCommunication(format!(
                    "Failed to send commitment to all peers: sent to {} of {}",
                    sent_count, expected_count
                )));
            }

            if sent_count < expected_count {
                tracing::warn!(
                    sent = sent_count,
                    expected = expected_count,
                    session_id = session_id,
                    "Reshare: commitment broadcast did not reach every new-committee peer; continuing until threshold selection or timeout"
                );
            }

            if is_reshare && role != DkgRole::Receiver {
                coord.initiate_phase2_shares(session_id, &peer_ids).await?;
            }
        }
    }

    if let Some(peer_ids) = coord
        .app_state
        .dkg_session_state
        .get_peer_ids(&session_id)
        .await
    {
        coord
            .check_and_trigger_phase2(session_id, &peer_ids)
            .await?;
    }

    let is_reshare = coord
        .app_state
        .dkg_session_state
        .with_state(&session_id, |state| {
            matches!(state.kind, SessionKind::Reshare { .. })
        })
        .await
        .ok_or_else(|| session_not_found(session_id))?;

    if is_reshare {
        // A selected dealer's commitment can arrive after the participant set;
        // retry Phase 4 because the public polynomial/aggregate key may now be unblocked.
        coord.check_and_trigger_phase4(session_id).await?;
    }

    if let Some(pending_share) = coord
        .app_state
        .dkg_session_state
        .take_pending_share_waiting_for_commitment(&session_id, from_node_id)
        .await
    {
        tracing::debug!(
            from_node_id = from_node_id,
            to_node_id = pending_share.share.to_id,
            session_id = session_id,
            "DKG Coordinator: Replaying share that was waiting for commitment"
        );
        let _ = super::share::receive_and_record_share(
            coord,
            session_id,
            pending_share.share,
            pending_share.report_evidence,
        )
        .await
        .inspect_err(|error| {
            tracing::error!(
                from_node_id = from_node_id,
                session_id = session_id,
                error = %error,
                "DKG Coordinator: Queued share failed after commitment arrived"
            );
        });
    }

    Ok(None)
}
