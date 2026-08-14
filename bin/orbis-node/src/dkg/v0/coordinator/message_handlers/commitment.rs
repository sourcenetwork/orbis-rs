use super::*;
use crate::dkg::v0::coordinator::evidence::{
    queue_invalid_refresh_commitment_report, verify_commitment_evidence,
};
use crypto::SignImpl;

#[derive(Debug)]
pub(crate) enum PreparedCommitment {
    WaitingForHash,
    Ready {
        polynomial_commitment: PolynomialCommitment,
        verified_evidence: Box<Option<SignedDkgCommitment>>,
        is_fresh: bool,
        is_reshare: bool,
    },
}

/// Shared by every Refresh-commitment failure mode that carries verified
/// evidence. The report statement carries the dealer's exact signed bytes
/// rather than a decoded value, so an undecodable commitment is just as
/// reportable as a decodable-but-wrong one.
async fn report_invalid_refresh_commitment<D>(
    coord: &DkgCoordinator<D>,
    session_id: u128,
    from_node_id: u32,
    is_refresh: bool,
    verified_evidence: &Option<SignedDkgCommitment>,
) where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    if !is_refresh {
        return;
    }
    let Some(evidence) = verified_evidence else {
        return;
    };
    if let Err(error) = queue_invalid_refresh_commitment_report(
        coord.app_state.clone(),
        coord.routes,
        evidence.clone(),
    )
    .await
    {
        tracing::warn!(
            session_id,
            from_node_id,
            error = %error,
            "Failed to queue invalid-refresh-commitment report"
        );
    }
}

pub(crate) async fn prepare_commitment_message<D>(
    coord: &DkgCoordinator<D>,
    attempt: AttemptKey,
    from_node_id: u32,
    commitment: &[u8],
    report_evidence: Option<&SignedDkgCommitment>,
    expected_hash_override: Option<[u8; 32]>,
) -> Result<PreparedCommitment>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    let session_id = attempt.session_id();
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

    let (expected_coeff_count, is_refresh, is_fresh, is_reshare, expected_hash, mut node_probe) =
        coord
            .app_state
            .dkg_session_state
            .with_attempt_state(attempt, |state| {
                (
                    state.expected_commitment_size(),
                    matches!(state.kind, SessionKind::Refresh { .. }),
                    matches!(state.kind, SessionKind::Fresh),
                    matches!(state.kind, SessionKind::Reshare { .. }),
                    expected_hash_override.or_else(|| {
                        state
                            .commit_reveal
                            .received_hashes
                            .get(&from_node_id)
                            .copied()
                    }),
                    state.node.clone(),
                )
            })
            .await
            .map_err(|error| attempt_state_error(attempt, error))?;

    if num_coefficients != expected_coeff_count {
        return Err(DkgError::CommitmentVerificationFailed(format!(
            "Invalid number of commitment coefficients: got {}, expected {}",
            num_coefficients, expected_coeff_count
        )));
    }
    let waiting_for_hash = is_fresh && expected_hash.is_none();
    if is_fresh {
        if let Some(expected_hash) = expected_hash {
            let actual_hash = fresh_commitment_hash(session_id, from_node_id, commitment);
            if actual_hash != expected_hash {
                return Err(DkgError::CommitmentVerificationFailed(format!(
                    "Fresh commitment from node {} does not match its commitment hash",
                    from_node_id
                )));
            }
        }
    }

    let verified_evidence = verify_commitment_evidence(
        coord,
        attempt,
        from_node_id,
        commitment,
        report_evidence.cloned(),
    )
    .await?;
    let mut commitment_coeffs = Vec::with_capacity(num_coefficients);
    for i in 0..num_coefficients {
        let start = i * G1_COMPRESSED_SIZE;
        let end = start + G1_COMPRESSED_SIZE;
        let coeff = match <D::PublicKey>::from_bytes(&commitment[start..end]) {
            Ok(coeff) => coeff,
            Err(e) => {
                report_invalid_refresh_commitment(
                    coord,
                    session_id,
                    from_node_id,
                    is_refresh,
                    &verified_evidence,
                )
                .await;
                return Err(DkgError::Deserialization(format!(
                    "Failed to deserialize commitment coefficient {}: {}",
                    i, e
                )));
            }
        };
        commitment_coeffs.push(coeff);
    }
    let polynomial_commitment = PolynomialCommitment {
        coefficients: commitment_coeffs,
    };

    if is_refresh && !polynomial_commitment.constant_term_is_identity() {
        report_invalid_refresh_commitment(
            coord,
            session_id,
            from_node_id,
            is_refresh,
            &verified_evidence,
        )
        .await;
        return Err(DkgError::CommitmentVerificationFailed(format!(
            "Refresh commitment from node {} has a non-identity constant term \
             (a nonzero delta at x=0 would shift the ring key)",
            from_node_id
        )));
    }
    node_probe
        .receive_commitment(from_node_id, polynomial_commitment.clone())
        .map_err(|e| DkgError::Crypto(format!("Failed to receive commitment: {}", e)))?;

    if waiting_for_hash {
        return Ok(PreparedCommitment::WaitingForHash);
    }

    Ok(PreparedCommitment::Ready {
        polynomial_commitment,
        verified_evidence: Box::new(verified_evidence),
        is_fresh,
        is_reshare,
    })
}

/// Apply a typed public commitment contribution.
///
/// Deserializes and stores the commitment, optionally triggers polynomial generation
/// for this node (if this is the first commitment received and we haven't yet
/// generated ours), then checks whether Phase 1 is complete.
pub async fn handle_commitment_message<D>(
    coord: &DkgCoordinator<D>,
    attempt: AttemptKey,
    from_node_id: u32,
    commitment: Vec<u8>,
    report_evidence: Option<SignedDkgCommitment>,
) -> Result<()>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    let session_id = attempt.session_id();
    tracing::debug!(
        from_node_id = from_node_id,
        session_id = session_id,
        commitment_bytes = commitment.len(),
        "DKG Coordinator: Received commitment"
    );

    let PreparedCommitment::Ready {
        polynomial_commitment,
        verified_evidence,
        is_fresh,
        is_reshare,
    } = prepare_commitment_message(
        coord,
        attempt,
        from_node_id,
        &commitment,
        report_evidence.as_ref(),
        None,
    )
    .await?
    else {
        let inserted = coord
            .app_state
            .dkg_session_state
            .with_attempt_state_mut(attempt, |state| {
                if state
                    .pending
                    .pending_commitments_waiting_for_hash
                    .contains_key(&from_node_id)
                {
                    return false;
                }
                state.pending.pending_commitments_waiting_for_hash.insert(
                    from_node_id,
                    crate::dkg::v0::session_state::PendingDkgCommitment {
                        commitment,
                        report_evidence,
                    },
                );
                true
            })
            .await
            .map_err(|error| attempt_state_error(attempt, error))?;
        tracing::debug!(
            session_id,
            from_node_id,
            inserted,
            "DKG Coordinator: Fresh commitment arrived before hash; queued for replay"
        );
        return Ok(());
    };

    let need_to_generate_polynomial = coord
        .app_state
        .dkg_session_state
        .with_attempt_state_mut(attempt, |state| {
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
            state.commitments_received += 1;
            if let Some(evidence) = *verified_evidence {
                state
                    .commitment_audit
                    .received_commitments
                    .insert(from_node_id, evidence);
            }

            // Receiver nodes never generate a polynomial — they only accumulate
            // commitments to verify the shares they will receive.
            Ok::<_, DkgError>(!is_fresh && generates_polynomial && local_commitment_empty)
        })
        .await
        .map_err(|error| attempt_state_error(attempt, error))??;

    // If this is the first commitment received and we haven't yet generated our
    // polynomial, generate it now and broadcast our commitment.
    if need_to_generate_polynomial {
        tracing::info!(
            "DKG Coordinator: First commitment received, generating our polynomial and sending commitment"
        );

        let generated_polynomial = coord
            .app_state
            .dkg_session_state
            .with_attempt_state_mut(attempt, |state| {
                if !state.node.commitment().coefficients.is_empty() {
                    return Ok::<_, DkgError>(false);
                }
                state.generate_polynomial()?;
                Ok(true)
            })
            .await
            .map_err(|error| attempt_state_error(attempt, error))??;

        if !generated_polynomial {
            tracing::debug!(
                session_id = session_id,
                "Polynomial was already generated by a concurrent first-commitment path"
            );
        } else {
            let peer_ids = coord
                .app_state
                .dkg_session_state
                .with_attempt_state(attempt, |state| state.routing.peer_ids.clone())
                .await
                .map_err(|error| attempt_state_error(attempt, error))?;
            coord
                .initiate_phase1_commitments(attempt, &peer_ids)
                .await?;
        }
    }

    let peer_ids = coord
        .app_state
        .dkg_session_state
        .with_attempt_state(attempt, |state| state.routing.peer_ids.clone())
        .await
        .map_err(|error| attempt_state_error(attempt, error))?;
    if !peer_ids.is_empty() {
        coord.check_and_trigger_phase2(attempt, &peer_ids).await?;
    }

    if is_reshare {
        // A selected dealer's commitment can arrive after the participant set;
        // retry Phase 4 because the public polynomial/aggregate key may now be unblocked.
        coord.check_and_trigger_phase4(attempt).await?;
    }

    if let Some(pending_share) = coord
        .app_state
        .dkg_session_state
        .take_pending_share_for_attempt(attempt, from_node_id)
        .await
        .map_err(|error| attempt_state_error(attempt, error))?
    {
        tracing::debug!(
            from_node_id = from_node_id,
            to_node_id = pending_share.share.to_id,
            session_id = session_id,
            "DKG Coordinator: Replaying share that was waiting for commitment"
        );
        let _ = super::share::receive_and_record_share(
            coord,
            attempt,
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

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::helpers::test_helpers::{cleanup_db, create_test_app_state_default, test_db_path};
    use crypto::r#trait::DkgRole;
    use std::sync::Arc;

    /// A fresh single-node-view coordinator with a session whose threshold
    /// (and therefore `expected_commitment_size()`) is `threshold`. Every
    /// test below exercises `prepare_commitment_message`'s structural
    /// preflight checks, which run unconditionally before evidence
    /// verification or any per-`SessionKind` logic — this is the same
    /// preflight the organic Docker integration test relies on real,
    /// unmodified receiving nodes to run when a leader broadcasts a
    /// structurally invalid commitment (`dkg_public_origin_fault`/
    /// `InvalidPayload`); this covers that rejection directly and quickly,
    /// without needing a live multi-node ceremony to reach it.
    async fn test_coord(
        db_name: &str,
        threshold: usize,
        total_nodes: usize,
    ) -> (DkgCoordinator<crypto::DkgImpl>, AttemptKey) {
        let app_state = create_test_app_state_default(db_name).await;
        let coord = DkgCoordinator::with_routes(Arc::new(app_state), &::network::V0);
        let attempt = AttemptKey::test(4242);
        coord
            .create_session(
                attempt,
                1,
                threshold,
                total_nodes,
                DkgRole::Standard,
                |_state| {},
            )
            .await
            .expect("create test DKG session");
        (coord, attempt)
    }

    fn assert_verification_failed(error: &DkgError) {
        assert!(
            matches!(error, DkgError::CommitmentVerificationFailed(_)),
            "expected CommitmentVerificationFailed, got {error:?}"
        );
    }

    #[tokio::test]
    async fn prepare_commitment_message_rejects_empty_commitment() {
        let db_name = "prepare_commitment_message_rejects_empty_commitment";
        let db_path = test_db_path(db_name);
        let (coord, attempt) = test_coord(db_name, 2, 3).await;

        let error = prepare_commitment_message(&coord, attempt, 2, &[], None, None)
            .await
            .expect_err("empty commitment must be rejected");
        assert_verification_failed(&error);

        cleanup_db(&db_path);
    }

    #[tokio::test]
    async fn prepare_commitment_message_rejects_wrong_length_commitment() {
        let db_name = "prepare_commitment_message_rejects_wrong_length_commitment";
        let db_path = test_db_path(db_name);
        let (coord, attempt) = test_coord(db_name, 2, 3).await;

        // Deliberately not a multiple of G1_COMPRESSED_SIZE — the same shape
        // of malformed payload the organic Docker test broadcasts to
        // exercise this exact rejection.
        let malformed = vec![0u8; 7];
        let error = prepare_commitment_message(&coord, attempt, 2, &malformed, None, None)
            .await
            .expect_err("wrong-length commitment must be rejected");
        assert_verification_failed(&error);

        cleanup_db(&db_path);
    }

    #[tokio::test]
    async fn prepare_commitment_message_rejects_wrong_coefficient_count() {
        let db_name = "prepare_commitment_message_rejects_wrong_coefficient_count";
        let db_path = test_db_path(db_name);
        let (coord, attempt) = test_coord(db_name, 2, 3).await;

        // Correct length-multiple, but the wrong number of coefficients for
        // this ceremony's threshold (2) — zero bytes are fine here since the
        // coefficient-count check runs before any point deserialization is
        // ever attempted.
        let wrong_count = vec![0u8; G1_COMPRESSED_SIZE * 3];
        let error = prepare_commitment_message(&coord, attempt, 2, &wrong_count, None, None)
            .await
            .expect_err("wrong coefficient count must be rejected");
        assert_verification_failed(&error);

        cleanup_db(&db_path);
    }

    #[tokio::test]
    async fn prepare_commitment_message_rejects_too_many_coefficients() {
        let db_name = "prepare_commitment_message_rejects_too_many_coefficients";
        let db_path = test_db_path(db_name);
        let (coord, attempt) = test_coord(db_name, 2, 3).await;

        let oversized = vec![0u8; G1_COMPRESSED_SIZE * (MAX_COMMITMENT_COEFFICIENTS + 1)];
        let error = prepare_commitment_message(&coord, attempt, 2, &oversized, None, None)
            .await
            .expect_err("commitment exceeding the coefficient cap must be rejected");
        assert_verification_failed(&error);

        cleanup_db(&db_path);
    }
}
