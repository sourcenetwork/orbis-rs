use super::*;

pub(crate) fn build_commitment_evidence_with_context<D>(
    coord: &DkgCoordinator<D>,
    context: &DkgEvidenceBuildContext,
    from_node_id: u32,
    commitment: Vec<u8>,
) -> Result<SignedDkgCommitment>
where
    D: CoordinatorDkg,
{
    let binding = &context.binding;
    let signed_at = now_unix_secs()?;
    let statement = DkgCommitmentStatement {
        domain: DKG_COMMITMENT_DOMAIN.to_string(),
        chain_id: binding.chain_id.clone(),
        ring_id: binding.ring_id.clone(),
        ring_pk: binding.ring_pk.clone(),
        ring_state_sha256: binding.ring_state_sha256.clone(),
        protocol_version: binding.protocol_version,
        request_id: binding.request_id.clone(),
        signed_at,
        responder_node_key: coord.app_state.node_key.clone(),
        origin_protocol: binding.origin_protocol.clone(),
        accused_committee_scope: CommitteeScope::Current,
        signing_committee_scope: CommitteeScope::Current,
        from_node_id,
        commitment,
        session_nonce: context.session_nonce,
        attempt_id: context.attempt_id,
        crypto_backend: D::name(),
    };
    let signature =
        sign_statement_with_key(&context.signing_key_hex, &statement.canonical_bytes())?;
    Ok(SignedDkgCommitment {
        statement,
        signature,
    })
}

pub async fn build_and_store_commitment_evidence<D>(
    coord: &DkgCoordinator<D>,
    attempt: AttemptKey,
    from_node_id: u32,
    commitment: Vec<u8>,
) -> Result<Option<SignedDkgCommitment>>
where
    D: CoordinatorDkg,
{
    let Some(context) = evidence_build_context(coord, attempt).await? else {
        return Ok(None);
    };
    let report_evidence = build_and_store_commitment_evidence_with_context(
        coord,
        attempt,
        &context,
        from_node_id,
        commitment,
    )
    .await?;
    Ok(Some(report_evidence))
}

pub(crate) async fn build_and_store_commitment_evidence_with_context<D>(
    coord: &DkgCoordinator<D>,
    attempt: AttemptKey,
    context: &DkgEvidenceBuildContext,
    from_node_id: u32,
    commitment: Vec<u8>,
) -> Result<SignedDkgCommitment>
where
    D: CoordinatorDkg,
{
    let report_evidence =
        build_commitment_evidence_with_context(coord, context, from_node_id, commitment)?;
    coord
        .app_state
        .dkg_session_state
        .with_attempt_state_mut(attempt, |state| {
            state.local_signed_commitment = Some(report_evidence.clone());
        })
        .await
        .map_err(|error| attempt_state_error(attempt, error))?;
    Ok(report_evidence)
}

pub async fn verify_commitment_evidence<D>(
    coord: &DkgCoordinator<D>,
    attempt: AttemptKey,
    from_node_id: u32,
    commitment: &[u8],
    evidence: Option<SignedDkgCommitment>,
) -> Result<Option<SignedDkgCommitment>>
where
    D: CoordinatorDkg,
{
    let Some(binding) = evidence_binding(coord, attempt).await? else {
        return Ok(None);
    };
    let evidence = evidence.ok_or_else(|| {
        DkgError::Unauthorized("PSS DKG commitment is missing signed report evidence".to_string())
    })?;
    validate_commitment_statement::<D>(&binding, from_node_id, commitment, &evidence.statement)?;
    verify_node_message(
        &evidence.statement.responder_node_key,
        &evidence.statement.canonical_bytes(),
        &evidence.signature,
    )
    .map_err(|error| {
        DkgError::Unauthorized(format!(
            "invalid DKG commitment evidence signature: {error}"
        ))
    })?;
    Ok(Some(evidence))
}

/// Two commitments are equivocation iff the same dealer signed both for the same attempt
/// under the SAME per-attempt nonce with different bytes.
pub(crate) fn commitments_prove_equivocation(
    commitment_a: &SignedDkgCommitment,
    commitment_b: &SignedDkgCommitment,
) -> bool {
    commitment_a
        .statement
        .proves_equivocation_with(&commitment_b.statement)
}

pub async fn queue_or_relay_equivocation<D>(
    coord: &DkgCoordinator<D>,
    attempt: AttemptKey,
    commitment_a: SignedDkgCommitment,
    commitment_b: SignedDkgCommitment,
) -> Result<()>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    if local_node_is_current_route_member(coord, attempt).await? {
        queue_equivocation_report(
            coord.app_state.clone(),
            coord.routes,
            commitment_a,
            commitment_b,
        )
        .await
    } else if commitment_a.statement.origin_protocol == "pss_reshare" {
        let app_state = coord.app_state.clone();
        let routes = coord.routes;
        spawn_evidence_relay(attempt.session_id(), "dkg_equivocation", async move {
            let coordinator = DkgCoordinator::with_routes(app_state, routes);
            relay_equivocation_evidence(&coordinator, attempt, commitment_a, commitment_b).await
        });
        Ok(())
    } else {
        Err(DkgError::Unauthorized(
            "local node is not in the report signing committee".to_string(),
        ))
    }
}

async fn relay_equivocation_evidence<D>(
    coord: &DkgCoordinator<D>,
    attempt: AttemptKey,
    commitment_a: SignedDkgCommitment,
    commitment_b: SignedDkgCommitment,
) -> Result<()>
where
    D: CoordinatorDkg,
{
    relay_invalid_commitment_evidence(coord, attempt, commitment_a, commitment_b).await
}

pub async fn handle_invalid_commitment_evidence_relay<D>(
    coord: &DkgCoordinator<D>,
    attempt: AttemptKey,
    commitment_a: SignedDkgCommitment,
    commitment_b: SignedDkgCommitment,
) -> Result<()>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    if commitment_a.statement.origin_protocol != "pss_reshare" {
        return Err(DkgError::Unauthorized(
            "DKG equivocation evidence relay is only valid for reshare".to_string(),
        ));
    }
    verify_relay_is_current_signer(coord, attempt).await?;

    // Relayed evidence is otherwise unauthenticated input: re-authenticate both commitments
    // against this session (ring binding + the dealer's signature) and re-confirm they
    // actually prove equivocation before spending a report attempt on them.
    let from_node_id_a = commitment_a.statement.from_node_id;
    let commitment_bytes_a = commitment_a.statement.commitment.clone();
    let verified_a = verify_commitment_evidence(
        coord,
        attempt,
        from_node_id_a,
        &commitment_bytes_a,
        Some(commitment_a),
    )
    .await?
    .ok_or_else(|| {
        DkgError::Unauthorized(
            "relayed DKG equivocation commitment is not valid for this session".to_string(),
        )
    })?;
    let from_node_id_b = commitment_b.statement.from_node_id;
    let commitment_bytes_b = commitment_b.statement.commitment.clone();
    let verified_b = verify_commitment_evidence(
        coord,
        attempt,
        from_node_id_b,
        &commitment_bytes_b,
        Some(commitment_b),
    )
    .await?
    .ok_or_else(|| {
        DkgError::Unauthorized(
            "relayed DKG equivocation commitment is not valid for this session".to_string(),
        )
    })?;
    if !commitments_prove_equivocation(&verified_a, &verified_b) {
        return Err(DkgError::Unauthorized(
            "relayed DKG commitments do not prove equivocation".to_string(),
        ));
    }

    queue_equivocation_report(
        coord.app_state.clone(),
        coord.routes,
        verified_a,
        verified_b,
    )
    .await?;
    Ok(())
}

pub(super) fn validate_commitment_statement<D>(
    binding: &DkgReportEvidenceBinding,
    from_node_id: u32,
    commitment: &[u8],
    statement: &DkgCommitmentStatement,
) -> Result<()>
where
    D: CoordinatorDkg,
{
    if statement.domain != DKG_COMMITMENT_DOMAIN
        || statement.chain_id != binding.chain_id
        || statement.ring_id != binding.ring_id
        || statement.ring_pk != binding.ring_pk
        || statement.ring_state_sha256 != binding.ring_state_sha256
        || statement.protocol_version != binding.protocol_version
        || statement.request_id != binding.request_id
        || statement.origin_protocol != binding.origin_protocol
        || statement.accused_committee_scope != CommitteeScope::Current
        || statement.signing_committee_scope != CommitteeScope::Current
        || statement.from_node_id != from_node_id
        || statement.commitment != commitment
        || statement.crypto_backend != D::name()
    {
        return Err(DkgError::Unauthorized(
            "DKG commitment evidence does not match this session".to_string(),
        ));
    }
    if statement.responder_node_key.trim().is_empty() {
        return Err(DkgError::Unauthorized(
            "DKG commitment evidence responder cannot be empty".to_string(),
        ));
    }
    let expected_responder_node_key =
        node_key_for_canonical_node_id(from_node_id, &binding.current_node_keys).ok_or_else(
            || {
                DkgError::Unauthorized(format!(
                    "DKG commitment from_node_id {from_node_id} is outside the current committee"
                ))
            },
        )?;
    if statement.responder_node_key != expected_responder_node_key {
        return Err(DkgError::Unauthorized(
            "DKG commitment evidence responder does not match from_node_id".to_string(),
        ));
    }
    Ok(())
}

/// Report a refresh dealer whose signed commitment has a non-identity constant term.
/// Refresh keeps the same committee, so the detector is always a current-committee member —
/// this queues directly (no relay). Single self-incriminating statement.
pub async fn queue_invalid_refresh_commitment_report<D>(
    app_state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    commitment: SignedDkgCommitment,
) -> Result<()>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    let accused_node_key = commitment.statement.responder_node_key.clone();
    let accused_info = read_node_info(&app_state, &accused_node_key).await?;
    let observed_at = commitment
        .statement
        .signed_at
        .saturating_sub(CHAIN_BLOCK_GRACE_SECS);
    let observation = InvalidCryptoResponseObservation {
        ring_id: commitment.statement.ring_id.clone(),
        accused_node_key,
        accused_peer_id: accused_info.peer_id,
        observed_at,
        inline_document: None,
        evidence: InvalidCryptoResponse::DkgInvalidRefreshCommitment {
            statement: Box::new(commitment.statement),
            response_signature: commitment.signature,
        },
    };

    queue_report::<D, SignImpl>(
        app_state,
        routes,
        ReportObservation::InvalidCryptoResponse(Box::new(observation)),
    )
    .await
    .map_err(|error| DkgError::Generic(error.to_string()))?;
    Ok(())
}

async fn queue_equivocation_report<D>(
    app_state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    commitment_a: SignedDkgCommitment,
    commitment_b: SignedDkgCommitment,
) -> Result<()>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    // Both commitments name the same dealer. Anchor the envelope to the LATER
    // of the two signed_at values, not whichever happens to be "commitment_a"
    // (typically the earlier, already-retained one) — equivocation is only
    // detectable once the second, conflicting commitment arrives, which can
    // legitimately be well after the first within a long-running attempt.
    // Anchoring to the earlier one would let the report's TTL close before
    // the fault is even provable.
    let accused_node_key = commitment_a.statement.responder_node_key.clone();
    let accused_info = read_node_info(&app_state, &accused_node_key).await?;
    let observed_at = commitment_a
        .statement
        .signed_at
        .max(commitment_b.statement.signed_at)
        .saturating_sub(CHAIN_BLOCK_GRACE_SECS);
    let observation = InvalidCryptoResponseObservation {
        ring_id: commitment_a.statement.ring_id.clone(),
        accused_node_key,
        accused_peer_id: accused_info.peer_id,
        observed_at,
        inline_document: None,
        evidence: InvalidCryptoResponse::DkgEquivocation {
            commitment_a: Box::new(commitment_a),
            commitment_b: Box::new(commitment_b),
        },
    };

    queue_report::<D, SignImpl>(
        app_state,
        routes,
        ReportObservation::InvalidCryptoResponse(Box::new(observation)),
    )
    .await
    .map_err(|error| DkgError::Generic(error.to_string()))?;
    Ok(())
}
