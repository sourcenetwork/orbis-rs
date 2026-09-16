use super::*;

pub(crate) fn build_share_evidence_with_context<D>(
    coord: &DkgCoordinator<D>,
    context: &DkgEvidenceBuildContext,
    from_node_id: u32,
    to_node_id: u32,
    share_value: Vec<u8>,
    nonce: [u8; 16],
    commitment_evidence: &SignedDkgCommitment,
) -> Result<SignedDkgShare>
where
    D: CoordinatorDkg,
{
    let binding = &context.binding;
    let receiver_node_key = binding
        .receiver_node_keys
        .get(to_node_id.saturating_sub(1) as usize)
        .ok_or_else(|| {
            DkgError::InvalidState(format!(
                "DKG share to_node_id {} is outside the receiver committee",
                to_node_id
            ))
        })?
        .clone();

    let signed_at = now_unix_secs()?;
    let statement = DkgShareStatement {
        domain: DKG_SHARE_DOMAIN.to_string(),
        chain_id: binding.chain_id.clone(),
        ring_id: binding.ring_id.clone(),
        ring_pk: binding.ring_pk.clone(),
        ring_state_sha256: binding.ring_state_sha256.clone(),
        protocol_version: binding.protocol_version,
        request_id: binding.request_id.clone(),
        signed_at,
        responder_node_key: coord.app_state.node_key.clone(),
        receiver_node_key,
        origin_protocol: binding.origin_protocol.clone(),
        accused_committee_scope: CommitteeScope::Current,
        signing_committee_scope: CommitteeScope::Current,
        from_node_id,
        to_node_id,
        commitment_statement: commitment_evidence.statement.clone(),
        commitment_signature: commitment_evidence.signature.clone(),
        share_value,
        nonce,
        crypto_backend: D::name(),
    };
    let signature =
        sign_statement_with_key(&context.signing_key_hex, &statement.canonical_bytes())?;
    Ok(SignedDkgShare {
        statement,
        signature,
    })
}

pub async fn verify_share_evidence<D>(
    coord: &DkgCoordinator<D>,
    attempt: AttemptKey,
    from_node_id: u32,
    to_node_id: u32,
    share_value: &[u8],
    nonce: [u8; 16],
    evidence: Option<SignedDkgShare>,
) -> Result<Option<SignedDkgShare>>
where
    D: CoordinatorDkg,
{
    let Some(binding) = evidence_binding(coord, attempt).await? else {
        return Ok(None);
    };
    let evidence = evidence.ok_or_else(|| {
        DkgError::Unauthorized("PSS DKG share is missing signed report evidence".to_string())
    })?;
    validate_share_statement::<D>(
        &binding,
        from_node_id,
        to_node_id,
        share_value,
        nonce,
        &evidence.statement,
    )?;
    verify_node_message(
        &evidence.statement.responder_node_key,
        &evidence.statement.commitment_statement.canonical_bytes(),
        &evidence.statement.commitment_signature,
    )
    .map_err(|error| {
        DkgError::Unauthorized(format!("invalid nested DKG commitment signature: {error}"))
    })?;
    verify_node_message(
        &evidence.statement.responder_node_key,
        &evidence.statement.canonical_bytes(),
        &evidence.signature,
    )
    .map_err(|error| {
        DkgError::Unauthorized(format!("invalid DKG share evidence signature: {error}"))
    })?;
    Ok(Some(evidence))
}

pub fn share_evidence_proves_failure(evidence: &SignedDkgShare) -> bool {
    // A responder that signs share evidence whose commitment or share value cannot
    // be decoded distributed an unusable share; a decode failure is itself proof of
    // a bad share, so treat it the same as a share that fails verification. Registry
    // co-signers reach the same conclusion because deserialization is deterministic
    // (see `require_dkg_share_verification_failure`).
    let Ok(commitment) =
        deserialize_wire_commitment(&evidence.statement.commitment_statement.commitment)
    else {
        return true;
    };
    let Ok(share_value) = Fr::from_bytes(&evidence.statement.share_value) else {
        return true;
    };
    !commitment.verify_share(evidence.statement.to_node_id, &share_value)
}

pub async fn queue_or_relay_invalid_share<D>(
    coord: &DkgCoordinator<D>,
    attempt: AttemptKey,
    evidence: SignedDkgShare,
) -> Result<()>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    if local_node_is_current_route_member(coord, attempt).await? {
        queue_invalid_share_report(coord.app_state.clone(), coord.routes, evidence).await
    } else if evidence.statement.origin_protocol == "pss_reshare" {
        let app_state = coord.app_state.clone();
        let routes = coord.routes;
        spawn_evidence_relay(attempt.session_id(), "dkg_share", async move {
            let coordinator = DkgCoordinator::with_routes(app_state, routes);
            relay_invalid_share_evidence(&coordinator, attempt, evidence).await
        });
        Ok(())
    } else {
        Err(DkgError::Unauthorized(
            "local node is not in the report signing committee".to_string(),
        ))
    }
}

pub async fn handle_invalid_share_evidence_relay<D>(
    coord: &DkgCoordinator<D>,
    attempt: AttemptKey,
    report_evidence: SignedDkgShare,
) -> Result<()>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    if report_evidence.statement.origin_protocol != "pss_reshare" {
        return Err(DkgError::Unauthorized(
            "DKG bad-share evidence relay is only valid for reshare".to_string(),
        ));
    }
    verify_relay_is_current_signer(coord, attempt).await?;

    // A relayed report is otherwise unauthenticated network input, so re-run the
    // same checks the direct receiver path runs before spending a report attempt
    // on it: authenticate the evidence against this session (ring binding plus the
    // responder's commitment and share signatures) and confirm it actually proves a
    // verification failure. Without this a peer could relay altered evidence or
    // evidence for a perfectly valid share and force a bogus report.
    let from_node_id = report_evidence.statement.from_node_id;
    let to_node_id = report_evidence.statement.to_node_id;
    let share_value = report_evidence.statement.share_value.clone();
    let nonce = report_evidence.statement.nonce;
    let verified = verify_share_evidence(
        coord,
        attempt,
        from_node_id,
        to_node_id,
        &share_value,
        nonce,
        Some(report_evidence),
    )
    .await?
    .ok_or_else(|| {
        DkgError::Unauthorized(
            "relayed DKG bad-share evidence is not valid for this session".to_string(),
        )
    })?;
    if !share_evidence_proves_failure(&verified) {
        return Err(DkgError::Unauthorized(
            "relayed DKG share evidence does not prove a verification failure".to_string(),
        ));
    }

    queue_invalid_share_report(coord.app_state.clone(), coord.routes, verified).await?;
    Ok(())
}

pub(super) fn validate_share_statement<D>(
    binding: &DkgReportEvidenceBinding,
    from_node_id: u32,
    to_node_id: u32,
    share_value: &[u8],
    nonce: [u8; 16],
    statement: &DkgShareStatement,
) -> Result<()>
where
    D: CoordinatorDkg,
{
    if statement.domain != DKG_SHARE_DOMAIN
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
        || statement.to_node_id != to_node_id
        || statement.share_value != share_value
        || statement.nonce != nonce
        || statement.crypto_backend != D::name()
    {
        return Err(DkgError::Unauthorized(
            "DKG share evidence does not match this session".to_string(),
        ));
    }
    let receiver_node_key = binding
        .receiver_node_keys
        .get(to_node_id.saturating_sub(1) as usize)
        .ok_or_else(|| {
            DkgError::Unauthorized(format!(
                "DKG share to_node_id {} is outside the receiver committee",
                to_node_id
            ))
        })?;
    if &statement.receiver_node_key != receiver_node_key {
        return Err(DkgError::Unauthorized(
            "DKG share evidence receiver does not match to_node_id".to_string(),
        ));
    }
    validate_commitment_statement::<D>(
        binding,
        from_node_id,
        &statement.commitment_statement.commitment,
        &statement.commitment_statement,
    )?;
    if statement.commitment_statement.responder_node_key != statement.responder_node_key
        || statement.commitment_statement.signed_at > statement.signed_at
    {
        return Err(DkgError::Unauthorized(
            "DKG share evidence has invalid nested commitment binding".to_string(),
        ));
    }
    Ok(())
}

async fn queue_invalid_share_report<D>(
    app_state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    evidence: SignedDkgShare,
) -> Result<()>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    let accused_node_key = evidence.statement.responder_node_key.clone();
    let accused_info = read_node_info(&app_state, &accused_node_key).await?;
    let observed_at = evidence
        .statement
        .signed_at
        .saturating_sub(CHAIN_BLOCK_GRACE_SECS);
    let observation = InvalidCryptoResponseObservation {
        ring_id: evidence.statement.ring_id.clone(),
        accused_node_key,
        accused_peer_id: accused_info.peer_id,
        observed_at,
        inline_document: None,
        evidence: InvalidCryptoResponse::DkgShare {
            statement: Box::new(evidence.statement),
            response_signature: evidence.signature,
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

async fn relay_invalid_share_evidence<D>(
    coord: &DkgCoordinator<D>,
    attempt: AttemptKey,
    evidence: SignedDkgShare,
) -> Result<()>
where
    D: CoordinatorDkg,
{
    crate::dkg::v0::network::relay_invalid_share_evidence(coord, attempt, evidence).await
}
