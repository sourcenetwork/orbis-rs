use super::*;

#[allow(clippy::too_many_arguments)]
pub async fn queue_or_relay_control_message_fault<D>(
    coord: &DkgCoordinator<D>,
    attempt: AttemptKey,
    accused_node_key: String,
    message_kind: String,
    fault_kind: DkgControlMessageFaultKind,
    artifact_a: ControlMessageArtifact,
    artifact_b: Option<ControlMessageArtifact>,
) -> Result<()>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    if local_node_is_current_route_member(coord, attempt).await? {
        queue_control_message_fault_report(
            coord.app_state.clone(),
            coord.routes,
            attempt,
            accused_node_key,
            message_kind,
            fault_kind,
            artifact_a,
            artifact_b,
        )
        .await
    } else {
        let origin_protocol = evidence_binding(coord, attempt)
            .await?
            .ok_or_else(|| {
                DkgError::Unauthorized(
                    "Fresh DKG control-message faults are not reportable".to_string(),
                )
            })?
            .origin_protocol;
        if origin_protocol != "pss_reshare" {
            return Err(DkgError::Unauthorized(
                "local node is not in the report signing committee".to_string(),
            ));
        }
        let app_state = coord.app_state.clone();
        let routes = coord.routes;
        spawn_evidence_relay(
            attempt.session_id(),
            "dkg_control_message_fault",
            async move {
                let coordinator = DkgCoordinator::with_routes(app_state, routes);
                crate::dkg::v0::network::relay_control_message_fault_evidence(
                    &coordinator,
                    attempt,
                    accused_node_key,
                    message_kind,
                    fault_kind,
                    artifact_a,
                    artifact_b,
                )
                .await
            },
        );
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn handle_control_message_fault_evidence_relay<D>(
    coord: &DkgCoordinator<D>,
    attempt: AttemptKey,
    accused_node_key: String,
    message_kind: String,
    fault_kind: DkgControlMessageFaultKind,
    artifact_a: ControlMessageArtifact,
    artifact_b: Option<ControlMessageArtifact>,
) -> Result<()>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    verify_relay_is_current_signer(coord, attempt).await?;
    let binding = evidence_binding(coord, attempt).await?.ok_or_else(|| {
        DkgError::Unauthorized("Fresh DKG control-message faults are not reportable".to_string())
    })?;
    if binding.origin_protocol != "pss_reshare" {
        return Err(DkgError::Unauthorized(
            "control-message fault evidence relay is only valid for Reshare".to_string(),
        ));
    }
    queue_control_message_fault_report(
        coord.app_state.clone(),
        coord.routes,
        attempt,
        accused_node_key,
        message_kind,
        fault_kind,
        artifact_a,
        artifact_b,
    )
    .await
}

/// Report a `Prepare` that is independently provable as invalid (noncanonical
/// leader, or routes/digest contradicting Vera) before any session is
/// created for it. Best-effort and queue-only: unlike the other control
/// evidence kinds, a pure pending-new reshare receiver that detects this
/// (rather than a current-committee member) cannot relay it in this pass —
/// relaying requires the current-committee routing that normally comes from
/// live session state, which by construction does not exist yet here. A
/// current-committee detector (every recipient for Fresh/Refresh, current
/// dealers/dealer-receivers for Reshare) is unaffected.
pub(crate) async fn report_leader_prepare_fault_best_effort<D>(
    app_state: &Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    prepare: &PrepareSession,
) where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    let Some(signature) = prepare.report_signature.clone() else {
        return;
    };
    if verify_control_signature(
        prepare.ceremony_id,
        prepare.attempt_id,
        "prepare",
        prepare.config_digest,
        &prepare.leader_node_key,
        &signature,
    )
    .is_err()
    {
        return;
    }
    // A signature only covers `config_digest`, not the rest of the message.
    // Without also confirming the digest is self-consistent with the
    // fields actually present, a relay that tampers with `leader_node_key`
    // or `committees` post-signature while leaving the original digest
    // intact could produce a mismatch that looks attributable to the real
    // signer but isn't — the signer never endorsed the tampered content.
    // Only a self-consistent (and therefore untampered) `Prepare` is safe
    // to report.
    match transport::config_digest(prepare) {
        Ok(recomputed) if recomputed == prepare.config_digest => {}
        _ => return,
    }
    if !prepare
        .committees
        .current
        .node_keys
        .contains(&app_state.node_key)
    {
        // Not a current-committee member: cannot queue directly, and relay
        // is not built for this fault kind yet (see doc comment above).
        return;
    }
    let Ok(Some(binding)) = evidence_binding_from_prepare(app_state, routes, prepare).await else {
        return;
    };
    let Ok(data) = transport::encode(prepare) else {
        return;
    };
    crate::metrics::record_dkg_transport_event("control", "leader_prepare_fault_candidate");
    let accused_info = match read_node_info(app_state, &prepare.leader_node_key).await {
        Ok(info) => info,
        Err(error) => {
            tracing::warn!(
                session_id = prepare.ceremony_id.0,
                %error,
                "failed to resolve accused leader NodeInfo for Prepare-fault report"
            );
            return;
        }
    };
    // Anchored to the leader's own signed `signed_at` (authenticated by
    // `control_ack_signing_bytes` binding it into the signature) rather than
    // report-construction time — a relay or delayed local processing must
    // not be able to shift the report's observed_at/TTL basis away from
    // when the leader actually signed the fault.
    let signed_at = signature.signed_at;
    let accused_committee_scope = if binding.origin_protocol == "pss_reshare" {
        CommitteeScope::PendingNew
    } else {
        CommitteeScope::Current
    };
    let statement = DkgControlMessageFaultStatement {
        domain: DKG_CONTROL_MESSAGE_FAULT_DOMAIN.to_string(),
        chain_id: binding.chain_id,
        ring_id: binding.ring_id.clone(),
        ring_pk: binding.ring_pk,
        ring_state_sha256: binding.ring_state_sha256,
        protocol_version: binding.protocol_version,
        request_id: binding.request_id,
        signed_at,
        responder_node_key: prepare.leader_node_key.clone(),
        origin_protocol: binding.origin_protocol,
        accused_committee_scope,
        signing_committee_scope: CommitteeScope::Current,
        attempt_id: prepare.attempt_id.0,
        message_kind: "prepare".to_string(),
        fault_kind: DkgControlMessageFaultKind::LeaderPrepareFault,
        artifact_a: ControlMessageArtifact {
            signature: signature.signature,
            data,
            signed_at,
        },
        artifact_b: None,
    };
    let observation = InvalidCryptoResponseObservation {
        ring_id: binding.ring_id,
        accused_node_key: prepare.leader_node_key.clone(),
        accused_peer_id: accused_info.peer_id,
        observed_at: statement.signed_at.saturating_sub(CHAIN_BLOCK_GRACE_SECS),
        inline_document: None,
        evidence: InvalidCryptoResponse::DkgControlMessageFault {
            statement: Box::new(statement),
        },
    };
    match queue_report::<D, SignImpl>(
        app_state.clone(),
        routes,
        ReportObservation::InvalidCryptoResponse(Box::new(observation)),
    )
    .await
    {
        Ok(_) => crate::metrics::record_dkg_transport_event(
            "control",
            "leader_prepare_fault_report_queued",
        ),
        Err(error) => {
            crate::metrics::record_dkg_transport_event(
                "control",
                "leader_prepare_fault_report_failed",
            );
            tracing::warn!(
                session_id = prepare.ceremony_id.0,
                attempt_id = %hex::encode(prepare.attempt_id.0),
                %error,
                "failed to queue authenticated leader-Prepare fault report"
            );
        }
    }
}

/// Node-key sign one control-handshake message's existing digest field
/// (`config_digest`/`activation_digest`), binding it to
/// (ceremony_id, attempt_id, message_kind). Unconditional across every
/// `SessionKind` — Fresh DKG is excluded later, at report-build time
/// (`evidence_binding` returns `None`), not here; the signature itself is
/// cheap and this keeps signing uniform regardless of reportability.
pub(crate) fn sign_control_message<D>(
    app_state: &Arc<AppState<D>>,
    ceremony_id: transport::CeremonyId,
    attempt_id: transport::AttemptId,
    message_kind: &str,
    digest: [u8; 32],
) -> Result<ControlSignature>
where
    D: Dkg + Clone + 'static,
{
    let signing_key_hex = read_node_signing_key_hex(app_state)?;
    let signed_at = now_unix_secs()?;
    let message = transport::control_ack_signing_bytes(
        ceremony_id,
        attempt_id,
        message_kind,
        digest,
        signed_at,
    );
    let signature = sign_statement_with_key(&signing_key_hex, &message)?;
    Ok(ControlSignature {
        signer_node_key: app_state.node_key.clone(),
        signed_at,
        signature,
    })
}

/// Independently re-verify a `ControlSignature` against the claimed
/// digest/message-kind/attempt binding and the expected signer. Does not
/// trust `signature.signer_node_key` for identity — the caller supplies
/// `expected_signer_node_key` from its own authoritative source (e.g. the
/// committee route the message arrived on).
pub(crate) fn verify_control_signature(
    ceremony_id: transport::CeremonyId,
    attempt_id: transport::AttemptId,
    message_kind: &str,
    digest: [u8; 32],
    expected_signer_node_key: &str,
    signature: &ControlSignature,
) -> Result<()> {
    if signature.signer_node_key != expected_signer_node_key {
        return Err(DkgError::Unauthorized(format!(
            "control message signature claims signer {} but expected {}",
            signature.signer_node_key, expected_signer_node_key
        )));
    }
    let message = transport::control_ack_signing_bytes(
        ceremony_id,
        attempt_id,
        message_kind,
        digest,
        signature.signed_at,
    );
    verify_node_message(expected_signer_node_key, &message, &signature.signature).map_err(|error| {
        DkgError::Unauthorized(format!("invalid control message signature: {error}"))
    })
}

async fn queue_control_message_fault_report<D>(
    app_state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    attempt: AttemptKey,
    accused_node_key: String,
    message_kind: String,
    fault_kind: DkgControlMessageFaultKind,
    artifact_a: ControlMessageArtifact,
    artifact_b: Option<ControlMessageArtifact>,
) -> Result<()>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    let coordinator = DkgCoordinator::with_routes(app_state.clone(), routes);
    let binding = evidence_binding(&coordinator, attempt)
        .await?
        .ok_or_else(|| {
            DkgError::Unauthorized(
                "Fresh DKG control-message faults are not reportable".to_string(),
            )
        })?;
    // The expected scope is fixed by origin_protocol (mirrors the registry's
    // validation rule and the leader-fault/leader-equivocation call sites) —
    // not derived from whichever committee list the accused happens to be in
    // first. A Reshare dealer-receiver sits in both `current_node_keys` and
    // `receiver_node_keys`; checking `current_node_keys` first mis-scoped
    // that common case as `Current` when the registry always requires
    // `PendingNew` for `pss_reshare`.
    //
    // `LeaderPrepareFault`'s accused is always the canonical leader, who for
    // Reshare is always drawn from the new/pending committee (`canonical_
    // leader()`'s reshare rule) — origin_protocol alone determines scope, as
    // above. `AckEquivocation`'s accused is whichever follower equivocated,
    // which can be a pure old-committee dealer (never in `receiver_node_
    // keys`, unlike a dealer-receiver or pure-new receiver) — for that one
    // fault kind, derive the scope from where the accused actually sits,
    // preferring `PendingNew` when both apply so dealer-receivers keep their
    // existing, already-correct classification.
    let accused_committee_scope = if binding.origin_protocol == "pss_reshare"
        && fault_kind == DkgControlMessageFaultKind::AckEquivocation
        && !binding.receiver_node_keys.contains(&accused_node_key)
        && binding.current_node_keys.contains(&accused_node_key)
    {
        CommitteeScope::Current
    } else if binding.origin_protocol == "pss_reshare" {
        CommitteeScope::PendingNew
    } else {
        CommitteeScope::Current
    };
    let accused_committee_keys = match accused_committee_scope {
        CommitteeScope::Current => &binding.current_node_keys,
        CommitteeScope::PendingNew => &binding.receiver_node_keys,
    };
    if !accused_committee_keys.contains(&accused_node_key) {
        return Err(DkgError::Unauthorized(
            "control-message fault accused is not in the bound committee".to_string(),
        ));
    }
    // Anchored to the accused's own signed `signed_at` values (authenticated
    // by `control_ack_signing_bytes` binding it into each artifact's
    // signature) rather than report-construction time — see
    // `report_leader_prepare_fault_best_effort`'s identical rationale.
    // `AckEquivocation` has two independently-signed artifacts; the later of
    // the two is used so the report's observed_at/TTL basis reflects when
    // the fault actually became provable (both signatures existing), not
    // just the earlier one.
    let signed_at = match &artifact_b {
        Some(b) => artifact_a.signed_at.max(b.signed_at),
        None => artifact_a.signed_at,
    };
    let accused_info = read_node_info(&app_state, &accused_node_key).await?;
    let statement = DkgControlMessageFaultStatement {
        domain: DKG_CONTROL_MESSAGE_FAULT_DOMAIN.to_string(),
        chain_id: binding.chain_id,
        ring_id: binding.ring_id.clone(),
        ring_pk: binding.ring_pk,
        ring_state_sha256: binding.ring_state_sha256,
        protocol_version: binding.protocol_version,
        request_id: binding.request_id,
        signed_at,
        responder_node_key: accused_node_key.clone(),
        origin_protocol: binding.origin_protocol,
        accused_committee_scope,
        signing_committee_scope: CommitteeScope::Current,
        attempt_id: attempt.attempt_id.0,
        message_kind: message_kind.to_string(),
        fault_kind,
        artifact_a,
        artifact_b,
    };
    let observation = InvalidCryptoResponseObservation {
        ring_id: binding.ring_id,
        accused_node_key,
        accused_peer_id: accused_info.peer_id,
        observed_at: statement.signed_at.saturating_sub(CHAIN_BLOCK_GRACE_SECS),
        inline_document: None,
        evidence: InvalidCryptoResponse::DkgControlMessageFault {
            statement: Box::new(statement),
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
