use super::*;

/// Generous upper bound on the encoded size of a `page_digest` +
/// `report_signature` pair. `public_phase_response_page` sizes its
/// candidates against `MAX_PUBLIC_REPAIR_PAGE_BYTES` minus this margin
/// (`sign_public_phase_response` attaches the real signature afterward,
/// once the final contributions/next_cursor are settled) — without it, an
/// honest leader's page could land a few hundred bytes over the true limit
/// purely from signature overhead, and get flagged as a fault it didn't
/// commit.
const PUBLIC_REPAIR_PAGE_SIGNATURE_OVERHEAD_BYTES: usize = 512;

pub(super) fn public_phase_response_page(
    ceremony_id: CeremonyId,
    attempt_id: AttemptId,
    phase: PublicPhase,
    retained: &BTreeMap<ParticipantRef, SignedPayload>,
    after: Option<ParticipantRef>,
) -> Result<DkgControlMessage> {
    let entries: Vec<_> = retained
        .iter()
        .filter(|(origin, _)| after.is_none_or(|cursor| **origin > cursor))
        .collect();
    if entries.is_empty() {
        return Ok(DkgControlMessage::PublicPhaseResponse {
            ceremony_id,
            attempt_id,
            phase,
            contributions: Vec::new(),
            next_cursor: None,
            // Placeholder — the real digest/signature are computed by the
            // caller once the final contributions/next_cursor are settled
            // (`sign_public_phase_response`), since signing needs access to
            // the local signing key this pure/sync sizing loop doesn't have.
            // Candidates below are sized against a smaller effective budget
            // (`PUBLIC_REPAIR_PAGE_SIGNATURE_OVERHEAD_BYTES` margin) so the
            // real signature's byte cost can never push the final signed
            // message over `MAX_PUBLIC_REPAIR_PAGE_BYTES`.
            page_digest: [0; 32],
            report_signature: None,
        });
    }

    let mut contributions = Vec::new();
    let mut last_origin = None;
    for (position, (origin, signed)) in entries.iter().enumerate() {
        contributions.push((*signed).clone());
        let has_more = position + 1 < entries.len();
        let candidate = DkgControlMessage::PublicPhaseResponse {
            ceremony_id,
            attempt_id,
            phase,
            contributions: contributions.clone(),
            next_cursor: has_more.then_some(**origin),
            page_digest: [0; 32],
            report_signature: None,
        };
        let encoded_len = transport::encode(&candidate)
            .map_err(DkgError::Serialization)?
            .len();
        if encoded_len
            > transport::MAX_PUBLIC_REPAIR_PAGE_BYTES - PUBLIC_REPAIR_PAGE_SIGNATURE_OVERHEAD_BYTES
        {
            contributions.pop();
            let Some(cursor) = last_origin else {
                crate::metrics::record_dkg_transport_event(
                    "public",
                    "repair_contribution_oversize",
                );
                return Err(DkgError::ProtocolError(format!(
                    "one signed public contribution exceeds the {}-byte repair page limit",
                    transport::MAX_PUBLIC_REPAIR_PAGE_BYTES
                )));
            };
            return Ok(DkgControlMessage::PublicPhaseResponse {
                ceremony_id,
                attempt_id,
                phase,
                contributions,
                next_cursor: Some(cursor),
                page_digest: [0; 32],
                report_signature: None,
            });
        }
        last_origin = Some(**origin);
        if !has_more {
            return Ok(candidate);
        }
    }

    unreachable!("a non-empty retained page returns from the loop")
}

/// Attach a real `page_digest`/`report_signature` to a `PublicPhaseResponse`
/// built by `public_phase_response_page` (which fills placeholders, since it
/// has no access to the local signing key). Lets an oversized or otherwise
/// invalid repair page be attributed to the leader later — unlike Gossip
/// broadcasts, direct-QUIC control messages have no transport-layer
/// signature to reclaim, and `PublicPhaseResponse` didn't carry one of its
/// own the way `Prepare`/`Prepared`/etc. do.
pub(super) fn sign_public_phase_response<D>(
    state: &Arc<AppState<D>>,
    response: DkgControlMessage,
) -> Result<DkgControlMessage>
where
    D: crypto::r#trait::Dkg + Clone + 'static,
{
    let DkgControlMessage::PublicPhaseResponse {
        ceremony_id,
        attempt_id,
        phase,
        contributions,
        next_cursor,
        ..
    } = response
    else {
        return Ok(response);
    };
    let page_digest = transport::public_repair_page_digest(
        ceremony_id,
        attempt_id,
        phase,
        &contributions,
        next_cursor,
    );
    let report_signature = Some(sign_control_message(
        state,
        ceremony_id,
        attempt_id,
        "public_phase_response",
        page_digest,
    )?);
    Ok(DkgControlMessage::PublicPhaseResponse {
        ceremony_id,
        attempt_id,
        phase,
        contributions,
        next_cursor,
        page_digest,
        report_signature,
    })
}

pub(super) fn validate_public_repair_page_progress(
    after: Option<ParticipantRef>,
    origins: &[ParticipantRef],
    next_cursor: Option<ParticipantRef>,
    seen: &BTreeSet<ParticipantRef>,
) -> Result<()> {
    if origins.is_empty() {
        if next_cursor.is_some() {
            return Err(DkgError::ProtocolError(
                "empty public repair page supplied a continuation cursor".into(),
            ));
        }
        return Ok(());
    }
    if after.is_some_and(|cursor| origins[0] <= cursor) {
        return Err(DkgError::ProtocolError(
            "public repair page did not advance beyond its requested cursor".into(),
        ));
    }
    if origins.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(DkgError::ProtocolError(
            "public repair page origins are not in strict canonical order".into(),
        ));
    }
    if origins.iter().any(|origin| seen.contains(origin)) {
        return Err(DkgError::ProtocolError(
            "public repair response repeated an origin across pages".into(),
        ));
    }
    if next_cursor.is_some_and(|cursor| Some(&cursor) != origins.last()) {
        return Err(DkgError::ProtocolError(
            "public repair continuation cursor does not name the page's final origin".into(),
        ));
    }
    Ok(())
}

pub(super) fn repairable_public_phases(kind: &SessionKind) -> &'static [PublicPhase] {
    const FRESH: &[PublicPhase] = &[PublicPhase::CommitmentHashes, PublicPhase::Commitments];
    const REFRESH: &[PublicPhase] = &[
        PublicPhase::Commitments,
        PublicPhase::CommitmentAudit,
        PublicPhase::RefreshHealthCheck,
    ];
    const RESHARE: &[PublicPhase] = &[
        PublicPhase::Commitments,
        PublicPhase::CommitmentAudit,
        PublicPhase::ReshareParticipantSet,
    ];
    match kind {
        SessionKind::Fresh => FRESH,
        SessionKind::Refresh { .. } => REFRESH,
        SessionKind::Reshare { .. } => RESHARE,
    }
}

#[derive(Debug)]
pub(super) enum PublicRepairFailure {
    Error(DkgError),
    Violation(PublicProtocolViolation),
}

impl From<DkgError> for PublicRepairFailure {
    fn from(error: DkgError) -> Self {
        Self::Error(error)
    }
}

pub(super) type PublicRepairResult<T> = std::result::Result<T, PublicRepairFailure>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum LeaderPublicRepairOutcome {
    Complete,
    Incomplete {
        retained: usize,
    },
    Unavailable {
        retained: usize,
        detail: String,
        offline: bool,
    },
}

#[derive(Debug)]
pub(super) enum OriginPublicRepairOutcome {
    Verified(Box<VerifiedPublicContribution>),
    Missing {
        origin: ParticipantRef,
    },
    Unavailable {
        origin: ParticipantRef,
        detail: String,
        offline: bool,
    },
    Violation(PublicProtocolViolation),
    Error(DkgError),
}

#[derive(Debug, Clone, Copy)]
pub(super) enum RepairContributionSource {
    Leader,
    Origin,
}

#[async_trait]
pub(super) trait PublicRepairRequester: Send + Sync {
    async fn request(&self, peer: &str, request: DkgControlMessage) -> PublicRepairRequestOutcome;
}

pub(super) struct PublicRepairRequestOutcome {
    pub(super) result: Result<DkgControlMessage>,
    pub(super) offline: bool,
}

pub(super) struct NetworkPublicRepairRequester<D>
where
    D: CoordinatorDkg,
{
    state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
}

#[async_trait]
impl<D> PublicRepairRequester for NetworkPublicRepairRequester<D>
where
    D: CoordinatorDkg,
{
    async fn request(&self, peer: &str, request: DkgControlMessage) -> PublicRepairRequestOutcome {
        match control_request_with_timeout_classified(
            &self.state,
            self.routes,
            peer,
            request,
            PEER_RESPONSE_TIMEOUT,
        )
        .await
        {
            Ok(response) => PublicRepairRequestOutcome {
                result: Ok(response),
                offline: false,
            },
            Err(error) => PublicRepairRequestOutcome {
                offline: error.is_unreachable(),
                result: Err(error.into_error()),
            },
        }
    }
}

pub(super) async fn public_repair_retained_count<D>(
    state: &Arc<AppState<D>>,
    prepare: &PrepareSession,
    phase: PublicPhase,
) -> usize
where
    D: CoordinatorDkg,
{
    state
        .dkg_session_state
        .public_contributions(&prepare.ceremony_id.0, prepare.attempt_id, phase)
        .await
        .map_or(0, |items| items.len())
}

pub(super) fn retryable_public_repair_control_error(error: &DkgError) -> bool {
    matches!(
        error,
        DkgError::NetworkConnection(_)
            | DkgError::NetworkCommunication(_)
            | DkgError::ProtocolError(_)
    )
}

pub(super) fn repair_contribution_violation(
    source: RepairContributionSource,
    phase: PublicPhase,
    origin: ParticipantRef,
    detail: impl Into<String>,
) -> PublicProtocolViolation {
    match source {
        RepairContributionSource::Leader => PublicProtocolViolation::leader(
            PublicProtocolViolationKind::InvalidContribution,
            Some(phase),
            None,
            detail,
        ),
        RepairContributionSource::Origin => PublicProtocolViolation::origin_with_kind(
            PublicProtocolViolationKind::InvalidContribution,
            phase,
            None,
            origin,
            detail,
        ),
    }
}

pub(super) async fn apply_repair_contributions<D>(
    state: &Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    prepare: &PrepareSession,
    phase: PublicPhase,
    contributions: Vec<VerifiedPublicContribution>,
    source: RepairContributionSource,
) -> PublicRepairResult<bool>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    if contributions.is_empty() {
        return Ok(true);
    }
    for verified in &contributions {
        if let Err(error) = preflight_public_contribution_if_new(
            state,
            routes,
            &verified.signed,
            &verified.contribution,
        )
        .await
        {
            if state
                .dkg_session_state
                .transport_attempt(&prepare.ceremony_id.0)
                .await
                != Some(prepare.attempt_id)
            {
                return Ok(false);
            }
            if attributable_public_preflight_error(&error) {
                return Err(PublicRepairFailure::Violation(
                    repair_contribution_violation(
                        source,
                        phase,
                        verified.contribution.origin,
                        format!("direct-repair contribution failed payload preflight: {error}"),
                    )
                    .with_message_id(verified.contribution.message_id)
                    .with_public_origin_fault(Some(
                        PublicOriginFaultEvidence {
                            fault_kind: DkgPublicOriginFaultKind::InvalidPayload,
                            contribution_a: verified.signed.clone(),
                            contribution_b: None,
                        },
                    )),
                ));
            }
            return Err(PublicRepairFailure::Error(error));
        }
    }
    let retained: BTreeMap<_, _> = contributions
        .iter()
        .map(|verified| (verified.contribution.origin, verified.signed.clone()))
        .collect();
    match state
        .dkg_session_state
        .record_public_batch(&prepare.ceremony_id.0, prepare.attempt_id, phase, retained)
        .await
    {
        PublicBatchRecordOutcome::Recorded => {}
        PublicBatchRecordOutcome::DuplicateSame => {
            crate::metrics::record_dkg_transport_event("public", "batch_duplicate");
        }
        PublicBatchRecordOutcome::ConflictingDuplicate {
            origin,
            retained,
            conflicting,
        } => {
            return Err(PublicRepairFailure::Violation(
                PublicProtocolViolation::origin(
                    phase,
                    None,
                    origin,
                    "direct repair conflicts with a retained signed contribution",
                )
                .with_commitment_equivocation((phase == PublicPhase::Commitments).then_some(
                    PublicCommitmentEquivocation {
                        origin,
                        retained: retained.clone(),
                        conflicting: conflicting.clone(),
                    },
                ))
                .with_public_origin_fault(
                    (phase != PublicPhase::Commitments).then_some(PublicOriginFaultEvidence {
                        fault_kind: DkgPublicOriginFaultKind::OriginEquivocation,
                        contribution_a: retained,
                        contribution_b: Some(conflicting),
                    }),
                ),
            ));
        }
        PublicBatchRecordOutcome::StaleAttempt | PublicBatchRecordOutcome::MissingSession => {
            return Ok(false);
        }
    }

    if phase == PublicPhase::RefreshHealthCheck {
        return Ok(true);
    }
    for verified in contributions {
        let origin = verified.contribution.origin;
        let message_id = verified.contribution.message_id;
        if let Err(error) = dispatch_public_contribution(
            state.clone(),
            routes,
            verified.signed,
            verified.contribution,
        )
        .await
        {
            if state
                .dkg_session_state
                .transport_attempt(&prepare.ceremony_id.0)
                .await
                != Some(prepare.attempt_id)
            {
                return Ok(false);
            }
            if matches!(
                &error,
                DkgError::Unauthorized(_)
                    | DkgError::Deserialization(_)
                    | DkgError::Crypto(_)
                    | DkgError::InvalidInput(_)
                    | DkgError::ProtocolError(_)
                    | DkgError::CommitmentVerificationFailed(_)
            ) {
                return Err(PublicRepairFailure::Violation(
                    repair_contribution_violation(
                        source,
                        phase,
                        origin,
                        format!(
                            "verified repair contribution failed protocol application: {error}"
                        ),
                    )
                    .with_message_id(message_id),
                ));
            }
            tracing::warn!(
                %error,
                phase = ?phase,
                origin = ?origin,
                "failed to dispatch a verified direct-repair contribution"
            );
        }
    }
    Ok(true)
}

pub(super) async fn dispatch_retained_public_repair<D>(
    state: &Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    prepare: &PrepareSession,
    phase: PublicPhase,
) -> PublicRepairResult<bool>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    if phase == PublicPhase::RefreshHealthCheck {
        return Ok(true);
    }
    let items = state
        .dkg_session_state
        .public_contributions(&prepare.ceremony_id.0, prepare.attempt_id, phase)
        .await
        .unwrap_or_default();
    let mut verified = Vec::with_capacity(items.len());
    for signed in items.into_values() {
        let contribution = verify_signed_contribution(state, &signed).await?;
        verified.push(VerifiedPublicContribution {
            signed,
            contribution,
        });
    }
    apply_repair_contributions(
        state,
        routes,
        prepare,
        phase,
        verified,
        RepairContributionSource::Origin,
    )
    .await
}

pub(super) async fn collect_public_phase_from_leader<D, R>(
    state: &Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    requester: &R,
    prepare: &PrepareSession,
    phase: PublicPhase,
    expected_origins: &BTreeSet<ParticipantRef>,
) -> PublicRepairResult<LeaderPublicRepairOutcome>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
    R: PublicRepairRequester + ?Sized,
{
    let leader_peer = prepare
        .leader_route()
        .ok_or_else(|| DkgError::InvalidState("leader repair route is missing".into()))?;
    let max_pages = expected_origins.len().max(1);
    let mut after = None;
    let mut seen_origins = BTreeSet::new();
    let mut page_count = 0usize;

    loop {
        if page_count >= max_pages {
            return Err(PublicRepairFailure::Violation(
                PublicProtocolViolation::leader(
                    PublicProtocolViolationKind::BatchMismatch,
                    Some(phase),
                    None,
                    format!("public repair exceeded its maximum {max_pages} pages"),
                ),
            ));
        }
        let request_outcome = requester
            .request(
                leader_peer,
                DkgControlMessage::GetPublicPhase {
                    ceremony_id: prepare.ceremony_id,
                    attempt_id: prepare.attempt_id,
                    phase,
                    after,
                },
            )
            .await;
        let offline = request_outcome.offline;
        let response = match request_outcome.result {
            Ok(response) => response,
            Err(error) if retryable_public_repair_control_error(&error) => {
                return Ok(LeaderPublicRepairOutcome::Unavailable {
                    retained: public_repair_retained_count(state, prepare, phase).await,
                    detail: error.to_string(),
                    offline,
                });
            }
            Err(DkgError::Deserialization(error)) => {
                return Err(PublicRepairFailure::Violation(
                    PublicProtocolViolation::leader(
                        PublicProtocolViolationKind::MalformedLeaderMessage,
                        Some(phase),
                        None,
                        error,
                    ),
                ));
            }
            Err(error) => return Err(PublicRepairFailure::Error(error)),
        };
        let encoded = transport::encode(&response).map_err(DkgError::Serialization)?;
        let encoded_len = encoded.len();
        if encoded_len > transport::MAX_PUBLIC_REPAIR_PAGE_BYTES {
            // Only attributable if the leader actually signed this response
            // (`None` for Fresh DKG, which has no ring to bind evidence to —
            // see `PublicPhaseResponse::report_signature`). Re-encodes the
            // whole decoded response (not just the oversized field) as the
            // artifact data, matching `leader_prepare_fault`'s pattern, so
            // independent re-verification can recompute `page_digest` from
            // it directly.
            let control_message_fault = if let DkgControlMessage::PublicPhaseResponse {
                report_signature: Some(signature),
                ..
            } = &response
            {
                Some(ControlMessageArtifact {
                    signature: signature.signature.clone(),
                    data: encoded,
                    signed_at: signature.signed_at,
                })
            } else {
                None
            };
            return Err(PublicRepairFailure::Violation(
                PublicProtocolViolation::leader(
                    PublicProtocolViolationKind::BufferLimit,
                    Some(phase),
                    None,
                    format!(
                        "encoded public repair page is {encoded_len} bytes, exceeding the {}-byte limit",
                        transport::MAX_PUBLIC_REPAIR_PAGE_BYTES
                    ),
                )
                .with_control_message_fault(control_message_fault),
            ));
        }
        let DkgControlMessage::PublicPhaseResponse {
            ceremony_id,
            attempt_id,
            phase: response_phase,
            contributions,
            next_cursor,
            page_digest: _,
            report_signature: _,
        } = response
        else {
            return Err(PublicRepairFailure::Violation(
                PublicProtocolViolation::leader(
                    PublicProtocolViolationKind::MalformedLeaderMessage,
                    Some(phase),
                    None,
                    "leader returned an unexpected public repair response",
                ),
            ));
        };
        if ceremony_id != prepare.ceremony_id
            || attempt_id != prepare.attempt_id
            || response_phase != phase
        {
            return Err(PublicRepairFailure::Violation(
                PublicProtocolViolation::leader(
                    PublicProtocolViolationKind::BatchMismatch,
                    Some(phase),
                    None,
                    "leader public repair response scope mismatch",
                ),
            ));
        }

        let mut verified_page = Vec::with_capacity(contributions.len());
        let mut page_origins = Vec::with_capacity(contributions.len());
        for signed in contributions {
            let contribution =
                verify_signed_contribution(state, &signed)
                    .await
                    .map_err(|error| {
                        PublicRepairFailure::Violation(PublicProtocolViolation::leader(
                            PublicProtocolViolationKind::InvalidContribution,
                            Some(phase),
                            None,
                            error.to_string(),
                        ))
                    })?;
            if contribution.payload.phase() != phase
                || !expected_origins.contains(&contribution.origin)
            {
                return Err(PublicRepairFailure::Violation(
                    PublicProtocolViolation::leader(
                        PublicProtocolViolationKind::InvalidContribution,
                        Some(phase),
                        None,
                        format!(
                            "leader repair returned contribution {:?} outside the expected phase scope",
                            contribution.origin
                        ),
                    )
                    .with_message_id(contribution.message_id),
                ));
            }
            page_origins.push(contribution.origin);
            verified_page.push(VerifiedPublicContribution {
                signed,
                contribution,
            });
        }
        validate_public_repair_page_progress(after, &page_origins, next_cursor, &seen_origins)
            .map_err(|error| {
                PublicRepairFailure::Violation(PublicProtocolViolation::leader(
                    PublicProtocolViolationKind::BatchMismatch,
                    Some(phase),
                    None,
                    error.to_string(),
                ))
            })?;
        seen_origins.extend(page_origins.iter().copied());
        if !apply_repair_contributions(
            state,
            routes,
            prepare,
            phase,
            verified_page,
            RepairContributionSource::Leader,
        )
        .await?
        {
            return Err(PublicRepairFailure::Error(DkgError::ProtocolError(
                "public repair targets an inactive attempt".into(),
            )));
        }

        page_count += 1;
        crate::metrics::record_dkg_transport_event("public", "repair_page_received");
        tracing::debug!(
            session_id = prepare.ceremony_id.0,
            attempt_id = %hex::encode(prepare.attempt_id.0),
            phase = ?phase,
            page_count,
            after = ?after,
            next_cursor = ?next_cursor,
            contribution_count = page_origins.len(),
            encoded_len,
            "received public DKG repair page"
        );

        let Some(cursor) = next_cursor else {
            let retained = public_repair_retained_count(state, prepare, phase).await;
            return Ok(if retained >= expected_origins.len() {
                LeaderPublicRepairOutcome::Complete
            } else {
                LeaderPublicRepairOutcome::Incomplete { retained }
            });
        };
        after = Some(cursor);
    }
}

pub(super) async fn fetch_public_contribution_from_origin<D, R>(
    state: Arc<AppState<D>>,
    requester: &R,
    prepare: PrepareSession,
    phase: PublicPhase,
    origin: ParticipantRef,
    origin_peer: String,
) -> OriginPublicRepairOutcome
where
    D: CoordinatorDkg,
    R: PublicRepairRequester + ?Sized,
{
    let request_outcome = requester
        .request(
            &origin_peer,
            DkgControlMessage::GetPublicContribution {
                ceremony_id: prepare.ceremony_id,
                attempt_id: prepare.attempt_id,
                phase,
                origin,
            },
        )
        .await;
    let offline = request_outcome.offline;
    let response = match request_outcome.result {
        Ok(response) => response,
        Err(error) if retryable_public_repair_control_error(&error) => {
            return OriginPublicRepairOutcome::Unavailable {
                origin,
                detail: error.to_string(),
                offline,
            };
        }
        Err(DkgError::Deserialization(error)) => {
            return OriginPublicRepairOutcome::Violation(
                PublicProtocolViolation::origin_with_kind(
                    PublicProtocolViolationKind::MalformedOriginMessage,
                    phase,
                    None,
                    origin,
                    error,
                ),
            );
        }
        Err(error) => return OriginPublicRepairOutcome::Error(error),
    };
    let encoded_len = match transport::encode(&response) {
        Ok(encoded) => encoded.len(),
        Err(error) => {
            return OriginPublicRepairOutcome::Error(DkgError::Serialization(error));
        }
    };
    if encoded_len > transport::MAX_PUBLIC_REPAIR_PAGE_BYTES {
        return OriginPublicRepairOutcome::Violation(
            PublicProtocolViolation::origin_with_kind(
                PublicProtocolViolationKind::BufferLimit,
                phase,
                None,
                origin,
                format!(
                    "encoded origin repair response is {encoded_len} bytes, exceeding the {}-byte limit",
                    transport::MAX_PUBLIC_REPAIR_PAGE_BYTES
                ),
            ),
        );
    }
    let DkgControlMessage::PublicContributionResponse {
        ceremony_id,
        attempt_id,
        contribution,
    } = response
    else {
        return OriginPublicRepairOutcome::Violation(PublicProtocolViolation::origin_with_kind(
            PublicProtocolViolationKind::MalformedOriginMessage,
            phase,
            None,
            origin,
            "origin returned an unexpected public repair response",
        ));
    };
    if ceremony_id != prepare.ceremony_id || attempt_id != prepare.attempt_id {
        return OriginPublicRepairOutcome::Violation(PublicProtocolViolation::origin_with_kind(
            PublicProtocolViolationKind::MalformedOriginMessage,
            phase,
            None,
            origin,
            "origin public repair response scope mismatch",
        ));
    }
    let Some(signed) = contribution else {
        return OriginPublicRepairOutcome::Missing { origin };
    };
    let contribution = match verify_signed_contribution(&state, &signed).await {
        Ok(contribution) => contribution,
        Err(error)
            if state
                .dkg_session_state
                .transport_attempt(&prepare.ceremony_id.0)
                .await
                != Some(prepare.attempt_id) =>
        {
            return OriginPublicRepairOutcome::Error(error);
        }
        Err(error) => {
            return OriginPublicRepairOutcome::Violation(
                PublicProtocolViolation::origin_with_kind(
                    PublicProtocolViolationKind::InvalidContribution,
                    phase,
                    None,
                    origin,
                    error.to_string(),
                ),
            );
        }
    };
    if contribution.origin != origin || contribution.payload.phase() != phase {
        return OriginPublicRepairOutcome::Violation(
            PublicProtocolViolation::origin_with_kind(
                PublicProtocolViolationKind::InvalidContribution,
                phase,
                None,
                origin,
                "origin public repair returned the wrong contribution",
            )
            .with_message_id(contribution.message_id),
        );
    }
    OriginPublicRepairOutcome::Verified(Box::new(VerifiedPublicContribution {
        signed,
        contribution,
    }))
}

pub(super) async fn collect_public_phase_from_origins<D, R>(
    state: &Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    requester: &R,
    prepare: &PrepareSession,
    phase: PublicPhase,
    expected_origins: &BTreeSet<ParticipantRef>,
) -> PublicRepairResult<()>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
    R: PublicRepairRequester + ?Sized,
{
    let retained = state
        .dkg_session_state
        .public_contributions(&prepare.ceremony_id.0, prepare.attempt_id, phase)
        .await
        .unwrap_or_default();
    let retained_origins: BTreeSet<_> = retained.keys().copied().collect();
    let missing: Vec<_> = expected_origins
        .difference(&retained_origins)
        .copied()
        .collect();
    let mut requests = FuturesUnordered::new();
    for origin in missing {
        let origin_peer = prepare
            .committees
            .route(origin)
            .ok_or_else(|| {
                DkgError::InvalidState(format!("origin repair route for {origin:?} is missing"))
            })?
            .to_owned();
        requests.push(fetch_public_contribution_from_origin(
            state.clone(),
            requester,
            prepare.clone(),
            phase,
            origin,
            origin_peer,
        ));
    }

    let mut verified = BTreeMap::new();
    let mut unavailable_origins = Vec::new();
    while let Some(outcome) = requests.next().await {
        match outcome {
            OriginPublicRepairOutcome::Verified(contribution) => {
                verified.insert(contribution.contribution.origin, *contribution);
            }
            OriginPublicRepairOutcome::Missing { origin } => {
                crate::metrics::record_dkg_transport_event("public", "origin_repair_missing");
                tracing::debug!(
                    session_id = prepare.ceremony_id.0,
                    attempt_id = %hex::encode(prepare.attempt_id.0),
                    phase = ?phase,
                    origin = ?origin,
                    "origin has not retained the requested public contribution"
                );
                // Soft-stall gate: only counts once direct-origin repair (this
                // function) has actually been attempted and come up short, not
                // on the first ordinary miss.
                state
                    .dkg_session_state
                    .record_peer_no_progress(
                        AttemptKey::new(prepare.ceremony_id, prepare.attempt_id),
                        origin.node_id,
                    )
                    .await;
            }
            OriginPublicRepairOutcome::Unavailable {
                origin,
                detail,
                offline,
            } => {
                if offline {
                    unavailable_origins.push(origin);
                }
                crate::metrics::record_dkg_transport_event("public", "origin_repair_unavailable");
                tracing::warn!(
                    session_id = prepare.ceremony_id.0,
                    attempt_id = %hex::encode(prepare.attempt_id.0),
                    phase = ?phase,
                    origin = ?origin,
                    detail,
                    "public contribution origin is unavailable during direct repair"
                );
                state
                    .dkg_session_state
                    .record_peer_no_progress(
                        AttemptKey::new(prepare.ceremony_id, prepare.attempt_id),
                        origin.node_id,
                    )
                    .await;
            }
            OriginPublicRepairOutcome::Violation(violation) => {
                return Err(PublicRepairFailure::Violation(violation));
            }
            OriginPublicRepairOutcome::Error(error) => {
                return Err(PublicRepairFailure::Error(error));
            }
        }
    }

    if !unavailable_origins.is_empty() {
        spawn_pss_offline_observations(
            state.clone(),
            routes,
            PssOfflineObservationSeed::from_prepare(
                prepare,
                routes.version,
                PssOfflineStage::PublicRepairOrigin,
                unavailable_origins,
            ),
        );
    }

    let verified: Vec<_> = verified.into_values().collect();
    let repaired_count = verified.len();
    if !apply_repair_contributions(
        state,
        routes,
        prepare,
        phase,
        verified,
        RepairContributionSource::Origin,
    )
    .await?
    {
        return Err(PublicRepairFailure::Error(DkgError::ProtocolError(
            "origin repair targets an inactive attempt".into(),
        )));
    }
    for _ in 0..repaired_count {
        crate::metrics::record_dkg_transport_event("public", "origin_repair");
    }
    Ok(())
}

pub(super) async fn repair_public_phase_claimed<D, R>(
    state: &Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    requester: &R,
    prepare: &PrepareSession,
    phase: PublicPhase,
) -> PublicRepairResult<()>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
    R: PublicRepairRequester + ?Sized,
{
    let expected_origins = expected_public_origins(state, prepare, phase).await;
    let expected = expected_origins.len();
    if expected > MAX_DKG_COMMITTEE_SIZE {
        return Err(PublicRepairFailure::Error(DkgError::InvalidState(format!(
            "public repair expected {expected} origins, maximum is {MAX_DKG_COMMITTEE_SIZE}"
        ))));
    }
    let present = public_repair_retained_count(state, prepare, phase).await;
    if present >= expected {
        dispatch_retained_public_repair(state, routes, prepare, phase).await?;
        return Ok(());
    }

    tracing::info!(
        session_id = prepare.ceremony_id.0,
        attempt_id = %hex::encode(prepare.attempt_id.0),
        phase = ?phase,
        present,
        expected,
        "requesting public DKG completeness repair"
    );
    let leader_outcome = collect_public_phase_from_leader(
        state,
        routes,
        requester,
        prepare,
        phase,
        &expected_origins,
    )
    .await?;
    match &leader_outcome {
        LeaderPublicRepairOutcome::Complete => {}
        LeaderPublicRepairOutcome::Incomplete { retained } => {
            crate::metrics::record_dkg_transport_event("public", "leader_repair_fallback");
            tracing::warn!(
                session_id = prepare.ceremony_id.0,
                attempt_id = %hex::encode(prepare.attempt_id.0),
                phase = ?phase,
                retained,
                expected,
                "leader repair completed without every expected origin; using direct origins"
            );
        }
        LeaderPublicRepairOutcome::Unavailable {
            retained,
            detail,
            offline,
        } => {
            if *offline {
                if let Some(leader) = participant_for_transport_peer(
                    &prepare.committees,
                    prepare.leader_route().unwrap_or_default(),
                ) {
                    spawn_pss_offline_observations(
                        state.clone(),
                        routes,
                        PssOfflineObservationSeed::from_prepare(
                            prepare,
                            routes.version,
                            PssOfflineStage::PublicRepairLeader,
                            [leader],
                        ),
                    );
                }
            }
            crate::metrics::record_dkg_transport_event("public", "leader_repair_fallback");
            tracing::warn!(
                session_id = prepare.ceremony_id.0,
                attempt_id = %hex::encode(prepare.attempt_id.0),
                phase = ?phase,
                retained,
                expected,
                detail,
                "leader repair is unavailable; using direct origins"
            );
        }
    }
    if phase == PublicPhase::CommitmentAudit {
        crate::metrics::record_dkg_transport_event("public", "repair");
        return Ok(());
    }
    if !matches!(leader_outcome, LeaderPublicRepairOutcome::Complete) {
        collect_public_phase_from_origins(
            state,
            routes,
            requester,
            prepare,
            phase,
            &expected_origins,
        )
        .await?;
    }

    let repaired = public_repair_retained_count(state, prepare, phase).await;
    if repaired < expected {
        crate::metrics::record_dkg_transport_event("public", "repair_incomplete");
        return Err(PublicRepairFailure::Error(DkgError::NetworkCommunication(
            format!("public phase repair retained {repaired} of {expected} contributions"),
        )));
    }
    dispatch_retained_public_repair(state, routes, prepare, phase).await?;
    crate::metrics::record_dkg_transport_event("public", "repair");
    tracing::info!(
        session_id = prepare.ceremony_id.0,
        attempt_id = %hex::encode(prepare.attempt_id.0),
        phase = ?phase,
        "applied direct public DKG completeness repair"
    );
    Ok(())
}

pub(super) async fn repair_public_phase<D>(
    state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    prepare: PrepareSession,
    phase: PublicPhase,
    force_after_lag: bool,
    violation_topic_task: TopicTaskDisposition,
) -> Result<()>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    if prepare.leader_node_key == state.node_key {
        // The leader ACKs a directly-submitted contribution once it is
        // durably retained, before applying it to its own local state
        // machine (see the `PublicContribution` control handler's spawned
        // `dispatch_public_contribution` call). If that local application
        // fails, nothing else ever retries it: the leader already told the
        // sender it is done, so the sender never re-submits, and this
        // function was otherwise a complete no-op for the leader.
        // `dispatch_retained_public_repair` re-verifies and redispatches
        // every retained contribution for the phase; `dispatch_public_contribution`
        // is attempt-scoped and idempotent, so this is a safe no-op for
        // anything already successfully applied.
        return match dispatch_retained_public_repair(&state, routes, &prepare, phase).await {
            Ok(_) => Ok(()),
            Err(PublicRepairFailure::Violation(violation)) => {
                abort_public_protocol_violation(
                    &state,
                    routes,
                    &prepare,
                    &violation,
                    violation_topic_task,
                )
                .await;
                Err(DkgError::ProtocolError(format!(
                    "authenticated public repair violation {:?}: {}",
                    violation.kind, violation.detail
                )))
            }
            Err(PublicRepairFailure::Error(error)) => Err(error),
        };
    }
    let activated = state
        .dkg_session_state
        .transport_info(&prepare.ceremony_id.0)
        .await
        .is_some_and(|(_, attempt_id, _, _, activated)| {
            attempt_id == prepare.attempt_id && activated
        });
    if !activated {
        return Ok(());
    }
    if !force_after_lag
        && !state
            .dkg_session_state
            .transport_repair_due(
                &prepare.ceremony_id.0,
                prepare.attempt_id,
                DKG_REPAIR_STALL_INTERVAL,
            )
            .await
    {
        return Ok(());
    }
    match state
        .dkg_session_state
        .claim_public_phase_repair(&prepare.ceremony_id.0, prepare.attempt_id, phase)
        .await
    {
        PublicRepairClaimOutcome::Claimed => {}
        PublicRepairClaimOutcome::InFlight => {
            crate::metrics::record_dkg_transport_event("public", "repair_coalesced");
            return Ok(());
        }
        PublicRepairClaimOutcome::Backoff | PublicRepairClaimOutcome::StaleAttempt => {
            return Ok(());
        }
    }

    let before = public_repair_retained_count(&state, &prepare, phase).await;
    let requester = NetworkPublicRepairRequester {
        state: state.clone(),
        routes,
    };
    let result = repair_public_phase_claimed(&state, routes, &requester, &prepare, phase).await;
    if let Err(PublicRepairFailure::Violation(violation)) = &result {
        abort_public_protocol_violation(&state, routes, &prepare, violation, violation_topic_task)
            .await;
        return Err(DkgError::ProtocolError(format!(
            "authenticated public repair violation {:?}: {}",
            violation.kind, violation.detail
        )));
    }
    let after = public_repair_retained_count(&state, &prepare, phase).await;
    state
        .dkg_session_state
        .finish_public_phase_repair(
            &prepare.ceremony_id.0,
            prepare.attempt_id,
            phase,
            after > before,
            DKG_MAX_REPAIR_BACKOFF,
        )
        .await;
    match result {
        Ok(()) => Ok(()),
        Err(PublicRepairFailure::Error(error)) => Err(error),
        Err(PublicRepairFailure::Violation(_)) => {
            unreachable!("public repair violations return after attempt cleanup")
        }
    }
}
