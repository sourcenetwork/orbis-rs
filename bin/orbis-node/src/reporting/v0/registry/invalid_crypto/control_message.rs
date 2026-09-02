use super::*;

impl InvalidCryptoResponseHandler {
    pub(super) async fn validate_dkg_control_message_fault_evidence(
        &self,
        envelope: &ReportEnvelope,
        context: &ReportValidationContext,
        ring: &RingPayload,
        statement: &DkgControlMessageFaultStatement,
    ) -> Result<()> {
        validate_invalid_crypto_statement_prologue(
            envelope,
            context,
            InvalidCryptoStatementPrologue {
                label: "DKG control-message fault".to_string(),
                domain: statement.domain.clone(),
                expected_domain: DKG_CONTROL_MESSAGE_FAULT_DOMAIN.to_string(),
                chain_id: statement.chain_id.clone(),
                ring_id: statement.ring_id.clone(),
                ring_pk: statement.ring_pk.clone(),
                ring_state_sha256: statement.ring_state_sha256.clone(),
                request_id: statement.request_id.clone(),
                signed_at: statement.signed_at,
                responder_node_key: statement.responder_node_key.clone(),
                check_anchor: true,
            },
        )?;
        if !is_valid_invalid_crypto_dkg_origin(&statement.origin_protocol) {
            return Err(ReportingError::InvalidReport(format!(
                "unsupported DKG control-message fault origin protocol {}",
                statement.origin_protocol
            )));
        }
        if statement.signing_committee_scope != CommitteeScope::Current {
            return Err(ReportingError::Unauthorized(
                "DKG control-message fault reports must use the current signing committee"
                    .to_string(),
            ));
        }
        // `AckEquivocation`'s accused can be a pure old-committee Reshare
        // dealer (never a member of the new/pending committee) — unlike
        // `LeaderPrepareFault`, whose accused is always the canonical leader
        // and therefore always drawn from the new committee for Reshare —
        // so this one fault kind accepts either scope here. The real
        // enforcement isn't this equality check, it's the accused-membership
        // containment check below (`accused_committee.peer_node_keys.
        // contains(...)`), which independently confirms the accused is a
        // genuine member of whichever scope the statement actually claims.
        let expected_accused_scope = match statement.origin_protocol.as_str() {
            "pss_reshare"
                if statement.fault_kind == DkgControlMessageFaultKind::AckEquivocation =>
            {
                None
            }
            "pss_reshare" => Some(CommitteeScope::PendingNew),
            _ => Some(CommitteeScope::Current),
        };
        if let Some(expected_accused_scope) = expected_accused_scope {
            if statement.accused_committee_scope != expected_accused_scope {
                return Err(ReportingError::Unauthorized(
                    "DKG control-message fault accused committee scope does not match origin protocol"
                        .to_string(),
                ));
            }
        }
        let effective_version =
            validate_report_route_version_at_observed_at(envelope, ring, context.routes.version)?;
        if statement.protocol_version != effective_version {
            return Err(ReportingError::Unauthorized(format!(
                "DKG control-message fault protocol version {} does not match effective ring version {}",
                statement.protocol_version, effective_version
            )));
        }

        let signing_committee = validate_ring_and_membership_for_scopes(
            envelope,
            ring,
            statement.accused_committee_scope,
            CommitteeScope::Current,
            "DKG control-message fault",
        )?;
        validate_node_routes(envelope, context, ring).await?;
        validate_local_signer(
            envelope,
            context,
            &signing_committee,
            "DKG control-message fault",
        )?;

        let accused_committee = committee_for_scope(ring, statement.accused_committee_scope)?;
        if !accused_committee
            .peer_node_keys
            .contains(&statement.responder_node_key)
        {
            return Err(ReportingError::Unauthorized(
                "control-message fault accused is not in the claimed committee".to_string(),
            ));
        }

        let ceremony_id = statement.request_id.parse::<u128>().map_err(|_| {
            ReportingError::InvalidReport(
                "DKG control-message fault request_id is not a ceremony ID".to_string(),
            )
        })?;

        match statement.fault_kind {
            DkgControlMessageFaultKind::LeaderPrepareFault => {
                if statement.artifact_b.is_some() {
                    return Err(ReportingError::InvalidReport(
                        "leader-prepare-fault evidence must contain exactly one artifact"
                            .to_string(),
                    ));
                }
                if statement.message_kind != "prepare" {
                    return Err(ReportingError::InvalidReport(
                        "leader-prepare-fault evidence must target the Prepare message".to_string(),
                    ));
                }
                let prepare: transport::PrepareSession = transport::decode(
                    &statement.artifact_a.data,
                    transport::MAX_PUBLIC_ORIGIN_EVIDENCE_BYTES,
                )
                .map_err(ReportingError::InvalidReport)?;
                if prepare.ceremony_id.0 != ceremony_id
                    || prepare.attempt_id.0 != statement.attempt_id
                {
                    return Err(ReportingError::Unauthorized(
                        "leader-prepare-fault evidence does not target the claimed attempt"
                            .to_string(),
                    ));
                }
                if prepare.leader_node_key != statement.responder_node_key {
                    return Err(ReportingError::Unauthorized(
                        "leader-prepare-fault Prepare is not self-consistently attributed to the accused"
                            .to_string(),
                    ));
                }
                let recomputed_digest =
                    transport::config_digest(&prepare).map_err(ReportingError::InvalidReport)?;
                if recomputed_digest != prepare.config_digest {
                    return Err(ReportingError::Unauthorized(
                        "leader-prepare-fault Prepare content does not match its own config_digest"
                            .to_string(),
                    ));
                }
                // `signed_at` is bound into `control_ack_signing_bytes` itself, so
                // verifying the signature below already proves the accused leader
                // authenticated this exact timestamp — only a self-consistency
                // check against the statement's own top-level `signed_at` (its
                // observed_at/TTL anchor) is needed on top of that.
                if statement.signed_at != statement.artifact_a.signed_at {
                    return Err(ReportingError::Unauthorized(
                        "leader-prepare-fault statement signed_at does not match its artifact"
                            .to_string(),
                    ));
                }
                let signed_bytes = transport::control_ack_signing_bytes(
                    prepare.ceremony_id,
                    prepare.attempt_id,
                    "prepare",
                    recomputed_digest,
                    statement.artifact_a.signed_at,
                );
                verify_node_message(
                    &statement.responder_node_key,
                    &signed_bytes,
                    &statement.artifact_a.signature,
                )
                .map_err(|error| {
                    ReportingError::Unauthorized(format!(
                        "invalid leader-prepare-fault signature: {error}"
                    ))
                })?;

                let noncanonical_leader =
                    prepare.canonical_leader_node_key() != Some(prepare.leader_node_key.as_str());
                let routes_contradict_vera = if noncanonical_leader {
                    false
                } else {
                    // Reshare (`PendingNew` scope) always attributes the accused
                    // via the *new* committee — `report_leader_prepare_fault_
                    // best_effort` scopes it that way since the leader is always
                    // drawn from there — but the disputed route claim inside the
                    // same signed Prepare could be about either committee it
                    // names. So for Reshare, independently re-check both: the
                    // old/current committee against the ring's still-current
                    // membership, and the new/next committee against the
                    // accused's own claimed scope. Refresh only ever has a
                    // current committee, so only that one applies.
                    let current_contradicts = committee_routes_contradict_vera(
                        context,
                        &prepare.committees.current,
                        &ring.peer_node_keys,
                    )
                    .await;
                    let next_contradicts =
                        if statement.accused_committee_scope == CommitteeScope::PendingNew {
                            let next = prepare.committees.next.as_ref().ok_or_else(|| {
                                ReportingError::InvalidReport(
                                    "leader-prepare-fault Reshare Prepare omits the next committee"
                                        .to_string(),
                                )
                            })?;
                            committee_routes_contradict_vera(
                                context,
                                next,
                                &accused_committee.peer_node_keys,
                            )
                            .await
                        } else {
                            false
                        };
                    current_contradicts || next_contradicts
                };
                if !noncanonical_leader && !routes_contradict_vera {
                    return Err(ReportingError::Unauthorized(
                        "Prepare content does not prove a leader-prepare fault".to_string(),
                    ));
                }
            }
            DkgControlMessageFaultKind::AckEquivocation => {
                if !matches!(
                    statement.message_kind.as_str(),
                    "prepared" | "activated" | "begun"
                ) {
                    return Err(ReportingError::InvalidReport(format!(
                        "unsupported DKG control-ack message kind {}",
                        statement.message_kind
                    )));
                }
                let artifact_b = statement.artifact_b.as_ref().ok_or_else(|| {
                    ReportingError::InvalidReport(
                        "ack-equivocation evidence requires two artifacts".to_string(),
                    )
                })?;
                let digest_a: [u8; 32] =
                    statement.artifact_a.data.clone().try_into().map_err(|_| {
                        ReportingError::InvalidReport(
                            "ack-equivocation artifact_a digest must be 32 bytes".to_string(),
                        )
                    })?;
                let digest_b: [u8; 32] = artifact_b.data.clone().try_into().map_err(|_| {
                    ReportingError::InvalidReport(
                        "ack-equivocation artifact_b digest must be 32 bytes".to_string(),
                    )
                })?;
                if digest_a == digest_b {
                    return Err(ReportingError::Unauthorized(
                        "ack-equivocation artifacts claim the identical digest".to_string(),
                    ));
                }
                // Same self-consistency rationale as `LeaderPrepareFault` above —
                // the later of the two authenticated `signed_at` values is the
                // statement's own anchor (matching `queue_control_message_fault_
                // report`'s construction-side `max()`).
                if statement.signed_at != statement.artifact_a.signed_at.max(artifact_b.signed_at) {
                    return Err(ReportingError::Unauthorized(
                        "ack-equivocation statement signed_at does not match its artifacts"
                            .to_string(),
                    ));
                }
                let attempt_id = transport::AttemptId(statement.attempt_id);
                for (digest, artifact) in
                    [(digest_a, &statement.artifact_a), (digest_b, artifact_b)]
                {
                    let signed_bytes = transport::control_ack_signing_bytes(
                        transport::CeremonyId(ceremony_id),
                        attempt_id,
                        &statement.message_kind,
                        digest,
                        artifact.signed_at,
                    );
                    verify_node_message(
                        &statement.responder_node_key,
                        &signed_bytes,
                        &artifact.signature,
                    )
                    .map_err(|error| {
                        ReportingError::Unauthorized(format!(
                            "invalid ack-equivocation signature: {error}"
                        ))
                    })?;
                }
            }
            DkgControlMessageFaultKind::OversizedRepairPage => {
                if statement.artifact_b.is_some() {
                    return Err(ReportingError::InvalidReport(
                        "oversized-repair-page evidence must contain exactly one artifact"
                            .to_string(),
                    ));
                }
                if statement.message_kind != "public_phase_response" {
                    return Err(ReportingError::InvalidReport(
                        "oversized-repair-page evidence must target the PublicPhaseResponse \
                         message"
                            .to_string(),
                    ));
                }
                // Pure byte-length check against a fixed protocol constant,
                // against the artifact's own raw bytes (not a re-encoding) —
                // same precedent as `dkg_leader_public_fault`'s
                // `oversized_chunk`.
                if statement.artifact_a.data.len() <= transport::MAX_PUBLIC_REPAIR_PAGE_BYTES {
                    return Err(ReportingError::Unauthorized(
                        "reported repair page is independently verifiable as within the size \
                         limit"
                            .to_string(),
                    ));
                }
                let response: transport::DkgControlMessage = transport::decode(
                    &statement.artifact_a.data,
                    transport::MAX_PUBLIC_ORIGIN_EVIDENCE_BYTES,
                )
                .map_err(ReportingError::InvalidReport)?;
                let transport::DkgControlMessage::PublicPhaseResponse {
                    ceremony_id: response_ceremony_id,
                    attempt_id: response_attempt_id,
                    phase,
                    contributions,
                    next_cursor,
                    page_digest,
                    report_signature,
                } = response
                else {
                    return Err(ReportingError::InvalidReport(
                        "oversized-repair-page evidence does not decode as a PublicPhaseResponse"
                            .to_string(),
                    ));
                };
                if response_ceremony_id.0 != ceremony_id
                    || response_attempt_id.0 != statement.attempt_id
                {
                    return Err(ReportingError::Unauthorized(
                        "oversized-repair-page evidence does not target the claimed attempt"
                            .to_string(),
                    ));
                }
                let recomputed_digest = transport::public_repair_page_digest(
                    response_ceremony_id,
                    response_attempt_id,
                    phase,
                    &contributions,
                    next_cursor,
                );
                if recomputed_digest != page_digest {
                    return Err(ReportingError::Unauthorized(
                        "oversized-repair-page evidence content does not match its own \
                         page_digest"
                            .to_string(),
                    ));
                }
                let Some(embedded_signature) = report_signature else {
                    return Err(ReportingError::Unauthorized(
                        "oversized-repair-page evidence has no report signature".to_string(),
                    ));
                };
                // `data` is a full re-decodable `PublicPhaseResponse`, whose
                // embedded `report_signature.signed_at` must agree with the
                // top-level artifact's `signed_at` — same self-consistency
                // rationale as recomputing `page_digest` above, so a relay can't
                // swap in a mismatched timestamp on either side.
                if embedded_signature.signed_at != statement.artifact_a.signed_at
                    || statement.signed_at != statement.artifact_a.signed_at
                {
                    return Err(ReportingError::Unauthorized(
                        "oversized-repair-page statement signed_at does not match its artifact"
                            .to_string(),
                    ));
                }
                let signed_bytes = transport::control_ack_signing_bytes(
                    response_ceremony_id,
                    response_attempt_id,
                    "public_phase_response",
                    page_digest,
                    statement.artifact_a.signed_at,
                );
                verify_node_message(
                    &statement.responder_node_key,
                    &signed_bytes,
                    &statement.artifact_a.signature,
                )
                .map_err(|error| {
                    ReportingError::Unauthorized(format!(
                        "invalid oversized-repair-page signature: {error}"
                    ))
                })?;
            }
        }

        Ok(())
    }
}

/// Whether a claimed committee's node_keys/routes (from a signed Prepare)
/// contradict Vera's own authoritative NodeInfo for the given expected
/// membership. Degrades to "no contradiction" if routes can't currently be
/// resolved — an unrelated resolution hiccup should not manufacture a false
/// attribution.
pub(crate) async fn committee_routes_contradict_vera(
    context: &ReportValidationContext,
    claimed: &transport::CommitteeConfig,
    expected_node_keys: &[String],
) -> bool {
    let claimed_keys: std::collections::BTreeSet<_> = claimed.node_keys.iter().collect();
    let expected_keys: std::collections::BTreeSet<_> = expected_node_keys.iter().collect();
    if claimed_keys != expected_keys {
        return true;
    }
    resolve_node_routes(&context.bulletin, expected_node_keys)
        .await
        .is_ok_and(|resolved| {
            let resolved_routes: std::collections::BTreeMap<_, _> = resolved
                .into_iter()
                .map(|route| (route.node_key, route.peer_id))
                .collect();
            claimed
                .node_keys
                .iter()
                .zip(&claimed.peer_routes)
                .any(|(node_key, route)| resolved_routes.get(node_key) != Some(route))
        })
}
