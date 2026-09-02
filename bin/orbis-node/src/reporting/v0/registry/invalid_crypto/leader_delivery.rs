use super::*;

impl InvalidCryptoResponseHandler {
    pub(super) async fn validate_dkg_leader_equivocation_evidence(
        &self,
        envelope: &ReportEnvelope,
        context: &ReportValidationContext,
        ring: &RingPayload,
        statement: &DkgLeaderEquivocationStatement,
    ) -> Result<()> {
        validate_invalid_crypto_statement_prologue(
            envelope,
            context,
            InvalidCryptoStatementPrologue {
                label: "DKG leader equivocation".to_string(),
                domain: statement.domain.clone(),
                expected_domain: DKG_LEADER_EQUIVOCATION_DOMAIN.to_string(),
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
                "unsupported DKG leader-equivocation origin protocol {}",
                statement.origin_protocol
            )));
        }
        if statement.signing_committee_scope != CommitteeScope::Current {
            return Err(ReportingError::Unauthorized(
                "DKG leader-equivocation reports must use the current signing committee"
                    .to_string(),
            ));
        }
        // The canonical leader is drawn from the current committee for a
        // refresh (same committee throughout) and from the pending-new
        // committee for a reshare (`PrepareSession::leader_committee`).
        let expected_accused_scope = match statement.origin_protocol.as_str() {
            "pss_reshare" => CommitteeScope::PendingNew,
            _ => CommitteeScope::Current,
        };
        if statement.accused_committee_scope != expected_accused_scope {
            return Err(ReportingError::Unauthorized(
                "DKG leader-equivocation accused committee scope does not match origin protocol"
                    .to_string(),
            ));
        }
        let effective_version =
            validate_report_route_version_at_observed_at(envelope, ring, context.routes.version)?;
        if statement.protocol_version != effective_version {
            return Err(ReportingError::Unauthorized(format!(
                "DKG leader-equivocation protocol version {} does not match effective ring version {}",
                statement.protocol_version, effective_version
            )));
        }

        let signing_committee = validate_ring_and_membership_for_scopes(
            envelope,
            ring,
            statement.accused_committee_scope,
            CommitteeScope::Current,
            "DKG leader equivocation",
        )?;
        validate_node_routes(envelope, context, ring).await?;
        validate_local_signer(
            envelope,
            context,
            &signing_committee,
            "DKG leader equivocation",
        )?;

        // Independently re-derive who the leader should have been rather
        // than trusting the reporter's characterization of the accused.
        let accused_committee = committee_for_scope(ring, statement.accused_committee_scope)?;
        let canonical_leader = transport::canonical_leader(&accused_committee.peer_node_keys)
            .ok_or_else(|| {
                ReportingError::InvalidReport(
                    "DKG leader-equivocation accused committee is empty".to_string(),
                )
            })?;
        if canonical_leader != envelope.accused_node_key {
            return Err(ReportingError::Unauthorized(
                "accused node is not the canonical leader for this committee".to_string(),
            ));
        }

        let next_peer_node_keys = if statement.origin_protocol == "pss_reshare" {
            Some(ring.new_peer_node_keys.clone().ok_or_else(|| {
                ReportingError::Unauthorized(
                    "DKG leader-equivocation reshare evidence requires a pending reshare"
                        .to_string(),
                )
            })?)
        } else {
            None
        };
        let committee_digest = transport::ceremony_committee_digest(
            &ring.peer_node_keys,
            next_peer_node_keys.as_deref(),
        );
        let ceremony_id = statement.request_id.parse::<u128>().map_err(|_| {
            ReportingError::InvalidReport(
                "DKG leader-equivocation request_id is not a ceremony ID".to_string(),
            )
        })?;
        let attempt_id = transport::AttemptId(statement.attempt_id);
        let topic = transport::derive_topic_id(
            &statement.chain_id,
            &statement.ring_id,
            &committee_digest,
            transport::CeremonyId(ceremony_id),
            attempt_id,
        );

        let delivery_a = verify_leader_delivery_envelope(
            envelope,
            context,
            topic,
            statement.delivery_id_a,
            &statement.delivery_a,
        )
        .await?;
        let delivery_b = verify_leader_delivery_envelope(
            envelope,
            context,
            topic,
            statement.delivery_id_b,
            &statement.delivery_b,
        )
        .await?;
        if !leader_deliveries_prove_equivocation(&delivery_a, &delivery_b) {
            return Err(ReportingError::Unauthorized(
                "leader deliveries do not prove manifest/chunk equivocation".to_string(),
            ));
        }
        let (delivery_ceremony_id, delivery_attempt_id, delivery_phase) =
            leader_delivery_coordinates(&delivery_a).ok_or_else(|| {
                ReportingError::Unauthorized(
                    "leader delivery is not a manifest or chunk".to_string(),
                )
            })?;
        if delivery_ceremony_id.0 != ceremony_id
            || delivery_attempt_id != attempt_id
            || delivery_phase.as_metric_label() != statement.phase
        {
            return Err(ReportingError::Unauthorized(
                "leader delivery does not target the claimed attempt/phase".to_string(),
            ));
        }
        if !public_origin_protocol_allows_phase(&statement.origin_protocol, delivery_phase) {
            return Err(ReportingError::Unauthorized(
                "leader delivery phase is not valid for the claimed PSS protocol".to_string(),
            ));
        }
        // The prologue only checked `signed_at` is self-consistent with the
        // envelope's own `observed_at` — it never cross-checked it against
        // what the leader actually claimed inside the (now independently
        // decoded) deliveries. Without this, a reporter could still anchor
        // to an arbitrary `signed_at` regardless of the deliveries' real
        // content, defeating the point of anchoring to evidence instead of
        // report-construction time.
        let signed_at_a = leader_delivery_signed_at(&delivery_a).ok_or_else(|| {
            ReportingError::Unauthorized("leader delivery A is not a manifest or chunk".to_string())
        })?;
        let signed_at_b = leader_delivery_signed_at(&delivery_b).ok_or_else(|| {
            ReportingError::Unauthorized("leader delivery B is not a manifest or chunk".to_string())
        })?;
        if statement.signed_at != signed_at_a.max(signed_at_b) {
            return Err(ReportingError::Unauthorized(
                "DKG leader-equivocation signed_at does not match the deliveries' own claimed \
                 timestamps"
                    .to_string(),
            ));
        }

        Ok(())
    }

    /// Independently re-verify two leader deliveries (any combination of
    /// manifest/chunk) that each reference the same origin under two
    /// *different* phase roots — the leader's own packaging contradiction
    /// `claim_origins` (`network.rs`) detects locally. Reuses
    /// `DkgLeaderEquivocationStatement`'s wire shape (see that type's doc
    /// comment); the predicate differs: shared origin + different root,
    /// rather than same coordinate + different content.
    pub(super) async fn validate_dkg_leader_batch_mismatch_evidence(
        &self,
        envelope: &ReportEnvelope,
        context: &ReportValidationContext,
        ring: &RingPayload,
        statement: &DkgLeaderEquivocationStatement,
    ) -> Result<()> {
        validate_invalid_crypto_statement_prologue(
            envelope,
            context,
            InvalidCryptoStatementPrologue {
                label: "DKG leader batch mismatch".to_string(),
                domain: statement.domain.clone(),
                expected_domain: DKG_LEADER_BATCH_MISMATCH_DOMAIN.to_string(),
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
                "unsupported DKG leader batch-mismatch origin protocol {}",
                statement.origin_protocol
            )));
        }
        if statement.signing_committee_scope != CommitteeScope::Current {
            return Err(ReportingError::Unauthorized(
                "DKG leader batch-mismatch reports must use the current signing committee"
                    .to_string(),
            ));
        }
        let expected_accused_scope = match statement.origin_protocol.as_str() {
            "pss_reshare" => CommitteeScope::PendingNew,
            _ => CommitteeScope::Current,
        };
        if statement.accused_committee_scope != expected_accused_scope {
            return Err(ReportingError::Unauthorized(
                "DKG leader batch-mismatch accused committee scope does not match origin protocol"
                    .to_string(),
            ));
        }
        let effective_version =
            validate_report_route_version_at_observed_at(envelope, ring, context.routes.version)?;
        if statement.protocol_version != effective_version {
            return Err(ReportingError::Unauthorized(format!(
                "DKG leader batch-mismatch protocol version {} does not match effective ring version {}",
                statement.protocol_version, effective_version
            )));
        }

        let signing_committee = validate_ring_and_membership_for_scopes(
            envelope,
            ring,
            statement.accused_committee_scope,
            CommitteeScope::Current,
            "DKG leader batch mismatch",
        )?;
        validate_node_routes(envelope, context, ring).await?;
        validate_local_signer(
            envelope,
            context,
            &signing_committee,
            "DKG leader batch mismatch",
        )?;

        // Independently re-derive who the leader should have been rather
        // than trusting the reporter's characterization of the accused.
        let accused_committee = committee_for_scope(ring, statement.accused_committee_scope)?;
        let canonical_leader = transport::canonical_leader(&accused_committee.peer_node_keys)
            .ok_or_else(|| {
                ReportingError::InvalidReport(
                    "DKG leader batch-mismatch accused committee is empty".to_string(),
                )
            })?;
        if canonical_leader != envelope.accused_node_key {
            return Err(ReportingError::Unauthorized(
                "accused node is not the canonical leader for this committee".to_string(),
            ));
        }

        let next_peer_node_keys = if statement.origin_protocol == "pss_reshare" {
            Some(ring.new_peer_node_keys.clone().ok_or_else(|| {
                ReportingError::Unauthorized(
                    "DKG leader batch-mismatch reshare evidence requires a pending reshare"
                        .to_string(),
                )
            })?)
        } else {
            None
        };
        let committee_digest = transport::ceremony_committee_digest(
            &ring.peer_node_keys,
            next_peer_node_keys.as_deref(),
        );
        let ceremony_id = statement.request_id.parse::<u128>().map_err(|_| {
            ReportingError::InvalidReport(
                "DKG leader batch-mismatch request_id is not a ceremony ID".to_string(),
            )
        })?;
        let attempt_id = transport::AttemptId(statement.attempt_id);
        let topic = transport::derive_topic_id(
            &statement.chain_id,
            &statement.ring_id,
            &committee_digest,
            transport::CeremonyId(ceremony_id),
            attempt_id,
        );

        let delivery_a = verify_leader_delivery_envelope(
            envelope,
            context,
            topic,
            statement.delivery_id_a,
            &statement.delivery_a,
        )
        .await?;
        let delivery_b = verify_leader_delivery_envelope(
            envelope,
            context,
            topic,
            statement.delivery_id_b,
            &statement.delivery_b,
        )
        .await?;

        let (ceremony_id_a, attempt_id_a, phase_a) = leader_delivery_coordinates(&delivery_a)
            .ok_or_else(|| {
                ReportingError::Unauthorized(
                    "leader delivery A is not a manifest or chunk".to_string(),
                )
            })?;
        let (ceremony_id_b, attempt_id_b, phase_b) = leader_delivery_coordinates(&delivery_b)
            .ok_or_else(|| {
                ReportingError::Unauthorized(
                    "leader delivery B is not a manifest or chunk".to_string(),
                )
            })?;
        if ceremony_id_a.0 != ceremony_id
            || attempt_id_a != attempt_id
            || phase_a.as_metric_label() != statement.phase
            || ceremony_id_b.0 != ceremony_id
            || attempt_id_b != attempt_id
            || phase_b != phase_a
        {
            return Err(ReportingError::Unauthorized(
                "leader deliveries do not both target the claimed attempt/phase".to_string(),
            ));
        }
        if !public_origin_protocol_allows_phase(&statement.origin_protocol, phase_a) {
            return Err(ReportingError::Unauthorized(
                "leader delivery phase is not valid for the claimed PSS protocol".to_string(),
            ));
        }

        let root_a = leader_delivery_root(&delivery_a).ok_or_else(|| {
            ReportingError::Unauthorized("leader delivery A has no phase root".to_string())
        })?;
        let root_b = leader_delivery_root(&delivery_b).ok_or_else(|| {
            ReportingError::Unauthorized("leader delivery B has no phase root".to_string())
        })?;
        if root_a == root_b {
            return Err(ReportingError::Unauthorized(
                "leader deliveries claim the same phase root — not a batch mismatch".to_string(),
            ));
        }

        let origins_a = leader_delivery_origins(&delivery_a).unwrap_or_default();
        let origins_b = leader_delivery_origins(&delivery_b).unwrap_or_default();
        let shares_an_origin = origins_a
            .iter()
            .any(|(origin, message_id)| origins_b.get(origin) == Some(message_id));
        if !shares_an_origin {
            return Err(ReportingError::Unauthorized(
                "leader deliveries do not prove a shared-origin batch mismatch".to_string(),
            ));
        }
        // See `validate_dkg_leader_equivocation_evidence`'s matching check —
        // the prologue anchor alone doesn't tie `signed_at` to what the
        // deliveries themselves claim.
        let signed_at_a = leader_delivery_signed_at(&delivery_a).ok_or_else(|| {
            ReportingError::Unauthorized("leader delivery A is not a manifest or chunk".to_string())
        })?;
        let signed_at_b = leader_delivery_signed_at(&delivery_b).ok_or_else(|| {
            ReportingError::Unauthorized("leader delivery B is not a manifest or chunk".to_string())
        })?;
        if statement.signed_at != signed_at_a.max(signed_at_b) {
            return Err(ReportingError::Unauthorized(
                "DKG leader batch-mismatch signed_at does not match the deliveries' own claimed \
                 timestamps"
                    .to_string(),
            ));
        }

        Ok(())
    }

    pub(super) async fn validate_dkg_leader_public_fault_evidence(
        &self,
        envelope: &ReportEnvelope,
        context: &ReportValidationContext,
        ring: &RingPayload,
        statement: &DkgLeaderPublicFaultStatement,
    ) -> Result<()> {
        validate_invalid_crypto_statement_prologue(
            envelope,
            context,
            InvalidCryptoStatementPrologue {
                label: "DKG leader public fault".to_string(),
                domain: statement.domain.clone(),
                expected_domain: DKG_LEADER_PUBLIC_FAULT_DOMAIN.to_string(),
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
                "unsupported DKG leader public-fault origin protocol {}",
                statement.origin_protocol
            )));
        }
        if statement.signing_committee_scope != CommitteeScope::Current {
            return Err(ReportingError::Unauthorized(
                "DKG leader public-fault reports must use the current signing committee"
                    .to_string(),
            ));
        }
        // The canonical leader is drawn from the current committee for a
        // refresh (same committee throughout) and from the pending-new
        // committee for a reshare (`PrepareSession::leader_committee`) —
        // same rule as `dkg_leader_equivocation`, since this fault's accused
        // is likewise always the canonical leader (only the leader publishes
        // manifests).
        let expected_accused_scope = match statement.origin_protocol.as_str() {
            "pss_reshare" => CommitteeScope::PendingNew,
            _ => CommitteeScope::Current,
        };
        if statement.accused_committee_scope != expected_accused_scope {
            return Err(ReportingError::Unauthorized(
                "DKG leader public-fault accused committee scope does not match origin protocol"
                    .to_string(),
            ));
        }
        let effective_version =
            validate_report_route_version_at_observed_at(envelope, ring, context.routes.version)?;
        if statement.protocol_version != effective_version {
            return Err(ReportingError::Unauthorized(format!(
                "DKG leader public-fault protocol version {} does not match effective ring version {}",
                statement.protocol_version, effective_version
            )));
        }

        let signing_committee = validate_ring_and_membership_for_scopes(
            envelope,
            ring,
            statement.accused_committee_scope,
            CommitteeScope::Current,
            "DKG leader public fault",
        )?;
        validate_node_routes(envelope, context, ring).await?;
        validate_local_signer(
            envelope,
            context,
            &signing_committee,
            "DKG leader public fault",
        )?;

        // Independently re-derive who the leader should have been rather
        // than trusting the reporter's characterization of the accused.
        let accused_committee = committee_for_scope(ring, statement.accused_committee_scope)?;
        let canonical_leader = transport::canonical_leader(&accused_committee.peer_node_keys)
            .ok_or_else(|| {
                ReportingError::InvalidReport(
                    "DKG leader public-fault accused committee is empty".to_string(),
                )
            })?;
        if canonical_leader != envelope.accused_node_key {
            return Err(ReportingError::Unauthorized(
                "accused node is not the canonical leader for this committee".to_string(),
            ));
        }

        let next_peer_node_keys = if statement.origin_protocol == "pss_reshare" {
            Some(ring.new_peer_node_keys.clone().ok_or_else(|| {
                ReportingError::Unauthorized(
                    "DKG leader public-fault reshare evidence requires a pending reshare"
                        .to_string(),
                )
            })?)
        } else {
            None
        };
        let committee_digest = transport::ceremony_committee_digest(
            &ring.peer_node_keys,
            next_peer_node_keys.as_deref(),
        );
        let ceremony_id = statement.request_id.parse::<u128>().map_err(|_| {
            ReportingError::InvalidReport(
                "DKG leader public-fault request_id is not a ceremony ID".to_string(),
            )
        })?;
        let attempt_id = transport::AttemptId(statement.attempt_id);
        let topic = transport::derive_topic_id(
            &statement.chain_id,
            &statement.ring_id,
            &committee_digest,
            transport::CeremonyId(ceremony_id),
            attempt_id,
        );

        let delivery = verify_leader_delivery_envelope(
            envelope,
            context,
            topic,
            statement.delivery_id,
            &statement.delivery,
        )
        .await?;
        let (delivery_ceremony_id, delivery_attempt_id, delivery_phase) =
            leader_delivery_coordinates(&delivery).ok_or_else(|| {
                ReportingError::Unauthorized(
                    "leader delivery is not a manifest or chunk".to_string(),
                )
            })?;
        if delivery_ceremony_id.0 != ceremony_id
            || delivery_attempt_id != attempt_id
            || delivery_phase.as_metric_label() != statement.phase
        {
            return Err(ReportingError::Unauthorized(
                "leader delivery does not target the claimed attempt/phase".to_string(),
            ));
        }
        if !public_origin_protocol_allows_phase(&statement.origin_protocol, delivery_phase) {
            return Err(ReportingError::Unauthorized(
                "leader delivery phase is not valid for the claimed PSS protocol".to_string(),
            ));
        }
        // See `validate_dkg_leader_equivocation_evidence`'s matching check —
        // the prologue anchor alone doesn't tie `signed_at` to what the
        // delivery itself claims.
        let delivery_signed_at = leader_delivery_signed_at(&delivery).ok_or_else(|| {
            ReportingError::Unauthorized("leader delivery is not a manifest or chunk".to_string())
        })?;
        if statement.signed_at != delivery_signed_at {
            return Err(ReportingError::Unauthorized(
                "DKG leader public-fault signed_at does not match the delivery's own claimed \
                 timestamp"
                    .to_string(),
            ));
        }

        match statement.fault_kind {
            DkgLeaderPublicFaultKind::InvalidManifest => {
                let transport::DkgPublicMessage::Manifest(manifest) = &delivery else {
                    return Err(ReportingError::Unauthorized(
                        "invalid-manifest evidence must target a Manifest delivery".to_string(),
                    ));
                };
                let expected = expected_leader_manifest_shape(
                    ring,
                    &statement.origin_protocol,
                    delivery_phase,
                )?;
                let is_actually_invalid = manifest.validate(&expected.origins).is_err()
                    || manifest.complete != expected.complete;
                if !is_actually_invalid {
                    return Err(ReportingError::Unauthorized(
                        "reported manifest is independently verifiable as valid".to_string(),
                    ));
                }
            }
            DkgLeaderPublicFaultKind::ChunkIndexOutOfRange => {
                let transport::DkgPublicMessage::Chunk { index, .. } = &delivery else {
                    return Err(ReportingError::Unauthorized(
                        "chunk-index-out-of-range evidence must target a Chunk delivery"
                            .to_string(),
                    ));
                };
                let expected = expected_leader_manifest_shape(
                    ring,
                    &statement.origin_protocol,
                    delivery_phase,
                )?;
                if (*index as usize) < expected.origins.len() {
                    return Err(ReportingError::Unauthorized(
                        "reported chunk index is independently verifiable as within range"
                            .to_string(),
                    ));
                }
            }
            DkgLeaderPublicFaultKind::OversizedChunk => {
                if !matches!(delivery, transport::DkgPublicMessage::Chunk { .. }) {
                    return Err(ReportingError::Unauthorized(
                        "oversized-chunk evidence must target a Chunk delivery".to_string(),
                    ));
                }
                // Pure byte-length check against a fixed protocol constant —
                // no committee/ring lookup needed, unlike the other two
                // kinds, so this is provable even for the one phase
                // (`expected_leader_manifest_shape`'s Reshare-Commitments
                // exclusion) that InvalidManifest/ChunkIndexOutOfRange can't
                // independently verify.
                if statement.delivery.data.len() <= transport::MAX_PUBLIC_CHUNK_BYTES {
                    return Err(ReportingError::Unauthorized(
                        "reported chunk is independently verifiable as within the size limit"
                            .to_string(),
                    ));
                }
            }
            DkgLeaderPublicFaultKind::DuplicateChunkOrigin => {
                let transport::DkgPublicMessage::Chunk { contributions, .. } = &delivery else {
                    return Err(ReportingError::Unauthorized(
                        "duplicate-chunk-origin evidence must target a Chunk delivery".to_string(),
                    ));
                };
                // Pure structural check on the delivery's own contributions —
                // no committee/ring lookup needed, unlike InvalidManifest/
                // ChunkIndexOutOfRange, so (like OversizedChunk) this is
                // provable even for the Reshare-Commitments exclusion.
                if !chunk_has_duplicate_origin(contributions) {
                    return Err(ReportingError::Unauthorized(
                        "reported chunk is independently verifiable as free of duplicate origins"
                            .to_string(),
                    ));
                }
            }
        }

        Ok(())
    }
}

/// Independently re-verify one retained leader delivery: the endpoint
/// signature under the exact per-broadcast topic-delivery domain, that the
/// signing endpoint matches the accused's registered peer ID, and that the
/// bytes decode as a public-plane Gossip message.
pub(crate) async fn verify_leader_delivery_envelope(
    envelope: &ReportEnvelope,
    context: &ReportValidationContext,
    topic: network::TopicId,
    delivery_id: [u8; 16],
    evidence: &EndpointSignedContribution,
) -> Result<transport::DkgPublicMessage> {
    if evidence.origin.len() != 32 || evidence.signature.len() != 64 || evidence.data.is_empty() {
        return Err(ReportingError::InvalidReport(
            "DKG leader-delivery endpoint envelope has invalid field lengths".to_string(),
        ));
    }
    let pubsub = context.network.pubsub().ok_or_else(|| {
        ReportingError::InvalidReport(
            "network backend does not support endpoint-authenticated public evidence".to_string(),
        )
    })?;
    let signed = network::SignedPayload {
        origin: evidence.origin.clone(),
        signature: evidence.signature.clone(),
        data: evidence.data.clone(),
    };
    let authenticated = pubsub
        .verify_topic_delivery(topic, delivery_id, &signed)
        .await
        .map_err(|error| {
            ReportingError::Unauthorized(format!(
                "invalid DKG leader-delivery endpoint signature: {error}"
            ))
        })?;
    let accused_endpoint = extract_node_part(&envelope.accused_peer_id).to_lowercase();
    if hex::encode(authenticated.origin.as_bytes()) != accused_endpoint {
        return Err(ReportingError::Unauthorized(
            "leader delivery endpoint does not match the accused peer ID".to_string(),
        ));
    }
    transport::decode::<transport::DkgPublicMessage>(
        &authenticated.data,
        transport::MAX_PUBLIC_ORIGIN_EVIDENCE_BYTES,
    )
    .map_err(ReportingError::InvalidReport)
}

/// The ceremony/attempt/phase a decoded leader delivery targets, or `None`
/// for `TopologyProbe`, which never carries retained equivocation evidence
/// (unreachable in practice: `leader_deliveries_prove_equivocation` only
/// returns `true` for a Manifest/Manifest or Chunk/Chunk pairing).
pub(crate) fn leader_delivery_coordinates(
    message: &transport::DkgPublicMessage,
) -> Option<(transport::CeremonyId, transport::AttemptId, DkgPublicPhase)> {
    match message {
        transport::DkgPublicMessage::Manifest(manifest) => {
            Some((manifest.ceremony_id, manifest.attempt_id, manifest.phase))
        }
        transport::DkgPublicMessage::Chunk {
            ceremony_id,
            attempt_id,
            phase,
            ..
        } => Some((*ceremony_id, *attempt_id, *phase)),
        transport::DkgPublicMessage::TopologyProbe { .. } => None,
    }
}

/// The phase root a leader delivery claims, or `None` for `TopologyProbe`.
pub(crate) fn leader_delivery_root(message: &transport::DkgPublicMessage) -> Option<[u8; 32]> {
    match message {
        transport::DkgPublicMessage::Manifest(manifest) => Some(manifest.phase_root),
        transport::DkgPublicMessage::Chunk { phase_root, .. } => Some(*phase_root),
        transport::DkgPublicMessage::TopologyProbe { .. } => None,
    }
}

/// When the leader claims to have constructed a decoded delivery, or `None`
/// for `TopologyProbe`. Used to independently re-derive what a leader-fault
/// statement's own `signed_at` *should* be, rather than trusting the
/// reporter's claim — `signed_at` is authenticated by the same enclosing
/// Gossip delivery signature `verify_leader_delivery_envelope` already
/// checked, so this is exactly as trustworthy as `leader_delivery_root`.
pub(crate) fn leader_delivery_signed_at(message: &transport::DkgPublicMessage) -> Option<u64> {
    match message {
        transport::DkgPublicMessage::Manifest(manifest) => Some(manifest.signed_at),
        transport::DkgPublicMessage::Chunk { signed_at, .. } => Some(*signed_at),
        transport::DkgPublicMessage::TopologyProbe { .. } => None,
    }
}

/// The origin → message_id map a leader delivery (manifest or chunk)
/// claims, or `None` for `TopologyProbe`. For chunks, each nested
/// `SignedPayload` is independently decoded to recover its origin/
/// message_id; entries that fail to decode are silently skipped — an
/// undecodable contribution can't back a claim about that specific origin
/// either way, so this can only make the caller's "shared origin" search
/// more conservative, never wrongly permissive.
pub(crate) fn leader_delivery_origins(
    message: &transport::DkgPublicMessage,
) -> Option<BTreeMap<ParticipantRef, transport::MessageId>> {
    match message {
        transport::DkgPublicMessage::Manifest(manifest) => Some(manifest.contribution_ids.clone()),
        transport::DkgPublicMessage::Chunk { contributions, .. } => Some(
            contributions
                .iter()
                .filter_map(|signed| {
                    transport::decode::<DkgPublicContribution>(
                        &signed.data,
                        transport::MAX_PUBLIC_ORIGIN_EVIDENCE_BYTES,
                    )
                    .ok()
                    .map(|contribution| (contribution.origin, contribution.message_id))
                })
                .collect(),
        ),
        transport::DkgPublicMessage::TopologyProbe { .. } => None,
    }
}

/// Whether a chunk's own contributions name the same origin more than once.
/// Each nested `SignedPayload` is independently decoded (same tolerance as
/// `leader_delivery_origins`: an undecodable entry can't back a duplicate
/// claim either way, so skipping it can only make this check *more*
/// conservative, never wrongly permissive). Manifests can't have this
/// problem — `contribution_ids` is a `BTreeMap`, which cannot contain the
/// same key twice by construction.
pub(crate) fn chunk_has_duplicate_origin(contributions: &[network::SignedPayload]) -> bool {
    let mut seen = BTreeSet::new();
    contributions.iter().any(|signed| {
        transport::decode::<DkgPublicContribution>(
            &signed.data,
            transport::MAX_PUBLIC_ORIGIN_EVIDENCE_BYTES,
        )
        .ok()
        .is_some_and(|contribution| !seen.insert(contribution.origin))
    })
}

/// Two leader deliveries prove equivocation only if they claim the exact
/// same coordinate (manifest phase_root, or chunk phase_root+index) but
/// carry different content.
pub(crate) fn leader_deliveries_prove_equivocation(
    a: &transport::DkgPublicMessage,
    b: &transport::DkgPublicMessage,
) -> bool {
    match (a, b) {
        (
            transport::DkgPublicMessage::Manifest(manifest_a),
            transport::DkgPublicMessage::Manifest(manifest_b),
        ) => {
            manifest_a.ceremony_id == manifest_b.ceremony_id
                && manifest_a.attempt_id == manifest_b.attempt_id
                && manifest_a.phase == manifest_b.phase
                && manifest_a.phase_root == manifest_b.phase_root
                && manifest_a != manifest_b
        }
        (
            transport::DkgPublicMessage::Chunk {
                ceremony_id: ceremony_a,
                attempt_id: attempt_a,
                phase: phase_a,
                phase_root: root_a,
                index: index_a,
                contributions: contributions_a,
                signed_at: _,
            },
            transport::DkgPublicMessage::Chunk {
                ceremony_id: ceremony_b,
                attempt_id: attempt_b,
                phase: phase_b,
                phase_root: root_b,
                index: index_b,
                contributions: contributions_b,
                signed_at: _,
            },
        ) => {
            ceremony_a == ceremony_b
                && attempt_a == attempt_b
                && phase_a == phase_b
                && root_a == root_b
                && index_a == index_b
                && contributions_a != contributions_b
        }
        _ => false,
    }
}

/// Every canonical `ParticipantRef` for a committee's node-key list, using
/// the same sort-then-assign scheme (`canonical_node_id_assignments_from_
/// node_keys`) real ceremony setup uses to build `PhaseManifest::
/// contribution_ids` keys — so this reproduces the exact set a real manifest
/// would name, not just "the right people" in some other numbering.
pub(crate) fn committee_participant_refs(
    peer_node_keys: &[String],
    scope: transport::CommitteeScope,
) -> Result<BTreeSet<ParticipantRef>> {
    let assignments = canonical_node_id_assignments_from_node_keys(peer_node_keys)
        .map_err(ReportingError::InvalidReport)?;
    Ok(assignments
        .into_values()
        .map(|node_id| ParticipantRef { scope, node_id })
        .collect())
}

/// The manifest shape (expected contributing origins, and whether it should
/// be a `complete` publication) a `dkg_leader_public_fault`/
/// `InvalidManifest` report must be checked against — independently
/// re-derived from chain-visible committee membership, never from the
/// reporter's own claim. Mirrors `expected_public_origins`/`public_batch_
/// mode` (`dkg/v0/network.rs`), restricted to the phases/origin_protocols
/// this evidence kind supports.
///
/// Deliberately unsupported: the Reshare `Commitments` phase. Its real
/// expected-origins set is the ceremony's *active dealers*, a live,
/// leader-determined value cryptographically committed to only via the
/// leader's signed `activation_digest` (`ControlSignature`) — not
/// derivable from `ring.peer_node_keys`/`new_peer_node_keys` alone. A
/// report naming this phase is rejected outright rather than validated
/// against a wrong/looser membership set.
#[derive(Debug)]
pub(crate) struct ExpectedLeaderManifestShape {
    pub(crate) origins: BTreeSet<ParticipantRef>,
    pub(crate) complete: bool,
}

pub(crate) fn expected_leader_manifest_shape(
    ring: &RingPayload,
    origin_protocol: &str,
    phase: DkgPublicPhase,
) -> Result<ExpectedLeaderManifestShape> {
    match (origin_protocol, phase) {
        ("pss_refresh", DkgPublicPhase::RefreshHealthCheck) => Ok(ExpectedLeaderManifestShape {
            origins: BTreeSet::from([ParticipantRef::current(1)]),
            complete: true,
        }),
        ("pss_refresh", DkgPublicPhase::Commitments) => Ok(ExpectedLeaderManifestShape {
            origins: committee_participant_refs(
                &ring.peer_node_keys,
                transport::CommitteeScope::Current,
            )?,
            complete: true,
        }),
        ("pss_refresh", DkgPublicPhase::CommitmentAudit) => Ok(ExpectedLeaderManifestShape {
            origins: committee_participant_refs(
                &ring.peer_node_keys,
                transport::CommitteeScope::Current,
            )?,
            complete: false,
        }),
        ("pss_reshare", DkgPublicPhase::ReshareParticipantSet) => Ok(ExpectedLeaderManifestShape {
            origins: BTreeSet::from([ParticipantRef::next(1)]),
            complete: true,
        }),
        ("pss_reshare", DkgPublicPhase::CommitmentAudit) => {
            let next_keys = ring.new_peer_node_keys.as_deref().ok_or_else(|| {
                ReportingError::Unauthorized(
                    "DKG leader public-fault reshare evidence requires a pending reshare"
                        .to_string(),
                )
            })?;
            Ok(ExpectedLeaderManifestShape {
                origins: committee_participant_refs(next_keys, transport::CommitteeScope::Next)?,
                complete: false,
            })
        }
        ("pss_reshare", DkgPublicPhase::Commitments) => Err(ReportingError::Unauthorized(
            "DKG leader public-fault reporting is not supported for the Reshare Commitments \
             phase: the expected origin set depends on live active-dealer selection, which is \
             not independently derivable from chain state"
                .to_string(),
        )),
        _ => Err(ReportingError::Unauthorized(format!(
            "DKG leader public-fault phase {phase:?} is not valid for origin protocol {origin_protocol}"
        ))),
    }
}
