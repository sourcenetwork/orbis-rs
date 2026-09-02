use super::*;

pub(super) struct InvalidCryptoResponseHandler;

#[async_trait]
impl ReportHandler for InvalidCryptoResponseHandler {
    fn report_type(&self) -> &'static str {
        INVALID_CRYPTO_RESPONSE_REPORT_TYPE
    }

    fn in_flight_key(&self, observation: &ReportObservation) -> Result<InFlightReportKey> {
        let observation = Self::observation(observation)?;
        // For DKG evidence kinds, fold in `attempt_id` too — `request_id`
        // (the ceremony ID) is deliberately reused across an attempt's
        // retries, so without this, a second attempt's genuinely
        // independent fault against the same accused would collide with
        // the first attempt's still-in-flight report and get silently
        // dropped as a "duplicate" before it ever reaches the chain, even
        // though the chain-side dedupe key (RPT-16) would have accepted it
        // as a distinct report. PRE/Sign have no `attempt_id` at all
        // (`InvalidCryptoResponse::attempt_id`'s own doc comment) and keep
        // the original two-part key unchanged.
        let subject_key = match observation.evidence.attempt_id() {
            Some(attempt_id) => format!(
                "{}:{}:{}",
                observation.accused_node_key,
                observation.evidence.request_id(),
                hex::encode(attempt_id)
            ),
            None => format!(
                "{}:{}",
                observation.accused_node_key,
                observation.evidence.request_id()
            ),
        };
        Ok(InFlightReportKey {
            report_type: self.report_type(),
            ring_id: observation.ring_id.clone(),
            subject_key,
        })
    }

    async fn prepare(
        &self,
        observation: ReportObservation,
        context: &ReportPreparationContext,
    ) -> Result<PreparedReport> {
        let ReportObservation::InvalidCryptoResponse(observation) = observation else {
            return Err(ReportingError::InvalidReport(
                "invalid_crypto_response handler received the wrong observation type".to_string(),
            ));
        };

        let (ring, ring_config) = build_signing_ring_config(
            &observation.ring_id,
            observation.evidence.signing_committee_scope(),
            context,
        )
        .await?;

        let envelope = self.build_envelope(
            &observation,
            &ring,
            &context.reporter_node_key,
            context.bulletin.chain_id(),
        );

        Ok(PreparedReport {
            signing_options: self.signing_options(&envelope),
            envelope,
            ring_config,
            inline_document: observation.inline_document,
        })
    }

    async fn validate(
        &self,
        envelope: &ReportEnvelope,
        context: &ReportValidationContext,
    ) -> Result<()> {
        let evidence = InvalidCryptoResponse::from_canonical_bytes(&envelope.payload)?;

        let ring_post = context
            .bulletin
            .read(envelope.ring_id.clone(), BulletinKind::Ring)
            .await
            .map_err(|error| ReportingError::Bulletin(error.to_string()))?;
        let ring = RingPayload::try_from(ring_post)
            .map_err(|error| ReportingError::InvalidReport(error.to_string()))?;

        match &evidence {
            InvalidCryptoResponse::Pre {
                statement,
                response_signature,
            } => {
                self.validate_pre_evidence(envelope, context, &ring, statement, response_signature)
                    .await
            }
            InvalidCryptoResponse::Sign {
                statement,
                response_signature,
            } => {
                self.validate_sign_evidence(envelope, context, &ring, statement, response_signature)
                    .await
            }
            InvalidCryptoResponse::DkgShare {
                statement,
                response_signature,
            } => {
                self.validate_dkg_share_evidence(
                    envelope,
                    context,
                    &ring,
                    statement,
                    response_signature,
                )
                .await
            }
            InvalidCryptoResponse::DkgInvalidRefreshCommitment {
                statement,
                response_signature,
            } => {
                self.validate_dkg_invalid_refresh_commitment_evidence(
                    envelope,
                    context,
                    &ring,
                    statement,
                    response_signature,
                )
                .await
            }
            InvalidCryptoResponse::DkgEquivocation {
                commitment_a,
                commitment_b,
            } => {
                self.validate_dkg_equivocation_evidence(
                    envelope,
                    context,
                    &ring,
                    commitment_a,
                    commitment_b,
                )
                .await
            }
            InvalidCryptoResponse::DkgPublicOriginFault { statement } => {
                self.validate_dkg_public_origin_fault(envelope, context, &ring, statement)
                    .await
            }
            InvalidCryptoResponse::DkgLeaderEquivocation { statement } => {
                self.validate_dkg_leader_equivocation_evidence(envelope, context, &ring, statement)
                    .await
            }
            InvalidCryptoResponse::DkgLeaderPublicFault { statement } => {
                self.validate_dkg_leader_public_fault_evidence(envelope, context, &ring, statement)
                    .await
            }
            InvalidCryptoResponse::DkgLeaderBatchMismatch { statement } => {
                self.validate_dkg_leader_batch_mismatch_evidence(
                    envelope, context, &ring, statement,
                )
                .await
            }
            InvalidCryptoResponse::DkgControlMessageFault { statement } => {
                self.validate_dkg_control_message_fault_evidence(
                    envelope, context, &ring, statement,
                )
                .await
            }
        }
    }
}

impl InvalidCryptoResponseHandler {
    pub(super) fn observation(
        observation: &ReportObservation,
    ) -> Result<&InvalidCryptoResponseObservation> {
        match observation {
            ReportObservation::InvalidCryptoResponse(observation) => Ok(observation.as_ref()),
            _ => Err(ReportingError::InvalidReport(
                "invalid_crypto_response handler received the wrong observation type".to_string(),
            )),
        }
    }

    pub(super) fn build_envelope(
        &self,
        observation: &InvalidCryptoResponseObservation,
        ring: &RingPayload,
        reporter_node_key: &str,
        chain_id: String,
    ) -> ReportEnvelope {
        ReportEnvelope {
            domain: REPORT_DOMAIN.to_string(),
            report_type: self.report_type().to_string(),
            chain_id,
            ring_id: observation.ring_id.clone(),
            ring_pk: ring.ring_pk.clone(),
            ring_state_sha256: ring_state_sha256(ring),
            reporter_node_key: reporter_node_key.to_string(),
            accused_node_key: observation.accused_node_key.clone(),
            accused_peer_id: observation.accused_peer_id.clone(),
            observed_at: observation.observed_at,
            expires_at: observation.observed_at.saturating_add(REPORT_TTL_SECS),
            payload: observation.evidence.canonical_bytes(),
            session_id: observation.evidence.request_id().to_string(),
        }
    }

    pub(super) fn signing_options(&self, envelope: &ReportEnvelope) -> SigningOptions {
        let mut excluded_node_keys = HashSet::new();
        excluded_node_keys.insert(envelope.accused_node_key.clone());
        SigningOptions { excluded_node_keys }
    }
}

pub(super) fn public_origin_protocol_allows_phase(
    origin_protocol: &str,
    phase: DkgPublicPhase,
) -> bool {
    matches!(
        (origin_protocol, phase),
        (
            "pss_refresh",
            DkgPublicPhase::Commitments
                | DkgPublicPhase::CommitmentAudit
                | DkgPublicPhase::RefreshHealthCheck
        ) | (
            "pss_reshare",
            DkgPublicPhase::Commitments
                | DkgPublicPhase::CommitmentAudit
                | DkgPublicPhase::ReshareParticipantSet
        )
    )
}

pub(super) fn validate_equivocation_commitment_shape(
    envelope: &ReportEnvelope,
    context: &ReportValidationContext,
    commitment: &DkgCommitmentStatement,
    signature: &[u8],
    check_anchor: bool,
) -> Result<()> {
    validate_invalid_crypto_statement_prologue(
        envelope,
        context,
        InvalidCryptoStatementPrologue {
            label: "DKG equivocation commitment".to_string(),
            domain: commitment.domain.clone(),
            expected_domain: DKG_COMMITMENT_DOMAIN.to_string(),
            chain_id: commitment.chain_id.clone(),
            ring_id: commitment.ring_id.clone(),
            ring_pk: commitment.ring_pk.clone(),
            ring_state_sha256: commitment.ring_state_sha256.clone(),
            request_id: commitment.request_id.clone(),
            signed_at: commitment.signed_at,
            responder_node_key: commitment.responder_node_key.clone(),
            check_anchor,
        },
    )?;
    if !is_valid_invalid_crypto_dkg_origin(&commitment.origin_protocol) {
        return Err(ReportingError::InvalidReport(format!(
            "unsupported DKG equivocation origin protocol {}",
            commitment.origin_protocol
        )));
    }
    if commitment.accused_committee_scope != CommitteeScope::Current
        || commitment.signing_committee_scope != CommitteeScope::Current
    {
        return Err(ReportingError::Unauthorized(
            "DKG equivocation reports must use current accused and signing scopes".to_string(),
        ));
    }
    if commitment.from_node_id == 0 {
        return Err(ReportingError::InvalidReport(
            "DKG equivocation from_node_id must be non-zero".to_string(),
        ));
    }
    if commitment.crypto_backend != DkgImpl::name() {
        return Err(ReportingError::Unauthorized(format!(
            "DKG equivocation crypto backend {} does not match local backend {}",
            commitment.crypto_backend,
            DkgImpl::name()
        )));
    }
    if commitment.commitment.is_empty() {
        return Err(ReportingError::InvalidReport(
            "DKG equivocation commitment cannot be empty".to_string(),
        ));
    }
    if !commitment.commitment.len().is_multiple_of(GROUP_POINT_SIZE) {
        return Err(ReportingError::InvalidReport(format!(
            "DKG equivocation commitment length {} is not a multiple of {}",
            commitment.commitment.len(),
            GROUP_POINT_SIZE
        )));
    }
    if signature.is_empty() {
        return Err(ReportingError::InvalidReport(
            "DKG equivocation commitment signature cannot be empty".to_string(),
        ));
    }
    Ok(())
}

pub(super) fn is_valid_invalid_crypto_pre_origin(origin_protocol: &str) -> bool {
    origin_protocol == "pre"
}

pub(super) fn is_valid_invalid_crypto_sign_origin(origin_protocol: &str) -> bool {
    matches!(
        origin_protocol,
        "sign" | "pss_refresh" | "pss_reshare" | "report"
    )
}

pub(super) fn is_valid_invalid_crypto_dkg_origin(origin_protocol: &str) -> bool {
    matches!(origin_protocol, "pss_refresh" | "pss_reshare")
}

mod control_message;
mod dkg_share;
mod leader_delivery;
mod pre_sign;
mod public_origin;

// Re-export the sub-submodule helpers (each `pub(crate)`) so the registry
// test module reaches them through mod.rs's flatten glob.
#[allow(unused_imports)]
pub(crate) use self::{
    control_message::*, dkg_share::*, leader_delivery::*, pre_sign::*, public_origin::*,
};
