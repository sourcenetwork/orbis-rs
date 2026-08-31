use super::*;

pub(super) struct NodeOfflineHandler;

#[async_trait]
impl ReportHandler for NodeOfflineHandler {
    fn report_type(&self) -> &'static str {
        NODE_OFFLINE_REPORT_TYPE
    }

    fn in_flight_key(&self, observation: &ReportObservation) -> Result<InFlightReportKey> {
        let observation = Self::node_offline_observation(observation)?;
        Ok(InFlightReportKey {
            report_type: self.report_type(),
            ring_id: observation.ring_id.clone(),
            subject_key: observation.accused_node_key.clone(),
        })
    }

    async fn prepare(
        &self,
        observation: ReportObservation,
        context: &ReportPreparationContext,
    ) -> Result<PreparedReport> {
        let ReportObservation::NodeOffline(observation) = observation else {
            return Err(ReportingError::InvalidReport(
                "node_offline handler received the wrong observation type".to_string(),
            ));
        };

        let (ring, ring_config) = build_signing_ring_config(
            &observation.ring_id,
            observation.signing_committee_scope,
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
            inline_document: None,
        })
    }

    async fn validate(
        &self,
        envelope: &ReportEnvelope,
        context: &ReportValidationContext,
    ) -> Result<()> {
        let payload = NodeOffline::from_canonical_bytes(&envelope.payload)?;
        if payload.origin_protocol.trim().is_empty() {
            return Err(ReportingError::InvalidReport(
                "offline report origin protocol cannot be empty".to_string(),
            ));
        }

        let ring_post = context
            .bulletin
            .read(envelope.ring_id.clone(), BulletinKind::Ring)
            .await
            .map_err(|error| ReportingError::Bulletin(error.to_string()))?;
        let ring = RingPayload::try_from(ring_post)
            .map_err(|error| ReportingError::InvalidReport(error.to_string()))?;

        if envelope.chain_id != context.bulletin.chain_id() {
            return Err(ReportingError::Unauthorized(
                "report chain ID does not match the configured bulletin".to_string(),
            ));
        }
        let effective_version =
            validate_report_route_version_at_observed_at(envelope, &ring, context.routes.version)?;
        if payload.origin_protocol_version != effective_version {
            return Err(ReportingError::Unauthorized(format!(
                "report origin protocol version {} does not match effective ring version {}",
                payload.origin_protocol_version, effective_version
            )));
        }

        let signing_committee = validate_ring_and_membership(envelope, &payload, &ring)?;
        validate_node_routes(envelope, context, &ring).await?;
        validate_local_signer(envelope, context, &signing_committee, "offline")?;

        if let ReportValidationMode::IndependentSigner {
            perform_health_probe: true,
        } = context.mode
        {
            require_peer_offline(
                &context.network,
                &context.peer_connection_pool,
                &envelope.accused_peer_id,
                context.routes,
            )
            .await?;
        }

        Ok(())
    }
}

impl NodeOfflineHandler {
    pub(super) fn node_offline_observation(
        observation: &ReportObservation,
    ) -> Result<&OfflineObservation> {
        match observation {
            ReportObservation::NodeOffline(observation) => Ok(observation),
            _ => Err(ReportingError::InvalidReport(
                "node_offline handler received the wrong observation type".to_string(),
            )),
        }
    }

    pub(super) fn build_envelope(
        &self,
        observation: &OfflineObservation,
        ring: &RingPayload,
        reporter_node_key: &str,
        chain_id: String,
    ) -> ReportEnvelope {
        let payload = NodeOffline {
            origin_protocol: observation.origin_protocol.clone(),
            origin_protocol_version: observation.origin_protocol_version,
            accused_committee_scope: observation.accused_committee_scope,
            signing_committee_scope: observation.signing_committee_scope,
        };
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
            payload: payload.canonical_bytes(),
            session_id: observation.session_id.clone(),
        }
    }

    pub(super) fn signing_options(&self, envelope: &ReportEnvelope) -> SigningOptions {
        let mut excluded_node_keys = HashSet::new();
        excluded_node_keys.insert(envelope.accused_node_key.clone());
        SigningOptions { excluded_node_keys }
    }
}
