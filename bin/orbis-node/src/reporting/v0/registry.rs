use crate::app_state::PeerConnectionPool;
use crate::dkg::v0::helpers::deserialize_wire_commitment;
use crate::dkg::v0::messages::SignedDkgCommitment;
use crate::helpers::identity::{determine_session_node_id, extract_node_part};
use crate::helpers::node_routes::{peer_ids_from_routes, resolve_node_routes};
use crate::helpers::ring::RingConfig;
use crate::pre::v0::helpers::deserialize_secret;
use crate::reporting::v0::error::{ReportingError, Result};
use crate::reporting::v0::health::require_peer_offline;
use crate::reporting::v0::observation::{
    InvalidCryptoResponseObservation, OfflineObservation, ReportObservation,
};
use crate::reporting::v0::state::InFlightReportKey;
use crate::reporting::v0::types::{
    ring_state_sha256, CommitteeScope, DkgCommitmentStatement, DkgShareStatement,
    InvalidCryptoResponse, NodeOffline, PreReencryptResponseStatement, ReportEnvelope,
    SignResponseStatement, CHAIN_BLOCK_GRACE_SECS, DKG_COMMITMENT_DOMAIN, DKG_SHARE_DOMAIN,
    INVALID_CRYPTO_RESPONSE_REPORT_TYPE, NODE_OFFLINE_REPORT_TYPE, PRE_REENCRYPT_RESPONSE_DOMAIN,
    REPORT_DOMAIN, REPORT_TTL_SECS, SIGN_RESPONSE_DOMAIN,
};
use crate::ring_state::RingPolyState;
use crate::sign::v0::coordinator::SigningOptions;
use crate::sign::v0::helpers::deserialize_commitments;
use async_trait::async_trait;
use bulletin::r#trait::{Bulletin, BulletinKind, DocumentPayload, NodeInfo, RingPayload};
use common::blockchain::verify_node_message;
use crypto::r#trait::{
    CryptoDeserialize, Dkg, PolynomialCommitment as PolynomialCommitmentTrait, PubShare,
    ReencryptReply, ThresholdDealer, ThresholdSigner,
};
use crypto::{
    DkgImpl, GroupAffine, PreImpl, PubPolyImpl, ScalarField, SigShareInner, SignImpl,
    GROUP_POINT_SIZE,
};
use local_storage::LocalStorageImpl;
use network::{Network, PeerId};
use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportValidationMode {
    ReporterObservation,
    IndependentSigner { perform_health_probe: bool },
}

pub struct ReportValidationContext {
    pub local_node_key: String,
    pub requester_peer_id: Option<PeerId>,
    pub network: Arc<dyn Network>,
    pub peer_connection_pool: Arc<PeerConnectionPool>,
    pub bulletin: Arc<dyn Bulletin + Send + Sync>,
    pub local_storage: LocalStorageImpl,
    pub routes: &'static network::ProtocolRoutes,
    pub now: u64,
    pub mode: ReportValidationMode,
}

pub struct ReportPreparationContext {
    pub reporter_node_key: String,
    pub bulletin: Arc<dyn Bulletin + Send + Sync>,
    pub local_storage: LocalStorageImpl,
}

pub struct PreparedReport {
    pub envelope: ReportEnvelope,
    pub ring_config: RingConfig,
    pub signing_options: SigningOptions,
}

#[async_trait]
pub trait ReportHandler: Send + Sync {
    fn report_type(&self) -> &'static str;
    fn in_flight_key(&self, observation: &ReportObservation) -> Result<InFlightReportKey>;
    async fn prepare(
        &self,
        observation: ReportObservation,
        context: &ReportPreparationContext,
    ) -> Result<PreparedReport>;
    async fn validate(
        &self,
        envelope: &ReportEnvelope,
        context: &ReportValidationContext,
    ) -> Result<()>;
}

pub struct ReportRegistry {
    handlers: HashMap<String, Arc<dyn ReportHandler>>,
}

impl ReportRegistry {
    pub fn with_defaults() -> Self {
        let mut registry = Self {
            handlers: HashMap::new(),
        };
        registry.register(Arc::new(NodeOfflineHandler));
        registry.register(Arc::new(InvalidCryptoResponseHandler));
        registry
    }

    pub fn register(&mut self, handler: Arc<dyn ReportHandler>) {
        self.handlers
            .insert(handler.report_type().to_string(), handler);
    }

    pub async fn validate(
        &self,
        envelope: &ReportEnvelope,
        context: &ReportValidationContext,
    ) -> Result<()> {
        envelope.validate_shape(context.now)?;
        let handler = self.handler_for(&envelope.report_type)?;
        handler.validate(envelope, context).await
    }

    pub fn handler_for_observation(
        &self,
        observation: &ReportObservation,
    ) -> Result<Arc<dyn ReportHandler>> {
        self.handlers
            .get(observation.report_type())
            .cloned()
            .ok_or_else(|| ReportingError::UnsupportedReportType {
                name: observation.report_type().to_string(),
            })
    }

    fn handler_for(&self, report_type: &str) -> Result<&dyn ReportHandler> {
        self.handlers
            .get(report_type)
            .map(Arc::as_ref)
            .ok_or_else(|| ReportingError::UnsupportedReportType {
                name: report_type.to_string(),
            })
    }
}

impl Default for ReportRegistry {
    fn default() -> Self {
        Self::with_defaults()
    }
}

struct NodeOfflineHandler;

#[derive(Debug, Clone)]
struct CommitteeView {
    peer_node_keys: Vec<String>,
    threshold: u32,
}

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
    fn node_offline_observation(observation: &ReportObservation) -> Result<&OfflineObservation> {
        match observation {
            ReportObservation::NodeOffline(observation) => Ok(observation),
            _ => Err(ReportingError::InvalidReport(
                "node_offline handler received the wrong observation type".to_string(),
            )),
        }
    }

    fn build_envelope(
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

    fn signing_options(&self, envelope: &ReportEnvelope) -> SigningOptions {
        let mut excluded_node_keys = HashSet::new();
        excluded_node_keys.insert(envelope.accused_node_key.clone());
        SigningOptions { excluded_node_keys }
    }
}

struct InvalidCryptoResponseHandler;

#[async_trait]
impl ReportHandler for InvalidCryptoResponseHandler {
    fn report_type(&self) -> &'static str {
        INVALID_CRYPTO_RESPONSE_REPORT_TYPE
    }

    fn in_flight_key(&self, observation: &ReportObservation) -> Result<InFlightReportKey> {
        let observation = Self::observation(observation)?;
        Ok(InFlightReportKey {
            report_type: self.report_type(),
            ring_id: observation.ring_id.clone(),
            subject_key: format!(
                "{}:{}",
                observation.accused_node_key,
                observation.evidence.request_id()
            ),
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
        }
    }
}

impl InvalidCryptoResponseHandler {
    async fn validate_pre_evidence(
        &self,
        envelope: &ReportEnvelope,
        context: &ReportValidationContext,
        ring: &RingPayload,
        statement: &crate::reporting::v0::types::PreReencryptResponseStatement,
        response_signature: &[u8],
    ) -> Result<()> {
        validate_pre_reencrypt_response_statement_shape(
            envelope,
            statement,
            response_signature,
            context,
        )?;
        let effective_version =
            validate_report_route_version_at_observed_at(envelope, ring, context.routes.version)?;
        if statement.protocol_version != effective_version {
            return Err(ReportingError::Unauthorized(format!(
                "PRE response protocol version {} does not match effective ring version {}",
                statement.protocol_version, effective_version
            )));
        }

        let signing_committee = validate_ring_and_membership_for_scopes(
            envelope,
            ring,
            CommitteeScope::Current,
            CommitteeScope::Current,
            "PRE invalid-proof",
        )?;
        validate_node_routes(envelope, context, ring).await?;
        validate_local_signer(envelope, context, &signing_committee, "PRE invalid-proof")?;

        let expected_node_id =
            determine_session_node_id(&envelope.accused_node_key, &ring.peer_node_keys)
                .ok_or_else(|| {
                    ReportingError::Unauthorized(
                        "accused node is not in the current ring node-id map".to_string(),
                    )
                })?;
        if statement.from_node_id != expected_node_id {
            return Err(ReportingError::Unauthorized(format!(
                "PRE response from_node_id {} does not match accused node_id {}",
                statement.from_node_id, expected_node_id
            )));
        }

        verify_node_message(
            &envelope.accused_node_key,
            &statement.canonical_bytes(),
            response_signature,
        )
        .map_err(|error| {
            ReportingError::Unauthorized(format!("invalid PRE response signature: {}", error))
        })?;

        require_pre_proof_verification_failure(statement, context).await
    }

    async fn validate_sign_evidence(
        &self,
        envelope: &ReportEnvelope,
        context: &ReportValidationContext,
        ring: &RingPayload,
        statement: &SignResponseStatement,
        response_signature: &[u8],
    ) -> Result<()> {
        validate_sign_response_statement_shape(envelope, statement, response_signature, context)?;

        let effective_version =
            validate_report_route_version_at_observed_at(envelope, ring, context.routes.version)?;
        if statement.protocol_version != effective_version {
            return Err(ReportingError::Unauthorized(format!(
                "Sign response protocol version {} does not match effective ring version {}",
                statement.protocol_version, effective_version
            )));
        }

        let signing_committee = validate_ring_and_membership_for_scopes(
            envelope,
            ring,
            statement.accused_committee_scope,
            statement.signing_committee_scope,
            "Sign invalid-response",
        )?;
        validate_node_routes(envelope, context, ring).await?;
        validate_local_signer(
            envelope,
            context,
            &signing_committee,
            "Sign invalid-response",
        )?;

        let accused_committee = committee_for_scope(ring, statement.accused_committee_scope)?;
        let expected_node_id = determine_session_node_id(
            &envelope.accused_node_key,
            &accused_committee.peer_node_keys,
        )
        .ok_or_else(|| {
            ReportingError::Unauthorized(
                "accused node is not in the Sign response node-id map".to_string(),
            )
        })?;
        if statement.from_node_id != expected_node_id {
            return Err(ReportingError::Unauthorized(format!(
                "Sign response from_node_id {} does not match accused node_id {}",
                statement.from_node_id, expected_node_id
            )));
        }

        verify_node_message(
            &envelope.accused_node_key,
            &statement.canonical_bytes(),
            response_signature,
        )
        .map_err(|error| {
            ReportingError::Unauthorized(format!("invalid Sign response signature: {}", error))
        })?;

        require_sign_share_verification_failure(statement, context)
    }

    async fn validate_dkg_share_evidence(
        &self,
        envelope: &ReportEnvelope,
        context: &ReportValidationContext,
        ring: &RingPayload,
        statement: &DkgShareStatement,
        response_signature: &[u8],
    ) -> Result<()> {
        validate_dkg_share_statement_shape(envelope, statement, response_signature, context)?;

        let effective_version =
            validate_report_route_version_at_observed_at(envelope, ring, context.routes.version)?;
        if statement.protocol_version != effective_version {
            return Err(ReportingError::Unauthorized(format!(
                "DKG share protocol version {} does not match effective ring version {}",
                statement.protocol_version, effective_version
            )));
        }

        let signing_committee = validate_ring_and_membership_for_scopes(
            envelope,
            ring,
            statement.accused_committee_scope,
            statement.signing_committee_scope,
            "DKG invalid-share",
        )?;
        validate_node_routes(envelope, context, ring).await?;
        validate_local_signer(envelope, context, &signing_committee, "DKG invalid-share")?;

        let accused_committee = committee_for_scope(ring, statement.accused_committee_scope)?;
        let expected_from_node_id = determine_session_node_id(
            &envelope.accused_node_key,
            &accused_committee.peer_node_keys,
        )
        .ok_or_else(|| {
            ReportingError::Unauthorized(
                "accused node is not in the DKG share node-id map".to_string(),
            )
        })?;
        if statement.from_node_id != expected_from_node_id {
            return Err(ReportingError::Unauthorized(format!(
                "DKG share from_node_id {} does not match accused node_id {}",
                statement.from_node_id, expected_from_node_id
            )));
        }

        let receiver_committee = if statement.origin_protocol == "pss_reshare" {
            committee_for_scope(ring, CommitteeScope::PendingNew)?
        } else {
            committee_for_scope(ring, CommitteeScope::Current)?
        };
        let expected_receiver_node_key = receiver_committee
            .peer_node_keys
            .get(statement.to_node_id.saturating_sub(1) as usize)
            .ok_or_else(|| {
                ReportingError::Unauthorized(format!(
                    "DKG share to_node_id {} is outside the receiver committee",
                    statement.to_node_id
                ))
            })?;
        if &statement.receiver_node_key != expected_receiver_node_key {
            return Err(ReportingError::Unauthorized(
                "DKG share receiver node key does not match to_node_id".to_string(),
            ));
        }

        verify_node_message(
            &envelope.accused_node_key,
            &statement.commitment_statement.canonical_bytes(),
            &statement.commitment_signature,
        )
        .map_err(|error| {
            ReportingError::Unauthorized(format!("invalid DKG commitment signature: {}", error))
        })?;

        verify_node_message(
            &envelope.accused_node_key,
            &statement.canonical_bytes(),
            response_signature,
        )
        .map_err(|error| {
            ReportingError::Unauthorized(format!("invalid DKG share signature: {}", error))
        })?;

        require_dkg_share_verification_failure(statement)
    }

    async fn validate_dkg_equivocation_evidence(
        &self,
        envelope: &ReportEnvelope,
        context: &ReportValidationContext,
        ring: &RingPayload,
        commitment_a: &SignedDkgCommitment,
        commitment_b: &SignedDkgCommitment,
    ) -> Result<()> {
        // commitment_a anchors the envelope's observed_at; commitment_b only needs
        // ring/session binding (its signed_at may differ within the attempt).
        validate_equivocation_commitment_shape(
            envelope,
            context,
            &commitment_a.statement,
            &commitment_a.signature,
            true,
        )?;
        validate_equivocation_commitment_shape(
            envelope,
            context,
            &commitment_b.statement,
            &commitment_b.signature,
            false,
        )?;

        let effective_version =
            validate_report_route_version_at_observed_at(envelope, ring, context.routes.version)?;
        if commitment_a.statement.protocol_version != effective_version
            || commitment_b.statement.protocol_version != effective_version
        {
            return Err(ReportingError::Unauthorized(format!(
                "DKG equivocation protocol version does not match effective ring version {}",
                effective_version
            )));
        }

        let signing_committee = validate_ring_and_membership_for_scopes(
            envelope,
            ring,
            CommitteeScope::Current,
            CommitteeScope::Current,
            "DKG equivocation",
        )?;
        validate_node_routes(envelope, context, ring).await?;
        validate_local_signer(envelope, context, &signing_committee, "DKG equivocation")?;

        let accused_committee = committee_for_scope(ring, CommitteeScope::Current)?;
        let expected_from_node_id = determine_session_node_id(
            &envelope.accused_node_key,
            &accused_committee.peer_node_keys,
        )
        .ok_or_else(|| {
            ReportingError::Unauthorized(
                "accused node is not in the DKG equivocation node-id map".to_string(),
            )
        })?;
        if commitment_a.statement.from_node_id != expected_from_node_id
            || commitment_b.statement.from_node_id != expected_from_node_id
        {
            return Err(ReportingError::Unauthorized(format!(
                "DKG equivocation from_node_id does not match accused node_id {}",
                expected_from_node_id
            )));
        }

        verify_node_message(
            &envelope.accused_node_key,
            &commitment_a.statement.canonical_bytes(),
            &commitment_a.signature,
        )
        .map_err(|error| {
            ReportingError::Unauthorized(format!(
                "invalid DKG equivocation commitment_a signature: {}",
                error
            ))
        })?;
        verify_node_message(
            &envelope.accused_node_key,
            &commitment_b.statement.canonical_bytes(),
            &commitment_b.signature,
        )
        .map_err(|error| {
            ReportingError::Unauthorized(format!(
                "invalid DKG equivocation commitment_b signature: {}",
                error
            ))
        })?;

        // The refutation: equivocation requires the SAME per-attempt nonce with different
        // bytes. Identical bytes, or a different nonce (honest retry), is not equivocation.
        if commitment_a.statement.session_nonce != commitment_b.statement.session_nonce
            || commitment_a.statement.commitment == commitment_b.statement.commitment
        {
            return Err(ReportingError::Unauthorized(
                "reported commitments are not equivocation".to_string(),
            ));
        }

        Ok(())
    }

    fn observation(observation: &ReportObservation) -> Result<&InvalidCryptoResponseObservation> {
        match observation {
            ReportObservation::InvalidCryptoResponse(observation) => Ok(observation.as_ref()),
            _ => Err(ReportingError::InvalidReport(
                "invalid_crypto_response handler received the wrong observation type".to_string(),
            )),
        }
    }

    fn build_envelope(
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

    fn signing_options(&self, envelope: &ReportEnvelope) -> SigningOptions {
        let mut excluded_node_keys = HashSet::new();
        excluded_node_keys.insert(envelope.accused_node_key.clone());
        SigningOptions { excluded_node_keys }
    }
}

async fn build_signing_ring_config(
    ring_id: &str,
    signing_committee_scope: CommitteeScope,
    context: &ReportPreparationContext,
) -> Result<(RingPayload, RingConfig)> {
    let ring_post = context
        .bulletin
        .read(ring_id.to_string(), BulletinKind::Ring)
        .await
        .map_err(|error| ReportingError::Bulletin(error.to_string()))?;
    let ring = RingPayload::try_from(ring_post)
        .map_err(|error| ReportingError::InvalidReport(error.to_string()))?;

    let signing_committee = committee_for_scope(&ring, signing_committee_scope)?;
    let node_routes = resolve_node_routes(&context.bulletin, &signing_committee.peer_node_keys)
        .await
        .map_err(ReportingError::InvalidReport)?;
    let peer_ids = peer_ids_from_routes(&node_routes);
    let ring_pk_bytes = hex::decode(&ring.ring_pk)
        .map_err(|error| ReportingError::Serialization(error.to_string()))?;
    let poly_state = RingPolyState::load_from_ring_pk_hex(&context.local_storage, &ring.ring_pk)
        .map_err(ReportingError::InvalidReport)?;
    let ring_config = RingConfig {
        ring_id: ring_id.to_string(),
        ring_pk_bytes,
        peer_ids,
        peer_node_keys: signing_committee.peer_node_keys,
        threshold: signing_committee.threshold as usize,
        total_participants: node_routes.len(),
        public_polynomial_hex: poly_state.public_polynomial,
    };

    Ok((ring, ring_config))
}

fn validate_ring_and_membership(
    envelope: &ReportEnvelope,
    payload: &NodeOffline,
    ring: &RingPayload,
) -> Result<CommitteeView> {
    validate_ring_and_membership_for_scopes(
        envelope,
        ring,
        payload.accused_committee_scope,
        payload.signing_committee_scope,
        "offline",
    )
}

fn report_effective_version_at_observed_at(
    envelope: &ReportEnvelope,
    ring: &RingPayload,
) -> Result<u64> {
    ring.upgrade_info
        .effective_version(envelope.observed_at)
        .map_err(|error| ReportingError::InvalidReport(error.to_string()))
}

fn validate_report_route_version_at_observed_at(
    envelope: &ReportEnvelope,
    ring: &RingPayload,
    route_version: u64,
) -> Result<u64> {
    let effective_version = report_effective_version_at_observed_at(envelope, ring)?;
    if effective_version != route_version {
        return Err(ReportingError::Unauthorized(format!(
            "report protocol version {} is not effective for ring {}",
            route_version, envelope.ring_id
        )));
    }
    Ok(effective_version)
}

fn validate_ring_and_membership_for_scopes(
    envelope: &ReportEnvelope,
    ring: &RingPayload,
    accused_committee_scope: CommitteeScope,
    signing_committee_scope: CommitteeScope,
    report_label: &str,
) -> Result<CommitteeView> {
    if ring.ring_pk.is_empty() {
        return Err(ReportingError::Unauthorized(format!(
            "{report_label} reports require a finalized ring"
        )));
    }
    if ring.ring_pk != envelope.ring_pk {
        return Err(ReportingError::Unauthorized(
            "report ring public key is stale".to_string(),
        ));
    }
    if ring_state_sha256(ring) != envelope.ring_state_sha256 {
        return Err(ReportingError::Unauthorized(
            "report ring-state digest is stale".to_string(),
        ));
    }
    let accused_committee = committee_for_scope(ring, accused_committee_scope)?;
    let signing_committee = committee_for_scope(ring, signing_committee_scope)?;
    if signing_committee.threshold < 2 {
        return Err(ReportingError::Unauthorized(format!(
            "{report_label} reporting requires ring threshold >= 2"
        )));
    }
    if signing_committee.threshold as usize > signing_committee.peer_node_keys.len() {
        return Err(ReportingError::Unauthorized(format!(
            "{report_label} reporting threshold exceeds signing committee size"
        )));
    }
    if signing_committee
        .peer_node_keys
        .iter()
        .any(|member| member == &envelope.accused_node_key)
        && signing_committee.threshold as usize
            > signing_committee.peer_node_keys.len().saturating_sub(1)
    {
        return Err(ReportingError::Unauthorized(
            "ring threshold cannot be met while excluding the accused node".to_string(),
        ));
    }
    if !signing_committee
        .peer_node_keys
        .iter()
        .any(|member| member == &envelope.reporter_node_key)
    {
        return Err(ReportingError::Unauthorized(format!(
            "reporter node {} is not in the signing committee",
            envelope.reporter_node_key
        )));
    }
    if !accused_committee
        .peer_node_keys
        .iter()
        .any(|member| member == &envelope.accused_node_key)
    {
        return Err(ReportingError::Unauthorized(format!(
            "accused node {} is not in the accused committee",
            envelope.accused_node_key
        )));
    }
    Ok(signing_committee)
}

fn committee_for_scope(ring: &RingPayload, scope: CommitteeScope) -> Result<CommitteeView> {
    match scope {
        CommitteeScope::Current => Ok(CommitteeView {
            peer_node_keys: ring.peer_node_keys.clone(),
            threshold: ring.threshold,
        }),
        CommitteeScope::PendingNew => {
            if ring.new_peer_node_keys.is_none() && ring.new_threshold.is_none() {
                return Err(ReportingError::Unauthorized(
                    "pending-new committee scope requires a pending reshare".to_string(),
                ));
            }
            Ok(CommitteeView {
                peer_node_keys: ring
                    .new_peer_node_keys
                    .clone()
                    .unwrap_or_else(|| ring.peer_node_keys.clone()),
                threshold: ring.new_threshold.unwrap_or(ring.threshold),
            })
        }
    }
}

async fn validate_node_routes(
    envelope: &ReportEnvelope,
    context: &ReportValidationContext,
    _ring: &RingPayload,
) -> Result<()> {
    let accused_info = read_node_info(&context.bulletin, &envelope.accused_node_key).await?;
    if accused_info.peer_id != envelope.accused_peer_id {
        return Err(ReportingError::Unauthorized(
            "accused peer ID no longer matches NodeInfo".to_string(),
        ));
    }

    let reporter_info = read_node_info(&context.bulletin, &envelope.reporter_node_key).await?;
    let reporter_peer_hex = context
        .requester_peer_id
        .as_ref()
        .map(|requester| hex::encode(requester.as_bytes()))
        .unwrap_or_else(|| hex::encode(context.network.local_peer_id().as_bytes()));
    if extract_node_part(&reporter_info.peer_id) != reporter_peer_hex {
        return Err(ReportingError::Unauthorized(
            "report coordinator peer does not match reporter NodeInfo".to_string(),
        ));
    }
    Ok(())
}

fn validate_local_signer(
    envelope: &ReportEnvelope,
    context: &ReportValidationContext,
    signing_committee: &CommitteeView,
    report_label: &str,
) -> Result<()> {
    if context.local_node_key == envelope.accused_node_key {
        return Err(ReportingError::Unauthorized(format!(
            "the accused node cannot sign its own {report_label} report"
        )));
    }
    if !signing_committee
        .peer_node_keys
        .iter()
        .any(|node_key| node_key == &context.local_node_key)
    {
        return Err(ReportingError::Unauthorized(format!(
            "local signer is not in the {report_label} report ring"
        )));
    }
    Ok(())
}

struct InvalidCryptoStatementPrologue {
    label: String,
    domain: String,
    expected_domain: String,
    chain_id: String,
    ring_id: String,
    ring_pk: String,
    ring_state_sha256: String,
    request_id: String,
    signed_at: u64,
    responder_node_key: String,
    /// Whether `signed_at` must anchor the envelope's `observed_at`. True for the statement
    /// whose timestamp anchors the report; false for a second statement (e.g. the other
    /// commitment in an equivocation report) that only needs ring/session binding.
    check_anchor: bool,
}

fn validate_invalid_crypto_statement_prologue(
    envelope: &ReportEnvelope,
    context: &ReportValidationContext,
    statement: InvalidCryptoStatementPrologue,
) -> Result<()> {
    let label = statement.label.as_str();
    if statement.domain != statement.expected_domain {
        return Err(ReportingError::InvalidReport(format!(
            "unexpected {label} domain {}",
            statement.domain
        )));
    }
    if statement.chain_id != envelope.chain_id || envelope.chain_id != context.bulletin.chain_id() {
        return Err(ReportingError::Unauthorized(format!(
            "{label} chain ID does not match report chain ID"
        )));
    }
    if statement.ring_id != envelope.ring_id
        || statement.ring_pk != envelope.ring_pk
        || statement.ring_state_sha256 != envelope.ring_state_sha256
    {
        return Err(ReportingError::Unauthorized(format!(
            "{label} ring binding does not match report envelope"
        )));
    }
    if statement.request_id != envelope.session_id {
        return Err(ReportingError::Unauthorized(format!(
            "{label} request_id does not match report session_id"
        )));
    }
    if statement.check_anchor {
        validate_evidence_anchor(statement.signed_at, envelope.observed_at)?;
    }
    if statement.responder_node_key != envelope.accused_node_key {
        return Err(ReportingError::Unauthorized(format!(
            "{label} responder does not match accused node"
        )));
    }
    Ok(())
}

fn validate_pre_reencrypt_response_statement_shape(
    envelope: &ReportEnvelope,
    statement: &PreReencryptResponseStatement,
    response_signature: &[u8],
    context: &ReportValidationContext,
) -> Result<()> {
    validate_invalid_crypto_statement_prologue(
        envelope,
        context,
        InvalidCryptoStatementPrologue {
            label: "PRE response".to_string(),
            domain: statement.domain.clone(),
            expected_domain: PRE_REENCRYPT_RESPONSE_DOMAIN.to_string(),
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
    if !is_valid_invalid_crypto_pre_origin(&statement.origin_protocol) {
        return Err(ReportingError::InvalidReport(format!(
            "unsupported PRE response origin protocol {}",
            statement.origin_protocol
        )));
    }
    if statement.object_id.trim().is_empty() {
        return Err(ReportingError::InvalidReport(
            "PRE response object_id cannot be empty".to_string(),
        ));
    }
    if statement.crypto_backend != PreImpl::name() {
        return Err(ReportingError::Unauthorized(format!(
            "PRE response crypto backend {} does not match local backend {}",
            statement.crypto_backend,
            PreImpl::name()
        )));
    }
    if response_signature.is_empty() {
        return Err(ReportingError::InvalidReport(
            "PRE response signature cannot be empty".to_string(),
        ));
    }
    Ok(())
}

fn validate_sign_response_statement_shape(
    envelope: &ReportEnvelope,
    statement: &SignResponseStatement,
    response_signature: &[u8],
    context: &ReportValidationContext,
) -> Result<()> {
    validate_invalid_crypto_statement_prologue(
        envelope,
        context,
        InvalidCryptoStatementPrologue {
            label: "Sign response".to_string(),
            domain: statement.domain.clone(),
            expected_domain: SIGN_RESPONSE_DOMAIN.to_string(),
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
    if !is_valid_invalid_crypto_sign_origin(&statement.origin_protocol) {
        return Err(ReportingError::InvalidReport(format!(
            "unsupported Sign response origin protocol {}",
            statement.origin_protocol
        )));
    }
    if statement.crypto_backend != SignImpl::name() {
        return Err(ReportingError::Unauthorized(format!(
            "Sign response crypto backend {} does not match local backend {}",
            statement.crypto_backend,
            SignImpl::name()
        )));
    }
    if statement.message.is_empty() {
        return Err(ReportingError::InvalidReport(
            "Sign response message cannot be empty".to_string(),
        ));
    }
    if statement.sig_share.is_empty() {
        return Err(ReportingError::InvalidReport(
            "Sign response sig_share cannot be empty".to_string(),
        ));
    }
    if response_signature.is_empty() {
        return Err(ReportingError::InvalidReport(
            "Sign response signature cannot be empty".to_string(),
        ));
    }
    Ok(())
}

fn validate_dkg_share_statement_shape(
    envelope: &ReportEnvelope,
    statement: &DkgShareStatement,
    response_signature: &[u8],
    context: &ReportValidationContext,
) -> Result<()> {
    validate_invalid_crypto_statement_prologue(
        envelope,
        context,
        InvalidCryptoStatementPrologue {
            label: "DKG share".to_string(),
            domain: statement.domain.clone(),
            expected_domain: DKG_SHARE_DOMAIN.to_string(),
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
            "unsupported DKG share origin protocol {}",
            statement.origin_protocol
        )));
    }
    if statement.accused_committee_scope != CommitteeScope::Current
        || statement.signing_committee_scope != CommitteeScope::Current
    {
        return Err(ReportingError::Unauthorized(
            "DKG share reports must use current accused and signing scopes".to_string(),
        ));
    }
    if statement.from_node_id == 0 || statement.to_node_id == 0 {
        return Err(ReportingError::InvalidReport(
            "DKG share node IDs must be non-zero".to_string(),
        ));
    }
    if statement.receiver_node_key.trim().is_empty() {
        return Err(ReportingError::InvalidReport(
            "DKG share receiver_node_key cannot be empty".to_string(),
        ));
    }
    if statement.crypto_backend != DkgImpl::name() {
        return Err(ReportingError::Unauthorized(format!(
            "DKG share crypto backend {} does not match local backend {}",
            statement.crypto_backend,
            DkgImpl::name()
        )));
    }
    if statement.share_value.is_empty() {
        return Err(ReportingError::InvalidReport(
            "DKG share value cannot be empty".to_string(),
        ));
    }
    if statement.commitment_signature.is_empty() {
        return Err(ReportingError::InvalidReport(
            "DKG commitment signature cannot be empty".to_string(),
        ));
    }
    if response_signature.is_empty() {
        return Err(ReportingError::InvalidReport(
            "DKG share signature cannot be empty".to_string(),
        ));
    }
    validate_dkg_commitment_statement_shape(statement)
}

fn validate_dkg_commitment_statement_shape(statement: &DkgShareStatement) -> Result<()> {
    let commitment = &statement.commitment_statement;
    if commitment.domain != DKG_COMMITMENT_DOMAIN {
        return Err(ReportingError::InvalidReport(format!(
            "unexpected DKG commitment domain {}",
            commitment.domain
        )));
    }
    if commitment.chain_id != statement.chain_id
        || commitment.ring_id != statement.ring_id
        || commitment.ring_pk != statement.ring_pk
        || commitment.ring_state_sha256 != statement.ring_state_sha256
        || commitment.protocol_version != statement.protocol_version
        || commitment.request_id != statement.request_id
        || commitment.responder_node_key != statement.responder_node_key
        || commitment.origin_protocol != statement.origin_protocol
        || commitment.accused_committee_scope != statement.accused_committee_scope
        || commitment.signing_committee_scope != statement.signing_committee_scope
        || commitment.from_node_id != statement.from_node_id
        || commitment.crypto_backend != statement.crypto_backend
    {
        return Err(ReportingError::Unauthorized(
            "DKG commitment binding does not match DKG share statement".to_string(),
        ));
    }
    if commitment.signed_at > statement.signed_at {
        return Err(ReportingError::Unauthorized(
            "DKG commitment was signed after the DKG share".to_string(),
        ));
    }
    if commitment.commitment.is_empty() {
        return Err(ReportingError::InvalidReport(
            "DKG commitment cannot be empty".to_string(),
        ));
    }
    if !commitment.commitment.len().is_multiple_of(GROUP_POINT_SIZE) {
        return Err(ReportingError::InvalidReport(format!(
            "DKG commitment length {} is not a multiple of {}",
            commitment.commitment.len(),
            GROUP_POINT_SIZE
        )));
    }
    Ok(())
}

fn validate_equivocation_commitment_shape(
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

fn is_valid_invalid_crypto_pre_origin(origin_protocol: &str) -> bool {
    origin_protocol == "pre"
}

fn is_valid_invalid_crypto_sign_origin(origin_protocol: &str) -> bool {
    matches!(
        origin_protocol,
        "sign" | "pss_refresh" | "pss_reshare" | "report"
    )
}

fn is_valid_invalid_crypto_dkg_origin(origin_protocol: &str) -> bool {
    matches!(origin_protocol, "pss_refresh" | "pss_reshare")
}

/// Pin the envelope to the evidence: `observed_at == signed_at - grace`.
/// The envelope's fixed `observed_at + REPORT_TTL_SECS` expiry then doubles as
/// the evidence expiry, so the shared shape checks (`observed_at <= now`,
/// `now <= expires_at`) bound how long one signed bad response stays
/// reportable — without this, it could be re-wrapped in fresh envelopes and
/// re-reported indefinitely once the chain prunes its dedupe records.
fn validate_evidence_anchor(signed_at: u64, observed_at: u64) -> Result<()> {
    if signed_at < CHAIN_BLOCK_GRACE_SECS || observed_at != signed_at - CHAIN_BLOCK_GRACE_SECS {
        return Err(ReportingError::Unauthorized(
            "report envelope is not anchored to the evidence timestamp".to_string(),
        ));
    }
    Ok(())
}

fn require_sign_share_verification_failure(
    statement: &SignResponseStatement,
    context: &ReportValidationContext,
) -> Result<()> {
    let poly_state =
        RingPolyState::load_from_ring_pk_hex(&context.local_storage, &statement.ring_pk)
            .map_err(ReportingError::InvalidReport)?;
    let pub_poly_bytes = hex::decode(&poly_state.public_polynomial)
        .map_err(|error| ReportingError::InvalidReport(error.to_string()))?;
    let pub_poly = PubPolyImpl::from_bytes(&pub_poly_bytes).map_err(|error| {
        ReportingError::InvalidReport(format!("failed to deserialize public polynomial: {error}"))
    })?;
    // The sig_share is the responder's own signed crypto output. A responder that
    // signs a statement whose sig_share cannot be decoded returned an unusable
    // response, which is itself an attributable verification failure — confirm the
    // report on a decode error rather than rejecting it. (pub_poly above and
    // signing_commitments below are round/infrastructure inputs, so a decode error
    // there stays InvalidReport.)
    let Ok(sig_share_v) = SigShareInner::from_bytes(&statement.sig_share) else {
        return Ok(());
    };
    let sig_share = PubShare {
        i: statement.from_node_id,
        v: sig_share_v,
    };
    let signing_commitments = deserialize_commitments::<SignImpl>(&statement.signing_commitments)
        .map_err(|error| {
        ReportingError::InvalidReport(format!("failed to deserialize Sign commitments: {error}"))
    })?;
    let signer = SignImpl::new();
    match signer.verify_share(
        &statement.message,
        &pub_poly,
        &sig_share,
        &signing_commitments,
        statement.derivation.as_deref(),
        statement.metadata.as_deref(),
    ) {
        Ok(()) => Err(ReportingError::Unauthorized(
            "reported Sign share verifies successfully".to_string(),
        )),
        Err(_) => Ok(()),
    }
}

fn require_dkg_share_verification_failure(statement: &DkgShareStatement) -> Result<()> {
    // The nested commitment and share value are the responder's own signed crypto
    // output. A responder that signs a statement whose commitment or share value
    // cannot be decoded returned an unusable share, which is itself an attributable
    // verification failure — confirm the report on a decode error rather than
    // rejecting it.
    let Ok(commitment) = deserialize_wire_commitment(&statement.commitment_statement.commitment)
    else {
        return Ok(());
    };
    let Ok(share_value) = ScalarField::from_bytes(&statement.share_value) else {
        return Ok(());
    };

    if commitment.verify_share(statement.to_node_id, &share_value) {
        return Err(ReportingError::Unauthorized(
            "reported DKG share verifies successfully".to_string(),
        ));
    }
    Ok(())
}

async fn require_pre_proof_verification_failure(
    statement: &crate::reporting::v0::types::PreReencryptResponseStatement,
    context: &ReportValidationContext,
) -> Result<()> {
    let document_post = context
        .bulletin
        .read(statement.object_id.clone(), BulletinKind::Document)
        .await
        .map_err(|error| ReportingError::Bulletin(error.to_string()))?;
    let document = DocumentPayload::try_from(document_post)
        .map_err(|error| ReportingError::InvalidReport(error.to_string()))?;
    if document.ring_id != statement.ring_id {
        return Err(ReportingError::Unauthorized(
            "PRE response object is not bound to the report ring".to_string(),
        ));
    }

    let secret = deserialize_secret(&document.document)
        .map_err(|error| ReportingError::InvalidReport(error.to_string()))?;
    let rdr_pk = GroupAffine::from_bytes(&statement.rdr_pk).map_err(|error| {
        ReportingError::InvalidReport(format!("failed to deserialize reader public key: {error}"))
    })?;
    let enc_cmt = GroupAffine::from_bytes(&secret.enc_cmt).map_err(|error| {
        ReportingError::InvalidReport(format!(
            "failed to deserialize encrypted commitment: {error}"
        ))
    })?;
    // The share, challenge, and proof are the responder's own signed crypto
    // output. A responder that signs a statement whose share/challenge/proof
    // cannot be decoded returned an unusable response, which is itself an
    // attributable verification failure — confirm the report on a decode error
    // rather than rejecting it. (rdr_pk, enc_cmt, and pub_poly above are
    // request/infrastructure inputs, so a decode error there stays InvalidReport.)
    let Ok(share) = GroupAffine::from_bytes(&statement.share) else {
        return Ok(());
    };
    let Ok(challenge) = ScalarField::from_bytes(&statement.challenge) else {
        return Ok(());
    };
    let Ok(proof) = ScalarField::from_bytes(&statement.proof) else {
        return Ok(());
    };
    let poly_state =
        RingPolyState::load_from_ring_pk_hex(&context.local_storage, &statement.ring_pk)
            .map_err(ReportingError::InvalidReport)?;
    let pub_poly_bytes = hex::decode(&poly_state.public_polynomial)
        .map_err(|error| ReportingError::InvalidReport(error.to_string()))?;
    let pub_poly = PubPolyImpl::from_bytes(&pub_poly_bytes).map_err(|error| {
        ReportingError::InvalidReport(format!("failed to deserialize public polynomial: {error}"))
    })?;
    let reply = ReencryptReply {
        share: PubShare {
            i: statement.from_node_id,
            v: share,
        },
        challenge,
        proof,
    };

    match PreImpl::new().verify(
        &rdr_pk,
        &pub_poly,
        &enc_cmt,
        &reply,
        statement.derivation.as_deref(),
    ) {
        Ok(()) => Err(ReportingError::Unauthorized(
            "reported PRE proof verifies successfully".to_string(),
        )),
        Err(_) => Ok(()),
    }
}

async fn read_node_info(
    bulletin: &Arc<dyn Bulletin + Send + Sync>,
    node_key: &str,
) -> Result<NodeInfo> {
    let post = bulletin
        .read(node_key.to_string(), BulletinKind::NodeInfo)
        .await
        .map_err(|error| ReportingError::Bulletin(error.to_string()))?;
    NodeInfo::try_from(post).map_err(|error| ReportingError::InvalidReport(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dkg::v0::helpers::serialize_commitment_coefficients;
    use crate::reporting::v0::observation::{
        InvalidCryptoResponseObservation, OfflineObservation, ReportObservation,
    };
    use crate::reporting::v0::types::{
        CommitteeScope, DkgCommitmentStatement, DkgShareStatement, InvalidCryptoResponse,
        NodeOffline, PreReencryptResponseStatement, SignResponseStatement, DKG_COMMITMENT_DOMAIN,
        DKG_SHARE_DOMAIN, INVALID_CRYPTO_RESPONSE_REPORT_TYPE, PRE_REENCRYPT_RESPONSE_DOMAIN,
        REPORT_DOMAIN, REPORT_TTL_SECS, SIGN_RESPONSE_DOMAIN,
    };
    use bulletin::r#trait::UpgradeInfo;
    use crypto::r#trait::{CryptoSerialize, DkgMode, DkgRole};

    fn ring_fixture(threshold: u32) -> RingPayload {
        RingPayload {
            ring_pk: "pk".to_string(),
            peer_node_keys: vec![
                "reporter".to_string(),
                "accused".to_string(),
                "validator".to_string(),
            ],
            threshold,
            pss_interval: 86_400,
            upgrade_info: UpgradeInfo {
                current_version: 0,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn envelope(ring: &RingPayload) -> ReportEnvelope {
        ReportEnvelope {
            domain: REPORT_DOMAIN.to_string(),
            report_type: NODE_OFFLINE_REPORT_TYPE.to_string(),
            chain_id: "chain".to_string(),
            ring_id: "ring".to_string(),
            ring_pk: ring.ring_pk.clone(),
            ring_state_sha256: ring_state_sha256(ring),
            reporter_node_key: "reporter".to_string(),
            accused_node_key: "accused".to_string(),
            accused_peer_id: "aa".repeat(32),
            observed_at: 100,
            expires_at: 100 + REPORT_TTL_SECS,
            payload: NodeOffline {
                origin_protocol: "pre".to_string(),
                origin_protocol_version: 0,
                accused_committee_scope: CommitteeScope::Current,
                signing_committee_scope: CommitteeScope::Current,
            }
            .canonical_bytes(),
            session_id: "session-1".to_string(),
        }
    }

    fn payload(report: &ReportEnvelope) -> NodeOffline {
        NodeOffline::from_canonical_bytes(&report.payload).unwrap()
    }

    fn offline_observation() -> OfflineObservation {
        OfflineObservation {
            ring_id: "ring".to_string(),
            accused_node_key: "accused".to_string(),
            accused_peer_id: "aa".repeat(32),
            origin_protocol: "pre".to_string(),
            origin_protocol_version: 0,
            accused_committee_scope: CommitteeScope::Current,
            signing_committee_scope: CommitteeScope::Current,
            observed_at: 100,
            session_id: "session-1".to_string(),
        }
    }

    fn pre_invalid_observation() -> InvalidCryptoResponseObservation {
        InvalidCryptoResponseObservation {
            ring_id: "ring".to_string(),
            accused_node_key: "accused".to_string(),
            accused_peer_id: "aa".repeat(32),
            observed_at: 100,
            evidence: InvalidCryptoResponse::Pre {
                statement: PreReencryptResponseStatement {
                    domain: PRE_REENCRYPT_RESPONSE_DOMAIN.to_string(),
                    chain_id: "chain".to_string(),
                    ring_id: "ring".to_string(),
                    ring_pk: "pk".to_string(),
                    ring_state_sha256: "00".repeat(32),
                    protocol_version: 0,
                    request_id: "pre-request-1".to_string(),
                    signed_at: 110,
                    responder_node_key: "accused".to_string(),
                    origin_protocol: "pre".to_string(),
                    object_id: "object".to_string(),
                    rdr_pk: vec![1],
                    derivation: None,
                    from_node_id: 2,
                    share: vec![2],
                    challenge: vec![3],
                    proof: vec![4],
                    crypto_backend: "elgamal/test".to_string(),
                },
                response_signature: vec![5; 64],
            },
        }
    }

    fn sign_invalid_observation() -> InvalidCryptoResponseObservation {
        InvalidCryptoResponseObservation {
            ring_id: "ring".to_string(),
            accused_node_key: "accused".to_string(),
            accused_peer_id: "aa".repeat(32),
            observed_at: 100,
            evidence: InvalidCryptoResponse::Sign {
                statement: SignResponseStatement {
                    domain: SIGN_RESPONSE_DOMAIN.to_string(),
                    chain_id: "chain".to_string(),
                    ring_id: "ring".to_string(),
                    ring_pk: "pk".to_string(),
                    ring_state_sha256: "00".repeat(32),
                    protocol_version: 0,
                    request_id: "sign-request-1".to_string(),
                    signed_at: 110,
                    responder_node_key: "accused".to_string(),
                    origin_protocol: "sign".to_string(),
                    accused_committee_scope: CommitteeScope::Current,
                    signing_committee_scope: CommitteeScope::Current,
                    from_node_id: 2,
                    message: vec![1],
                    signing_commitments: Vec::new(),
                    derivation: None,
                    metadata: None,
                    sig_share: vec![2],
                    crypto_backend: "threshold-sign/test".to_string(),
                },
                response_signature: vec![5; 64],
            },
        }
    }

    fn dkg_share_statement(mutate_share: bool) -> DkgShareStatement {
        let ring = ring_fixture(2);
        let mut dealer = DkgImpl::new(2, 2, 3, 7, DkgRole::Standard).unwrap();
        dealer.generate_polynomial(DkgMode::Fresh).unwrap();
        let commitment =
            serialize_commitment_coefficients(&dealer.commitment().coefficients).unwrap();
        let share = dealer
            .generate_shares()
            .unwrap()
            .into_iter()
            .find(|share| share.to_id == 1)
            .unwrap();
        let mut share_value = <ScalarField as CryptoSerialize>::to_bytes(&share.value).unwrap();
        if mutate_share {
            let mut bad_share = ScalarField::from_bytes(&share_value).unwrap();
            bad_share += ScalarField::from(1u64);
            share_value = <ScalarField as CryptoSerialize>::to_bytes(&bad_share).unwrap();
        }
        let signed_at = CHAIN_BLOCK_GRACE_SECS + 100;
        let commitment_statement = DkgCommitmentStatement {
            domain: DKG_COMMITMENT_DOMAIN.to_string(),
            chain_id: "chain".to_string(),
            ring_id: "ring".to_string(),
            ring_pk: ring.ring_pk.clone(),
            ring_state_sha256: ring_state_sha256(&ring),
            protocol_version: 0,
            request_id: "dkg-session-1".to_string(),
            signed_at: signed_at - 1,
            responder_node_key: "accused".to_string(),
            origin_protocol: "pss_refresh".to_string(),
            accused_committee_scope: CommitteeScope::Current,
            signing_committee_scope: CommitteeScope::Current,
            from_node_id: 2,
            commitment,
            session_nonce: [0u8; 16],
            crypto_backend: DkgImpl::name(),
        };
        DkgShareStatement {
            domain: DKG_SHARE_DOMAIN.to_string(),
            chain_id: "chain".to_string(),
            ring_id: "ring".to_string(),
            ring_pk: ring.ring_pk.clone(),
            ring_state_sha256: ring_state_sha256(&ring),
            protocol_version: 0,
            request_id: "dkg-session-1".to_string(),
            signed_at,
            responder_node_key: "accused".to_string(),
            receiver_node_key: "reporter".to_string(),
            origin_protocol: "pss_refresh".to_string(),
            accused_committee_scope: CommitteeScope::Current,
            signing_committee_scope: CommitteeScope::Current,
            from_node_id: 2,
            to_node_id: share.to_id,
            commitment_statement,
            commitment_signature: vec![7; 64],
            share_value,
            nonce: share.nonce,
            crypto_backend: DkgImpl::name(),
        }
    }

    fn dkg_invalid_observation() -> InvalidCryptoResponseObservation {
        let statement = dkg_share_statement(true);
        InvalidCryptoResponseObservation {
            ring_id: "ring".to_string(),
            accused_node_key: "accused".to_string(),
            accused_peer_id: "aa".repeat(32),
            observed_at: statement.signed_at - CHAIN_BLOCK_GRACE_SECS,
            evidence: InvalidCryptoResponse::DkgShare {
                statement: Box::new(statement),
                response_signature: vec![9; 64],
            },
        }
    }

    #[test]
    fn routes_node_offline_observation_to_handler() {
        let registry = ReportRegistry::with_defaults();
        let handler = registry
            .handler_for_observation(&ReportObservation::NodeOffline(offline_observation()))
            .unwrap();
        assert_eq!(handler.report_type(), NODE_OFFLINE_REPORT_TYPE);
    }

    #[test]
    fn routes_pre_invalid_observation_to_handler() {
        let registry = ReportRegistry::with_defaults();
        let handler = registry
            .handler_for_observation(&ReportObservation::InvalidCryptoResponse(Box::new(
                pre_invalid_observation(),
            )))
            .unwrap();
        assert_eq!(handler.report_type(), INVALID_CRYPTO_RESPONSE_REPORT_TYPE);
    }

    #[test]
    fn node_offline_handler_builds_envelope_key_and_signing_options() {
        let ring = ring_fixture(2);
        let observation = offline_observation();
        let handler = NodeOfflineHandler;
        let report_observation = ReportObservation::NodeOffline(observation.clone());

        let key = handler.in_flight_key(&report_observation).unwrap();
        assert_eq!(key.report_type, NODE_OFFLINE_REPORT_TYPE);
        assert_eq!(key.ring_id, "ring");
        assert_eq!(key.subject_key, "accused");

        let built = handler.build_envelope(&observation, &ring, "reporter", "chain".to_string());
        assert_eq!(built, envelope(&ring));
        assert_eq!(built.report_id(), envelope(&ring).report_id());

        let options = handler.signing_options(&built);
        assert!(options.excluded_node_keys.contains("accused"));
        assert!(!options.excluded_node_keys.contains("reporter"));
    }

    #[test]
    fn pre_invalid_handler_builds_envelope_key_and_signing_options() {
        let ring = ring_fixture(2);
        let observation = pre_invalid_observation();
        let handler = InvalidCryptoResponseHandler;
        let report_observation =
            ReportObservation::InvalidCryptoResponse(Box::new(observation.clone()));

        let key = handler.in_flight_key(&report_observation).unwrap();
        assert_eq!(key.report_type, INVALID_CRYPTO_RESPONSE_REPORT_TYPE);
        assert_eq!(key.ring_id, "ring");
        assert_eq!(key.subject_key, "accused:pre-request-1");

        let built = handler.build_envelope(&observation, &ring, "reporter", "chain".to_string());
        assert_eq!(built.report_type, INVALID_CRYPTO_RESPONSE_REPORT_TYPE);
        assert_eq!(built.session_id, "pre-request-1");
        assert_eq!(built.payload, observation.evidence.canonical_bytes());

        let options = handler.signing_options(&built);
        assert!(options.excluded_node_keys.contains("accused"));
        assert!(!options.excluded_node_keys.contains("reporter"));
    }

    #[test]
    fn dkg_invalid_handler_builds_envelope_from_share_evidence() {
        let ring = ring_fixture(2);
        let observation = dkg_invalid_observation();
        let handler = InvalidCryptoResponseHandler;
        let report_observation =
            ReportObservation::InvalidCryptoResponse(Box::new(observation.clone()));

        let key = handler.in_flight_key(&report_observation).unwrap();
        assert_eq!(key.report_type, INVALID_CRYPTO_RESPONSE_REPORT_TYPE);
        assert_eq!(key.ring_id, "ring");
        assert_eq!(key.subject_key, "accused:dkg-session-1");

        let built = handler.build_envelope(&observation, &ring, "reporter", "chain".to_string());
        assert_eq!(built.report_type, INVALID_CRYPTO_RESPONSE_REPORT_TYPE);
        assert_eq!(built.session_id, "dkg-session-1");
        assert_eq!(built.payload, observation.evidence.canonical_bytes());
        assert_eq!(built.observed_at, observation.observed_at);

        let options = handler.signing_options(&built);
        assert!(options.excluded_node_keys.contains("accused"));
        assert!(!options.excluded_node_keys.contains("reporter"));
    }

    #[test]
    fn invalid_crypto_in_flight_key_includes_evidence_request_id() {
        let handler = InvalidCryptoResponseHandler;
        let pre = ReportObservation::InvalidCryptoResponse(Box::new(pre_invalid_observation()));
        let sign = ReportObservation::InvalidCryptoResponse(Box::new(sign_invalid_observation()));

        let pre_key = handler.in_flight_key(&pre).unwrap();
        let sign_key = handler.in_flight_key(&sign).unwrap();

        assert_ne!(pre_key, sign_key);
        assert_eq!(pre_key.subject_key, "accused:pre-request-1");
        assert_eq!(sign_key.subject_key, "accused:sign-request-1");
    }

    #[test]
    fn evidence_anchor_requires_exact_backdated_observed_at() {
        let signed_at = 1_700_000_000u64;
        let anchored = signed_at - CHAIN_BLOCK_GRACE_SECS;

        validate_evidence_anchor(signed_at, anchored).unwrap();

        // Any drift decouples the envelope's expires_at from the evidence age,
        // which would let one signed bad response be re-reported after the
        // chain prunes its dedupe records.
        for observed_at in [anchored - 1, anchored + 1, signed_at, 0] {
            assert!(matches!(
                validate_evidence_anchor(signed_at, observed_at),
                Err(ReportingError::Unauthorized(_))
            ));
        }

        // signed_at below the grace can never be anchored.
        assert!(matches!(
            validate_evidence_anchor(CHAIN_BLOCK_GRACE_SECS - 1, 0),
            Err(ReportingError::Unauthorized(_))
        ));
    }

    #[test]
    fn dkg_share_crypto_failure_is_required() {
        let bad = dkg_share_statement(true);
        require_dkg_share_verification_failure(&bad).unwrap();

        let good = dkg_share_statement(false);
        let error = require_dkg_share_verification_failure(&good).unwrap_err();
        assert!(error
            .to_string()
            .contains("reported DKG share verifies successfully"));
    }

    #[test]
    fn dkg_share_undecodable_responder_output_is_treated_as_failure() {
        // A signed but undeserializable share value is attributable bad crypto, so
        // co-signers must accept the report (Ok) rather than refuse it.
        let mut bad_share_value = dkg_share_statement(false);
        bad_share_value.share_value = vec![0xff; 4];
        require_dkg_share_verification_failure(&bad_share_value).unwrap();

        // Likewise for an undeserializable nested commitment.
        let mut bad_commitment = dkg_share_statement(false);
        bad_commitment.commitment_statement.commitment = vec![0xff; 3];
        require_dkg_share_verification_failure(&bad_commitment).unwrap();
    }

    #[tokio::test]
    async fn dkg_share_shape_rejects_wrong_origin() {
        let db_name = "registry_dkg_share_shape_rejects_wrong_origin";
        let db_path = crate::helpers::test_helpers::test_db_path(db_name);
        crate::helpers::test_helpers::cleanup_db(&db_path);
        let app_state = crate::helpers::test_helpers::create_test_app_state_default(db_name).await;
        let chain_id = app_state.bulletin.chain_id();
        let ring = ring_fixture(2);
        let mut envelope = InvalidCryptoResponseHandler.build_envelope(
            &dkg_invalid_observation(),
            &ring,
            "reporter",
            chain_id.clone(),
        );
        let mut statement = dkg_share_statement(true);
        statement.chain_id = chain_id.clone();
        statement.commitment_statement.chain_id = chain_id;
        statement.origin_protocol = "fresh_dkg".to_string();
        statement.commitment_statement.origin_protocol = "fresh_dkg".to_string();
        envelope.payload = InvalidCryptoResponse::DkgShare {
            statement: Box::new(statement.clone()),
            response_signature: vec![9; 64],
        }
        .canonical_bytes();

        let error = validate_dkg_share_statement_shape(
            &envelope,
            &statement,
            &[9; 64],
            &ReportValidationContext {
                local_node_key: app_state.node_key.clone(),
                requester_peer_id: None,
                network: app_state.network.clone(),
                peer_connection_pool: app_state.peer_connection_pool.clone(),
                bulletin: app_state.bulletin.clone(),
                local_storage: app_state.local_storage.clone(),
                routes: &network::V0,
                now: envelope.observed_at,
                mode: ReportValidationMode::ReporterObservation,
            },
        )
        .unwrap_err();
        crate::helpers::test_helpers::cleanup_db(&db_path);
        assert!(error.to_string().contains("unsupported DKG share origin"));
    }

    fn equivocation_commitment(
        ring: &RingPayload,
        chain_id: &str,
        commitment: Vec<u8>,
        session_nonce: [u8; 16],
        signed_at: u64,
    ) -> SignedDkgCommitment {
        SignedDkgCommitment {
            statement: DkgCommitmentStatement {
                domain: DKG_COMMITMENT_DOMAIN.to_string(),
                chain_id: chain_id.to_string(),
                ring_id: "ring".to_string(),
                ring_pk: ring.ring_pk.clone(),
                ring_state_sha256: ring_state_sha256(ring),
                protocol_version: 0,
                request_id: "dkg-session-1".to_string(),
                signed_at,
                responder_node_key: "accused".to_string(),
                origin_protocol: "pss_reshare".to_string(),
                accused_committee_scope: CommitteeScope::Current,
                signing_committee_scope: CommitteeScope::Current,
                from_node_id: 2,
                commitment,
                session_nonce,
                crypto_backend: DkgImpl::name(),
            },
            signature: vec![1; 64],
        }
    }

    #[tokio::test]
    async fn validate_equivocation_commitment_shape_accepts_bound_and_rejects_bad_origin() {
        let db_name = "registry_equivocation_commitment_shape";
        let db_path = crate::helpers::test_helpers::test_db_path(db_name);
        crate::helpers::test_helpers::cleanup_db(&db_path);
        let app_state = crate::helpers::test_helpers::create_test_app_state_default(db_name).await;
        let chain_id = app_state.bulletin.chain_id();
        let ring = ring_fixture(2);

        let mut dealer = DkgImpl::new(2, 2, 3, 7, DkgRole::Standard).unwrap();
        dealer.generate_polynomial(DkgMode::Fresh).unwrap();
        let commitment =
            serialize_commitment_coefficients(&dealer.commitment().coefficients).unwrap();
        let signed_at = CHAIN_BLOCK_GRACE_SECS + 100;
        let nonce = [3u8; 16];
        let commitment_a =
            equivocation_commitment(&ring, &chain_id, commitment.clone(), nonce, signed_at);
        let mut different = commitment.clone();
        different[0] ^= 0xff;
        let commitment_b = equivocation_commitment(&ring, &chain_id, different, nonce, signed_at);

        let observation = InvalidCryptoResponseObservation {
            ring_id: "ring".to_string(),
            accused_node_key: "accused".to_string(),
            accused_peer_id: "aa".repeat(32),
            observed_at: signed_at - CHAIN_BLOCK_GRACE_SECS,
            evidence: InvalidCryptoResponse::DkgEquivocation {
                commitment_a: Box::new(commitment_a.clone()),
                commitment_b: Box::new(commitment_b),
            },
        };
        let envelope = InvalidCryptoResponseHandler.build_envelope(
            &observation,
            &ring,
            "reporter",
            chain_id.clone(),
        );
        let context = ReportValidationContext {
            local_node_key: app_state.node_key.clone(),
            requester_peer_id: None,
            network: app_state.network.clone(),
            peer_connection_pool: app_state.peer_connection_pool.clone(),
            bulletin: app_state.bulletin.clone(),
            local_storage: app_state.local_storage.clone(),
            routes: &network::V0,
            now: envelope.observed_at,
            mode: ReportValidationMode::ReporterObservation,
        };

        // A well-bound commitment passes the shape check.
        validate_equivocation_commitment_shape(
            &envelope,
            &context,
            &commitment_a.statement,
            &commitment_a.signature,
            true,
        )
        .unwrap();

        // A non-DKG origin is rejected.
        let mut bad = commitment_a.clone();
        bad.statement.origin_protocol = "not_dkg".to_string();
        let error = validate_equivocation_commitment_shape(
            &envelope,
            &context,
            &bad.statement,
            &bad.signature,
            true,
        )
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("unsupported DKG equivocation origin"));

        crate::helpers::test_helpers::cleanup_db(&db_path);
    }

    #[test]
    fn report_protocol_version_is_resolved_at_observed_at() {
        let mut ring = ring_fixture(2);
        ring.upgrade_info = UpgradeInfo {
            current_version: 0,
            next_version: Some(1),
            activation_time: Some(110),
        };
        let mut report = envelope(&ring);
        report.observed_at = 100;

        assert_eq!(
            validate_report_route_version_at_observed_at(&report, &ring, 0).unwrap(),
            0
        );
        assert!(matches!(
            validate_report_route_version_at_observed_at(&report, &ring, 1),
            Err(ReportingError::Unauthorized(_))
        ));

        report.observed_at = 110;
        assert_eq!(
            validate_report_route_version_at_observed_at(&report, &ring, 1).unwrap(),
            1
        );
    }

    #[test]
    fn rejects_threshold_one() {
        let ring = ring_fixture(1);
        let report = envelope(&ring);
        let error = validate_ring_and_membership(&report, &payload(&report), &ring).unwrap_err();
        assert!(error.to_string().contains("threshold >= 2"));
    }

    #[test]
    fn rejects_threshold_that_needs_accused() {
        let ring = ring_fixture(3);
        let report = envelope(&ring);
        let error = validate_ring_and_membership(&report, &payload(&report), &ring).unwrap_err();
        assert!(error.to_string().contains("excluding the accused"));
    }

    #[test]
    fn accepts_current_scope_during_pending_reshare_and_rejects_stale_digest() {
        let mut ring = ring_fixture(2);
        let report = envelope(&ring);
        ring.new_threshold = Some(3);
        ring.new_peer_node_keys = Some(vec![
            "reporter".to_string(),
            "accused".to_string(),
            "validator".to_string(),
        ]);
        let mut scoped_report = report.clone();
        scoped_report.ring_state_sha256 = ring_state_sha256(&ring);
        validate_ring_and_membership(&scoped_report, &payload(&scoped_report), &ring).unwrap();

        let ring = ring_fixture(2);
        let mut report = envelope(&ring);
        report.ring_state_sha256 = "00".repeat(32);
        assert!(validate_ring_and_membership(&report, &payload(&report), &ring).is_err());
    }

    #[test]
    fn accepts_valid_report_shape_against_ring() {
        let ring = ring_fixture(2);
        let report = envelope(&ring);
        validate_ring_and_membership(&report, &payload(&report), &ring).unwrap();
    }

    #[test]
    fn validates_pending_new_accused_and_current_signing_scope() {
        let mut ring = ring_fixture(2);
        ring.new_peer_node_keys = Some(vec![
            "new-a".to_string(),
            "pending-accused".to_string(),
            "new-c".to_string(),
        ]);
        ring.new_threshold = Some(3);

        let mut report = envelope(&ring);
        report.ring_state_sha256 = ring_state_sha256(&ring);
        report.accused_node_key = "pending-accused".to_string();
        report.payload = NodeOffline {
            origin_protocol: "pss_reshare".to_string(),
            origin_protocol_version: 0,
            accused_committee_scope: CommitteeScope::PendingNew,
            signing_committee_scope: CommitteeScope::Current,
        }
        .canonical_bytes();

        validate_ring_and_membership(&report, &payload(&report), &ring).unwrap();
    }

    #[test]
    fn rejects_reporter_outside_signing_committee() {
        let mut ring = ring_fixture(2);
        ring.new_peer_node_keys = Some(vec![
            "new-a".to_string(),
            "pending-accused".to_string(),
            "new-c".to_string(),
        ]);
        ring.new_threshold = Some(2);

        let mut report = envelope(&ring);
        report.ring_state_sha256 = ring_state_sha256(&ring);
        report.payload = NodeOffline {
            origin_protocol: "pss_reshare".to_string(),
            origin_protocol_version: 0,
            accused_committee_scope: CommitteeScope::PendingNew,
            signing_committee_scope: CommitteeScope::PendingNew,
        }
        .canonical_bytes();

        let error = validate_ring_and_membership(&report, &payload(&report), &ring).unwrap_err();
        assert!(error.to_string().contains("signing committee"));
    }

    #[test]
    fn excludes_accused_only_when_in_signing_committee_capacity_check() {
        let mut ring = ring_fixture(3);
        ring.new_peer_node_keys = Some(vec![
            "new-a".to_string(),
            "pending-accused".to_string(),
            "new-c".to_string(),
        ]);
        ring.new_threshold = Some(3);

        let mut report = envelope(&ring);
        report.ring_state_sha256 = ring_state_sha256(&ring);
        report.accused_node_key = "pending-accused".to_string();
        report.payload = NodeOffline {
            origin_protocol: "pss_reshare".to_string(),
            origin_protocol_version: 0,
            accused_committee_scope: CommitteeScope::PendingNew,
            signing_committee_scope: CommitteeScope::Current,
        }
        .canonical_bytes();
        validate_ring_and_membership(&report, &payload(&report), &ring).unwrap();

        report.reporter_node_key = "new-a".to_string();
        report.payload = NodeOffline {
            origin_protocol: "pss_reshare".to_string(),
            origin_protocol_version: 0,
            accused_committee_scope: CommitteeScope::PendingNew,
            signing_committee_scope: CommitteeScope::PendingNew,
        }
        .canonical_bytes();
        let error = validate_ring_and_membership(&report, &payload(&report), &ring).unwrap_err();
        assert!(error.to_string().contains("excluding the accused"));
    }

    #[test]
    fn rejects_unknown_report_type() {
        let registry = ReportRegistry::with_defaults();
        assert!(matches!(
            registry.handler_for("future_fault"),
            Err(ReportingError::UnsupportedReportType { .. })
        ));
    }

    #[test]
    fn accused_not_in_accused_committee_is_rejected() {
        let ring = ring_fixture(2);
        let mut report = envelope(&ring);
        report.accused_node_key = "outsider".to_string();
        let error = validate_ring_and_membership(&report, &payload(&report), &ring).unwrap_err();
        assert!(error.to_string().contains("accused committee"));
    }
}
