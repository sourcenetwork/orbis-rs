use crate::app_state::PeerConnectionPool;
use crate::helpers::identity::{determine_session_node_id, extract_node_part};
use crate::helpers::node_routes::{peer_ids_from_routes, resolve_node_routes};
use crate::helpers::ring::RingConfig;
use crate::pre::v0::helpers::deserialize_secret;
use crate::reporting::v0::error::{ReportingError, Result};
use crate::reporting::v0::health::require_peer_offline;
use crate::reporting::v0::observation::{
    OfflineObservation, PreInvalidReencryptionProofObservation, ReportObservation,
};
use crate::reporting::v0::state::InFlightReportKey;
use crate::reporting::v0::types::{
    ring_state_sha256, CommitteeScope, NodeOffline, PreInvalidReencryptionProof, ReportEnvelope,
    CHAIN_BLOCK_GRACE_SECS, NODE_OFFLINE_REPORT_TYPE, PRE_INVALID_REENCRYPTION_PROOF_REPORT_TYPE,
    PRE_REENCRYPT_RESPONSE_DOMAIN, REPORT_DOMAIN, REPORT_TTL_SECS,
};
use crate::ring_state::RingPolyState;
use crate::sign::v0::coordinator::SigningOptions;
use async_trait::async_trait;
use bulletin::r#trait::{Bulletin, BulletinKind, DocumentPayload, NodeInfo, RingPayload};
use common::blockchain::verify_node_message;
use crypto::r#trait::{CryptoDeserialize, PubShare, ReencryptReply, ThresholdDealer};
use crypto::{GroupAffine, PreImpl, PubPolyImpl, ScalarField};
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
        registry.register(Arc::new(PreInvalidReencryptionProofHandler));
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

        let ring_post = context
            .bulletin
            .read(observation.ring_id.clone(), BulletinKind::Ring)
            .await
            .map_err(|error| ReportingError::Bulletin(error.to_string()))?;
        let ring = RingPayload::try_from(ring_post)
            .map_err(|error| ReportingError::InvalidReport(error.to_string()))?;

        let envelope = self.build_envelope(
            &observation,
            &ring,
            &context.reporter_node_key,
            context.bulletin.chain_id(),
        );

        let signing_committee = committee_for_scope(&ring, observation.signing_committee_scope)?;
        let node_routes = resolve_node_routes(&context.bulletin, &signing_committee.peer_node_keys)
            .await
            .map_err(ReportingError::InvalidReport)?;
        let peer_ids = peer_ids_from_routes(&node_routes);
        let ring_pk_bytes = hex::decode(&ring.ring_pk)
            .map_err(|error| ReportingError::Serialization(error.to_string()))?;
        let poly_state =
            RingPolyState::load_from_ring_pk_hex(&context.local_storage, &ring.ring_pk)
                .map_err(ReportingError::InvalidReport)?;
        let ring_config = RingConfig {
            ring_id: observation.ring_id.clone(),
            ring_pk_bytes,
            peer_ids,
            peer_node_keys: signing_committee.peer_node_keys,
            threshold: signing_committee.threshold as usize,
            total_participants: node_routes.len(),
            public_polynomial_hex: poly_state.public_polynomial,
        };

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
        let effective_version = ring
            .upgrade_info
            .effective_version(context.now)
            .map_err(|error| ReportingError::InvalidReport(error.to_string()))?;
        if effective_version != context.routes.version {
            return Err(ReportingError::Unauthorized(format!(
                "report protocol version {} is not effective for ring {}",
                context.routes.version, envelope.ring_id
            )));
        }
        if payload.origin_protocol_version != effective_version {
            return Err(ReportingError::Unauthorized(format!(
                "report origin protocol version {} does not match effective ring version {}",
                payload.origin_protocol_version, effective_version
            )));
        }

        let signing_committee = validate_ring_and_membership(envelope, &payload, &ring)?;
        validate_node_routes(envelope, context, &ring).await?;

        if context.local_node_key == envelope.accused_node_key {
            return Err(ReportingError::Unauthorized(
                "the accused node cannot sign its own offline report".to_string(),
            ));
        }
        if !signing_committee
            .peer_node_keys
            .iter()
            .any(|node_key| node_key == &context.local_node_key)
        {
            return Err(ReportingError::Unauthorized(
                "local signer is not in the report ring".to_string(),
            ));
        }

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

struct PreInvalidReencryptionProofHandler;

#[async_trait]
impl ReportHandler for PreInvalidReencryptionProofHandler {
    fn report_type(&self) -> &'static str {
        PRE_INVALID_REENCRYPTION_PROOF_REPORT_TYPE
    }

    fn in_flight_key(&self, observation: &ReportObservation) -> Result<InFlightReportKey> {
        let observation = Self::observation(observation)?;
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
        let ReportObservation::PreInvalidReencryptionProof(observation) = observation else {
            return Err(ReportingError::InvalidReport(
                "pre_invalid_reencryption_proof handler received the wrong observation type"
                    .to_string(),
            ));
        };

        let ring_post = context
            .bulletin
            .read(observation.ring_id.clone(), BulletinKind::Ring)
            .await
            .map_err(|error| ReportingError::Bulletin(error.to_string()))?;
        let ring = RingPayload::try_from(ring_post)
            .map_err(|error| ReportingError::InvalidReport(error.to_string()))?;

        let envelope = self.build_envelope(
            &observation,
            &ring,
            &context.reporter_node_key,
            context.bulletin.chain_id(),
        );

        let signing_committee = committee_for_scope(&ring, CommitteeScope::Current)?;
        let node_routes = resolve_node_routes(&context.bulletin, &signing_committee.peer_node_keys)
            .await
            .map_err(ReportingError::InvalidReport)?;
        let peer_ids = peer_ids_from_routes(&node_routes);
        let ring_pk_bytes = hex::decode(&ring.ring_pk)
            .map_err(|error| ReportingError::Serialization(error.to_string()))?;
        let poly_state =
            RingPolyState::load_from_ring_pk_hex(&context.local_storage, &ring.ring_pk)
                .map_err(ReportingError::InvalidReport)?;
        let ring_config = RingConfig {
            ring_id: observation.ring_id.clone(),
            ring_pk_bytes,
            peer_ids,
            peer_node_keys: signing_committee.peer_node_keys,
            threshold: signing_committee.threshold as usize,
            total_participants: node_routes.len(),
            public_polynomial_hex: poly_state.public_polynomial,
        };

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
        let evidence = PreInvalidReencryptionProof::from_canonical_bytes(&envelope.payload)?;
        let statement = &evidence.statement;

        let ring_post = context
            .bulletin
            .read(envelope.ring_id.clone(), BulletinKind::Ring)
            .await
            .map_err(|error| ReportingError::Bulletin(error.to_string()))?;
        let ring = RingPayload::try_from(ring_post)
            .map_err(|error| ReportingError::InvalidReport(error.to_string()))?;

        validate_pre_invalid_statement_shape(envelope, &evidence, context, &ring)?;

        let effective_version = ring
            .upgrade_info
            .effective_version(context.now)
            .map_err(|error| ReportingError::InvalidReport(error.to_string()))?;
        if effective_version != context.routes.version {
            return Err(ReportingError::Unauthorized(format!(
                "report protocol version {} is not effective for ring {}",
                context.routes.version, envelope.ring_id
            )));
        }
        if statement.protocol_version != effective_version {
            return Err(ReportingError::Unauthorized(format!(
                "PRE response protocol version {} does not match effective ring version {}",
                statement.protocol_version, effective_version
            )));
        }

        let signing_committee = validate_ring_and_membership_for_scopes(
            envelope,
            &ring,
            CommitteeScope::Current,
            CommitteeScope::Current,
            "PRE invalid-proof",
        )?;
        validate_node_routes(envelope, context, &ring).await?;
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
            &evidence.response_signature,
        )
        .map_err(|error| {
            ReportingError::Unauthorized(format!("invalid PRE response signature: {}", error))
        })?;

        require_pre_proof_verification_failure(statement, context).await
    }
}

impl PreInvalidReencryptionProofHandler {
    fn observation(
        observation: &ReportObservation,
    ) -> Result<&PreInvalidReencryptionProofObservation> {
        match observation {
            ReportObservation::PreInvalidReencryptionProof(observation) => Ok(observation.as_ref()),
            _ => Err(ReportingError::InvalidReport(
                "pre_invalid_reencryption_proof handler received the wrong observation type"
                    .to_string(),
            )),
        }
    }

    fn build_envelope(
        &self,
        observation: &PreInvalidReencryptionProofObservation,
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
            session_id: observation.evidence.statement.request_id.clone(),
        }
    }

    fn signing_options(&self, envelope: &ReportEnvelope) -> SigningOptions {
        let mut excluded_node_keys = HashSet::new();
        excluded_node_keys.insert(envelope.accused_node_key.clone());
        SigningOptions { excluded_node_keys }
    }
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

fn validate_pre_invalid_statement_shape(
    envelope: &ReportEnvelope,
    evidence: &PreInvalidReencryptionProof,
    context: &ReportValidationContext,
    _ring: &RingPayload,
) -> Result<()> {
    let statement = &evidence.statement;
    if statement.domain != PRE_REENCRYPT_RESPONSE_DOMAIN {
        return Err(ReportingError::InvalidReport(format!(
            "unexpected PRE response domain {}",
            statement.domain
        )));
    }
    if statement.chain_id != envelope.chain_id || envelope.chain_id != context.bulletin.chain_id() {
        return Err(ReportingError::Unauthorized(
            "PRE response chain ID does not match report chain ID".to_string(),
        ));
    }
    if statement.ring_id != envelope.ring_id
        || statement.ring_pk != envelope.ring_pk
        || statement.ring_state_sha256 != envelope.ring_state_sha256
    {
        return Err(ReportingError::Unauthorized(
            "PRE response ring binding does not match report envelope".to_string(),
        ));
    }
    if statement.request_id != envelope.session_id {
        return Err(ReportingError::Unauthorized(
            "PRE response request_id does not match report session_id".to_string(),
        ));
    }
    validate_pre_evidence_anchor(statement.signed_at, envelope.observed_at)?;
    if statement.responder_node_key != envelope.accused_node_key {
        return Err(ReportingError::Unauthorized(
            "PRE response responder does not match accused node".to_string(),
        ));
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
    if evidence.response_signature.is_empty() {
        return Err(ReportingError::InvalidReport(
            "PRE response signature cannot be empty".to_string(),
        ));
    }
    Ok(())
}

/// Pin the envelope to the evidence: `observed_at == signed_at - grace`.
/// The envelope's fixed `observed_at + REPORT_TTL_SECS` expiry then doubles as
/// the evidence expiry, so the shared shape checks (`observed_at <= now`,
/// `now <= expires_at`) bound how long one signed bad response stays
/// reportable — without this, it could be re-wrapped in fresh envelopes and
/// re-reported indefinitely once the chain prunes its dedupe records.
fn validate_pre_evidence_anchor(signed_at: u64, observed_at: u64) -> Result<()> {
    if signed_at < CHAIN_BLOCK_GRACE_SECS || observed_at != signed_at - CHAIN_BLOCK_GRACE_SECS {
        return Err(ReportingError::Unauthorized(
            "report envelope is not anchored to the evidence timestamp".to_string(),
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
    let share = GroupAffine::from_bytes(&statement.share).map_err(|error| {
        ReportingError::InvalidReport(format!("failed to deserialize PRE share: {error}"))
    })?;
    let challenge = ScalarField::from_bytes(&statement.challenge).map_err(|error| {
        ReportingError::InvalidReport(format!("failed to deserialize PRE challenge: {error}"))
    })?;
    let proof = ScalarField::from_bytes(&statement.proof).map_err(|error| {
        ReportingError::InvalidReport(format!("failed to deserialize PRE proof: {error}"))
    })?;
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
    use crate::reporting::v0::observation::{OfflineObservation, ReportObservation};
    use crate::reporting::v0::types::{
        CommitteeScope, NodeOffline, PreInvalidReencryptionProof, PreReencryptResponseStatement,
        PRE_INVALID_REENCRYPTION_PROOF_REPORT_TYPE, PRE_REENCRYPT_RESPONSE_DOMAIN, REPORT_DOMAIN,
        REPORT_TTL_SECS,
    };
    use bulletin::r#trait::UpgradeInfo;

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

    fn pre_invalid_observation() -> PreInvalidReencryptionProofObservation {
        PreInvalidReencryptionProofObservation {
            ring_id: "ring".to_string(),
            accused_node_key: "accused".to_string(),
            accused_peer_id: "aa".repeat(32),
            observed_at: 100,
            evidence: PreInvalidReencryptionProof {
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

    #[test]
    fn routes_node_offline_observation_to_handler() {
        let registry = ReportRegistry::with_defaults();
        let handler = registry
            .handler_for_observation(&ReportObservation::NodeOffline(offline_observation()))
            .unwrap();
        assert_eq!(handler.report_type(), NODE_OFFLINE_REPORT_TYPE);
    }

    #[test]
    fn routes_pre_invalid_proof_observation_to_handler() {
        let registry = ReportRegistry::with_defaults();
        let handler = registry
            .handler_for_observation(&ReportObservation::PreInvalidReencryptionProof(Box::new(
                pre_invalid_observation(),
            )))
            .unwrap();
        assert_eq!(
            handler.report_type(),
            PRE_INVALID_REENCRYPTION_PROOF_REPORT_TYPE
        );
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
        let handler = PreInvalidReencryptionProofHandler;
        let report_observation =
            ReportObservation::PreInvalidReencryptionProof(Box::new(observation.clone()));

        let key = handler.in_flight_key(&report_observation).unwrap();
        assert_eq!(key.report_type, PRE_INVALID_REENCRYPTION_PROOF_REPORT_TYPE);
        assert_eq!(key.ring_id, "ring");
        assert_eq!(key.subject_key, "accused");

        let built = handler.build_envelope(&observation, &ring, "reporter", "chain".to_string());
        assert_eq!(
            built.report_type,
            PRE_INVALID_REENCRYPTION_PROOF_REPORT_TYPE
        );
        assert_eq!(built.session_id, "pre-request-1");
        assert_eq!(built.payload, observation.evidence.canonical_bytes());

        let options = handler.signing_options(&built);
        assert!(options.excluded_node_keys.contains("accused"));
        assert!(!options.excluded_node_keys.contains("reporter"));
    }

    #[test]
    fn pre_evidence_anchor_requires_exact_backdated_observed_at() {
        let signed_at = 1_700_000_000u64;
        let anchored = signed_at - CHAIN_BLOCK_GRACE_SECS;

        validate_pre_evidence_anchor(signed_at, anchored).unwrap();

        // Any drift decouples the envelope's expires_at from the evidence age,
        // which would let one signed bad response be re-reported after the
        // chain prunes its dedupe records.
        for observed_at in [anchored - 1, anchored + 1, signed_at, 0] {
            assert!(matches!(
                validate_pre_evidence_anchor(signed_at, observed_at),
                Err(ReportingError::Unauthorized(_))
            ));
        }

        // signed_at below the grace can never be anchored.
        assert!(matches!(
            validate_pre_evidence_anchor(CHAIN_BLOCK_GRACE_SECS - 1, 0),
            Err(ReportingError::Unauthorized(_))
        ));
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
