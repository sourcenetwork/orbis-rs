use crate::app_state::PeerConnectionPool;
use crate::constants::RELAY_CHECK_MAX_DRIFT_SECS;
use crate::dkg::v0::helpers::deserialize_wire_commitment;
use crate::dkg::v0::messages::SignedDkgCommitment;
use crate::dkg::v0::transport::{
    self, DkgPublicContribution, DkgPublicPayload, ParticipantRef, PublicPhase as DkgPublicPhase,
    PUBLIC_CONTRIBUTION_SIGNING_DOMAIN,
};
use crate::helpers::identity::{determine_session_node_id, extract_node_part};
use crate::helpers::node_routes::{
    canonical_node_id_assignments_from_node_keys, peer_ids_from_routes, resolve_node_routes,
};
use crate::helpers::ring::RingConfig;
use crate::pre::v0::helpers::deserialize_secret;
use crate::reporting::v0::error::{ReportingError, Result};
use crate::reporting::v0::health::require_peer_offline;
use crate::reporting::v0::observation::{
    InvalidCryptoResponseObservation, OfflineObservation, ReportObservation,
    UnauthorizedRequestObservation,
};
use crate::reporting::v0::state::InFlightReportKey;
use crate::reporting::v0::types::{
    ring_state_sha256, CommitteeScope, DkgCommitmentStatement, DkgControlMessageFaultKind,
    DkgControlMessageFaultStatement, DkgLeaderEquivocationStatement, DkgLeaderPublicFaultKind,
    DkgLeaderPublicFaultStatement, DkgPublicOriginFaultKind, DkgPublicOriginFaultStatement,
    DkgShareStatement, EndpointSignedContribution, InvalidCryptoResponse, NodeOffline,
    PreReencryptResponseStatement, RelayRequestStatement, ReportEnvelope, ReportedDocumentEvidence,
    SignResponseStatement, UnauthorizedRequestPayload, CHAIN_BLOCK_GRACE_SECS,
    DKG_COMMITMENT_DOMAIN, DKG_CONTROL_MESSAGE_FAULT_DOMAIN, DKG_LEADER_BATCH_MISMATCH_DOMAIN,
    DKG_LEADER_EQUIVOCATION_DOMAIN, DKG_LEADER_PUBLIC_FAULT_DOMAIN, DKG_PUBLIC_ORIGIN_FAULT_DOMAIN,
    DKG_SHARE_DOMAIN, INVALID_CRYPTO_RESPONSE_REPORT_TYPE, NODE_OFFLINE_REPORT_TYPE,
    PRE_REENCRYPT_RESPONSE_DOMAIN, RELAY_REQUEST_DOMAIN, REPORT_DOMAIN, REPORT_TTL_SECS,
    SIGN_RESPONSE_DOMAIN, UNAUTHORIZED_REQUEST_REPORT_TYPE,
};
use crate::ring_state::RingPolyState;
use crate::sign::v0::coordinator::SigningOptions;
use crate::sign::v0::helpers::{
    deserialize_commitments, refresh_health_check_message,
    refresh_health_check_peer_node_keys_sha256,
};
use crate::sign::v0::messages::REFRESH_HEALTH_CHECK_DOMAIN;
use ::common::blockchain::orbis::generate_document_id;
use ::common::blockchain::verify_node_message;
use async_trait::async_trait;
use authz::r#trait::Authz;
use authz::vera::{AccessCheckRequest, ValidWindow};
use bulletin::r#trait::{
    Bulletin, BulletinKind, DocumentPayload, KeyDerivation, NodeInfo, RingPayload,
};
use crypto::r#trait::{
    CryptoDeserialize, Dkg, PolynomialCommitment as PolynomialCommitmentTrait, PubShare,
    ReencryptReply, ThresholdDealer, ThresholdSigner,
};
use crypto::{
    DkgImpl, GroupAffine, PreImpl, PubPolyImpl, ScalarField, SigShareInner, SignImpl,
    SignaturePoint, GROUP_POINT_SIZE,
};
use local_storage::LocalStorageImpl;
use network::{Network, PeerId};
use std::collections::BTreeMap;
use std::collections::BTreeSet;
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
    /// Used by the `unauthorized_request` refutation to re-run the ACP check at the anchored height.
    pub authz: Arc<dyn Authz + Send + Sync>,
    pub local_storage: LocalStorageImpl,
    pub routes: &'static network::ProtocolRoutes,
    pub now: u64,
    pub mode: ReportValidationMode,
    /// Out-of-band inline-document evidence for a PRE report whose statement has `document_inline`
    /// set — supplied by the reporter's own observation, or by `ReportSigningContext` when
    /// validating as an independent co-signer. The PRE refutations
    /// (`require_pre_proof_verification_failure`, `require_relayed_request_unauthorized`) re-bind
    /// it to `object_id` before use. `None` for every bulletin-sourced report.
    pub inline_document: Option<ReportedDocumentEvidence>,
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
    /// Out-of-band inline-document evidence to carry into `ReportSigningContext` (and this
    /// reporter's own local validation). `None` for every report except a PRE one whose request
    /// carried its document inline.
    pub inline_document: Option<ReportedDocumentEvidence>,
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
        registry.register(Arc::new(UnauthorizedRequestHandler));
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

mod common;
mod invalid_crypto;
mod node_offline;
mod unauthorized_request;

// Internal cross-submodule glue: every submodule item shared across a module
// boundary is `pub(super)`; this glob flattens them so a sibling's (or the test
// module's) `use super::*` resolves them.
#[allow(unused_imports)]
use self::{common::*, invalid_crypto::*, node_offline::*, unauthorized_request::*};

#[cfg(test)]
mod tests;
