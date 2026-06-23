pub mod error;
pub mod health;
pub mod observation;
pub mod registry;
pub mod sink;
pub mod state;
pub mod types;

use crate::app_state::AppState;
use crate::helpers::node_routes::{peer_ids_from_routes, resolve_node_routes};
use crate::helpers::ring::RingConfig;
use crate::reporting::error::{ReportingError, Result};
use crate::reporting::registry::{ReportValidationContext, ReportValidationMode};
use crate::reporting::types::{
    ring_state_sha256, InFlightReportKey, NodeOfflineV1, OfflineObservation, ReportEnvelope,
    ReportSigningContext, SignedReport, NODE_OFFLINE_REPORT_TYPE, NODE_OFFLINE_REPORT_VERSION,
    REPORT_DOMAIN, REPORT_FRAMEWORK_VERSION, REPORT_TTL_SECS,
};
use crate::sign::v0::coordinator::{SignCoordinator, SignResponse, SigningOptions};
use crate::sign::v0::messages::SignContext;
use bulletin::r#trait::{BulletinKind, RingPayload};
use crypto::r#trait::{DistKeyShare, Dkg, PubShare, ThresholdSigner};
use crypto::{
    GroupAffine, ScalarField, SigShareInner, SignImpl, SignaturePoint, THRESHOLD_SIGNATURE_SCHEME,
};
use std::collections::HashSet;
use std::sync::Arc;

pub async fn queue_offline_observation<D>(
    app_state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    observation: OfflineObservation,
) -> Result<bool>
where
    D: Dkg<
            ShareValue = ScalarField,
            PublicKey = GroupAffine,
            PolynomialCommitment = crypto::PolynomialCommitmentImpl,
            PubPoly = crypto::PubPolyImpl,
        > + Clone
        + Send
        + Sync
        + 'static,
    SignImpl: ThresholdSigner<
            ShareValue = ScalarField,
            PublicKey = GroupAffine,
            DistKeyShare = DistKeyShare<ScalarField>,
            PubPoly = D::PubPoly,
            Signature = SignaturePoint,
            SigShare = PubShare<SigShareInner>,
        > + Send
        + Sync
        + 'static,
{
    let key = InFlightReportKey {
        report_type: NODE_OFFLINE_REPORT_TYPE,
        ring_id: observation.ring_id.clone(),
        accused_node_key: observation.accused_node_key.clone(),
    };
    let state = Arc::clone(&app_state.reporting_state);
    let outcome = state
        .spawn(key, async move {
            if let Err(error) = create_offline_report(app_state, routes, observation).await {
                crate::metrics::REPORT_ATTEMPTS_TOTAL
                    .with_label_values(&[NODE_OFFLINE_REPORT_TYPE, "failed"])
                    .inc();
                tracing::warn!(error = %error, "Offline report attempt did not complete");
            } else {
                crate::metrics::REPORT_ATTEMPTS_TOTAL
                    .with_label_values(&[NODE_OFFLINE_REPORT_TYPE, "signed"])
                    .inc();
            }
        })
        .await?;
    crate::metrics::REPORT_ATTEMPTS_TOTAL
        .with_label_values(&[
            NODE_OFFLINE_REPORT_TYPE,
            if outcome { "queued" } else { "duplicate" },
        ])
        .inc();
    Ok(outcome)
}

async fn create_offline_report<D>(
    app_state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    observation: OfflineObservation,
) -> Result<()>
where
    D: Dkg<
            ShareValue = ScalarField,
            PublicKey = GroupAffine,
            PolynomialCommitment = crypto::PolynomialCommitmentImpl,
            PubPoly = crypto::PubPolyImpl,
        > + Clone
        + Send
        + Sync
        + 'static,
    SignImpl: ThresholdSigner<
            ShareValue = ScalarField,
            PublicKey = GroupAffine,
            DistKeyShare = DistKeyShare<ScalarField>,
            PubPoly = D::PubPoly,
            Signature = SignaturePoint,
            SigShare = PubShare<SigShareInner>,
        > + Send
        + Sync
        + 'static,
{
    let ring_post = app_state
        .bulletin
        .read(observation.ring_id.clone(), BulletinKind::Ring)
        .await
        .map_err(|error| ReportingError::Bulletin(error.to_string()))?;
    let ring = RingPayload::try_from(ring_post)
        .map_err(|error| ReportingError::InvalidReport(error.to_string()))?;

    let payload = NodeOfflineV1 {
        origin_protocol: observation.origin_protocol,
        origin_protocol_version: observation.origin_protocol_version,
        failure_stage: observation.failure_stage,
    };
    let envelope = ReportEnvelope {
        domain: REPORT_DOMAIN.to_string(),
        framework_version: REPORT_FRAMEWORK_VERSION,
        report_type: NODE_OFFLINE_REPORT_TYPE.to_string(),
        report_version: NODE_OFFLINE_REPORT_VERSION,
        chain_id: app_state.bulletin.chain_id(),
        ring_id: observation.ring_id.clone(),
        ring_pk: ring.ring_pk.clone(),
        ring_state_sha256: ring_state_sha256(&ring),
        reporter_node_key: app_state.node_key.clone(),
        accused_node_key: observation.accused_node_key.clone(),
        accused_peer_id: observation.accused_peer_id,
        observed_at: observation.observed_at,
        expires_at: observation.observed_at.saturating_add(REPORT_TTL_SECS),
        payload: payload.canonical_bytes(),
    };

    let now = current_unix_time()?;
    app_state
        .reporting_state
        .registry
        .validate(
            &envelope,
            &ReportValidationContext {
                local_node_key: app_state.node_key.clone(),
                requester_peer_id: None,
                network: Arc::clone(&app_state.network),
                peer_connection_pool: Arc::clone(&app_state.peer_connection_pool),
                bulletin: Arc::clone(&app_state.bulletin),
                routes,
                now,
                mode: ReportValidationMode::ReporterObservation,
            },
        )
        .await?;

    let node_routes = resolve_node_routes(&app_state.bulletin, &ring.peer_node_keys)
        .await
        .map_err(ReportingError::InvalidReport)?;
    let peer_ids = peer_ids_from_routes(&node_routes);
    let ring_pk_bytes = hex::decode(&ring.ring_pk)
        .map_err(|error| ReportingError::Serialization(error.to_string()))?;
    let poly_state = crate::ring_state::RingPolyState::load_from_ring_pk_hex(
        &app_state.local_storage,
        &ring.ring_pk,
    )
    .map_err(ReportingError::InvalidReport)?;
    let ring_config = RingConfig {
        ring_id: observation.ring_id,
        ring_pk_bytes,
        peer_ids,
        peer_node_keys: ring.peer_node_keys,
        threshold: ring.threshold as usize,
        total_participants: node_routes.len(),
        public_polynomial_hex: poly_state.public_polynomial,
    };

    let report_id = envelope.report_id();
    let message = envelope.canonical_bytes();
    let mut excluded_node_keys = HashSet::new();
    excluded_node_keys.insert(envelope.accused_node_key.clone());
    let options = SigningOptions { excluded_node_keys };
    let coordinator = SignCoordinator::<D, SignImpl>::with_routes(app_state.clone(), routes);
    let response = coordinator
        .initiate_signing(
            format!("report-{report_id}"),
            ring_config,
            message,
            SignContext::Report(Box::new(ReportSigningContext {
                envelope: envelope.clone(),
            })),
            options,
        )
        .await
        .map_err(|error| ReportingError::Signing(error.to_string()))?;
    let sign_response: SignResponse = serde_json::from_slice(&response)
        .map_err(|error| ReportingError::Serialization(error.to_string()))?;

    app_state
        .reporting_state
        .sink
        .submit(SignedReport {
            report: envelope,
            report_id,
            signature_scheme: THRESHOLD_SIGNATURE_SCHEME.to_string(),
            signature: sign_response.signature,
        })
        .await
}

pub async fn validate_signing_report<D>(
    app_state: &Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    context: &ReportSigningContext,
    requester_peer_id: network::PeerId,
    perform_health_probe: bool,
) -> Result<String>
where
    D: Dkg + Clone + Send + Sync + 'static,
{
    let now = current_unix_time()?;
    let canonical = context.envelope.canonical_bytes();
    app_state
        .reporting_state
        .registry
        .validate(
            &context.envelope,
            &ReportValidationContext {
                local_node_key: app_state.node_key.clone(),
                requester_peer_id: Some(requester_peer_id),
                network: Arc::clone(&app_state.network),
                peer_connection_pool: Arc::clone(&app_state.peer_connection_pool),
                bulletin: Arc::clone(&app_state.bulletin),
                routes,
                now,
                mode: ReportValidationMode::IndependentSigner {
                    perform_health_probe,
                },
            },
        )
        .await?;
    if canonical.is_empty() {
        return Err(ReportingError::InvalidReport(
            "canonical report cannot be empty".to_string(),
        ));
    }
    Ok(context.envelope.ring_pk.clone())
}

fn current_unix_time() -> Result<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| ReportingError::InvalidReport(error.to_string()))
}

#[cfg(test)]
mod tests;
