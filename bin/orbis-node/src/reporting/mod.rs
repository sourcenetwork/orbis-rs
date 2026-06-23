pub mod error;
pub mod health;
pub mod observation;
pub mod registry;
pub mod sink;
pub mod state;
pub mod types;

use crate::app_state::AppState;
use crate::reporting::error::{ReportingError, Result};
use crate::reporting::observation::ReportObservation;
use crate::reporting::registry::{
    PreparedReport, ReportPreparationContext, ReportValidationContext, ReportValidationMode,
};
use crate::reporting::types::{ReportSigningContext, SignedReport};
use crate::sign::v0::coordinator::{SignCoordinator, SignResponse};
use crate::sign::v0::messages::SignContext;
use crypto::r#trait::{DistKeyShare, Dkg, PubShare, ThresholdSigner};
use crypto::{
    GroupAffine, ScalarField, SigShareInner, SignImpl, SignaturePoint, THRESHOLD_SIGNATURE_SCHEME,
};
use std::sync::Arc;

pub async fn queue_report<D>(
    app_state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    observation: ReportObservation,
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
    let report_type = observation.report_type();
    let handler = app_state
        .reporting_state
        .registry
        .handler_for_observation(&observation)?;
    let key = handler.in_flight_key(&observation)?;
    let state = Arc::clone(&app_state.reporting_state);
    let outcome = state
        .spawn(key, async move {
            if let Err(error) =
                create_report(app_state, routes, observation, Arc::clone(&handler)).await
            {
                crate::metrics::REPORT_ATTEMPTS_TOTAL
                    .with_label_values(&[report_type, "failed"])
                    .inc();
                tracing::warn!(error = %error, "Offline report attempt did not complete");
            } else {
                crate::metrics::REPORT_ATTEMPTS_TOTAL
                    .with_label_values(&[report_type, "signed"])
                    .inc();
            }
        })
        .await?;
    crate::metrics::REPORT_ATTEMPTS_TOTAL
        .with_label_values(&[report_type, if outcome { "queued" } else { "duplicate" }])
        .inc();
    Ok(outcome)
}

async fn create_report<D>(
    app_state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    observation: ReportObservation,
    handler: Arc<dyn crate::reporting::registry::ReportHandler>,
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
    let prepared = handler
        .prepare(
            observation,
            &ReportPreparationContext {
                reporter_node_key: app_state.node_key.clone(),
                bulletin: Arc::clone(&app_state.bulletin),
                local_storage: app_state.local_storage.clone(),
            },
        )
        .await?;

    let now = current_unix_time()?;
    app_state
        .reporting_state
        .registry
        .validate(
            &prepared.envelope,
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

    sign_and_submit_report(app_state, routes, prepared).await
}

async fn sign_and_submit_report<D>(
    app_state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    prepared: PreparedReport,
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
    let report_id = prepared.envelope.report_id();
    let message = prepared.envelope.canonical_bytes();
    let coordinator = SignCoordinator::<D, SignImpl>::with_routes(app_state.clone(), routes);
    let response = coordinator
        .initiate_signing(
            format!("report-{report_id}"),
            prepared.ring_config,
            message,
            SignContext::Report(Box::new(ReportSigningContext {
                envelope: prepared.envelope.clone(),
            })),
            prepared.signing_options,
        )
        .await
        .map_err(|error| ReportingError::Signing(error.to_string()))?;
    let sign_response: SignResponse = serde_json::from_slice(&response)
        .map_err(|error| ReportingError::Serialization(error.to_string()))?;

    app_state
        .reporting_state
        .sink
        .submit(SignedReport {
            report: prepared.envelope,
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
