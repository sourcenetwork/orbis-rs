pub mod error;
pub mod health;
pub mod observation;
pub mod registry;
pub mod sink;
pub mod state;
pub mod types;

use crate::app_state::AppState;
use crate::reporting::v0::error::{ReportingError, Result};
use crate::reporting::v0::observation::ReportObservation;
use crate::reporting::v0::registry::{
    PreparedReport, ReportPreparationContext, ReportValidationContext, ReportValidationMode,
};
use crate::reporting::v0::types::{ReportSigningContext, SignedReport};
use crate::sign::v0::coordinator::{SignCoordinator, SignResponse};
use crate::sign::v0::messages::SignContext;
use crypto::r#trait::{DistKeyShare, Dkg, PubShare, ThresholdSigner};
use crypto::{GroupAffine, ScalarField, SigShareInner, SignaturePoint, THRESHOLD_SIGNATURE_SCHEME};
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinSet;

pub async fn queue_report<D, S>(
    app_state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    observation: ReportObservation,
) -> Result<bool>
where
    D: Dkg<ShareValue = ScalarField, PublicKey = GroupAffine> + Clone + Send + Sync + 'static,
    S: ThresholdSigner<
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
                create_report::<D, S>(app_state, routes, observation, Arc::clone(&handler)).await
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

/// Build and queue an `unauthorized_request` report attributing the node that relayed a Sign/PRE
/// request whose ACP re-check failed on this node. `statement` + `relay_signature` are the relayer's
/// signed record of the request; `anchor_block_height` is the height the ACP refutation is anchored
/// to (the reporter's current chain height ≈ the relay height).
pub async fn queue_unauthorized_request_report<D, S>(
    app_state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    statement: crate::reporting::v0::types::RelayRequestStatement,
    relay_signature: Vec<u8>,
) -> Result<()>
where
    D: Dkg<ShareValue = ScalarField, PublicKey = GroupAffine> + Clone + Send + Sync + 'static,
    S: ThresholdSigner<
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
    use crate::reporting::v0::observation::UnauthorizedRequestObservation;
    use crate::reporting::v0::types::{UnauthorizedRequestPayload, CHAIN_BLOCK_GRACE_SECS};
    use bulletin::r#trait::{BulletinKind, NodeInfo};

    let accused_node_key = statement.relayer_node_key.clone();
    let node_info_post = app_state
        .bulletin
        .read(accused_node_key.clone(), BulletinKind::NodeInfo)
        .await
        .map_err(|error| ReportingError::Bulletin(error.to_string()))?;
    let node_info = NodeInfo::try_from(node_info_post)
        .map_err(|error| ReportingError::InvalidReport(error.to_string()))?;

    let observed_at = statement.signed_at.saturating_sub(CHAIN_BLOCK_GRACE_SECS);
    let ring_id = statement.ring_id.clone();
    let observation = UnauthorizedRequestObservation {
        ring_id,
        accused_node_key,
        accused_peer_id: node_info.peer_id,
        observed_at,
        payload: UnauthorizedRequestPayload {
            statement,
            relay_signature,
        },
    };
    queue_report::<D, S>(
        app_state,
        routes,
        ReportObservation::UnauthorizedRequest(Box::new(observation)),
    )
    .await?;
    Ok(())
}

/// Drain remaining JoinSet tasks in the background so peer errors that arrive
/// after the collection loop broke early (threshold met) still reach `queue_report`.
/// Call this instead of `drop(set)` after a JoinSet threshold-collection loop.
pub fn spawn_error_drain<D, S, T, E, F>(
    mut set: JoinSet<(String, std::result::Result<T, E>)>,
    app_state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    timeout: Duration,
    to_observation: F,
) where
    D: Dkg<ShareValue = ScalarField, PublicKey = GroupAffine> + Clone + Send + Sync + 'static,
    S: ThresholdSigner<
            ShareValue = ScalarField,
            PublicKey = GroupAffine,
            DistKeyShare = DistKeyShare<ScalarField>,
            PubPoly = D::PubPoly,
            Signature = SignaturePoint,
            SigShare = PubShare<SigShareInner>,
        > + Send
        + Sync
        + 'static,
    T: Send + 'static,
    E: Send + 'static,
    F: Fn(String, E) -> Option<ReportObservation> + Send + 'static,
{
    tokio::spawn(async move {
        let deadline = tokio::time::Instant::now() + timeout;
        while let Ok(Some(res)) = tokio::time::timeout_at(deadline, set.join_next()).await {
            match res {
                Ok((peer_id, Err(e))) => {
                    if let Some(obs) = to_observation(peer_id.clone(), e) {
                        let _ = queue_report::<D, S>(app_state.clone(), routes, obs)
                            .await
                            .inspect_err(|error| {
                                tracing::warn!(
                                    peer_id = %peer_id,
                                    error = %error,
                                    "Failed to queue offline report observation (post-threshold drain)"
                                );
                            });
                    }
                }
                Err(join_err) => {
                    tracing::error!(error = ?join_err, "Peer task panicked in error drain");
                }
                Ok((_, Ok(_))) => {}
            }
        }
    });
}

async fn create_report<D, S>(
    app_state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    observation: ReportObservation,
    handler: Arc<dyn crate::reporting::v0::registry::ReportHandler>,
) -> Result<()>
where
    D: Dkg<ShareValue = ScalarField, PublicKey = GroupAffine> + Clone + Send + Sync + 'static,
    S: ThresholdSigner<
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
                authz: Arc::clone(&app_state.authz),
                local_storage: app_state.local_storage.clone(),
                routes,
                now,
                mode: ReportValidationMode::ReporterObservation,
            },
        )
        .await?;

    sign_and_submit_report::<D, S>(app_state, routes, prepared).await
}

async fn sign_and_submit_report<D, S>(
    app_state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    prepared: PreparedReport,
) -> Result<()>
where
    D: Dkg<ShareValue = ScalarField, PublicKey = GroupAffine> + Clone + Send + Sync + 'static,
    S: ThresholdSigner<
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
    let coordinator = SignCoordinator::<D, S>::with_routes(app_state.clone(), routes);
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
    if sign_response.signature.is_empty() {
        return Err(ReportingError::Signing(
            "threshold signature response was empty".to_string(),
        ));
    }

    sink::submit(
        SignedReport {
            report: prepared.envelope,
            report_id,
            signature_scheme: THRESHOLD_SIGNATURE_SCHEME.to_string(),
            signature: sign_response.signature,
        },
        &*app_state.bulletin,
    )
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
                authz: Arc::clone(&app_state.authz),
                local_storage: app_state.local_storage.clone(),
                routes,
                now,
                mode: ReportValidationMode::IndependentSigner {
                    perform_health_probe,
                },
            },
        )
        .await?;
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
