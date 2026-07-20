pub mod error;
pub mod health;
pub mod observation;
pub mod registry;
pub mod sink;
pub mod state;
pub mod types;

use crate::app_state::AppState;
use crate::constants::RELAY_CHECK_MAX_DRIFT_SECS;
use crate::helpers::identity::determine_session_node_id;
use crate::reporting::v0::error::{ReportingError, Result};
use crate::reporting::v0::observation::ReportObservation;
use crate::reporting::v0::registry::{
    PreparedReport, ReportPreparationContext, ReportValidationContext, ReportValidationMode,
};
use crate::reporting::v0::types::{
    ring_state_sha256, CommitteeScope, RelayRequestStatement, ReportSigningContext, SignedReport,
    RELAY_REQUEST_DOMAIN,
};
use crate::sign::v0::coordinator::{SignCoordinator, SignResponse};
use crate::sign::v0::messages::SignContext;
use authz::sourcehub::ValidWindow;
use bulletin::r#trait::RingPayload;
use common::blockchain::{sign_node_message_with_hex_key, verify_node_message};
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
                tracing::warn!(
                    report_type,
                    error = %error,
                    "Report attempt did not complete"
                );
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
/// signed record of the request; `checked_at_anchor` is an opaque Authz anchor token whose format
/// may vary by backend (not necessarily a block height).
pub async fn queue_unauthorized_request_report<D, S>(
    app_state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    statement: crate::reporting::v0::types::RelayRequestStatement,
    relay_signature: Vec<u8>,
    checked_at_anchor: String,
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
            checked_at_anchor,
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

#[derive(Clone, Copy, Debug)]
pub enum RelayRequestTimestampBinding {
    Exact(Option<u64>),
    SignPolicy,
}

/// Responder-observed request fields that a relayer's signed statement must
/// describe before we can use it as `unauthorized_request` evidence.
pub struct RelayRequestBinding {
    pub ring: RingPayload,
    pub ring_id: String,
    pub protocol_version: u64,
    pub chain_id: String,
    pub request_id: String,
    pub origin_protocol: String,
    pub actor_id: String,
    pub object_id: String,
    pub user_signed_at: u64,
    pub valid_window: Option<ValidWindow>,
    pub timestamp: RelayRequestTimestampBinding,
    pub from_node_id: u32,
}

/// Ensure the signed relay statement is about the exact request that failed this
/// responder's ACP re-check. Without this binding, a relayer could attach a
/// statement for an authorized actor/object pair to an unrelated unauthorized
/// request and make co-signers reject the report.
pub fn validate_relay_request_binding(
    statement: &RelayRequestStatement,
    expected: RelayRequestBinding,
) -> Result<()> {
    if statement.chain_id != expected.chain_id {
        return Err(relay_binding_mismatch(
            "chain_id",
            &expected.chain_id,
            &statement.chain_id,
        ));
    }
    if statement.ring_id != expected.ring_id {
        return Err(relay_binding_mismatch(
            "ring_id",
            &expected.ring_id,
            &statement.ring_id,
        ));
    }
    if statement.ring_pk != expected.ring.ring_pk {
        return Err(relay_binding_mismatch(
            "ring_pk",
            &expected.ring.ring_pk,
            &statement.ring_pk,
        ));
    }
    let expected_ring_state_sha256 = ring_state_sha256(&expected.ring);
    if statement.ring_state_sha256 != expected_ring_state_sha256 {
        return Err(relay_binding_mismatch(
            "ring_state_sha256",
            &expected_ring_state_sha256,
            &statement.ring_state_sha256,
        ));
    }
    if statement.protocol_version != expected.protocol_version {
        return Err(relay_binding_mismatch(
            "protocol_version",
            expected.protocol_version,
            statement.protocol_version,
        ));
    }
    if statement.request_id != expected.request_id {
        return Err(relay_binding_mismatch(
            "request_id",
            &expected.request_id,
            &statement.request_id,
        ));
    }
    if statement.origin_protocol != expected.origin_protocol {
        return Err(relay_binding_mismatch(
            "origin_protocol",
            &expected.origin_protocol,
            &statement.origin_protocol,
        ));
    }
    if statement.actor_id != expected.actor_id {
        return Err(relay_binding_mismatch(
            "actor_id",
            &expected.actor_id,
            &statement.actor_id,
        ));
    }
    if statement.object_id != expected.object_id {
        return Err(relay_binding_mismatch(
            "object_id",
            &expected.object_id,
            &statement.object_id,
        ));
    }
    if statement.user_signed_at != expected.user_signed_at {
        return Err(relay_binding_mismatch(
            "user_signed_at",
            expected.user_signed_at,
            statement.user_signed_at,
        ));
    }

    let expected_valid_window = expected
        .valid_window
        .as_ref()
        .map(|window| (window.start, window.end));
    let actual_valid_window = match (statement.valid_window_start, statement.valid_window_end) {
        (Some(start), Some(end)) => Some((start, end)),
        (None, None) => None,
        _ => {
            return Err(ReportingError::InvalidReport(
                "relay request statement valid_window is only partially set".to_string(),
            ))
        }
    };
    if actual_valid_window != expected_valid_window {
        return Err(relay_binding_mismatch(
            "valid_window",
            expected_valid_window,
            actual_valid_window,
        ));
    }

    if statement.from_node_id != expected.from_node_id {
        return Err(relay_binding_mismatch(
            "from_node_id",
            expected.from_node_id,
            statement.from_node_id,
        ));
    }
    let relayer_node_id =
        determine_session_node_id(&statement.relayer_node_key, &expected.ring.peer_node_keys)
            .ok_or_else(|| {
                ReportingError::InvalidReport(
                    "relay request statement relayer_node_key is not in the ring".to_string(),
                )
            })?;
    if statement.from_node_id != relayer_node_id {
        return Err(relay_binding_mismatch(
            "relayer_node_id",
            relayer_node_id,
            statement.from_node_id,
        ));
    }

    match expected.timestamp {
        RelayRequestTimestampBinding::Exact(expected_timestamp) => {
            if statement.timestamp != expected_timestamp {
                return Err(relay_binding_mismatch(
                    "timestamp",
                    expected_timestamp,
                    statement.timestamp,
                ));
            }
        }
        RelayRequestTimestampBinding::SignPolicy => {
            if expected_valid_window.is_none() {
                if statement.timestamp.is_some() {
                    return Err(relay_binding_mismatch(
                        "timestamp",
                        None::<u64>,
                        statement.timestamp,
                    ));
                }
            } else {
                let timestamp = statement.timestamp.ok_or_else(|| {
                    ReportingError::InvalidReport(
                        "relay request statement timestamp is required for windowed sign requests"
                            .to_string(),
                    )
                })?;
                if timestamp.abs_diff(statement.signed_at) > RELAY_CHECK_MAX_DRIFT_SECS {
                    return Err(ReportingError::InvalidReport(format!(
                        "relay request statement timestamp {} drifts from signed_at {} by more than {}s",
                        timestamp, statement.signed_at, RELAY_CHECK_MAX_DRIFT_SECS
                    )));
                }
            }
        }
    }

    Ok(())
}

fn relay_binding_mismatch(
    field: &str,
    expected: impl std::fmt::Debug,
    actual: impl std::fmt::Debug,
) -> ReportingError {
    ReportingError::InvalidReport(format!(
        "relay request statement does not bind to failed request: {field} expected {expected:?}, got {actual:?}"
    ))
}

/// Attribute the relaying node when a relayed request fails a responder's ACP re-check.
///
/// Best-effort: verifies the relay statement is fresh and signed by the named relayer, captures the
/// current ACP anchor, and queues an `unauthorized_request` report. Any failure here is logged and
/// swallowed — the caller rejects the request regardless of whether a report is produced. Shared by
/// the PRE and Sign responders.
pub async fn report_unauthorized_relay<D, S>(
    app_state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    statement: RelayRequestStatement,
    relay_signature: Vec<u8>,
    now: u64,
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
{
    // Reject stale statements: the relay moment must be within the drift window of now, so the
    // anchor we capture below genuinely reflects the ACP state around the relay.
    let drift = now.abs_diff(statement.signed_at);
    if drift > RELAY_CHECK_MAX_DRIFT_SECS {
        tracing::warn!(
            request_id = %statement.request_id,
            drift,
            "Skipping unauthorized_request report: relay statement is stale"
        );
        return;
    }

    // The relayer signed its own statement; verify before attributing it.
    if let Err(error) = verify_node_message(
        &statement.relayer_node_key,
        &statement.canonical_bytes(),
        &relay_signature,
    ) {
        tracing::warn!(
            request_id = %statement.request_id,
            %error,
            "Skipping unauthorized_request report: relay signature is invalid"
        );
        return;
    }

    // Capture the ACP anchor at ~the relay moment (real now — cannot point at a favorable past).
    let checked_at_anchor = match app_state.authz.current_anchor().await {
        Ok(anchor) => anchor,
        Err(error) => {
            tracing::warn!(
                request_id = %statement.request_id,
                %error,
                "Skipping unauthorized_request report: failed to capture ACP anchor"
            );
            return;
        }
    };

    if let Err(error) = queue_unauthorized_request_report::<D, S>(
        app_state,
        routes,
        statement,
        relay_signature,
        checked_at_anchor,
    )
    .await
    {
        tracing::warn!(%error, "Failed to queue unauthorized_request report");
    }
}

/// Inputs to [`build_signed_relay_statement`], captured by the coordinator right after its own ACP
/// check passes and just before it relays a Sign/PRE request.
pub struct RelayStatementInputs {
    pub ring: RingPayload,
    /// Ring bulletin id (from the document / key-derivation payload).
    pub ring_id: String,
    pub protocol_version: u64,
    pub chain_id: String,
    pub request_id: String,
    /// `"pre"` or `"sign"`.
    pub origin_protocol: String,
    /// The relaying node's chain key.
    pub relayer_node_key: String,
    /// The caller (JWT issuer) whose access was checked.
    pub actor_id: String,
    /// PRE object id or Sign derivation id.
    pub object_id: String,
    /// The caller's JWT `iat`.
    pub user_signed_at: u64,
    /// The timestamp the relayer used for its ACP check (PRE: document timestamp; Sign: now-or-none).
    pub acp_timestamp: Option<u64>,
    pub valid_window: Option<ValidWindow>,
}

/// Build and sign the relayer's `RelayRequestStatement` — its self-incriminating record that it
/// forwarded this request. Signed with the node chain key so a peer's `unauthorized_request` report
/// can attribute the relayer. `from_node_id` is derived exactly as the refutation re-derives it.
pub fn build_signed_relay_statement(
    inputs: RelayStatementInputs,
    local_storage: &local_storage::LocalStorageImpl,
) -> Result<(RelayRequestStatement, Vec<u8>)> {
    use local_storage::r#trait::{LocalStorage, LocalStorageKeys};
    let signing_key = local_storage
        .get_encrypted(LocalStorageKeys::NodeSigningKey)
        .map_err(|error| {
            ReportingError::InvalidReport(format!("failed to read node signing key: {error}"))
        })?
        .ok_or_else(|| {
            ReportingError::InvalidReport("node signing key is not configured".to_string())
        })?;
    let signing_key_hex = String::from_utf8(signing_key.to_vec()).map_err(|error| {
        ReportingError::InvalidReport(format!("stored node signing key is not utf-8: {error}"))
    })?;

    let signed_at = current_unix_time()?;
    let from_node_id =
        determine_session_node_id(&inputs.relayer_node_key, &inputs.ring.peer_node_keys)
            .ok_or_else(|| {
                ReportingError::InvalidReport(format!(
                    "relayer node key {} is not in ring {}; cannot build relay request evidence",
                    inputs.relayer_node_key, inputs.ring_id
                ))
            })?;
    let (valid_window_start, valid_window_end) = match &inputs.valid_window {
        Some(window) => (Some(window.start), Some(window.end)),
        None => (None, None),
    };
    let statement = RelayRequestStatement {
        domain: RELAY_REQUEST_DOMAIN.to_string(),
        chain_id: inputs.chain_id,
        ring_id: inputs.ring_id,
        ring_pk: inputs.ring.ring_pk.clone(),
        ring_state_sha256: ring_state_sha256(&inputs.ring),
        protocol_version: inputs.protocol_version,
        request_id: inputs.request_id,
        signed_at,
        user_signed_at: inputs.user_signed_at,
        relayer_node_key: inputs.relayer_node_key,
        origin_protocol: inputs.origin_protocol,
        accused_committee_scope: CommitteeScope::Current,
        signing_committee_scope: CommitteeScope::Current,
        from_node_id,
        actor_id: inputs.actor_id,
        object_id: inputs.object_id,
        valid_window_start,
        valid_window_end,
        timestamp: inputs.acp_timestamp,
    };
    let signature = sign_node_message_with_hex_key(&signing_key_hex, &statement.canonical_bytes())
        .map_err(|error| ReportingError::InvalidReport(error.to_string()))?;
    Ok((statement, signature))
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
