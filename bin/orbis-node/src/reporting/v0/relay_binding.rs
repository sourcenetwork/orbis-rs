use super::pipeline::{current_unix_time, queue_report};
use crate::app_state::AppState;
use crate::constants::RELAY_CHECK_MAX_DRIFT_SECS;
use crate::helpers::identity::determine_session_node_id;
use crate::reporting::v0::error::{ReportingError, Result};
use crate::reporting::v0::observation::ReportObservation;
use crate::reporting::v0::types::{
    ring_state_sha256, CommitteeScope, RelayRequestStatement, ReportedDocumentEvidence,
    RELAY_REQUEST_DOMAIN, UNAUTHORIZED_REQUEST_REPORT_TYPE,
};
use authz::vera::ValidWindow;
use bulletin::r#trait::RingPayload;
use common::blockchain::{sign_node_message_with_hex_key, verify_node_message};
use crypto::r#trait::{DistKeyShare, Dkg, PubShare, ThresholdSigner};
use crypto::{GroupAffine, ScalarField, SigShareInner, SignaturePoint};
use std::sync::Arc;

/// Build and queue an `unauthorized_request` report attributing the node that relayed a Sign/PRE
/// request whose ACP re-check failed on this node. `statement` + `relay_signature` are the relayer's
/// signed record of the request; `checked_at_anchor` is an opaque Authz anchor token whose format
/// may vary by backend (not necessarily a block height). `inline_document` is this responder's own
/// view of the request's document — `Some` only for a PRE request the relayer marked
/// `document_inline` — carried out-of-band to co-signers, never into the on-chain envelope.
#[allow(clippy::too_many_arguments)]
pub async fn queue_unauthorized_request_report<D, S>(
    app_state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    statement: crate::reporting::v0::types::RelayRequestStatement,
    relay_signature: Vec<u8>,
    checked_at_anchor: String,
    inline_document: Option<ReportedDocumentEvidence>,
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
        inline_document,
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
#[derive(Clone)]
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
    /// Whether this node resolved the request's document inline (`ctx.document`) rather than from
    /// the bulletin. The statement's `document_inline` must match in both directions: a relayer
    /// claiming inline for a bulletin-sourced request (or the reverse) is itself a binding
    /// mismatch.
    pub document_inline: bool,
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

    if statement.document_inline != expected.document_inline {
        return Err(ReportingError::InvalidReport(
            "relay request statement does not bind to failed request: document_inline mismatch"
                .to_string(),
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
/// the PRE and Sign responders. `inline_document` is this responder's own view of the request's
/// document, `Some` only when the relayed PRE request carried its document inline
/// (`statement.document_inline`); it rides out-of-band to co-signers, never into the on-chain
/// envelope. Always `None` for Sign.
pub async fn report_unauthorized_relay<D, S>(
    app_state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    statement: RelayRequestStatement,
    relay_signature: Vec<u8>,
    now: u64,
    inline_document: Option<ReportedDocumentEvidence>,
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

    // A leader that keeps replaying the same captured, ACP-failing request forces
    // every responder that re-derives this far to re-run this whole path. Ask the
    // chain whether this exact incident was already accepted before paying for a
    // full threshold-signing round that would only end in ErrReportAlreadyAccepted.
    let already_accepted = app_state
        .bulletin
        .accepted_report_session(
            &statement.ring_id,
            UNAUTHORIZED_REQUEST_REPORT_TYPE,
            &statement.origin_protocol,
            &statement.relayer_node_key,
            &statement.request_id,
        )
        .await
        .unwrap_or_else(|error| {
            tracing::warn!(
                request_id = %statement.request_id,
                %error,
                "Failed to check accepted_report_session; proceeding without the pre-check"
            );
            false
        });
    if already_accepted {
        tracing::debug!(
            request_id = %statement.request_id,
            accused = %statement.relayer_node_key,
            "Skipping unauthorized_request report: session already accepted on-chain"
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
        inline_document,
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
    /// `true` when the relayed request's document was supplied inline rather than read from the
    /// bulletin. The evidence itself is not signed into the statement — it travels out-of-band in
    /// `ReportSigningContext` (see `ReportedDocumentEvidence`).
    pub document_inline: bool,
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
        document_inline: inputs.document_inline,
    };
    let signature = sign_node_message_with_hex_key(&signing_key_hex, &statement.canonical_bytes())
        .map_err(|error| ReportingError::InvalidReport(error.to_string()))?;
    Ok((statement, signature))
}
