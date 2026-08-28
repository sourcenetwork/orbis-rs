mod nonce;
mod signing;

use crate::app_state::AppState;
use crate::helpers::ring::RingConfig;
use crate::reporting::v0::observation::{
    offline_observation_from_sign_error_scoped, ReportObservation,
};
use crate::reporting::v0::queue_report;
use crate::reporting::v0::types::CommitteeScope;
use crate::sign::v0::error::SignError;
use crate::sign::v0::messages::SignContext;
use crypto::r#trait::{DistKeyShare, Dkg, PubShare, ThresholdSigner};
use crypto::{GroupAffine as G1Affine, ScalarField as Fr, SigShareInner, SignaturePoint};
use std::sync::Arc;

pub(super) fn queue_sign_offline_report<D, S>(
    app_state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    ring: &RingConfig,
    peer_id: &str,
    error: &SignError,
    session_id: &str,
    context: &SignContext,
    source: &'static str,
) where
    D: Dkg<ShareValue = Fr, PublicKey = G1Affine> + Clone + Send + Sync + 'static,
    S: ThresholdSigner<
            ShareValue = Fr,
            PublicKey = G1Affine,
            DistKeyShare = DistKeyShare<Fr>,
            PubPoly = D::PubPoly,
            Signature = SignaturePoint,
            SigShare = PubShare<SigShareInner>,
        > + Send
        + Sync
        + 'static,
{
    // Report signing is the terminal fault-reporting path. If a peer fails
    // while validating or signing a report, do not recursively create reports
    // about report failures.
    let Some((origin_protocol, accused_scope, signing_scope)) = sign_reporting_scopes(context)
    else {
        return;
    };

    let Some(observation) = offline_observation_from_sign_error_scoped(
        ring,
        peer_id,
        error,
        origin_protocol,
        routes.version,
        accused_scope,
        signing_scope,
        session_id,
    ) else {
        return;
    };

    let peer_id = peer_id.to_string();
    let _handle = tokio::spawn(async move {
        let result = queue_report::<D, S>(
            app_state,
            routes,
            ReportObservation::NodeOffline(observation),
        )
        .await;
        if let Err(error) = result {
            tracing::warn!(
                peer_id = %peer_id,
                error = %error,
                source,
                "Failed to queue sign offline report observation"
            );
        }
    });
}

/// Returns a closure suitable for `crate::reporting::v0::spawn_error_drain` that maps
/// a `(peer_id, SignError)` pair to an optional `ReportObservation`, reusing the same
/// recursive-report guard as `queue_sign_offline_report`.
pub(super) fn make_sign_drain_observation(
    ring: RingConfig,
    context: SignContext,
    session_id: String,
    version: u64,
) -> impl Fn(String, SignError) -> Option<ReportObservation> {
    move |peer_id, e| {
        let (origin_protocol, accused_scope, signing_scope) = sign_reporting_scopes(&context)?;
        offline_observation_from_sign_error_scoped(
            &ring,
            &peer_id,
            &e,
            origin_protocol,
            version,
            accused_scope,
            signing_scope,
            &session_id,
        )
        .map(ReportObservation::NodeOffline)
    }
}

fn sign_reporting_scopes(
    context: &SignContext,
) -> Option<(&'static str, CommitteeScope, CommitteeScope)> {
    match context {
        // Report signing is the terminal fault-reporting path. If a peer fails
        // while validating or signing a report, do not recursively create
        // reports about report failures.
        SignContext::Report(_) => None,
        SignContext::RefreshHealthCheck(_) => Some((
            "pss_refresh",
            CommitteeScope::Current,
            CommitteeScope::Current,
        )),
        SignContext::RingReshareUpdate(_) => Some((
            "pss_reshare",
            CommitteeScope::PendingNew,
            CommitteeScope::PendingNew,
        )),
        SignContext::Bulletin { .. } | SignContext::Policy(_) => {
            Some(("sign", CommitteeScope::Current, CommitteeScope::Current))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{make_sign_drain_observation, sign_reporting_scopes};
    use crate::helpers::ring::RingConfig;
    use crate::reporting::v0::observation::ReportObservation;
    use crate::reporting::v0::types::{
        CommitteeScope, NodeOffline, ReportEnvelope, ReportSigningContext,
        NODE_OFFLINE_REPORT_TYPE, REPORT_DOMAIN, REPORT_TTL_SECS,
    };
    use crate::sign::v0::error::SignError;
    use crate::sign::v0::messages::SignContext;

    fn stub_envelope() -> ReportEnvelope {
        ReportEnvelope {
            domain: REPORT_DOMAIN.to_string(),
            report_type: NODE_OFFLINE_REPORT_TYPE.to_string(),
            chain_id: "chain".to_string(),
            ring_id: "ring".to_string(),
            ring_pk: "pk".to_string(),
            ring_state_sha256: "00".repeat(32),
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

    #[test]
    fn report_sign_context_has_no_reporting_scope() {
        let ctx = SignContext::Report(Box::new(ReportSigningContext {
            envelope: stub_envelope(),
            inline_document: None,
        }));
        assert!(
            sign_reporting_scopes(&ctx).is_none(),
            "SignContext::Report must not trigger recursive offline reporting"
        );
    }

    #[test]
    fn bulletin_and_policy_contexts_use_sign_scope() {
        let ctx = SignContext::Bulletin {
            object_id: "x".to_string(),
        };
        let (protocol, accused, signing) = sign_reporting_scopes(&ctx).unwrap();
        assert_eq!(protocol, "sign");
        assert_eq!(accused, CommitteeScope::Current);
        assert_eq!(signing, CommitteeScope::Current);
    }

    #[test]
    fn sign_drain_observation_uses_request_id_as_session_id() {
        let ring = RingConfig {
            ring_id: "ring".to_string(),
            ring_pk_bytes: Vec::new(),
            peer_ids: vec!["aa".repeat(32)],
            peer_node_keys: vec!["accused".to_string()],
            threshold: 1,
            total_participants: 1,
            public_polynomial_hex: String::new(),
        };
        let to_observation = make_sign_drain_observation(
            ring,
            SignContext::Bulletin {
                object_id: "object".to_string(),
            },
            "sign-request-1".to_string(),
            7,
        );

        let ReportObservation::NodeOffline(observation) =
            to_observation("aa".repeat(32), SignError::Timeout("timeout".to_string())).unwrap()
        else {
            panic!("expected node_offline observation");
        };

        assert_eq!(observation.origin_protocol, "sign");
        assert_eq!(observation.session_id, "sign-request-1");
    }
}
