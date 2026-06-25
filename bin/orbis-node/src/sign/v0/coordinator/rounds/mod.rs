mod nonce;
mod signing;

use crate::app_state::AppState;
use crate::helpers::ring::RingConfig;
use crate::reporting::observation::{
    offline_observation_from_sign_error_scoped, ReportObservation,
};
use crate::reporting::queue_report;
use crate::reporting::types::CommitteeScope;
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

/// Returns a closure suitable for `crate::reporting::spawn_error_drain` that maps
/// a `(peer_id, SignError)` pair to an optional `ReportObservation`, reusing the same
/// recursive-report guard as `queue_sign_offline_report`.
pub(super) fn make_sign_drain_observation(
    ring: RingConfig,
    context: SignContext,
    version: u64,
) -> impl Fn(String, SignError) -> Option<ReportObservation> {
    move |peer_id, e| {
        let Some((origin_protocol, accused_scope, signing_scope)) = sign_reporting_scopes(&context)
        else {
            return None;
        };
        offline_observation_from_sign_error_scoped(
            &ring,
            &peer_id,
            &e,
            origin_protocol,
            version,
            accused_scope,
            signing_scope,
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
