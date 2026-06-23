mod nonce;
mod signing;

use crate::app_state::AppState;
use crate::helpers::ring::RingConfig;
use crate::reporting::observation::{offline_observation_from_sign_error, ReportObservation};
use crate::reporting::queue_report;
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
    if matches!(context, SignContext::Report(_)) {
        return;
    }

    let Some(observation) =
        offline_observation_from_sign_error(ring, peer_id, error, routes.version)
    else {
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
