use crate::app_state::AppState;
use crate::constants::{
    NETWORK_MAX_CONCURRENT_INBOUND_STREAMS, NETWORK_MAX_INBOUND_STREAMS_PER_PEER_PER_SECOND,
};
use crate::dkg::v0::coordinator::DkgCoordinator;
use crate::helpers::protocol_handler::GenericProtocolHandler;
use crate::pre::v0::coordinator::PreCoordinator;
use crate::reporting::health::HealthProtocolHandler;
use crate::sign::v0::coordinator::SignCoordinator;
use network::error::Result as NetworkResult;
use network::Router;
use std::sync::Arc;

fn apply_ingress_limits(
    router_builder: Box<dyn network::RouterBuilder>,
) -> Box<dyn network::RouterBuilder> {
    router_builder
        .max_concurrent_streams(NETWORK_MAX_CONCURRENT_INBOUND_STREAMS)
        .max_streams_per_peer_per_second(NETWORK_MAX_INBOUND_STREAMS_PER_PEER_PER_SECOND)
}

/// Create a router with both DKG and PRE protocol handlers
#[cfg(test)]
pub fn create_router_with_handlers<D, T>(
    network: &Arc<dyn network::Network>,
    app_state: Arc<AppState<D>>,
) -> NetworkResult<Box<dyn Router>>
where
    D: crypto::r#trait::Dkg<
            ShareValue = crypto::ScalarField,
            PublicKey = crypto::GroupAffine,
            PolynomialCommitment = crypto::PolynomialCommitmentImpl,
            PubPoly = crypto::PubPolyImpl,
        > + Clone
        + Send
        + Sync
        + 'static,
    T: crypto::r#trait::ThresholdDealer<
            ShareValue = crypto::ScalarField,
            PublicKey = crypto::GroupAffine,
            DistKeyShare = crypto::r#trait::DistKeyShare<crypto::ScalarField>,
            Secret = crypto::r#trait::Secret,
            ReencryptReply = crypto::r#trait::ReencryptReply<
                crypto::ScalarField,
                crypto::GroupAffine,
            >,
            PubPoly = D::PubPoly,
        > + Send
        + Sync
        + 'static,
{
    let mut router_builder = apply_ingress_limits(network.create_router_builder()?);
    for version in network::SUPPORTED_PROTOCOL_VERSIONS {
        let routes = network::routes_for_version(*version)
            .expect("supported protocol version must have registered routes");
        let dkg_handler = Arc::new(GenericProtocolHandler::new(Arc::new(
            DkgCoordinator::with_routes(app_state.clone(), routes),
        )));
        let pre_handler = Arc::new(GenericProtocolHandler::new(Arc::new(
            PreCoordinator::<D, T>::with_routes(app_state.clone(), routes),
        )));
        let health_handler = Arc::new(HealthProtocolHandler);
        router_builder = router_builder.accept(routes.dkg_alpn.to_vec(), dkg_handler);
        router_builder = router_builder.accept(routes.reencrypt_alpn.to_vec(), pre_handler);
        router_builder =
            router_builder.accept(routes.reporting_health_alpn.to_vec(), health_handler);
    }
    router_builder.spawn()
}

/// Create a router with DKG, PRE, and Sign protocol handlers
pub fn create_router_with_all_handlers<D, T, S>(
    network: &Arc<dyn network::Network>,
    app_state: Arc<AppState<D>>,
) -> NetworkResult<Box<dyn Router>>
where
    D: crypto::r#trait::Dkg<
            ShareValue = crypto::ScalarField,
            PublicKey = crypto::GroupAffine,
            PolynomialCommitment = crypto::PolynomialCommitmentImpl,
            PubPoly = crypto::PubPolyImpl,
        > + Clone
        + Send
        + Sync
        + 'static,
    T: crypto::r#trait::ThresholdDealer<
            ShareValue = crypto::ScalarField,
            PublicKey = crypto::GroupAffine,
            DistKeyShare = crypto::r#trait::DistKeyShare<crypto::ScalarField>,
            Secret = crypto::r#trait::Secret,
            ReencryptReply = crypto::r#trait::ReencryptReply<
                crypto::ScalarField,
                crypto::GroupAffine,
            >,
            PubPoly = D::PubPoly,
        > + Send
        + Sync
        + 'static,
    S: crypto::r#trait::ThresholdSigner<
            ShareValue = crypto::ScalarField,
            PublicKey = crypto::GroupAffine,
            DistKeyShare = crypto::r#trait::DistKeyShare<crypto::ScalarField>,
            PubPoly = D::PubPoly,
            Signature = crypto::SignaturePoint,
            SigShare = crypto::r#trait::PubShare<crypto::SigShareInner>,
        > + Send
        + Sync
        + 'static,
{
    let mut router_builder = apply_ingress_limits(network.create_router_builder()?);
    for version in network::SUPPORTED_PROTOCOL_VERSIONS {
        let routes = network::routes_for_version(*version)
            .expect("supported protocol version must have registered routes");
        let dkg_handler = Arc::new(GenericProtocolHandler::new(Arc::new(
            DkgCoordinator::with_routes(app_state.clone(), routes),
        )));
        let pre_handler = Arc::new(GenericProtocolHandler::new(Arc::new(
            PreCoordinator::<D, T>::with_routes(app_state.clone(), routes),
        )));
        let sign_handler = Arc::new(GenericProtocolHandler::new(Arc::new(
            SignCoordinator::<D, S>::with_routes(app_state.clone(), routes),
        )));
        let health_handler = Arc::new(HealthProtocolHandler);
        router_builder = router_builder.accept(routes.dkg_alpn.to_vec(), dkg_handler);
        router_builder = router_builder.accept(routes.reencrypt_alpn.to_vec(), pre_handler);
        router_builder = router_builder.accept(routes.sign_alpn.to_vec(), sign_handler);
        router_builder =
            router_builder.accept(routes.reporting_health_alpn.to_vec(), health_handler);
    }
    router_builder.spawn()
}
