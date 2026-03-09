use crate::app_state::AppState;
use crate::dkg::coordinator::DkgCoordinator;
use crate::helpers::protocol_handler::GenericProtocolHandler;
use crate::pre::coordinator::PreCoordinator;
use crate::sign::coordinator::SignCoordinator;
use network::error::Result as NetworkResult;
use network::{Router, DKG, REENCRYPT, SIGN};
use std::sync::Arc;

/// Create a router with DKG protocol handler registered
pub fn create_router_with_dkg_handler<D>(
    network: &Arc<dyn network::Network>,
    app_state: Arc<AppState<D>>,
) -> NetworkResult<Box<dyn Router>>
where
    D: crypto::r#trait::Dkg<
            ShareValue = crypto::ScalarField,
            PublicKey = crypto::GroupAffine,
            PolynomialCommitment = crypto::PolynomialCommitmentImpl,
        > + Clone
        + Send
        + Sync
        + 'static,
{
    let dkg_handler = Arc::new(GenericProtocolHandler::new(Arc::new(DkgCoordinator::new(
        app_state,
    ))));
    let mut router_builder = network.create_router_builder()?;
    router_builder = router_builder.accept(DKG.to_vec(), dkg_handler);
    router_builder.spawn()
}

/// Create a router with both DKG and PRE protocol handlers
pub fn create_router_with_handlers<D, T>(
    network: &Arc<dyn network::Network>,
    app_state: Arc<AppState<D>>,
) -> NetworkResult<Box<dyn Router>>
where
    D: crypto::r#trait::Dkg<
            ShareValue = crypto::ScalarField,
            PublicKey = crypto::GroupAffine,
            PolynomialCommitment = crypto::PolynomialCommitmentImpl,
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
    let dkg_handler = Arc::new(GenericProtocolHandler::new(Arc::new(DkgCoordinator::new(
        app_state.clone(),
    ))));
    let pre_handler = Arc::new(GenericProtocolHandler::new(Arc::new(
        PreCoordinator::<D, T>::new(app_state),
    )));
    let mut router_builder = network.create_router_builder()?;
    router_builder = router_builder.accept(DKG.to_vec(), dkg_handler);
    router_builder = router_builder.accept(REENCRYPT.to_vec(), pre_handler);
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
    let dkg_handler = Arc::new(GenericProtocolHandler::new(Arc::new(DkgCoordinator::new(
        app_state.clone(),
    ))));
    let pre_handler = Arc::new(GenericProtocolHandler::new(Arc::new(
        PreCoordinator::<D, T>::new(app_state.clone()),
    )));
    let sign_handler = Arc::new(GenericProtocolHandler::new(Arc::new(
        SignCoordinator::<D, S>::new(app_state),
    )));
    let mut router_builder = network.create_router_builder()?;
    router_builder = router_builder.accept(DKG.to_vec(), dkg_handler);
    router_builder = router_builder.accept(REENCRYPT.to_vec(), pre_handler);
    router_builder = router_builder.accept(SIGN.to_vec(), sign_handler);
    router_builder.spawn()
}
