use crate::app_state::AppState;
use crate::dkg::protocol_handler::DkgProtocolHandler;
use crate::pre::protocol_handler::PreProtocolHandler;
use crate::sign::protocol_handler::SignProtocolHandler;
use network::error::Result as NetworkResult;
use network::{Router, DKG, REENCRYPT, SIGN};
use std::sync::Arc;
/// Create a router with DKG protocol handler registered
///
/// This is a helper function that sets up a router with the DKG protocol handler.
/// It's used both in production (main.rs) and in tests.
///
/// # Arguments
/// * `network` - The network instance to create router for
/// * `app_state` - The application state (needed for DKG coordinator)
pub fn create_router_with_dkg_handler<D>(
    network: &Arc<dyn network::Network>,
    app_state: Arc<AppState<D>>,
) -> NetworkResult<Box<dyn Router>>
where
    D: crypto::r#trait::Dkg<
            ShareValue = ark_bls12_381::Fr,
            PublicKey = ark_bls12_381::G1Affine,
            PolynomialCommitment = crypto::bls12_381::common::PolynomialCommitment,
        > + Clone
        + Send
        + Sync
        + 'static,
{
    let dkg_handler = Arc::new(DkgProtocolHandler::new(app_state));
    let mut router_builder = network.create_router_builder()?;
    router_builder = router_builder.accept(DKG.to_vec(), dkg_handler);
    router_builder.spawn()
}

/// Create a router with both DKG and PRE protocol handlers
///
/// This is the recommended function for setting up a full node that supports
/// both DKG and PRE protocols.
///
/// # Arguments
/// * `network` - The network instance to create router for
/// * `app_state` - The application state (needed for coordinators)
pub fn create_router_with_handlers<D, T>(
    network: &Arc<dyn network::Network>,
    app_state: Arc<AppState<D>>,
) -> NetworkResult<Box<dyn Router>>
where
    D: crypto::r#trait::Dkg<
            ShareValue = ark_bls12_381::Fr,
            PublicKey = ark_bls12_381::G1Affine,
            PolynomialCommitment = crypto::bls12_381::common::PolynomialCommitment,
        > + Clone
        + Send
        + Sync
        + 'static,
    T: crypto::r#trait::ThresholdDealer<
            ShareValue = ark_bls12_381::Fr,
            PublicKey = ark_bls12_381::G1Affine,
            DistKeyShare = crypto::r#trait::DistKeyShare<ark_bls12_381::Fr>,
            Secret = crypto::r#trait::Secret,
            ReencryptReply = crypto::r#trait::ReencryptReply<
                ark_bls12_381::Fr,
                ark_bls12_381::G1Affine,
            >,
            PubPoly = D::PubPoly,
        > + Send
        + Sync
        + 'static,
{
    let dkg_handler = Arc::new(DkgProtocolHandler::new(app_state.clone()));
    let pre_handler = Arc::new(PreProtocolHandler::<D, T>::new(app_state));

    let mut router_builder = network.create_router_builder()?;
    router_builder = router_builder.accept(DKG.to_vec(), dkg_handler);
    router_builder = router_builder.accept(REENCRYPT.to_vec(), pre_handler);
    router_builder.spawn()
}

/// Create a router with DKG, PRE, and Sign protocol handlers
///
/// This is the recommended function for setting up a full node that supports
/// all protocols: DKG, PRE, and threshold BLS signing.
///
/// # Arguments
/// * `network` - The network instance to create router for
/// * `app_state` - The application state (needed for coordinators)
pub fn create_router_with_all_handlers<D, T, S>(
    network: &Arc<dyn network::Network>,
    app_state: Arc<AppState<D>>,
) -> NetworkResult<Box<dyn Router>>
where
    D: crypto::r#trait::Dkg<
            ShareValue = ark_bls12_381::Fr,
            PublicKey = ark_bls12_381::G1Affine,
            PolynomialCommitment = crypto::bls12_381::common::PolynomialCommitment,
        > + Clone
        + Send
        + Sync
        + 'static,
    T: crypto::r#trait::ThresholdDealer<
            ShareValue = ark_bls12_381::Fr,
            PublicKey = ark_bls12_381::G1Affine,
            DistKeyShare = crypto::r#trait::DistKeyShare<ark_bls12_381::Fr>,
            Secret = crypto::r#trait::Secret,
            ReencryptReply = crypto::r#trait::ReencryptReply<
                ark_bls12_381::Fr,
                ark_bls12_381::G1Affine,
            >,
            PubPoly = D::PubPoly,
        > + Send
        + Sync
        + 'static,
    S: crypto::r#trait::ThresholdSigner<
            ShareValue = ark_bls12_381::Fr,
            PublicKey = ark_bls12_381::G1Affine,
            DistKeyShare = crypto::r#trait::DistKeyShare<ark_bls12_381::Fr>,
            PubPoly = D::PubPoly,
            Signature = crypto::bls12_381::common::G2Point,
            SigShare = crypto::r#trait::PubShare<crypto::bls12_381::common::G2Point>,
        > + Send
        + Sync
        + 'static,
{
    let dkg_handler = Arc::new(DkgProtocolHandler::new(app_state.clone()));
    let pre_handler = Arc::new(PreProtocolHandler::<D, T>::new(app_state.clone()));
    let sign_handler = Arc::new(SignProtocolHandler::<D, S>::new(app_state));

    let mut router_builder = network.create_router_builder()?;
    router_builder = router_builder.accept(DKG.to_vec(), dkg_handler);
    router_builder = router_builder.accept(REENCRYPT.to_vec(), pre_handler);
    router_builder = router_builder.accept(SIGN.to_vec(), sign_handler);
    router_builder.spawn()
}
