use crypto::r#trait::Dkg;
use crypto::{
    GroupAffine as G1Affine, PolynomialCommitmentImpl as PolynomialCommitment,
    PubPolyImpl as PubPoly, ScalarField as Fr,
};

pub trait CoordinatorDkg:
    Dkg<
        ShareValue = Fr,
        PublicKey = G1Affine,
        PolynomialCommitment = PolynomialCommitment,
        PubPoly = PubPoly,
    > + Clone
    + Send
    + Sync
    + 'static
{
}

impl<T> CoordinatorDkg for T where
    T: Dkg<
            ShareValue = Fr,
            PublicKey = G1Affine,
            PolynomialCommitment = PolynomialCommitment,
            PubPoly = PubPoly,
        > + Clone
        + Send
        + Sync
        + 'static
{
}
