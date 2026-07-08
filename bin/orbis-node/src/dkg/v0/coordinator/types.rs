use crypto::r#trait::{DistKeyShare, Dkg, PubShare, ThresholdSigner};
use crypto::{
    GroupAffine as G1Affine, PolynomialCommitmentImpl as PolynomialCommitment,
    PubPolyImpl as PubPoly, ScalarField as Fr, SigShareInner, SignaturePoint,
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

pub trait CoordinatorReportSigner<D: CoordinatorDkg>:
    ThresholdSigner<
        ShareValue = Fr,
        PublicKey = G1Affine,
        DistKeyShare = DistKeyShare<Fr>,
        PubPoly = D::PubPoly,
        Signature = SignaturePoint,
        SigShare = PubShare<SigShareInner>,
    > + Send
    + Sync
    + 'static
{
}

impl<D, T> CoordinatorReportSigner<D> for T
where
    D: CoordinatorDkg,
    T: ThresholdSigner<
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
}
