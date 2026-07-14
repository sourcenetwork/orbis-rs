use crate::bls12_381::common::PubPoly;
use crate::bls12_381::dkg::DKGNode;
use crate::bls12_381::pre::ThresholdDealerNode;
use crate::bls12_381::sign::ThresholdBlsSigner;
use crate::dkg_tests::run_all_tests;
use crate::r#trait::{
    DistributedShare, Dkg, DkgMode, DkgRole, PolynomialCommitment as PolynomialCommitmentTrait,
};
use ark_bls12_381::{Fr, G1Affine, G1Projective};
use ark_ec::{AffineRepr, Group};
use ark_std::UniformRand;
use rand_core::{OsRng, RngCore};

#[test]
fn test_all_dkg_tests() {
    run_all_tests(
        |id, threshold, total_nodes, session_id, role| {
            DKGNode::new(id, threshold, total_nodes, session_id, role)
        },
        |pk: &G1Affine| *pk == G1Affine::zero(),
        |share_value: &Fr| (G1Projective::generator() * share_value).into(),
        || {
            let mut rng = OsRng;
            Fr::rand(&mut rng)
        },
        |from_id, to_id, session_id| {
            let mut rng = OsRng;
            let mut nonce = [0u8; 16];
            rng.fill_bytes(&mut nonce);
            DistributedShare {
                from_id,
                to_id,
                value: Fr::rand(&mut rng),
                nonce,
                session_id,
            }
        },
    )
    .unwrap();
}

#[test]
fn constant_term_is_identity_matches_dkg_mode() {
    // Fresh: random constant term → not identity (negligible chance of a false failure).
    let mut fresh = DKGNode::new(1, 2, 3, 42, DkgRole::Standard).unwrap();
    fresh.generate_polynomial(DkgMode::Fresh).unwrap();
    assert!(!fresh.commitment().constant_term_is_identity());

    // Refresh: zero constant term → identity (delta polynomial keeps the secret).
    let mut refresh = DKGNode::new(1, 2, 3, 42, DkgRole::Standard).unwrap();
    refresh.generate_polynomial(DkgMode::Refresh).unwrap();
    assert!(refresh.commitment().constant_term_is_identity());
}

#[test]
fn test_lifecycle() {
    crate::lifecycle_tests::run_lifecycle_test::<
        DKGNode,
        ThresholdDealerNode,
        ThresholdBlsSigner,
        _,
        _,
        _,
        _,
        _,
        _,
        _,
    >(
        |id, threshold, total_nodes, session_id, role| {
            <DKGNode as Dkg>::new(id, threshold, total_nodes, session_id, role)
        },
        || {
            let sk = Fr::rand(&mut OsRng);
            let pk: G1Affine = (G1Projective::generator() * sk).into();
            (sk, pk)
        },
        |a: &Fr, b: &Fr| *a + *b,
        |a: &PubPoly, b: &PubPoly| PubPoly {
            commits: a
                .commits
                .iter()
                .zip(b.commits.iter())
                .map(|(x, y)| (G1Projective::from(*x) + G1Projective::from(*y)).into())
                .collect(),
        },
    )
    .unwrap();
}
