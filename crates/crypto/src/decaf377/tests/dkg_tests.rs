use crate::decaf377::common::PubPoly;
use crate::decaf377::dkg::DKGNode;
use crate::decaf377::pre::ThresholdDealerNode;
use crate::decaf377::sign::ThresholdDecafSigner;
use crate::dkg_tests::run_all_tests;
use crate::r#trait::{
    DistributedShare, Dkg, DkgMode, DkgRole, PolynomialCommitment as PolynomialCommitmentTrait,
};
use decaf377::{Element, Fr};
use rand_core::{OsRng, RngCore};

#[test]
fn test_all_dkg_tests() {
    run_all_tests(
        |id, threshold, total_nodes, session_id, role| {
            DKGNode::new(id, threshold, total_nodes, session_id, role)
        },
        |pk: &Element| *pk == Element::default(),
        |share_value: &Fr| Element::GENERATOR * share_value,
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
        ThresholdDecafSigner,
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
            let pk = Element::GENERATOR * sk;
            (sk, pk)
        },
        |a: &Fr, b: &Fr| *a + *b,
        |a: &PubPoly, b: &PubPoly| PubPoly {
            commits: a
                .commits
                .iter()
                .zip(b.commits.iter())
                .map(|(x, y)| x + y)
                .collect(),
        },
    )
    .unwrap();
}
