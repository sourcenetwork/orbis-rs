use crate::bls12_381::pre::ThresholdDealerNode;
use crate::r#trait::ThresholdDealer;
use crate::test_helper::DKGCoordinator;
use ark_bls12_381::{Fr, G1Projective};
use ark_ec::Group;
use ark_std::UniformRand;
use rand_core::OsRng;

// ============================================================================
// Generic suite — runs all trait-level PRE tests
// ============================================================================

#[test]
fn test_all_pre() {
    crate::pre_tests::run_all_tests::<ThresholdDealerNode, _, _, _, _, _, _>(
        // make_keypair: random (scalar, group element) pair
        || {
            let sk = Fr::rand(&mut OsRng);
            let pk = G1Projective::generator() * sk;
            (sk, pk.into())
        },
        // make_pub_poly: construct PubPoly from commits
        |commits| crate::bls12_381::common::PubPoly { commits },
        // run_dkg: full DKG ceremony
        |n, t| {
            let mut coordinator = DKGCoordinator::new(
                |id: u32, threshold: usize, total_nodes: usize, session_id: u64, role| {
                    <crate::bls12_381::dkg::DKGNode as crate::r#trait::Dkg>::new(
                        id,
                        threshold,
                        total_nodes,
                        session_id,
                        role,
                    )
                },
                n,
                t,
            )?;
            coordinator.run_dkg()
        },
    )
    .unwrap();
}

// ============================================================================
// Impl-specific tests
// ============================================================================

#[test]
fn test_threshold_dealer_creation() {
    assert_eq!(ThresholdDealerNode::name(), "elgamal/bls12_381");
}
