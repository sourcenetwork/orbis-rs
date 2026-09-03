use crate::decaf377::pre::ThresholdDealerNode;
use crate::r#trait::ThresholdDealer;
use crate::test_helper::DKGCoordinator;
use decaf377::{Element, Fr};
use rand_core::OsRng;

// ============================================================================
// Generic suite — runs all trait-level PRE tests
// ============================================================================

#[test]
fn test_all_pre() {
    crate::pre_tests::run_all_tests::<ThresholdDealerNode, _, _, _, _, _, _, _>(
        // make_keypair: random (scalar, group element) pair
        || {
            let sk = Fr::rand(&mut OsRng);
            let pk = Element::GENERATOR * sk;
            (sk, pk)
        },
        // make_pub_poly: construct PubPoly from commits
        |commits| crate::decaf377::common::PubPoly { commits },
        // run_dkg: full DKG ceremony
        |n, t| {
            let mut coordinator = DKGCoordinator::new(
                |id: u32, threshold: usize, total_nodes: usize, session_id: u128, role| {
                    <crate::decaf377::dkg::DKGNode as crate::r#trait::Dkg>::new(
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
        // make_identity_pk: decaf377 identity element
        Element::default,
    )
    .unwrap();
}

/// Regression guard for the public shared-point disclosure: the serialized proof
/// must not carry AES key material, so a bulletin-only observer cannot decrypt.
#[test]
fn test_public_encryption_artifacts_cannot_decrypt() {
    crate::pre_tests::test_public_encryption_artifacts_cannot_decrypt::<
        ThresholdDealerNode,
        _,
        _,
        _,
    >(|| {
        let sk = Fr::rand(&mut OsRng);
        let pk = Element::GENERATOR * sk;
        (sk, pk)
    })
    .unwrap();
}

// ============================================================================
// Impl-specific tests
// ============================================================================

#[test]
fn test_threshold_dealer_creation() {
    assert_eq!(ThresholdDealerNode::name(), "elgamal/decaf377");
}
