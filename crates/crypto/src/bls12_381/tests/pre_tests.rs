use crate::bls12_381::pre::ThresholdDealerNode;
use crate::context::CiphertextContext;
use crate::r#trait::{DistKeyShare, PriShare, ThresholdDealer};
use crate::test_helper::DKGCoordinator;
use ark_bls12_381::{Fq, Fr, G1Affine, G1Projective};
use ark_ec::{AffineRepr, Group};
use ark_std::UniformRand;
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
            let pk = G1Projective::generator() * sk;
            (sk, pk.into())
        },
        // make_pub_poly: construct PubPoly from commits
        |commits| crate::bls12_381::common::PubPoly { commits },
        // run_dkg: full DKG ceremony
        |n, t| {
            let mut coordinator = DKGCoordinator::new(
                |id: u32, threshold: usize, total_nodes: usize, session_id: u128, role| {
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
        // make_identity_pk: G1 identity element
        G1Affine::identity,
    )
    .unwrap();
}

/// The published proof and secret must not carry anything from which the AES key
/// can be derived, so a party with only the bulletin data cannot decrypt.
#[test]
fn test_public_encryption_artifacts_cannot_decrypt() {
    crate::pre_tests::test_public_encryption_artifacts_cannot_decrypt::<
        ThresholdDealerNode,
        _,
        _,
        _,
    >(|| {
        let sk = Fr::rand(&mut OsRng);
        let pk = G1Projective::generator() * sk;
        (sk, pk.into())
    })
    .unwrap();
}

// ============================================================================
// Impl-specific tests
// ============================================================================

#[test]
fn test_threshold_dealer_creation() {
    assert_eq!(ThresholdDealerNode::name(), "elgamal/bls12_381");
}

/// First on-curve G1 point (by ascending x) that is NOT in the prime-order
/// subgroup. BLS12-381 G1 has a non-trivial cofactor, so such points exist and
/// a hostile caller could otherwise pass one as `rdr_pk`.
fn wrong_subgroup_g1_point() -> G1Affine {
    for x_u in 1u64..10_000 {
        if let Some(point) = G1Affine::get_point_from_x_unchecked(Fq::from(x_u), false) {
            if !point.is_zero() && !point.is_in_correct_subgroup_assuming_on_curve() {
                return point;
            }
        }
    }
    panic!("no small-x G1 point outside the prime-order subgroup found");
}

#[test]
fn test_reencrypt_rejects_reader_key_outside_prime_order_subgroup() {
    // Independent of whether the node deserialized `rdr_pk` through the
    // subgroup-checking path: `reencrypt` itself must refuse a low-order reader
    // key, otherwise `xnc_ski = ski * (rdr_pk + enc_cmt)` leaks `ski` modulo the
    // order of `rdr_pk`.
    let (_sk, ring_pk) = ThresholdDealerNode::generate_keypair();
    let ctx = CiphertextContext {
        ring_pk: vec![9, 9, 9],
        policy_id: "p".to_string(),
        resource: "r".to_string(),
        permission: "read".to_string(),
        tier: None,
        timestamp: None,
        salt: None,
    };
    let (_enc_cmt, secret, _proof) =
        ThresholdDealerNode::encrypt_secret(&ring_pk, b"payload", None, &ctx).expect("encrypt");

    let dks = DistKeyShare {
        pri_share: PriShare {
            i: 1,
            v: Fr::rand(&mut OsRng),
        },
    };
    let dealer = ThresholdDealerNode::new();

    let bad_rdr_pk = wrong_subgroup_g1_point();
    assert!(
        dealer.reencrypt(&dks, &secret, &bad_rdr_pk, None).is_err(),
        "reencrypt must reject a reader key outside the prime-order subgroup"
    );

    // Control: a well-formed reader key on the same code path still works.
    let (_rdr_sk, rdr_pk) = ThresholdDealerNode::generate_keypair();
    assert!(dealer.reencrypt(&dks, &secret, &rdr_pk, None).is_ok());
}
