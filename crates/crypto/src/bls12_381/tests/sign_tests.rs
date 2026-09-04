use crate::bls12_381::common::{G2Point, PubPoly};
use crate::bls12_381::dkg::DKGNode;
use crate::bls12_381::sign::{hash_to_g2, ThresholdBlsSigner};
use crate::r#trait::{DistKeyShare, Dkg, PubShare, ThresholdSigner};
use crate::test_helper::DKGCoordinator;
use ark_bls12_381::{Fr, G1Affine, G1Projective, G2Projective};
use ark_ec::Group;
use ark_std::UniformRand;
use rand_core::OsRng;

// ============================================================================
// Generic suite — runs all trait-level signing tests
// ============================================================================

#[test]
fn test_all_sign() {
    crate::sign_tests::run_all_tests::<ThresholdBlsSigner, _, _, _, _, _, _, _>(
        // make_keypair: random (scalar, G1 point) pair
        || {
            let sk = Fr::rand(&mut OsRng);
            let pk: G1Affine = (G1Projective::generator() * sk).into();
            (sk, pk)
        },
        // make_pub_poly: construct PubPoly from commits
        |commits| PubPoly { commits },
        // run_dkg: full DKG ceremony
        |n, t| {
            let mut coordinator = DKGCoordinator::new(
                |id: u32, threshold: usize, total_nodes: usize, session_id: u64| {
                    <DKGNode as Dkg>::new(id, threshold, total_nodes, session_id)
                },
                n,
                t,
            )?;
            coordinator.run_dkg()
        },
        // tamper_sig_share: replace the G2 share value with a random point
        |share: &mut PubShare<G2Point>| {
            share.v = G2Point::from(G2Projective::generator() * Fr::rand(&mut OsRng));
        },
    )
    .unwrap();
}

// ============================================================================
// Impl-specific tests
// ============================================================================

#[test]
fn test_signer_creation() {
    assert_eq!(ThresholdBlsSigner::name(), "threshold-bls-g2".to_string());
}

#[test]
fn test_hash_to_g2_deterministic() {
    let msg = b"test message";
    let h1 = hash_to_g2(msg).unwrap();
    let h2 = hash_to_g2(msg).unwrap();
    assert_eq!(h1, h2, "Hash should be deterministic");
}

#[test]
fn test_hash_to_g2_different_messages() {
    let h1 = hash_to_g2(b"message 1").unwrap();
    let h2 = hash_to_g2(b"message 2").unwrap();
    assert_ne!(h1, h2, "Different messages should hash to different points");
}

#[test]
fn test_threshold_signing_different_share_subsets_same_signature() {
    // BLS is deterministic: any two t-subsets of shares produce the SAME signature
    let n = 5;
    let t = 3;

    let mut coordinator = DKGCoordinator::new(
        |id: u32, threshold: usize, total_nodes: usize, session_id: u64| {
            <DKGNode as Dkg>::new(id, threshold, total_nodes, session_id)
        },
        n,
        t,
    )
    .unwrap();

    let (aggregate_pk, secret_shares, pub_poly) = coordinator.run_dkg().unwrap();

    let signer = ThresholdBlsSigner::new();
    let msg = b"Same signature from different shares";

    let all_sig_shares: Vec<_> = secret_shares
        .iter()
        .map(|share| {
            let dks = DistKeyShare {
                pri_share: share.clone(),
            };
            signer
                .sign(&dks, msg, &pub_poly, None, &[], None, None)
                .unwrap()
        })
        .collect();

    let subset1: Vec<_> = all_sig_shares.iter().take(3).cloned().collect();
    let sig1 = signer.recover(&subset1, t, n, msg, &[]).unwrap().unwrap();

    let subset2: Vec<_> = all_sig_shares.iter().skip(2).take(3).cloned().collect();
    let sig2 = signer.recover(&subset2, t, n, msg, &[]).unwrap().unwrap();

    assert_eq!(
        sig1, sig2,
        "BLS: different share subsets must produce the same signature"
    );

    assert!(signer.verify(&aggregate_pk, msg, &sig1).is_ok());
    assert!(signer.verify(&aggregate_pk, msg, &sig2).is_ok());
}

// ============================================================================
// Derivation: the signing scalar and the PRE capability scalar are different
// ============================================================================

/// A key derived for signing is not the key derived for proxy re-encryption.
///
/// Both traits expose `derive_public_key` over the same ring key and label, but
/// they use different scalars. Advertising one and signing with the other
/// yields a signature no verifier accepts, and nothing fails until a peer
/// rejects the block, so the distinction is pinned here.
#[test]
fn sign_derivation_differs_from_pre_capability_derivation() {
    use crate::bls12_381::pre::ThresholdDealerNode;
    use crate::r#trait::ThresholdDealer as _;

    let sk = Fr::rand(&mut OsRng);
    let ring_pk: G1Affine = (G1Projective::generator() * sk).into();
    let derivation = b"acme-corp";

    let for_signing =
        <ThresholdBlsSigner as ThresholdSigner>::derive_public_key(&ring_pk, derivation, None)
            .expect("signing derivation");
    let for_capability = ThresholdDealerNode::derive_public_key(&ring_pk, derivation)
        .expect("capability derivation");

    assert_ne!(
        for_signing, for_capability,
        "the two derivations must stay distinguishable; if they ever coincide, \
         the RPC that advertises a signing key can no longer be checked by this test"
    );
}

/// The signing derivation is deterministic and label-separating: the same label
/// gives the same key, a different label a different one.
#[test]
fn sign_derivation_is_deterministic_and_label_separating() {
    let sk = Fr::rand(&mut OsRng);
    let ring_pk: G1Affine = (G1Projective::generator() * sk).into();

    let acme =
        <ThresholdBlsSigner as ThresholdSigner>::derive_public_key(&ring_pk, b"acme-corp", None)
            .expect("acme derivation");
    let acme_again =
        <ThresholdBlsSigner as ThresholdSigner>::derive_public_key(&ring_pk, b"acme-corp", None)
            .expect("acme derivation again");
    let globex =
        <ThresholdBlsSigner as ThresholdSigner>::derive_public_key(&ring_pk, b"globex-inc", None)
            .expect("globex derivation");

    assert_eq!(acme, acme_again, "the same label must derive the same key");
    assert_ne!(acme, globex, "two tenants' labels must not derive one key");
}
