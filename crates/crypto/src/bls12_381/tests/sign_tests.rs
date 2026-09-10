use crate::bls12_381::common::{G2Point, PubPoly};
use crate::bls12_381::dkg::DKGNode;
use crate::bls12_381::sign::{hash_to_g2, ThresholdBlsSigner};
use crate::r#trait::{DistKeyShare, Dkg, PubShare, ThresholdSigner};
use crate::test_helper::DKGCoordinator;
use ark_bls12_381::{Fr, G1Affine, G1Projective, G2Projective};
use ark_ec::{CurveGroup, Group};
use ark_ff::{Field, PrimeField};
use ark_std::{UniformRand, Zero};
use rand_core::OsRng;
use sha2::{Digest, Sha512};

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
                |id: u32, threshold: usize, total_nodes: usize, session_id: u128, role| {
                    <DKGNode as Dkg>::new(id, threshold, total_nodes, session_id, role)
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
    assert_eq!(
        ThresholdBlsSigner::name(),
        "threshold-bls-g2-aug-v1".to_string()
    );
}

#[test]
fn test_hash_to_g2_deterministic() {
    let (_, pk) = random_keypair();
    let msg = b"test message";
    let h1 = hash_to_g2(&pk, msg).unwrap();
    let h2 = hash_to_g2(&pk, msg).unwrap();
    assert_eq!(h1, h2, "Hash should be deterministic");
}

#[test]
fn test_hash_to_g2_different_messages() {
    let (_, pk) = random_keypair();
    let h1 = hash_to_g2(&pk, b"message 1").unwrap();
    let h2 = hash_to_g2(&pk, b"message 2").unwrap();
    assert_ne!(h1, h2, "Different messages should hash to different points");
}

#[test]
fn test_hash_to_g2_binds_public_key() {
    let (_, pk_a) = random_keypair();
    let (_, pk_b) = random_keypair();
    let msg = b"same message";

    let h_a = hash_to_g2(&pk_a, msg).unwrap();
    let h_b = hash_to_g2(&pk_b, msg).unwrap();

    assert_ne!(h_a, h_b, "The augmented hash must bind the public key");
}

fn random_keypair() -> (Fr, G1Affine) {
    let sk = Fr::rand(&mut OsRng);
    let pk = (G1Projective::generator() * sk).into_affine();
    (sk, pk)
}

fn public_derivation_scalar(derivation: &[u8], metadata: Option<&[u8]>) -> Fr {
    let mut hasher = Sha512::new();
    hasher.update(b"sign-derivation-v1");
    hasher.update(derivation);
    if let Some(meta) = metadata {
        hasher.update(b"\x00");
        hasher.update((meta.len() as u64).to_le_bytes());
        hasher.update(meta);
    }
    Fr::from_le_bytes_mod_order(&hasher.finalize())
}

#[test]
fn test_signature_cannot_be_scaled_between_derived_keys() {
    let n = 3;
    let t = 2;
    let mut coordinator = DKGCoordinator::new(
        |id: u32, threshold: usize, total_nodes: usize, session_id: u128, role| {
            <DKGNode as Dkg>::new(id, threshold, total_nodes, session_id, role)
        },
        n,
        t,
    )
    .unwrap();
    let (aggregate_pk, secret_shares, pub_poly) = coordinator.run_dkg().unwrap();
    let signer = ThresholdBlsSigner::new();
    let message = b"attacker-chosen message";
    let attacker_derivation = b"attacker-derivation";
    let victim_derivation = b"victim-derivation";

    let attacker_shares: Vec<_> = secret_shares
        .iter()
        .take(t)
        .map(|share| {
            signer
                .sign(
                    &DistKeyShare {
                        pri_share: share.clone(),
                    },
                    message,
                    &pub_poly,
                    None,
                    &[],
                    Some(attacker_derivation),
                    None,
                )
                .unwrap()
        })
        .collect();
    let attacker_pk =
        ThresholdBlsSigner::derive_public_key(&aggregate_pk, attacker_derivation, None).unwrap();
    let victim_pk =
        ThresholdBlsSigner::derive_public_key(&aggregate_pk, victim_derivation, None).unwrap();
    let attacker_signature = signer
        .recover(&attacker_shares, t, n, &attacker_pk, message, &[])
        .unwrap()
        .unwrap();
    signer
        .verify(&attacker_pk, message, &attacker_signature)
        .unwrap();

    // This is the exact public related-key conversion that succeeds against
    // the old NUL construction: sigma_v = (d_v / d_a) * sigma_a.
    let d_a = public_derivation_scalar(attacker_derivation, None);
    let d_v = public_derivation_scalar(victim_derivation, None);
    assert!(!d_a.is_zero() && !d_v.is_zero());
    let ratio = d_v * d_a.inverse().unwrap();
    let scaled_attacker_pk = (G1Projective::from(attacker_pk) * ratio).into_affine();
    assert_eq!(
        scaled_attacker_pk, victim_pk,
        "The public ratio must map the attacker key to the victim key"
    );
    let converted_signature =
        G2Point::from((G2Projective::from(*attacker_signature.inner()) * ratio).into_affine());

    assert!(
        signer
            .verify(&victim_pk, message, &converted_signature)
            .is_err(),
        "A signature scaled from another derived key must not verify"
    );
}

#[test]
fn test_threshold_signing_different_share_subsets_same_signature() {
    // BLS is deterministic: any two t-subsets of shares produce the SAME signature
    let n = 5;
    let t = 3;

    let mut coordinator = DKGCoordinator::new(
        |id: u32, threshold: usize, total_nodes: usize, session_id: u128, role| {
            <DKGNode as Dkg>::new(id, threshold, total_nodes, session_id, role)
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
    let sig1 = signer
        .recover(&subset1, t, n, &aggregate_pk, msg, &[])
        .unwrap()
        .unwrap();

    let subset2: Vec<_> = all_sig_shares.iter().skip(2).take(3).cloned().collect();
    let sig2 = signer
        .recover(&subset2, t, n, &aggregate_pk, msg, &[])
        .unwrap()
        .unwrap();

    assert_eq!(
        sig1, sig2,
        "BLS: different share subsets must produce the same signature"
    );

    assert!(signer.verify(&aggregate_pk, msg, &sig1).is_ok());
    assert!(signer.verify(&aggregate_pk, msg, &sig2).is_ok());
}
