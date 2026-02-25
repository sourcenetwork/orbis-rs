use crate::bls12_381::common::{G2Point, PubPoly};
use crate::bls12_381::dkg::DKGNode;
use crate::bls12_381::sign::{hash_to_g2, ThresholdBlsSigner};
use crate::r#trait::{DistKeyShare, Dkg, PriShare, PubShare, ThresholdSigner};
use crate::test_helper::DKGCoordinator;
use ark_bls12_381::{Fr, G1Affine, G1Projective, G2Projective};
use ark_ec::{AffineRepr, Group};
use ark_std::UniformRand;
use rand_core::OsRng;

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
fn test_sign_and_verify_single_key() {
    // Test with a single key (non-threshold)
    let mut rng = OsRng;
    let sk = Fr::rand(&mut rng);
    let pk: G1Affine = (G1Projective::generator() * sk).into();

    let signer = ThresholdBlsSigner::new();
    let msg = b"Hello, BLS!";

    // Create a "share" with the full secret
    let dist_key_share = DistKeyShare {
        pri_share: PriShare { i: 1, v: sk },
    };

    // For BLS, we need a PubPoly for the sign call (though it's unused internally)
    // Create a minimal one - in practice this comes from DKG
    let pub_poly = PubPoly {
        commits: vec![pk], // aggregate pk as constant term
    };

    // Sign
    let sig_share = signer
        .sign(&dist_key_share, msg, &pub_poly, None, &[])
        .unwrap();

    // The signature share IS the full signature for a single signer
    let sig = sig_share.v;

    // Verify
    let result = signer.verify(&pk, msg, &sig);
    assert!(result.is_ok(), "Valid signature should verify");
}

#[test]
fn test_verify_fails_with_wrong_message() {
    let mut rng = OsRng;
    let sk = Fr::rand(&mut rng);
    let pk: G1Affine = (G1Projective::generator() * sk).into();

    let signer = ThresholdBlsSigner::new();

    let dist_key_share = DistKeyShare {
        pri_share: PriShare { i: 1, v: sk },
    };

    // Sign one message

    let pub_poly = PubPoly { commits: vec![pk] };
    let sig_share = signer
        .sign(&dist_key_share, b"original message", &pub_poly, None, &[])
        .unwrap();

    // Verify with different message
    let result = signer.verify(&pk, b"different message", &sig_share.v);
    assert!(
        result.is_err(),
        "Signature should not verify for wrong message"
    );
}

#[test]
fn test_verify_fails_with_wrong_key() {
    let mut rng = OsRng;
    let sk = Fr::rand(&mut rng);
    let wrong_sk = Fr::rand(&mut rng);
    let wrong_pk: G1Affine = (G1Projective::generator() * wrong_sk).into();

    let signer = ThresholdBlsSigner::new();
    let msg = b"test message";

    let dist_key_share = DistKeyShare {
        pri_share: PriShare { i: 1, v: sk },
    };

    let pk: G1Affine = (G1Projective::generator() * sk).into();
    let pub_poly = PubPoly { commits: vec![pk] };
    let sig_share = signer
        .sign(&dist_key_share, msg, &pub_poly, None, &[])
        .unwrap();

    // Verify with wrong public key
    let result = signer.verify(&wrong_pk, msg, &sig_share.v);
    assert!(
        result.is_err(),
        "Signature should not verify with wrong key"
    );
}

#[test]
fn test_threshold_signing_3_of_5() {
    // Setup: 3-of-5 threshold DKG
    let n = 5;
    let t = 3;

    // Run DKG
    let mut coordinator = DKGCoordinator::new(
        |id: u32, threshold: usize, total_nodes: usize, session_id: u64| {
            <DKGNode as Dkg>::new(id, threshold, total_nodes, session_id)
        },
        n,
        t,
    )
    .unwrap();

    let (aggregate_pk, secret_shares, pub_poly) = coordinator.run_dkg().unwrap();

    // Verify DKG setup
    assert_ne!(aggregate_pk, G1Affine::zero());
    assert_eq!(secret_shares.len(), n);

    let signer = ThresholdBlsSigner::new();
    let msg = b"Threshold BLS signature test!";

    // Step 1: Each participating node creates a signature share
    let mut sig_shares = Vec::new();
    for share in secret_shares.iter().take(t) {
        let dist_key_share = DistKeyShare {
            pri_share: share.clone(),
        };

        let sig_share = signer
            .sign(&dist_key_share, msg, &pub_poly, None, &[])
            .unwrap();

        // Verify the signature share
        let verify_result = signer.verify_share(msg, &pub_poly, &sig_share, &[]);
        assert!(
            verify_result.is_ok(),
            "Signature share {} should verify",
            share.i
        );

        sig_shares.push(sig_share);
    }

    assert_eq!(sig_shares.len(), t);

    // Step 2: Recover the full signature
    let recovered_sig = signer.recover(&sig_shares, t, n, msg, &[]).unwrap();
    assert!(recovered_sig.is_some(), "Should recover signature");

    let sig = recovered_sig.unwrap();
    assert!(!sig.is_zero(), "Signature should not be zero");

    // Step 3: Verify the final signature
    let verify_result = signer.verify(&aggregate_pk, msg, &sig);
    assert!(verify_result.is_ok(), "Final signature should verify");
}

#[test]
fn test_threshold_signing_different_share_subsets() {
    // Test that any t shares can recover the same signature
    let n = 5;
    let t = 3;

    // Run DKG
    let mut coordinator = DKGCoordinator::new(
        |id: u32, threshold: usize, total_nodes: usize, session_id: u64| {
            <DKGNode as Dkg>::new(id, threshold, total_nodes, session_id)
        },
        n,
        t,
    )
    .unwrap();

    let (aggregate_pk, secret_shares, _pub_poly) = coordinator.run_dkg().unwrap();

    let signer = ThresholdBlsSigner::new();
    let msg = b"Same signature from different shares";

    // Generate all signature shares
    let all_sig_shares: Vec<_> = secret_shares
        .iter()
        .map(|share| {
            let dist_key_share = DistKeyShare {
                pri_share: share.clone(),
            };
            signer
                .sign(&dist_key_share, msg, &_pub_poly, None, &[])
                .unwrap()
        })
        .collect();

    // Recover using shares 1, 2, 3
    let subset1: Vec<_> = all_sig_shares.iter().take(3).cloned().collect();
    let sig1 = signer.recover(&subset1, t, n, msg, &[]).unwrap().unwrap();

    // Recover using shares 3, 4, 5
    let subset2: Vec<_> = all_sig_shares.iter().skip(2).take(3).cloned().collect();
    let sig2 = signer.recover(&subset2, t, n, msg, &[]).unwrap().unwrap();

    // Both should produce the same signature
    assert_eq!(
        sig1, sig2,
        "Different share subsets should produce same signature"
    );

    // Both should verify
    assert!(signer.verify(&aggregate_pk, msg, &sig1).is_ok());
    assert!(signer.verify(&aggregate_pk, msg, &sig2).is_ok());
}

#[test]
fn test_insufficient_shares() {
    let signer = ThresholdBlsSigner::new();

    // Only 2 shares when threshold is 3
    let shares = vec![
        PubShare {
            i: 1,
            v: G2Point::generator(),
        },
        PubShare {
            i: 2,
            v: G2Point::generator(),
        },
    ];

    let result = signer.recover(&shares, 3, 5, b"test", &[]).unwrap();
    assert!(
        result.is_none(),
        "Should return None with insufficient shares"
    );
}

#[test]
fn test_verify_share_fails_with_wrong_share() {
    let n = 5;
    let t = 3;

    // Run DKG
    let mut coordinator = DKGCoordinator::new(
        |id: u32, threshold: usize, total_nodes: usize, session_id: u64| {
            <DKGNode as Dkg>::new(id, threshold, total_nodes, session_id)
        },
        n,
        t,
    )
    .unwrap();

    let (_aggregate_pk, secret_shares, pub_poly) = coordinator.run_dkg().unwrap();

    let signer = ThresholdBlsSigner::new();
    let msg = b"test message";

    // Create a valid signature share
    let dist_key_share = DistKeyShare {
        pri_share: secret_shares[0].clone(),
    };
    let mut sig_share = signer
        .sign(&dist_key_share, msg, &pub_poly, None, &[])
        .unwrap();

    // Tamper with the signature share
    let mut rng = OsRng;
    sig_share.v = G2Point::from(G2Projective::generator() * Fr::rand(&mut rng));

    // Verification should fail
    let result = signer.verify_share(msg, &pub_poly, &sig_share, &[]);
    assert!(
        result.is_err(),
        "Tampered signature share should not verify"
    );
}

#[test]
fn test_empty_message() {
    let mut rng = OsRng;
    let sk = Fr::rand(&mut rng);
    let pk: G1Affine = (G1Projective::generator() * sk).into();

    let signer = ThresholdBlsSigner::new();
    let msg = b"";

    let dist_key_share = DistKeyShare {
        pri_share: PriShare { i: 1, v: sk },
    };

    let pub_poly = PubPoly { commits: vec![pk] };
    let sig_share = signer
        .sign(&dist_key_share, msg, &pub_poly, None, &[])
        .unwrap();
    let result = signer.verify(&pk, msg, &sig_share.v);
    assert!(result.is_ok(), "Empty message signature should verify");
}

#[test]
fn test_large_message() {
    let mut rng = OsRng;
    let sk = Fr::rand(&mut rng);
    let pk: G1Affine = (G1Projective::generator() * sk).into();

    let signer = ThresholdBlsSigner::new();
    let msg = vec![0xABu8; 10000]; // 10KB message

    let dist_key_share = DistKeyShare {
        pri_share: PriShare { i: 1, v: sk },
    };

    let pub_poly = PubPoly { commits: vec![pk] };
    let sig_share = signer
        .sign(&dist_key_share, &msg, &pub_poly, None, &[])
        .unwrap();
    let result = signer.verify(&pk, &msg, &sig_share.v);
    assert!(result.is_ok(), "Large message signature should verify");
}
