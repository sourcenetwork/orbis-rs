use crate::decaf377::dkg::DKGNode;
use crate::decaf377::sign::ThresholdDecafSigner;
use crate::r#trait::{DistKeyShare, Dkg, PriShare, PubShare, ThresholdSigner};
use crate::test_helper::DKGCoordinator;
use ark_ff::UniformRand;
use decaf377::{Element, Fr};
use rand_core::OsRng;

#[test]
fn test_signer_creation() {
    let signer = ThresholdDecafSigner::new();
    assert_eq!(signer.name(), "threshold-frost-decaf377");
}

#[test]
fn test_frost_full_flow_3_of_5() {
    let n = 5;
    let t = 3;

    // Run DKG
    let mut coordinator = DKGCoordinator::new(
        |id: u32, threshold: usize, total_nodes: usize| {
            <DKGNode as Dkg>::new(id, threshold, total_nodes)
        },
        n,
        t,
    )
    .unwrap();

    let (aggregate_pk, secret_shares, pub_poly) = coordinator.run_dkg().unwrap();

    assert_ne!(aggregate_pk, Element::default());
    assert_eq!(secret_shares.len(), n);

    let signer = ThresholdDecafSigner::new();
    let msg = b"FROST threshold signature test!";

    // Select `t` participants
    let participants: Vec<_> = secret_shares.iter().take(t).collect();

    // Round 1: Generate nonces
    let mut commitments: Vec<(u32, <ThresholdDecafSigner as ThresholdSigner>::NonceCommitment)> =
        Vec::new();
    let mut signing_states = Vec::new();

    for share in &participants {
        let dist_key_share = DistKeyShare {
            pri_share: (*share).clone(),
        };
        let (commitment, state) = signer.generate_nonces(&dist_key_share).unwrap();
        commitments.push((share.i, commitment));
        signing_states.push(state);
    }

    // Round 2: Sign
    let mut sig_shares = Vec::new();
    for (i, share) in participants.iter().enumerate() {
        let dist_key_share = DistKeyShare {
            pri_share: (*share).clone(),
        };
        let sig_share = signer
            .sign(
                &dist_key_share,
                msg,
                &pub_poly,
                Some(&signing_states[i]),
                &commitments,
            )
            .unwrap();

        // Verify the share
        let verify_result = signer.verify_share(msg, &pub_poly, &sig_share, &commitments);
        assert!(
            verify_result.is_ok(),
            "Share {} should verify: {:?}",
            share.i,
            verify_result.err()
        );

        sig_shares.push(sig_share);
    }

    // Recover full signature
    let recovered_sig = signer
        .recover(&sig_shares, t, n, msg, &commitments)
        .unwrap();
    assert!(recovered_sig.is_some(), "Should recover signature");

    let sig = recovered_sig.unwrap();

    // Verify final signature
    let verify_result = signer.verify(&aggregate_pk, msg, &sig);
    assert!(
        verify_result.is_ok(),
        "Final signature should verify: {:?}",
        verify_result.err()
    );
}

#[test]
fn test_frost_wrong_message_fails_verification() {
    let n = 3;
    let t = 2;

    let mut coordinator = DKGCoordinator::new(
        |id: u32, threshold: usize, total_nodes: usize| {
            <DKGNode as Dkg>::new(id, threshold, total_nodes)
        },
        n,
        t,
    )
    .unwrap();

    let (aggregate_pk, secret_shares, pub_poly) = coordinator.run_dkg().unwrap();

    let signer = ThresholdDecafSigner::new();
    let msg = b"correct message";

    let participants: Vec<_> = secret_shares.iter().take(t).collect();

    // Generate nonces and sign
    let mut commitments = Vec::new();
    let mut signing_states = Vec::new();
    for share in &participants {
        let dks = DistKeyShare {
            pri_share: (*share).clone(),
        };
        let (c, s) = signer.generate_nonces(&dks).unwrap();
        commitments.push((share.i, c));
        signing_states.push(s);
    }

    let mut sig_shares = Vec::new();
    for (i, share) in participants.iter().enumerate() {
        let dks = DistKeyShare {
            pri_share: (*share).clone(),
        };
        sig_shares.push(
            signer
                .sign(&dks, msg, &pub_poly, Some(&signing_states[i]), &commitments)
                .unwrap(),
        );
    }

    let sig = signer
        .recover(&sig_shares, t, n, msg, &commitments)
        .unwrap()
        .unwrap();

    // Verify with correct message succeeds
    assert!(signer.verify(&aggregate_pk, msg, &sig).is_ok());

    // Verify with wrong message fails
    let result = signer.verify(&aggregate_pk, b"wrong message", &sig);
    assert!(result.is_err(), "Should fail with wrong message");
}

#[test]
fn test_frost_tampered_share_rejected() {
    let n = 3;
    let t = 2;

    let mut coordinator = DKGCoordinator::new(
        |id: u32, threshold: usize, total_nodes: usize| {
            <DKGNode as Dkg>::new(id, threshold, total_nodes)
        },
        n,
        t,
    )
    .unwrap();

    let (_aggregate_pk, secret_shares, pub_poly) = coordinator.run_dkg().unwrap();

    let signer = ThresholdDecafSigner::new();
    let msg = b"test message";

    let participants: Vec<_> = secret_shares.iter().take(t).collect();

    let mut commitments = Vec::new();
    let mut signing_states = Vec::new();
    for share in &participants {
        let dks = DistKeyShare {
            pri_share: (*share).clone(),
        };
        let (c, s) = signer.generate_nonces(&dks).unwrap();
        commitments.push((share.i, c));
        signing_states.push(s);
    }

    let dks = DistKeyShare {
        pri_share: participants[0].clone(),
    };
    let mut sig_share = signer
        .sign(
            &dks,
            msg,
            &pub_poly,
            Some(&signing_states[0]),
            &commitments,
        )
        .unwrap();

    // Tamper with the share
    sig_share.v = Fr::rand(&mut OsRng);

    let result = signer.verify_share(msg, &pub_poly, &sig_share, &commitments);
    assert!(result.is_err(), "Tampered share should not verify");
}

#[test]
fn test_frost_insufficient_shares() {
    let signer = ThresholdDecafSigner::new();

    let shares = vec![PubShare {
        i: 1,
        v: Fr::from(42u64),
    }];

    // Only 1 share when threshold is 2
    let result = signer.recover(&shares, 2, 3, b"test", &[]).unwrap();
    assert!(
        result.is_none(),
        "Should return None with insufficient shares"
    );
}

#[test]
fn test_frost_single_key_threshold_1() {
    let n = 3;
    let t = 1;

    let mut coordinator = DKGCoordinator::new(
        |id: u32, threshold: usize, total_nodes: usize| {
            <DKGNode as Dkg>::new(id, threshold, total_nodes)
        },
        n,
        t,
    )
    .unwrap();

    let (aggregate_pk, secret_shares, pub_poly) = coordinator.run_dkg().unwrap();

    let signer = ThresholdDecafSigner::new();
    let msg = b"threshold-1 test";

    // Only need 1 participant
    let share = &secret_shares[0];
    let dks = DistKeyShare {
        pri_share: share.clone(),
    };

    let (commitment, state) = signer.generate_nonces(&dks).unwrap();
    let commitments = vec![(share.i, commitment)];

    let sig_share = signer
        .sign(&dks, msg, &pub_poly, Some(&state), &commitments)
        .unwrap();

    assert!(
        signer
            .verify_share(msg, &pub_poly, &sig_share, &commitments)
            .is_ok()
    );

    let sig = signer
        .recover(&[sig_share], t, n, msg, &commitments)
        .unwrap()
        .unwrap();

    assert!(
        signer.verify(&aggregate_pk, msg, &sig).is_ok(),
        "Single-signer FROST should verify"
    );
}

#[test]
fn test_frost_different_share_subsets_produce_valid_signatures() {
    let n = 5;
    let t = 3;

    let mut coordinator = DKGCoordinator::new(
        |id: u32, threshold: usize, total_nodes: usize| {
            <DKGNode as Dkg>::new(id, threshold, total_nodes)
        },
        n,
        t,
    )
    .unwrap();

    let (aggregate_pk, secret_shares, pub_poly) = coordinator.run_dkg().unwrap();

    let signer = ThresholdDecafSigner::new();
    let msg = b"Different subsets test";

    // Sign with subset {1, 2, 3}
    let sign_with_subset = |indices: &[usize]| {
        let participants: Vec<_> = indices.iter().map(|&i| &secret_shares[i]).collect();

        let mut commitments = Vec::new();
        let mut signing_states = Vec::new();
        for share in &participants {
            let dks = DistKeyShare {
                pri_share: (*share).clone(),
            };
            let (c, s) = signer.generate_nonces(&dks).unwrap();
            commitments.push((share.i, c));
            signing_states.push(s);
        }

        let mut sig_shares = Vec::new();
        for (i, share) in participants.iter().enumerate() {
            let dks = DistKeyShare {
                pri_share: (*share).clone(),
            };
            sig_shares.push(
                signer
                    .sign(&dks, msg, &pub_poly, Some(&signing_states[i]), &commitments)
                    .unwrap(),
            );
        }

        signer
            .recover(&sig_shares, t, n, msg, &commitments)
            .unwrap()
            .unwrap()
    };

    let sig1 = sign_with_subset(&[0, 1, 2]);
    let sig2 = sign_with_subset(&[2, 3, 4]);

    // Both should verify (but will have different R values since nonces are random)
    assert!(signer.verify(&aggregate_pk, msg, &sig1).is_ok());
    assert!(signer.verify(&aggregate_pk, msg, &sig2).is_ok());
}
