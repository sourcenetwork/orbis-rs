use crate::decaf377::dkg::DKGNode;
use crate::decaf377::sign::{FrostNonceCommitment, ThresholdDecafSigner};
use crate::r#trait::{DistKeyShare, Dkg, PubShare, ThresholdSigner};
use crate::test_helper::DKGCoordinator;
use decaf377::{Element, Fr};
use rand_core::OsRng;

// ============================================================================
// Generic suite — runs all trait-level signing tests
// ============================================================================

#[test]
fn test_all_sign() {
    crate::sign_tests::run_all_tests::<ThresholdDecafSigner, _, _, _, _, _, _, _>(
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
                |id: u32, threshold: usize, total_nodes: usize, session_id: u64| {
                    <DKGNode as Dkg>::new(id, threshold, total_nodes, session_id)
                },
                n,
                t,
            )?;
            coordinator.run_dkg()
        },
        // tamper_sig_share: replace the share scalar with a random one
        |share: &mut PubShare<Fr>| {
            share.v = Fr::rand(&mut OsRng);
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
        ThresholdDecafSigner::name(),
        "threshold-frost-decaf377".to_string()
    );
}

#[test]
fn test_frost_rejects_tampered_commitment_from_coordinator() {
    let n = 3;
    let t = 2;

    let mut coordinator = DKGCoordinator::new(
        |id: u32, threshold: usize, total_nodes: usize, session_id: u64| {
            <DKGNode as Dkg>::new(id, threshold, total_nodes, session_id)
        },
        n,
        t,
    )
    .unwrap();

    let (_aggregate_pk, secret_shares, pub_poly) = coordinator.run_dkg().unwrap();

    let signer = ThresholdDecafSigner::new();
    let msg = b"tampered commitment test";

    let participants: Vec<_> = secret_shares.iter().take(t).collect();

    // Generate nonces honestly
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

    // Coordinator tampers with signer 0's commitment before relaying
    let mut tampered_commitments = commitments.clone();
    tampered_commitments[0].1 = FrostNonceCommitment {
        hiding: Element::GENERATOR * Fr::rand(&mut OsRng),
        binding: Element::GENERATOR * Fr::rand(&mut OsRng),
    };

    // Signer 0 should reject because its commitment doesn't match its nonces
    let dks = DistKeyShare {
        pri_share: participants[0].clone(),
    };
    let result = signer.sign(
        &dks,
        msg,
        &pub_poly,
        Some(&signing_states[0]),
        &tampered_commitments,
        None,
    );
    assert!(result.is_err(), "Should reject tampered own commitment");
    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("tampered"),
        "Error should mention tampering: {err_msg}"
    );

    // Signer 1's commitment wasn't tampered, so they would sign (but with wrong R)
    let dks1 = DistKeyShare {
        pri_share: participants[1].clone(),
    };
    let result1 = signer.sign(
        &dks1,
        msg,
        &pub_poly,
        Some(&signing_states[1]),
        &tampered_commitments,
        None,
    );
    assert!(
        result1.is_ok(),
        "Signer 1's commitment wasn't tampered — they sign (though R is wrong)"
    );
}

#[test]
fn test_frost_derived_key_signing() {
    let n = 3;
    let t = 2;

    let mut coordinator = DKGCoordinator::new(
        |id: u32, threshold: usize, total_nodes: usize, session_id: u64| {
            <DKGNode as Dkg>::new(id, threshold, total_nodes, session_id)
        },
        n,
        t,
    )
    .unwrap();

    let (aggregate_pk, secret_shares, pub_poly) = coordinator.run_dkg().unwrap();
    let signer = ThresholdDecafSigner::new();
    let derivation = b"policy:resource:read";
    let msg = b"FROST derived key test";

    // Derived public key
    let derived_pk = ThresholdDecafSigner::derive_public_key(&aggregate_pk, derivation).unwrap();
    assert_ne!(
        aggregate_pk, derived_pk,
        "derived pk must differ from base pk"
    );

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

    let mut sig_shares = Vec::new();
    for (idx, share) in participants.iter().enumerate() {
        let dks = DistKeyShare {
            pri_share: (*share).clone(),
        };
        let sig_share = signer
            .sign(
                &dks,
                msg,
                &pub_poly,
                Some(&signing_states[idx]),
                &commitments,
                Some(derivation),
            )
            .unwrap();
        signer
            .verify_share(msg, &pub_poly, &sig_share, &commitments, Some(derivation))
            .expect("derived share should verify");
        sig_shares.push(sig_share);
    }

    let sig = signer
        .recover(&sig_shares, t, n, msg, &commitments)
        .unwrap()
        .unwrap();

    // Verifies under derived key
    assert!(signer.verify(&derived_pk, msg, &sig).is_ok());
    // Fails under base key
    assert!(signer.verify(&aggregate_pk, msg, &sig).is_err());
}

#[test]
fn test_frost_derived_key_wrong_derivation_fails() {
    let n = 3;
    let t = 2;

    let mut coordinator = DKGCoordinator::new(
        |id: u32, threshold: usize, total_nodes: usize, session_id: u64| {
            <DKGNode as Dkg>::new(id, threshold, total_nodes, session_id)
        },
        n,
        t,
    )
    .unwrap();

    let (aggregate_pk, secret_shares, pub_poly) = coordinator.run_dkg().unwrap();
    let signer = ThresholdDecafSigner::new();
    let derivation = b"policy:resource:read";
    let wrong_derivation = b"policy:resource:write";
    let msg = b"FROST wrong derivation test";

    let correct_derived_pk =
        ThresholdDecafSigner::derive_public_key(&aggregate_pk, derivation).unwrap();
    let wrong_derived_pk =
        ThresholdDecafSigner::derive_public_key(&aggregate_pk, wrong_derivation).unwrap();

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

    let mut sig_shares = Vec::new();
    for (idx, share) in participants.iter().enumerate() {
        let dks = DistKeyShare {
            pri_share: (*share).clone(),
        };
        let sig_share = signer
            .sign(
                &dks,
                msg,
                &pub_poly,
                Some(&signing_states[idx]),
                &commitments,
                Some(derivation),
            )
            .unwrap();
        sig_shares.push(sig_share);
    }

    let sig = signer
        .recover(&sig_shares, t, n, msg, &commitments)
        .unwrap()
        .unwrap();

    // Correct derived key verifies
    assert!(signer.verify(&correct_derived_pk, msg, &sig).is_ok());
    // Wrong derived key fails
    assert!(signer.verify(&wrong_derived_pk, msg, &sig).is_err());
}

#[test]
fn test_frost_mixed_derivation_share_rejected() {
    // A share signed with derivation must not verify without derivation, and vice versa
    let n = 3;
    let t = 2;

    let mut coordinator = DKGCoordinator::new(
        |id: u32, threshold: usize, total_nodes: usize, session_id: u64| {
            <DKGNode as Dkg>::new(id, threshold, total_nodes, session_id)
        },
        n,
        t,
    )
    .unwrap();

    let (_aggregate_pk, secret_shares, pub_poly) = coordinator.run_dkg().unwrap();
    let signer = ThresholdDecafSigner::new();
    let derivation = b"policy:resource:read";
    let msg = b"FROST mixed derivation test";

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
    let derived_share = signer
        .sign(
            &dks,
            msg,
            &pub_poly,
            Some(&signing_states[0]),
            &commitments,
            Some(derivation),
        )
        .unwrap();

    // A share produced with derivation should not verify without derivation
    assert!(
        signer
            .verify_share(msg, &pub_poly, &derived_share, &commitments, None)
            .is_err(),
        "derived share must not verify without derivation"
    );
}
