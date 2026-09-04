use crate::decaf377::dkg::DKGNode;
use crate::decaf377::sign::{FrostNonceCommitment, SchnorrSignature, ThresholdDecafSigner};

use crate::r#trait::{DistKeyShare, Dkg, PriShare, PubShare, ThresholdSigner};
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
                |id: u32, threshold: usize, total_nodes: usize, session_id: u128, role| {
                    <DKGNode as Dkg>::new(id, threshold, total_nodes, session_id, role)
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
fn test_identity_public_key_cannot_verify_forged_signature() {
    let signer = ThresholdDecafSigner::new();
    let z = Fr::from(42u64);
    let forged = SchnorrSignature {
        // For Y = identity, choosing R = z*G makes zG = R + cY for every
        // message without knowledge of a secret key.
        r_point: Element::GENERATOR * z,
        z,
    };

    assert!(signer
        .verify(&Element::default(), b"identity-key forgery", &forged)
        .is_err());
    assert!(
        ThresholdDecafSigner::derive_public_key(&Element::default(), b"derivation", None,).is_err()
    );
}

#[test]
fn test_frost_group_commitment_is_bound_to_public_key() {
    let signer = ThresholdDecafSigner::new();
    let share = PriShare {
        i: 1,
        v: Fr::from(9u64),
    };
    let dks = DistKeyShare {
        pri_share: share.clone(),
    };
    let (commitment, _state) = signer.generate_nonces(&dks).unwrap();
    let commitments = vec![(share.i, commitment)];
    let shares = vec![PubShare {
        i: share.i,
        v: Fr::from(1u64),
    }];
    let pk_a = Element::GENERATOR * Fr::from(3u64);
    let pk_b = Element::GENERATOR * Fr::from(5u64);

    let sig_a = signer
        .recover(&shares, 1, 1, &pk_a, b"same message", &commitments)
        .unwrap()
        .unwrap();
    let sig_b = signer
        .recover(&shares, 1, 1, &pk_b, b"same message", &commitments)
        .unwrap()
        .unwrap();

    assert_ne!(
        sig_a.r_point, sig_b.r_point,
        "the FROST binding factors must commit to the effective group key"
    );
}

#[test]
fn test_hedged_nonces_are_fresh_each_call() {
    // RFC 9591 §4.1 hedging still draws fresh randomness on every call: a signer
    // that reused (d, e) — and therefore its commitment — across two FROST
    // sessions with different messages would leak its share. Two calls with the
    // same secret share must yield different nonces.
    let signer = ThresholdDecafSigner::new();
    let dks = DistKeyShare {
        pri_share: PriShare {
            i: 1,
            v: Fr::rand(&mut OsRng),
        },
    };

    let (_c1, s1) = signer.generate_nonces(&dks).unwrap();
    let (_c2, s2) = signer.generate_nonces(&dks).unwrap();

    assert_ne!(
        s1.hiding_nonce, s2.hiding_nonce,
        "hiding nonce repeated across calls"
    );
    assert_ne!(
        s1.binding_nonce, s2.binding_nonce,
        "binding nonce repeated across calls"
    );
    // Domain separation: the hiding and binding nonces of one call are distinct.
    assert_ne!(s1.hiding_nonce, s1.binding_nonce);
}

#[test]
fn test_frost_rejects_tampered_commitment_from_coordinator() {
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
        None,
    );
    assert!(
        result1.is_ok(),
        "Signer 1's commitment wasn't tampered — they sign (though R is wrong)"
    );
}

#[test]
fn test_frost_recover_rejects_share_outside_commitment_set() {
    // FROST's group commitment R is fixed by `all_commitments`. A partial
    // signature whose index has no entry in that set contributes a `z_i` with no
    // matching `D_i + rho_i·E_i` in R, so `recover` must reject it rather than
    // fold it into a silently invalid aggregate.
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
    let signer = ThresholdDecafSigner::new();
    let msg = b"share outside commitment set";

    // Signers 1 and 2 run a complete FROST round.
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
        sig_shares.push(
            signer
                .sign(
                    &dks,
                    msg,
                    &pub_poly,
                    Some(&signing_states[idx]),
                    &commitments,
                    None,
                    None,
                )
                .unwrap(),
        );
    }

    // The honest {1, 2} set recovers.
    signer
        .recover(&sig_shares, t, n, &aggregate_pk, msg, &commitments)
        .unwrap()
        .expect("honest FROST share set recovers");

    // Re-label signer 1's partial signature as node 3 — a valid ring index, but
    // one with no commitment in this signing set.
    let mut foreign = sig_shares[0].clone();
    foreign.i = 3;
    let tampered = vec![sig_shares[1].clone(), foreign];
    assert!(
        signer
            .recover(&tampered, t, n, &aggregate_pk, msg, &commitments)
            .is_err(),
        "recover must reject a share whose index is absent from all_commitments"
    );
}
