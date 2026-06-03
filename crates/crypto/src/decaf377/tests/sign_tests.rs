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
