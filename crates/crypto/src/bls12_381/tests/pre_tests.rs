use crate::bls12_381::pre::ThresholdDealerNode;
use crate::context::{context_digest, CiphertextContext};
use crate::r#trait::{DistKeyShare, PriShare, ReaderKeyProof, ThresholdDealer};
use crate::test_helper::DKGCoordinator;
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
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

    // No valid PoP can exist for a point outside the prime-order subgroup
    // either (the Schnorr equation over `rdr_pk` is still well-defined, but the
    // subgroup check in `verify_reader_key` rejects it before that matters), so
    // an empty placeholder proof is enough to exercise this path.
    let bogus_proof = ReaderKeyProof {
        challenge: Vec::new(),
        response: Vec::new(),
    };
    let bad_rdr_pk = wrong_subgroup_g1_point();
    assert!(
        dealer
            .reencrypt(&dks, &secret, &bad_rdr_pk, &bogus_proof, None)
            .is_err(),
        "reencrypt must reject a reader key outside the prime-order subgroup"
    );

    // Control: a well-formed reader key with a valid PoP on the same code path
    // still works.
    let (rdr_sk, rdr_pk) = ThresholdDealerNode::generate_keypair();
    let rdr_proof = ThresholdDealerNode::prove_reader_key(&rdr_sk, &rdr_pk).expect("prove");
    assert!(dealer
        .reencrypt(&dks, &secret, &rdr_pk, &rdr_proof, None)
        .is_ok());
}

/// a requester authorized for ciphertext A only must not
/// be able to read unrelated ciphertext B (same ring key) by submitting a
/// forged reader key instead of a real `X = xG`.
///
/// Before the [`ReaderKeyProof`] check was added, `reencrypt` computed
/// `Z = s_i * (rdr_pk + enc_cmt)` without checking that the caller knew
/// `rdr_pk`'s discrete log — only that it was a non-identity, correct-subgroup
/// point. A requester authorized to run PRE on A, and able to merely *read*
/// both ciphertexts' public commitments `U_A`/`U_B` off the bulletin, could
/// submit `rdr_pk* = U_B - U_A` (ordinary point subtraction, no discrete-log
/// knowledge required) to make the threshold reconstruct
/// `Z = s*(rdr_pk* + U_A) = s*U_B` — exactly B's KEM shared point — without
/// ever being authorized for B. This test pins the fix: `reencrypt` must now
/// reject the forged key at the very first node, before any share computation,
/// because the attacker cannot produce a [`ReaderKeyProof`] for a point whose
/// discrete log they don't know.
#[test]
fn test_reader_key_pop_blocks_cross_ciphertext_substitution() {
    let n = 5;
    let t = 3;
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
    )
    .expect("dkg coordinator setup");
    let (ring_pk, secret_shares, pub_poly) = coordinator.run_dkg().expect("dkg ceremony");

    let ctx_a = CiphertextContext {
        ring_pk: b"ring".to_vec(),
        policy_id: "policy-a".to_string(),
        resource: "secret-a".to_string(),
        permission: "read".to_string(),
        tier: None,
        timestamp: None,
        salt: None,
    };
    let ctx_b = CiphertextContext {
        ring_pk: b"ring".to_vec(),
        policy_id: "policy-b".to_string(),
        resource: "secret-b".to_string(),
        permission: "read".to_string(),
        tier: None,
        timestamp: None,
        salt: None,
    };

    // Two independent documents under the same ring key; the attacker is
    // authorized to run PRE on A only, but both ciphertexts and their public
    // commitments/contexts are visible on the bulletin.
    let (enc_cmt_a, secret_a, _proof_a) =
        ThresholdDealerNode::encrypt_secret(&ring_pk, b"plaintext A", None, &ctx_a)
            .expect("encrypt A");
    let (enc_cmt_b, secret_b, _proof_b) = ThresholdDealerNode::encrypt_secret(
        &ring_pk,
        b"plaintext B - not authorized",
        None,
        &ctx_b,
    )
    .expect("encrypt B");

    // The attacker never learns a discrete log; ordinary point subtraction of
    // two published commitments — this is the same rdr_pk* that, pre-fix, made
    // every node's `reencrypt` happily compute s_i*(rdr_pk* + U_A) = s_i*U_B.
    let forged_rdr_pk: G1Affine =
        (G1Projective::from(enc_cmt_b) - G1Projective::from(enc_cmt_a)).into();
    let dealer = ThresholdDealerNode::new();
    let dist_key_share = DistKeyShare {
        pri_share: secret_shares[0].clone(),
    };

    // Attempt 1: no proof at all (a placeholder). Rejected immediately — no
    // share is ever computed with the forged key.
    let no_proof = ReaderKeyProof {
        challenge: Vec::new(),
        response: Vec::new(),
    };
    assert!(
        dealer
            .reencrypt(&dist_key_share, &secret_a, &forged_rdr_pk, &no_proof, None)
            .is_err(),
        "forged rdr_pk with no proof must be rejected"
    );

    // Attempt 2: the attacker attaches a *valid* PoP — but for a different key
    // they legitimately own, not for `forged_rdr_pk` itself. Still rejected:
    // verify_reader_key checks the proof against the exact rdr_pk supplied, not
    // merely "the caller knows some key's discrete log".
    let (attacker_sk, attacker_pk) = ThresholdDealerNode::generate_keypair();
    let attacker_own_proof =
        ThresholdDealerNode::prove_reader_key(&attacker_sk, &attacker_pk).expect("prove own key");
    assert!(
        dealer
            .reencrypt(
                &dist_key_share,
                &secret_a,
                &forged_rdr_pk,
                &attacker_own_proof,
                None
            )
            .is_err(),
        "a proof of a different, honestly-owned key must not validate the forged rdr_pk"
    );

    // Control: the same request with a genuinely owned key and its matching
    // proof still succeeds — the fix rejects the forged input, not PRE itself.
    let (honest_sk, honest_pk) = ThresholdDealerNode::generate_keypair();
    let honest_proof =
        ThresholdDealerNode::prove_reader_key(&honest_sk, &honest_pk).expect("prove honest key");
    let mut replies = Vec::new();
    for share in secret_shares.iter().take(t) {
        let dist_key_share = DistKeyShare {
            pri_share: share.clone(),
        };
        let reply = dealer
            .reencrypt(&dist_key_share, &secret_a, &honest_pk, &honest_proof, None)
            .expect("node accepts a key the caller can prove knowledge of");
        dealer
            .verify(&honest_pk, &pub_poly, &enc_cmt_a, &reply, None)
            .expect("reencryption proof verifies");
        replies.push(reply);
    }
    let pub_shares: Vec<_> = replies.iter().map(|r| r.share.clone()).collect();
    let xnc_cmt = dealer
        .recover(&pub_shares, t, n)
        .expect("lagrange recovery")
        .expect("threshold met");
    let shared_point: G1Affine =
        (G1Projective::from(xnc_cmt) - G1Projective::from(ring_pk) * honest_sk).into();
    let aes_key = ThresholdDealerNode::derive_key_from_point(&shared_point).expect("kdf");
    let cipher = Aes256Gcm::new(&aes_key.into());
    let aad = context_digest(&ctx_a, &secret_a.enc_cmt);
    let plaintext_a = cipher
        .decrypt(
            Nonce::from_slice(&secret_a.nonce),
            Payload {
                msg: secret_a.encrypted_data.as_ref(),
                aad: &aad,
            },
        )
        .expect("honest reader still decrypts A");
    assert_eq!(plaintext_a, b"plaintext A");
    let _ = secret_b; // encrypted only to derive a realistic forged_rdr_pk above
}
