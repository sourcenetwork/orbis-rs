use crate::context::{context_digest, CiphertextContext};
use crate::decaf377::pre::ThresholdDealerNode;
use crate::r#trait::{DistKeyShare, ReaderKeyProof, ThresholdDealer};
use crate::test_helper::DKGCoordinator;
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
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

/// — decaf377's `reencrypt_internal` uses the identical linear
/// `effective_ski * (rdr_pk + enc_cmt)` structure with no proof of knowledge of
/// `rdr_pk`'s discrete log, so the forged-reader-key attack applied here too
/// before the [`ReaderKeyProof`] check was added.
#[test]
fn test_reader_key_pop_blocks_cross_ciphertext_substitution() {
    let n = 5;
    let t = 3;
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

    let (enc_cmt_a, secret_a, _proof_a) =
        ThresholdDealerNode::encrypt_secret(&ring_pk, b"plaintext A", None, &ctx_a)
            .expect("encrypt A");
    let (enc_cmt_b, _secret_b, _proof_b) = ThresholdDealerNode::encrypt_secret(
        &ring_pk,
        b"plaintext B - not authorized",
        None,
        &ctx_b,
    )
    .expect("encrypt B");

    // Ordinary point subtraction of two published commitments; no discrete-log
    // knowledge required — the same rdr_pk* that, pre-fix, made every node's
    // `reencrypt` happily compute s_i*(rdr_pk* + U_A) = s_i*U_B.
    let forged_rdr_pk = enc_cmt_b - enc_cmt_a;
    let dealer = ThresholdDealerNode::new();
    let dist_key_share = DistKeyShare {
        pri_share: secret_shares[0].clone(),
    };

    // Attempt 1: no proof at all (a placeholder). Rejected immediately.
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

    // Attempt 2: a *valid* PoP, but for a different key the attacker
    // legitimately owns, not for `forged_rdr_pk`. Still rejected.
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
    // proof still succeeds.
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
    let shared_point = xnc_cmt - ring_pk * honest_sk;
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
}
