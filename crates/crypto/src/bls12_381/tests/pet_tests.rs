use crate::bls12_381::pet::PetNode;
use crate::r#trait::{
    CryptoDeserialize, CryptoSerialize, Dkg, Pet, PetCheckReply, PetTag, PubShare,
};
use crate::test_helper::DKGCoordinator;
use ark_bls12_381::{Fr, G1Affine, G1Projective};
use ark_ec::Group;
use ark_ff::{Field, One, Zero};
use ark_std::UniformRand;
use rand_core::OsRng;

#[test]
fn test_all_pet() {
    crate::pet_tests::run_all_tests::<PetNode>().unwrap();
}

#[test]
fn test_all_tag_knowledge() {
    crate::pet_tests::run_all_tag_knowledge_tests::<PetNode, _>(|| {
        let r_tag = Fr::rand(&mut OsRng);
        let ephemeral_point: G1Affine = (G1Projective::generator() * r_tag).into();
        (r_tag, ephemeral_point)
    })
    .unwrap();
}

/// Builds a tag for owner `owner_id` whose defining equation
/// `T = F(owner_id) + pet_sk*R` genuinely holds, so the threshold-check
/// tests below exercise real cryptographic verification rather than
/// checking against arbitrary bytes.
fn make_valid_tag(owner_id: &[u8], pet_sk: Fr) -> (PetTag, G1Affine) {
    let r_tag = Fr::rand(&mut OsRng);
    let r_point: G1Affine = (G1Projective::generator() * r_tag).into();
    let fingerprint = PetNode::owner_fingerprint(owner_id).unwrap();
    let masked: G1Affine =
        (G1Projective::from(fingerprint) + G1Projective::from(r_point) * pet_sk).into();
    (
        PetTag {
            ephemeral_point: r_point.to_bytes().unwrap(),
            masked_fingerprint: masked.to_bytes().unwrap(),
        },
        fingerprint,
    )
}

/// `threshold`-many identical shares (all equal to `pet_sk`) simulate a
/// degree-0 constant polynomial — the same technique `pre_tests`' Lagrange
/// tests use — so combining them must recover exactly `pet_sk`, without
/// needing a real Shamir split for this crypto-level test.
fn identical_shares(pet_sk: Fr, tag: &PetTag, threshold: usize) -> Vec<PubShare<G1Affine>> {
    (1..=threshold as u32)
        .map(|i| {
            PetNode::partial_pet_check(&pet_sk, i, tag)
                .unwrap()
                .partial
                .clone()
        })
        .collect()
}

#[test]
fn threshold_check_accepts_the_real_target() {
    let pet_sk = Fr::rand(&mut OsRng);
    let (tag, fingerprint) = make_valid_tag(b"alice", pet_sk);
    let shares = identical_shares(pet_sk, &tag, 3);

    let combined = PetNode::combine_pet_check_shares(&shares, 3, 5).unwrap();
    PetNode::verify_pet_match(&tag, &combined, &fingerprint)
        .expect("threshold check must accept the tag's real target");
}

#[test]
fn threshold_check_rejects_wrong_target() {
    let pet_sk = Fr::rand(&mut OsRng);
    let (tag, _) = make_valid_tag(b"alice", pet_sk);
    let shares = identical_shares(pet_sk, &tag, 3);
    let combined = PetNode::combine_pet_check_shares(&shares, 3, 5).unwrap();

    let wrong_target = PetNode::owner_fingerprint(b"mallory").unwrap();
    assert!(
        PetNode::verify_pet_match(&tag, &combined, &wrong_target).is_err(),
        "a tag for alice must not verify against a different audit target"
    );
}

#[test]
fn threshold_check_rejects_insufficient_shares() {
    let pet_sk = Fr::rand(&mut OsRng);
    let (tag, _) = make_valid_tag(b"alice", pet_sk);
    let shares = identical_shares(pet_sk, &tag, 2);

    assert!(
        PetNode::combine_pet_check_shares(&shares, 3, 5).is_err(),
        "combining fewer than threshold shares must fail"
    );
}

#[test]
fn threshold_check_rejects_duplicate_share_indices() {
    let pet_sk = Fr::rand(&mut OsRng);
    let (tag, _) = make_valid_tag(b"alice", pet_sk);
    let partial = PetNode::partial_pet_check(&pet_sk, 1, &tag)
        .unwrap()
        .partial
        .v;
    let shares = vec![
        PubShare { i: 1, v: partial },
        PubShare { i: 1, v: partial },
        PubShare { i: 2, v: partial },
    ];

    assert!(
        PetNode::combine_pet_check_shares(&shares, 3, 5).is_err(),
        "duplicate share indices must be rejected"
    );
}

#[test]
fn threshold_check_rejects_out_of_range_share_index() {
    let pet_sk = Fr::rand(&mut OsRng);
    let (tag, _) = make_valid_tag(b"alice", pet_sk);
    let partial = PetNode::partial_pet_check(&pet_sk, 1, &tag)
        .unwrap()
        .partial
        .v;
    let shares = vec![
        PubShare { i: 0, v: partial },
        PubShare { i: 1, v: partial },
        PubShare { i: 2, v: partial },
    ];

    assert!(
        PetNode::combine_pet_check_shares(&shares, 3, 5).is_err(),
        "a share index of 0 is out of the valid [1, n] range and must be rejected"
    );
}

// ============================================================================
// Per-share DLEQ proof: `partial_pet_check`/`verify_partial_pet_check`
// ============================================================================

/// Runs a real 3-of-3 DKG ceremony and returns `(aggregate_pk, shares, pub_poly)`
/// — genuine Shamir shares consistent with `pub_poly`, exactly like the PET
/// checking key's own fresh-DKG ceremony produces in production.
fn run_pet_key_dkg() -> (
    G1Affine,
    Vec<crate::r#trait::PriShare<Fr>>,
    crate::bls12_381::common::PubPoly,
) {
    let mut coordinator = DKGCoordinator::new(
        |id: u32, threshold: usize, total_nodes: usize, session_id: u128, role| {
            <crate::bls12_381::dkg::DKGNode as Dkg>::new(
                id,
                threshold,
                total_nodes,
                session_id,
                role,
            )
        },
        3,
        3,
    )
    .unwrap();
    coordinator.run_dkg().unwrap()
}

fn share_for(shares: &[crate::r#trait::PriShare<Fr>], i: u32) -> Fr {
    shares.iter().find(|s| s.i == i).unwrap().v
}

/// A tag with a genuine ephemeral point `R = r_tag*G` and an unused
/// `masked_fingerprint` — sufficient for `partial_pet_check`/
/// `verify_partial_pet_check`, which never read `masked_fingerprint` at all
/// (only `verify_pet_match` does).
fn sample_ephemeral_tag() -> PetTag {
    let r_tag = Fr::rand(&mut OsRng);
    let r_point: G1Affine = (G1Projective::generator() * r_tag).into();
    PetTag {
        ephemeral_point: r_point.to_bytes().unwrap(),
        masked_fingerprint: vec![1, 2, 3],
    }
}

#[test]
fn partial_pet_check_proof_verifies_against_the_authoritative_public_share() {
    let (_pet_pk, shares, pub_poly) = run_pet_key_dkg();
    let tag = sample_ephemeral_tag();
    let reply = PetNode::partial_pet_check(&share_for(&shares, 1), 1, &tag).unwrap();

    PetNode::verify_partial_pet_check(&pub_poly, &tag, &reply)
        .expect("a genuine per-share proof must verify against the authoritative public share");
}

#[test]
fn partial_pet_check_rejects_tampered_partial() {
    let (_pet_pk, shares, pub_poly) = run_pet_key_dkg();
    let tag = sample_ephemeral_tag();
    let mut reply = PetNode::partial_pet_check(&share_for(&shares, 1), 1, &tag).unwrap();
    reply.partial.v = (G1Projective::from(reply.partial.v) + G1Projective::generator()).into();

    assert!(
        PetNode::verify_partial_pet_check(&pub_poly, &tag, &reply).is_err(),
        "a tampered partial value must fail verification"
    );
}

#[test]
fn partial_pet_check_rejects_tampered_challenge() {
    let (_pet_pk, shares, pub_poly) = run_pet_key_dkg();
    let tag = sample_ephemeral_tag();
    let mut reply = PetNode::partial_pet_check(&share_for(&shares, 1), 1, &tag).unwrap();
    reply.challenge += Fr::one();

    assert!(
        PetNode::verify_partial_pet_check(&pub_poly, &tag, &reply).is_err(),
        "a tampered challenge must fail verification"
    );
}

#[test]
fn partial_pet_check_rejects_tampered_proof() {
    let (_pet_pk, shares, pub_poly) = run_pet_key_dkg();
    let tag = sample_ephemeral_tag();
    let mut reply = PetNode::partial_pet_check(&share_for(&shares, 1), 1, &tag).unwrap();
    reply.proof += Fr::one();

    assert!(
        PetNode::verify_partial_pet_check(&pub_poly, &tag, &reply).is_err(),
        "a tampered proof response must fail verification"
    );
}

#[test]
fn partial_pet_check_rejects_a_proof_relabeled_under_a_different_index() {
    let (_pet_pk, shares, pub_poly) = run_pet_key_dkg();
    let tag = sample_ephemeral_tag();
    // Genuinely computed and proved for node 1, then relabeled as node 2's
    // contribution — node 2's real public share differs from node 1's, so
    // the proof (bound to node 1's index and public share) must not verify.
    let mut reply = PetNode::partial_pet_check(&share_for(&shares, 1), 1, &tag).unwrap();
    reply.partial.i = 2;

    assert!(
        PetNode::verify_partial_pet_check(&pub_poly, &tag, &reply).is_err(),
        "a proof genuinely computed for one index must not verify when relabeled as another's"
    );
}

/// Headline regression scenario: per-share verification exists specifically
/// because the final-equation check alone is insufficient. Two genuinely
/// honest contributions (nodes 1 and 2, real DKG shares) plus a fabricated
/// third contribution — never derived from node 3's real secret share, and
/// requiring no knowledge of it — chosen so the Lagrange combination still
/// satisfies the tag's defining equation for a target the attacker chose
/// (here: framing "mallory" for a tag that was never issued to them).
/// `combine_pet_check_shares`/`verify_pet_match` alone are fooled by this;
/// `verify_partial_pet_check` is not.
#[test]
fn per_share_verification_rejects_a_cancellation_attack_that_would_otherwise_frame_a_wrong_target()
{
    let (pet_pk, shares, pub_poly) = run_pet_key_dkg();

    // A genuine tag, actually issued for "alice" — never for "mallory".
    let r_tag = Fr::rand(&mut OsRng);
    let r_point: G1Affine = (G1Projective::generator() * r_tag).into();
    let alice_fingerprint = PetNode::owner_fingerprint(b"alice").unwrap();
    let masked: G1Affine =
        (G1Projective::from(alice_fingerprint) + G1Projective::from(pet_pk) * r_tag).into();
    let tag = PetTag {
        ephemeral_point: r_point.to_bytes().unwrap(),
        masked_fingerprint: masked.to_bytes().unwrap(),
    };
    let mallory_fingerprint = PetNode::owner_fingerprint(b"mallory").unwrap();

    // Two genuine, honestly-computed contributions.
    let reply_1 = PetNode::partial_pet_check(&share_for(&shares, 1), 1, &tag).unwrap();
    let reply_2 = PetNode::partial_pet_check(&share_for(&shares, 2), 2, &tag).unwrap();
    let p1 = reply_1.partial.v;
    let p2 = reply_2.partial.v;

    // Lagrange coefficients for index set {1, 2, 3} evaluated at x=0 — the
    // same computation `combine_pet_check_shares` performs internally.
    let lagrange_coeff_at_zero = |indices: &[u32], i: u32| -> Fr {
        let xi = Fr::from(i as u64);
        let mut num = Fr::one();
        let mut den = Fr::one();
        for &j in indices {
            if j != i {
                let xj = Fr::from(j as u64);
                num *= xj;
                den *= xj - xi;
            }
        }
        num * den.inverse().unwrap()
    };
    let indices = [1u32, 2, 3];
    let lambda1 = lagrange_coeff_at_zero(&indices, 1);
    let lambda2 = lagrange_coeff_at_zero(&indices, 2);
    let lambda3 = lagrange_coeff_at_zero(&indices, 3);

    // What `combined` must equal for `verify_pet_match` to (incorrectly)
    // accept "mallory" as the audit target: T == F(mallory) + combined.
    let combined_target = G1Projective::from(masked) - G1Projective::from(mallory_fingerprint);
    // Solve for the fabricated third contribution — computable from public
    // information alone (the tag, the two honest contributions observed on
    // the wire, and the chosen target), no secret share needed:
    //   combined_target = lambda1*p1 + lambda2*p2 + lambda3*p3'
    let rhs = combined_target - G1Projective::from(p1) * lambda1 - G1Projective::from(p2) * lambda2;
    let fabricated_p3: G1Affine = (rhs * lambda3.inverse().unwrap()).into();

    // Sanity check: confirm the vulnerability this feature closes is real —
    // combining {p1, p2, fabricated_p3} and checking only the final equation
    // is fooled into accepting "mallory".
    let shares_for_combine = vec![
        PubShare { i: 1, v: p1 },
        PubShare { i: 2, v: p2 },
        PubShare {
            i: 3,
            v: fabricated_p3,
        },
    ];
    let combined = PetNode::combine_pet_check_shares(&shares_for_combine, 3, 3).unwrap();
    PetNode::verify_pet_match(&tag, &combined, &mallory_fingerprint).expect(
        "sanity: the fabricated contribution must fool the final-equation-only check, proving \
         the cancellation attack this feature closes is real",
    );

    // The actual regression: per-share verification rejects the fabricated
    // contribution on its own terms, before it ever reaches combination —
    // any (challenge, proof) pair works here, since no valid DLEQ proof can
    // exist for a point that isn't genuinely `share_3 * R` for node 3's real
    // secret share.
    let fabricated_reply = PetCheckReply {
        partial: PubShare {
            i: 3,
            v: fabricated_p3,
        },
        challenge: Fr::one(),
        proof: Fr::one(),
    };
    assert!(
        PetNode::verify_partial_pet_check(&pub_poly, &tag, &fabricated_reply).is_err(),
        "verify_partial_pet_check must reject the fabricated contribution even though it fools \
         the final equation and combine_pet_check_shares alone"
    );
}

// ============================================================================
// Blinding-correctness proof (audit finding #2's blind equality test)
// ============================================================================

/// `R`, `T` (masked_fingerprint), and `Y` (target) are independent random
/// points here — this suite exercises the blinding-proof math itself, not
/// the tag's own defining equation (see `make_valid_tag` for that).
fn sample_blind_inputs() -> (PetTag, G1Affine, Fr) {
    let r_tag = Fr::rand(&mut OsRng);
    let r_point: G1Affine = (G1Projective::generator() * r_tag).into();
    let masked: G1Affine = (G1Projective::generator() * Fr::rand(&mut OsRng)).into();
    let target: G1Affine = (G1Projective::generator() * Fr::rand(&mut OsRng)).into();
    let tag = PetTag {
        ephemeral_point: r_point.to_bytes().unwrap(),
        masked_fingerprint: masked.to_bytes().unwrap(),
    };
    (tag, target, Fr::rand(&mut OsRng))
}

#[test]
fn test_all_blinding_proof() {
    crate::pet_tests::run_all_blinding_proof_tests::<PetNode, _>(|| {
        let s = Fr::rand(&mut OsRng);
        let p: G1Affine = (G1Projective::generator() * s).into();
        (s, p)
    })
    .unwrap();
}

#[test]
fn blinding_proof_rejects_zero_scalar() {
    let (tag, target, _) = sample_blind_inputs();
    let digest = [7u8; 32];
    assert!(
        PetNode::prove_blinding_correctness(&Fr::zero(), &tag, &target, &digest).is_err(),
        "a zero blinding scalar must be rejected outright"
    );
}

#[test]
fn blinding_proof_rejects_tampered_blinded_r() {
    let (tag, target, z_i) = sample_blind_inputs();
    let digest = [7u8; 32];
    let mut reply = PetNode::prove_blinding_correctness(&z_i, &tag, &target, &digest).unwrap();
    reply.blinded_r = (G1Projective::from(reply.blinded_r) + G1Projective::generator()).into();

    assert!(
        PetNode::verify_blinding_correctness(&tag, &target, &reply, &digest).is_err(),
        "a tampered blinded_r must fail verification"
    );
}

#[test]
fn blinding_proof_rejects_tampered_blinded_diff() {
    let (tag, target, z_i) = sample_blind_inputs();
    let digest = [7u8; 32];
    let mut reply = PetNode::prove_blinding_correctness(&z_i, &tag, &target, &digest).unwrap();
    reply.blinded_diff =
        (G1Projective::from(reply.blinded_diff) + G1Projective::generator()).into();

    assert!(
        PetNode::verify_blinding_correctness(&tag, &target, &reply, &digest).is_err(),
        "a tampered blinded_diff must fail verification"
    );
}

#[test]
fn blinding_proof_rejects_tampered_challenge() {
    let (tag, target, z_i) = sample_blind_inputs();
    let digest = [7u8; 32];
    let mut reply = PetNode::prove_blinding_correctness(&z_i, &tag, &target, &digest).unwrap();
    reply.challenge += Fr::one();

    assert!(
        PetNode::verify_blinding_correctness(&tag, &target, &reply, &digest).is_err(),
        "a tampered challenge must fail verification"
    );
}

#[test]
fn blinding_proof_rejects_tampered_response() {
    let (tag, target, z_i) = sample_blind_inputs();
    let digest = [7u8; 32];
    let mut reply = PetNode::prove_blinding_correctness(&z_i, &tag, &target, &digest).unwrap();
    reply.proof += Fr::one();

    assert!(
        PetNode::verify_blinding_correctness(&tag, &target, &reply, &digest).is_err(),
        "a tampered proof response must fail verification"
    );
}

/// A genuinely valid Chaum-Pedersen proof for `z_i = 0`: any nonzero nonce
/// `w` produces a mathematically sound `(U, V, challenge, response)` tuple —
/// the DLEQ relation itself doesn't care that `z_i` is zero. Only the
/// explicit `blinded_r == O` check inside `verify_blinding_correctness`
/// catches this; this test confirms that check is load-bearing, not
/// redundant with the proof math itself.
#[test]
fn blinding_proof_rejects_a_validly_constructed_proof_for_a_zero_scalar() {
    let (tag, target, _) = sample_blind_inputs();
    let digest = [7u8; 32];
    let r_point = G1Affine::from_bytes(&tag.ephemeral_point).unwrap();
    let masked = G1Affine::from_bytes(&tag.masked_fingerprint).unwrap();
    let diff_point: G1Affine = (G1Projective::from(masked) - G1Projective::from(target)).into();

    let z_i = Fr::zero();
    let blinded_r: G1Affine = (G1Projective::from(r_point) * z_i).into(); // == O
    let blinded_diff: G1Affine = (G1Projective::from(diff_point) * z_i).into();

    let w = Fr::rand(&mut OsRng);
    let u_point: G1Affine = (G1Projective::from(r_point) * w).into();
    let v_point: G1Affine = (G1Projective::from(diff_point) * w).into();

    let challenge = PetNode::blinding_proof_challenge(
        &r_point,
        &diff_point,
        &blinded_r,
        &blinded_diff,
        &u_point,
        &v_point,
        &digest,
    )
    .unwrap();
    let response = w + challenge * z_i; // == w, since z_i == 0

    let reply = crate::r#trait::BlindingReply {
        blinded_r,
        blinded_diff,
        challenge,
        proof: response,
    };

    assert!(
        PetNode::verify_blinding_correctness(&tag, &target, &reply, &digest).is_err(),
        "a validly-constructed proof for a zero blinding scalar must still be rejected via the \
         explicit blinded_r == O check"
    );
}
