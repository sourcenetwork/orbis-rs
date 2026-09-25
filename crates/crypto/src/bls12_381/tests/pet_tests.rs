use crate::bls12_381::pet::PetNode;
use crate::r#trait::{CryptoSerialize, Pet, PetTag, PubShare};
use ark_bls12_381::{Fr, G1Affine, G1Projective};
use ark_ec::Group;
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
        .map(|i| PubShare {
            i,
            v: PetNode::partial_pet_check(&pet_sk, tag).unwrap(),
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
    let partial = PetNode::partial_pet_check(&pet_sk, &tag).unwrap();
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
    let partial = PetNode::partial_pet_check(&pet_sk, &tag).unwrap();
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
