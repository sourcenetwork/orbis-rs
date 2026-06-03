use crate::bls12_381::common::{
    G2Point, PolynomialCommitment, PubPoly, FR_COMPRESSED_SIZE, G1_COMPRESSED_SIZE,
    G2_COMPRESSED_SIZE,
};
use crate::bls12_381::pre::ThresholdDealerNode;
use crate::deserialization_prop_tests_helpers::{
    assert_canonical_from_bytes, assert_value_roundtrips, byte_vec, small_byte_vec, PROPTEST_CASES,
};
use crate::r#trait::{
    CryptoDeserialize, CryptoSerialize, DistKeyShare, DistributedShare, EncryptionProof, PriShare,
    PubShare, ReencryptReply, ThresholdDealer,
};
use ark_bls12_381::{Fr, G1Affine, G1Projective, G2Projective};
use ark_ec::Group;
use proptest::prelude::*;

fn scalar(seed: u64) -> Fr {
    Fr::from(seed)
}

fn g1(seed: u64) -> G1Affine {
    (G1Projective::generator() * scalar(seed)).into()
}

fn g2(seed: u64) -> G2Point {
    G2Point::new((G2Projective::generator() * scalar(seed)).into())
}

proptest! {
    #![proptest_config(proptest::test_runner::Config::with_cases(PROPTEST_CASES))]

    #[test]
    fn arbitrary_bytes_are_canonical_or_rejected(bytes in byte_vec()) {
        assert_canonical_from_bytes::<Fr>(&bytes)?;
        assert_canonical_from_bytes::<G1Affine>(&bytes)?;
        assert_canonical_from_bytes::<G2Point>(&bytes)?;
        assert_canonical_from_bytes::<PubPoly>(&bytes)?;
        assert_canonical_from_bytes::<PolynomialCommitment>(&bytes)?;
        assert_canonical_from_bytes::<DistributedShare<Fr>>(&bytes)?;
        assert_canonical_from_bytes::<PriShare<Fr>>(&bytes)?;
        assert_canonical_from_bytes::<DistKeyShare<Fr>>(&bytes)?;
        assert_canonical_from_bytes::<PubShare<G1Affine>>(&bytes)?;
        assert_canonical_from_bytes::<PubShare<G2Point>>(&bytes)?;
        assert_canonical_from_bytes::<ReencryptReply<Fr, G1Affine>>(&bytes)?;
    }

    #[test]
    fn generated_values_roundtrip_and_reject_trailing_bytes(
        from_id in any::<u32>(),
        to_id in any::<u32>(),
        index in any::<u32>(),
        session_id in any::<u128>(),
        nonce in any::<[u8; 16]>(),
        a in any::<u64>(),
        b in any::<u64>(),
        c in any::<u64>(),
        coeffs in prop::collection::vec(any::<u64>(), 0..8),
    ) {
        let share_value = scalar(a);
        let public_key = g1(b);
        let signature = g2(c);
        let commits = coeffs.iter().copied().map(g1).collect::<Vec<_>>();

        assert_value_roundtrips(&share_value)?;
        assert_value_roundtrips(&public_key)?;
        assert_value_roundtrips(&signature)?;
        assert_value_roundtrips(&PubPoly { commits: commits.clone() })?;
        assert_value_roundtrips(&PolynomialCommitment { coefficients: commits })?;
        assert_value_roundtrips(&DistributedShare {
            from_id,
            to_id,
            value: share_value,
            nonce,
            session_id,
        })?;
        assert_value_roundtrips(&PriShare { i: index, v: scalar(b) })?;
        assert_value_roundtrips(&DistKeyShare {
            pri_share: PriShare { i: index, v: scalar(c) },
        })?;
        assert_value_roundtrips(&PubShare { i: index, v: public_key })?;
        assert_value_roundtrips(&PubShare { i: index, v: signature })?;
        assert_value_roundtrips(&ReencryptReply {
            share: PubShare { i: index, v: g1(a) },
            challenge: scalar(b),
            proof: scalar(c),
        })?;
    }

    #[test]
    fn verify_encryption_rejects_or_handles_arbitrary_proof_bytes(
        shared_point in small_byte_vec(),
        challenge in small_byte_vec(),
        response in small_byte_vec(),
    ) {
        let effective_pk = g1(5);
        let enc_cmt = g1(7);
        let proof = EncryptionProof {
            shared_point,
            challenge,
            response,
        };

        let _ = ThresholdDealerNode::verify_encryption(&effective_pk, &enc_cmt, &proof, None);
    }
}

#[test]
fn malicious_length_prefixes_are_rejected_before_allocation() {
    let huge = u32::MAX.to_le_bytes();

    assert!(PubPoly::from_bytes(&huge).is_err());
    assert!(PolynomialCommitment::from_bytes(&huge).is_err());

    let mut share = vec![0u8; 44];
    share[40..44].copy_from_slice(&huge);
    assert!(DistributedShare::<Fr>::from_bytes(&share).is_err());

    let mut reply = Vec::with_capacity(12);
    reply.extend_from_slice(&huge);
    reply.extend_from_slice(&[0u8; 8]);
    assert!(ReencryptReply::<Fr, G1Affine>::from_bytes(&reply).is_err());
}

#[test]
fn primitive_lengths_are_exact() {
    assert!(Fr::from_bytes(&[0u8; FR_COMPRESSED_SIZE + 1]).is_err());
    assert!(G1Affine::from_bytes(&[0u8; G1_COMPRESSED_SIZE + 1]).is_err());
    assert!(G2Point::from_bytes(&[0u8; G2_COMPRESSED_SIZE + 1]).is_err());
}

#[test]
fn non_canonical_identity_encodings_are_rejected() {
    let mut canonical_g1_identity = vec![0u8; G1_COMPRESSED_SIZE];
    canonical_g1_identity[0] = 0xc0;
    let g1_identity = G1Affine::from_bytes(&canonical_g1_identity).unwrap();
    assert_eq!(g1_identity.to_bytes().unwrap(), canonical_g1_identity);

    let mut non_canonical_g1_identity = canonical_g1_identity;
    non_canonical_g1_identity[G1_COMPRESSED_SIZE - 1] = 1;
    assert!(G1Affine::from_bytes(&non_canonical_g1_identity).is_err());

    let mut canonical_g2_identity = vec![0u8; G2_COMPRESSED_SIZE];
    canonical_g2_identity[0] = 0xc0;
    let g2_identity = G2Point::from_bytes(&canonical_g2_identity).unwrap();
    assert_eq!(g2_identity.to_bytes().unwrap(), canonical_g2_identity);

    let mut non_canonical_g2_identity = canonical_g2_identity;
    non_canonical_g2_identity[G2_COMPRESSED_SIZE - 1] = 1;
    assert!(G2Point::from_bytes(&non_canonical_g2_identity).is_err());
}

#[test]
fn pre_proof_component_lengths_are_exact() {
    let dkg_pk = g1(11);
    let (enc_cmt, _secret, proof) =
        ThresholdDealerNode::encrypt_secret(&dkg_pk, b"proof length test", None, None).unwrap();
    ThresholdDealerNode::verify_encryption(&dkg_pk, &enc_cmt, &proof, None).unwrap();

    let mut with_trailing_shared = proof.clone();
    with_trailing_shared.shared_point.push(0);
    assert!(
        ThresholdDealerNode::verify_encryption(&dkg_pk, &enc_cmt, &with_trailing_shared, None)
            .is_err()
    );

    let mut with_trailing_challenge = proof.clone();
    with_trailing_challenge.challenge.push(0);
    assert!(ThresholdDealerNode::verify_encryption(
        &dkg_pk,
        &enc_cmt,
        &with_trailing_challenge,
        None
    )
    .is_err());

    let mut with_trailing_response = proof;
    with_trailing_response.response.push(0);
    assert!(ThresholdDealerNode::verify_encryption(
        &dkg_pk,
        &enc_cmt,
        &with_trailing_response,
        None
    )
    .is_err());
}
