use crate::decaf377::common::{
    PolynomialCommitment, PubPoly, ELEMENT_COMPRESSED_SIZE, FR_COMPRESSED_SIZE,
};
use crate::decaf377::pre::ThresholdDealerNode;
use crate::decaf377::sign::{FrostNonceCommitment, FrostSigningState, SchnorrSignature};
use crate::deserialization_prop_tests_helpers::{
    assert_canonical_from_bytes, assert_value_roundtrips, byte_vec, small_byte_vec, PROPTEST_CASES,
};
use crate::helpers::reject_non_canonical;
use crate::r#trait::{
    CryptoDeserialize, CryptoSerialize, DistKeyShare, DistributedShare, EncryptionProof, PriShare,
    PubShare, ReencryptReply, ThresholdDealer,
};
use ::decaf377::{Element, Fr};
use proptest::prelude::*;

fn scalar(seed: u64) -> Fr {
    Fr::from(seed)
}

fn element(seed: u64) -> Element {
    Element::GENERATOR * scalar(seed)
}

proptest! {
    #![proptest_config(proptest::test_runner::Config::with_cases(PROPTEST_CASES))]

    #[test]
    fn arbitrary_bytes_are_canonical_or_rejected(bytes in byte_vec()) {
        assert_canonical_from_bytes::<Fr>(&bytes)?;
        assert_canonical_from_bytes::<Element>(&bytes)?;
        assert_canonical_from_bytes::<PubPoly>(&bytes)?;
        assert_canonical_from_bytes::<PolynomialCommitment>(&bytes)?;
        assert_canonical_from_bytes::<DistributedShare<Fr>>(&bytes)?;
        assert_canonical_from_bytes::<PriShare<Fr>>(&bytes)?;
        assert_canonical_from_bytes::<DistKeyShare<Fr>>(&bytes)?;
        assert_canonical_from_bytes::<PubShare<Element>>(&bytes)?;
        assert_canonical_from_bytes::<PubShare<Fr>>(&bytes)?;
        assert_canonical_from_bytes::<ReencryptReply<Fr, Element>>(&bytes)?;
        assert_canonical_from_bytes::<SchnorrSignature>(&bytes)?;
        assert_canonical_from_bytes::<FrostNonceCommitment>(&bytes)?;
        assert_canonical_from_bytes::<FrostSigningState>(&bytes)?;
    }

    #[test]
    fn generated_values_roundtrip_and_reject_trailing_bytes(
        from_id in any::<u32>(),
        to_id in any::<u32>(),
        index in any::<u32>(),
        session_id in any::<u64>(),
        nonce in any::<[u8; 16]>(),
        a in any::<u64>(),
        b in any::<u64>(),
        c in any::<u64>(),
        coeffs in prop::collection::vec(any::<u64>(), 0..8),
    ) {
        let share_value = scalar(a);
        let public_key = element(b);
        let sig_share = scalar(c);
        let commits = coeffs.iter().copied().map(element).collect::<Vec<_>>();

        assert_value_roundtrips(&share_value)?;
        assert_value_roundtrips(&public_key)?;
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
        assert_value_roundtrips(&PubShare { i: index, v: sig_share })?;
        assert_value_roundtrips(&ReencryptReply {
            share: PubShare { i: index, v: element(a) },
            challenge: scalar(b),
            proof: scalar(c),
        })?;
        assert_value_roundtrips(&SchnorrSignature {
            r_point: element(a),
            z: scalar(b),
        })?;
        assert_value_roundtrips(&FrostNonceCommitment {
            hiding: element(a),
            binding: element(b),
        })?;
        assert_value_roundtrips(&FrostSigningState {
            hiding_nonce: scalar(a),
            binding_nonce: scalar(b),
            participant_index: index,
        })?;
    }

    #[test]
    fn verify_encryption_rejects_or_handles_arbitrary_proof_bytes(
        shared_point in small_byte_vec(),
        challenge in small_byte_vec(),
        response in small_byte_vec(),
    ) {
        let effective_pk = element(5);
        let enc_cmt = element(7);
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

    let mut share = vec![0u8; 36];
    share[32..36].copy_from_slice(&huge);
    assert!(DistributedShare::<Fr>::from_bytes(&share).is_err());

    let mut reply = Vec::with_capacity(12);
    reply.extend_from_slice(&huge);
    reply.extend_from_slice(&[0u8; 8]);
    assert!(ReencryptReply::<Fr, Element>::from_bytes(&reply).is_err());
}

#[test]
fn primitive_lengths_are_exact() {
    assert!(Fr::from_bytes(&[0u8; FR_COMPRESSED_SIZE + 1]).is_err());
    assert!(Element::from_bytes(&[0u8; ELEMENT_COMPRESSED_SIZE + 1]).is_err());
}

// For decaf377, ark_ff validates Fr < r and decaf377's decoder validates Element
// encodings bijectively, so there are no byte sequences that pass
// deserialize_compressed but re-serialize to different bytes.  reject_non_canonical
// is therefore purely defensive for these types.  The two tests below pin its
// core mismatch-detection behavior (ensuring it never silently becomes a no-op),
// and the two pipeline tests cover the nearest analog to "non-canonical": byte
// sequences the decoder explicitly rejects via the same code paths.
#[test]
fn reject_non_canonical_detects_fr_byte_mismatch() {
    let fr_one = scalar(1);
    let fr_zero_bytes = scalar(0).to_bytes().unwrap();
    assert!(
        reject_non_canonical(&fr_one, &fr_zero_bytes).is_err(),
        "reject_non_canonical must Err when the value re-serializes to bytes different from the supplied slice"
    );
}

#[test]
fn reject_non_canonical_detects_element_byte_mismatch() {
    let gen = element(1);
    let identity_bytes = Element::default().to_bytes().unwrap();
    assert!(
        reject_non_canonical(&gen, &identity_bytes).is_err(),
        "reject_non_canonical must Err when the value re-serializes to bytes different from the supplied slice"
    );
}

#[test]
fn fr_out_of_range_bytes_rejected() {
    // Any 32-byte sequence whose value >= r is invalid. The decaf377 scalar
    // field modulus r starts with 0x12 in the high byte (little-endian byte 31),
    // so setting byte 31 to 0xff produces a value far above r.
    let mut bytes = [0u8; FR_COMPRESSED_SIZE];
    bytes[FR_COMPRESSED_SIZE - 1] = 0xff;
    assert!(Fr::from_bytes(&bytes).is_err());
}

#[test]
fn element_with_high_bits_set_rejected() {
    // decaf377's decoder explicitly rejects encodings where the top 3 bits of
    // byte 31 are non-zero (bits 253-255 must be zero for all valid encodings).
    // Setting bit 7 of byte 31 (bit 255) is the closest analog to a
    // "non-canonical" element encoding — the underlying field value is in
    // range but the decoder rejects it before reaching the curve arithmetic.
    let mut bytes = [0u8; ELEMENT_COMPRESSED_SIZE];
    bytes[ELEMENT_COMPRESSED_SIZE - 1] = 0x80; // bit 255 set
    assert!(Element::from_bytes(&bytes).is_err());
}

#[test]
fn pre_proof_component_lengths_are_exact() {
    let dkg_pk = element(11);
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
