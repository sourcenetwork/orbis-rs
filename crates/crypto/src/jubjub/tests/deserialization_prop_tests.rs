use crate::context::CiphertextContext;
use crate::deserialization_prop_tests_helpers::{
    assert_canonical_from_bytes, assert_value_roundtrips, byte_vec, small_byte_vec, PROPTEST_CASES,
};
use crate::jubjub::common::{Element, Fr};
use crate::jubjub::common::{
    PolynomialCommitment, PubPoly, ELEMENT_COMPRESSED_SIZE, FR_COMPRESSED_SIZE,
};
use crate::jubjub::pre::ThresholdDealerNode;
use crate::jubjub::sign::{FrostNonceCommitment, FrostSigningState, SchnorrSignature};
use crate::r#trait::{
    CryptoDeserialize, CryptoSerialize, DistKeyShare, DistributedShare, EncryptionProof, PriShare,
    PubShare, ReencryptReply, Secret, ThresholdDealer,
};
use proptest::prelude::*;

fn scalar(seed: u64) -> Fr {
    Fr::from(seed)
}

fn element(seed: u64) -> Element {
    Element::generator() * scalar(seed)
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
        session_id in any::<u128>(),
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
        challenge in small_byte_vec(),
        response in small_byte_vec(),
    ) {
        let secret = Secret {
            enc_cmt: element(7).to_bytes().unwrap(),
            encrypted_data: vec![0u8; 32],
            nonce: vec![0u8; 12],
        };
        let ctx = CiphertextContext {
            ring_pk: vec![1, 2, 3],
            policy_id: "p".to_string(),
            resource: "r".to_string(),
            permission: "read".to_string(),
            tier: None,
            timestamp: None,
            salt: None,
            pet_tag: None,
        };
        let proof = EncryptionProof { challenge, response };

        let _ = ThresholdDealerNode::verify_encryption(&proof, &ctx, &secret);
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
    assert!(ReencryptReply::<Fr, Element>::from_bytes(&reply).is_err());
}

#[test]
fn primitive_lengths_are_exact() {
    assert!(Fr::from_bytes(&[0u8; FR_COMPRESSED_SIZE + 1]).is_err());
    assert!(Element::from_bytes(&[0u8; ELEMENT_COMPRESSED_SIZE + 1]).is_err());
}

#[test]
fn fr_out_of_range_bytes_rejected() {
    // Jubjub's 252-bit scalar modulus has high byte 0x0e.
    // A high byte of 0xff is outside the canonical scalar range.
    let mut bytes = [0u8; FR_COMPRESSED_SIZE];
    bytes[FR_COMPRESSED_SIZE - 1] = 0xff;
    assert!(Fr::from_bytes(&bytes).is_err());
}

#[test]
fn element_with_noncanonical_identity_sign_rejected() {
    // The sign bit must be zero when the u coordinate is zero.
    let mut bytes = Element::default().to_bytes().unwrap();
    bytes[ELEMENT_COMPRESSED_SIZE - 1] |= 0x80;
    assert!(Element::from_bytes(&bytes).is_err());
}

#[test]
fn pre_proof_component_lengths_are_exact() {
    let dkg_pk = element(11);
    let ctx = CiphertextContext {
        ring_pk: vec![9, 9, 9],
        policy_id: "p".to_string(),
        resource: "r".to_string(),
        permission: "read".to_string(),
        tier: None,
        timestamp: None,
        salt: None,
        pet_tag: None,
    };
    let (_enc_cmt, secret, proof) =
        ThresholdDealerNode::encrypt_secret(&dkg_pk, b"proof length test", None, &ctx).unwrap();
    ThresholdDealerNode::verify_encryption(&proof, &ctx, &secret).unwrap();

    let mut with_trailing_challenge = proof.clone();
    with_trailing_challenge.challenge.push(0);
    assert!(
        ThresholdDealerNode::verify_encryption(&with_trailing_challenge, &ctx, &secret).is_err()
    );

    let mut with_trailing_response = proof;
    with_trailing_response.response.push(0);
    assert!(
        ThresholdDealerNode::verify_encryption(&with_trailing_response, &ctx, &secret).is_err()
    );
}
