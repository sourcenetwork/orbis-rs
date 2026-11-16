use crate::context::{CiphertextContext, ReaderAuthorizationContext};
use crate::error::Result;
use crate::jubjub::{
    common::{Element, Fr, PubPoly},
    pet::PetNode,
    pre::ThresholdDealerNode,
};
use crate::r#trait::{
    CryptoDeserialize, CryptoSerialize, DistKeyShare, Pet, PetTag, PriShare, ThresholdDealer,
};
use ::jubjub::{AffinePoint, ExtendedPoint, Fq, SubgroupPoint};
use group_jubjub::{Group, GroupEncoding};

/// All fixtures have the correct wire length. The first two are canonical
/// curve points outside the prime-order subgroup; the last two exercise the
/// noncanonical sign encodings rejected by Jubjub's ZIP-216 decoding rules.
fn invalid_point_encodings() -> [(&'static str, [u8; 32]); 4] {
    // (u, v) = (0, -1), encoded with the canonical zero sign bit.
    let order_two_bytes = (-Fq::one()).to_bytes();
    let order_two = AffinePoint::from_bytes(order_two_bytes).unwrap();
    assert!(bool::from(order_two.is_small_order()));
    assert!(!bool::from(order_two.is_torsion_free()));

    let mixed_order = ExtendedPoint::from(SubgroupPoint::generator()) + order_two;
    assert!(!bool::from(mixed_order.is_small_order()));
    assert!(!bool::from(mixed_order.is_torsion_free()));
    let mixed_order_bytes = mixed_order.to_bytes();
    assert!(bool::from(
        AffinePoint::from_bytes(mixed_order_bytes).is_some()
    ));

    let mut signed_identity = AffinePoint::identity().to_bytes();
    signed_identity[31] |= 0x80;
    let mut signed_order_two = order_two_bytes;
    signed_order_two[31] |= 0x80;
    assert!(bool::from(
        AffinePoint::from_bytes(signed_identity).is_none()
    ));
    assert!(bool::from(
        AffinePoint::from_bytes(signed_order_two).is_none()
    ));

    [
        ("order-two point", order_two_bytes),
        ("mixed-order point", mixed_order_bytes),
        ("signed identity", signed_identity),
        ("signed order-two point", signed_order_two),
    ]
}

/// Require rejection at decoding, so an unrelated proof mismatch cannot make
/// these tests pass if unchecked points reach the secret-scalar operations.
fn assert_decode_error<T>(result: Result<T>, expected: &str, case: &str) {
    let error = match result {
        Ok(_) => panic!("accepted {case}"),
        Err(error) => error,
    };
    assert!(
        error.to_string().contains(expected),
        "{case} failed after decoding instead of at decoding: {error}"
    );
}

#[test]
fn pre_rejects_non_subgroup_and_noncanonical_points_at_decoding() {
    let secret_share = Fr::from(5u64);
    let public_key = Element::generator() * secret_share;
    let context = CiphertextContext {
        ring_pk: public_key.to_bytes().unwrap(),
        policy_id: "subgroup-test".to_owned(),
        resource: "secret".to_owned(),
        permission: "read".to_owned(),
        tier: None,
        timestamp: None,
        salt: None,
        pet_tag: None,
    };
    let (_, secret, proof) =
        ThresholdDealerNode::encrypt_secret(&public_key, b"plaintext", None, &context).unwrap();
    ThresholdDealerNode::verify_encryption(&proof, &context, &secret).unwrap();

    let reader_secret = Fr::from(7u64);
    let reader_key = Element::generator() * reader_secret;
    let reader_auth_context = ReaderAuthorizationContext {
        chain_id: "test-chain".to_string(),
        ring_pk: public_key.to_bytes().unwrap(),
        jwt_issuer: "did:key:issuer".to_string(),
        jwt_subject: None,
        resolved_actor: "did:key:issuer".to_string(),
        jwt_id: "jti-1".to_string(),
        jwt_issued_time: 1_700_000_000,
        jwt_expiration_time: 1_700_003_600,
        jwt_not_before: None,
        object_id: "secret".to_string(),
        recipient_pk: reader_key.to_bytes().unwrap(),
        derivation: None,
        salt: None,
        valid_window: None,
        audit_target_object_id: None,
    };
    let reader_signature = ThresholdDealerNode::sign_reader_authorization(
        &reader_secret,
        &reader_key,
        &reader_auth_context,
    )
    .unwrap();
    let share = DistKeyShare {
        pri_share: PriShare {
            i: 1,
            v: secret_share,
        },
    };
    let dealer = ThresholdDealerNode::new();
    dealer
        .reencrypt(
            &share,
            &secret,
            &reader_key,
            &reader_auth_context,
            &reader_signature,
        )
        .unwrap();

    for (case, bytes) in invalid_point_encodings() {
        type PublicKey = <ThresholdDealerNode as ThresholdDealer>::PublicKey;
        assert!(PublicKey::from_bytes(&bytes).is_err(), "accepted {case}");

        let mut malformed = secret.clone();
        malformed.enc_cmt = bytes.to_vec();
        assert_decode_error(
            ThresholdDealerNode::verify_encryption(&proof, &context, &malformed),
            "Failed to deserialize enc_cmt",
            case,
        );
        assert_decode_error(
            dealer.reencrypt(
                &share,
                &malformed,
                &reader_key,
                &reader_auth_context,
                &reader_signature,
            ),
            "failed to decompress point",
            case,
        );
    }
}

#[test]
fn pet_rejects_non_subgroup_and_noncanonical_ephemeral_points_at_decoding() {
    let r_tag = Fr::from(7u64);
    let secret_share = Fr::from(11u64);
    let r_point = Element::generator() * r_tag;
    let fingerprint = PetNode::owner_fingerprint(b"alice").unwrap();
    let tag = PetTag {
        ephemeral_point: r_point.to_bytes().unwrap(),
        masked_fingerprint: (fingerprint + r_point * secret_share).to_bytes().unwrap(),
    };
    let digest = [42u8; 32];
    let tag_proof = PetNode::prove_tag_knowledge(&r_tag, &tag, &digest).unwrap();
    PetNode::verify_tag_knowledge(&tag, &tag_proof, &digest).unwrap();
    let partial = PetNode::partial_pet_check(&secret_share, 1, &tag).unwrap();
    let pub_poly = PubPoly {
        commits: vec![Element::generator() * secret_share],
    };
    PetNode::verify_partial_pet_check(&pub_poly, &tag, &partial).unwrap();
    let blinding_scalar = Fr::from(13u64);
    let blind_proof =
        PetNode::prove_blinding_correctness(&blinding_scalar, &tag, &fingerprint, &digest).unwrap();
    PetNode::verify_blinding_correctness(&tag, &fingerprint, &blind_proof, &digest).unwrap();

    for (case, bytes) in invalid_point_encodings() {
        let mut malformed = tag.clone();
        malformed.ephemeral_point = bytes.to_vec();
        let expected = "failed to decompress ephemeral_point";
        assert_decode_error(
            PetNode::prove_tag_knowledge(&r_tag, &malformed, &digest),
            expected,
            case,
        );
        assert_decode_error(
            PetNode::verify_tag_knowledge(&malformed, &tag_proof, &digest),
            expected,
            case,
        );
        assert_decode_error(
            PetNode::partial_pet_check(&secret_share, 1, &malformed),
            expected,
            case,
        );
        assert_decode_error(
            PetNode::verify_partial_pet_check(&pub_poly, &malformed, &partial),
            expected,
            case,
        );
        assert_decode_error(
            PetNode::prove_blinding_correctness(
                &blinding_scalar,
                &malformed,
                &fingerprint,
                &digest,
            ),
            expected,
            case,
        );
        assert_decode_error(
            PetNode::verify_blinding_correctness(&malformed, &fingerprint, &blind_proof, &digest),
            expected,
            case,
        );
    }
}

#[test]
fn pet_rejects_non_subgroup_and_noncanonical_masked_fingerprints_at_decoding() {
    let r_point = Element::generator() * Fr::from(7u64);
    let combined_check = r_point * Fr::from(11u64);
    let fingerprint = PetNode::owner_fingerprint(b"alice").unwrap();
    let tag = PetTag {
        ephemeral_point: r_point.to_bytes().unwrap(),
        masked_fingerprint: (fingerprint + combined_check).to_bytes().unwrap(),
    };
    PetNode::verify_pet_match(&tag, &combined_check, &fingerprint).unwrap();
    let digest = [42u8; 32];
    let blinding_scalar = Fr::from(13u64);
    let blind_proof =
        PetNode::prove_blinding_correctness(&blinding_scalar, &tag, &fingerprint, &digest).unwrap();
    PetNode::verify_blinding_correctness(&tag, &fingerprint, &blind_proof, &digest).unwrap();

    for (case, bytes) in invalid_point_encodings() {
        let mut malformed = tag.clone();
        malformed.masked_fingerprint = bytes.to_vec();
        let expected = "failed to decompress masked_fingerprint";
        assert_decode_error(
            PetNode::verify_pet_match(&malformed, &combined_check, &fingerprint),
            expected,
            case,
        );
        assert_decode_error(
            PetNode::prove_blinding_correctness(
                &blinding_scalar,
                &malformed,
                &fingerprint,
                &digest,
            ),
            expected,
            case,
        );
        assert_decode_error(
            PetNode::verify_blinding_correctness(&malformed, &fingerprint, &blind_proof, &digest),
            expected,
            case,
        );
    }
}
