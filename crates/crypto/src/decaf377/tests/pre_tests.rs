use crate::decaf377::common::PubPoly;
use crate::decaf377::pre::ThresholdDealerNode;
use crate::r#trait::{
    DistKeyShare, PriShare, PubPoly as PubPolyTrait, PubShare, Secret, ThresholdDealer,
};
use crate::test_helper::DKGCoordinator;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::UniformRand;
use decaf377::{Element, Fr};
use rand_core::OsRng;

#[test]
fn test_threshold_dealer_creation() {
    let dealer = ThresholdDealerNode::new();
    assert_eq!(dealer.name(), "elgamal/decaf377");
}

#[test]
fn test_encrypt_decrypt_flow() {
    let secret = b"test secret data";
    let mut rng = OsRng;

    // Setup DKG key pair
    let dkg_sk = Fr::rand(&mut rng);
    let dkg_pk = Element::GENERATOR * dkg_sk;

    // Setup reader key pair
    let rdr_sk = Fr::rand(&mut rng);
    let rdr_pk = Element::GENERATOR * rdr_sk;

    // 1. Encrypt the secret (no derivation)
    let (enc_cmt, encrypted_secret, _proof) =
        ThresholdDealerNode::encrypt_secret(&dkg_pk, secret, None, None).unwrap();

    // Verify encryption produces valid output
    assert_ne!(enc_cmt, Element::default());
    assert!(!encrypted_secret.encrypted_data.is_empty());
    assert_eq!(encrypted_secret.nonce.len(), 12);

    // 2. Simulate re-encryption: xnc_cmt = dkg_sk * (rdr_pk + enc_cmt)
    let xr_g = rdr_pk + enc_cmt;
    let xnc_cmt = xr_g * dkg_sk;

    // 3. Decrypt the secret
    let decrypted =
        ThresholdDealerNode::decrypt_secret(&dkg_pk, &xnc_cmt, &rdr_sk, &encrypted_secret).unwrap();

    assert_eq!(decrypted, secret);
}

#[test]
fn test_encrypt_decrypt_large_data() {
    let secret = b"This is a much longer secret that contains multiple blocks of data. \
                   It should be properly encrypted and decrypted using AES-GCM, which \
                   handles arbitrary length data. This tests that our hybrid encryption \
                   scheme works correctly with larger payloads that exceed typical \
                   block sizes and ensures proper chunking and authentication.";

    let mut rng = OsRng;
    let dkg_sk = Fr::rand(&mut rng);
    let dkg_pk = Element::GENERATOR * dkg_sk;
    let rdr_sk = Fr::rand(&mut rng);
    let rdr_pk = Element::GENERATOR * rdr_sk;

    let (enc_cmt, encrypted_secret, _proof) =
        ThresholdDealerNode::encrypt_secret(&dkg_pk, secret, None, None).unwrap();

    assert_ne!(enc_cmt, Element::default());
    assert!(!encrypted_secret.encrypted_data.is_empty());

    let xr_g = rdr_pk + enc_cmt;
    let xnc_cmt = xr_g * dkg_sk;

    let decrypted =
        ThresholdDealerNode::decrypt_secret(&dkg_pk, &xnc_cmt, &rdr_sk, &encrypted_secret).unwrap();

    assert_eq!(decrypted.len(), secret.len());
    assert_eq!(decrypted, secret);
}

#[test]
fn test_encrypt_decrypt_empty_data() {
    let secret = b"";
    let mut rng = OsRng;
    let dkg_sk = Fr::rand(&mut rng);
    let dkg_pk = Element::GENERATOR * dkg_sk;
    let rdr_sk = Fr::rand(&mut rng);
    let rdr_pk = Element::GENERATOR * rdr_sk;

    let (enc_cmt, encrypted_secret, _proof) =
        ThresholdDealerNode::encrypt_secret(&dkg_pk, secret, None, None).unwrap();

    let xr_g = rdr_pk + enc_cmt;
    let xnc_cmt = xr_g * dkg_sk;

    let decrypted =
        ThresholdDealerNode::decrypt_secret(&dkg_pk, &xnc_cmt, &rdr_sk, &encrypted_secret).unwrap();

    assert_eq!(decrypted, secret);
}

#[test]
fn test_decryption_fails_with_wrong_key() {
    let secret = b"test secret";
    let mut rng = OsRng;
    let dkg_sk = Fr::rand(&mut rng);
    let dkg_pk = Element::GENERATOR * dkg_sk;
    let rdr_sk = Fr::rand(&mut rng);
    let rdr_pk = Element::GENERATOR * rdr_sk;

    let wrong_rdr_sk = Fr::rand(&mut rng);

    let (enc_cmt, encrypted_secret, _proof) =
        ThresholdDealerNode::encrypt_secret(&dkg_pk, secret, None, None).unwrap();

    let xr_g = rdr_pk + enc_cmt;
    let xnc_cmt = xr_g * dkg_sk;

    let result =
        ThresholdDealerNode::decrypt_secret(&dkg_pk, &xnc_cmt, &wrong_rdr_sk, &encrypted_secret);

    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("authentication failed"));
}

#[test]
fn test_reencrypt_and_verify() {
    let mut rng = OsRng;

    let dkg_sk = Fr::rand(&mut rng);
    let dkg_pk = Element::GENERATOR * dkg_sk;
    let _rdr_sk = Fr::rand(&mut rng);
    let rdr_pk = Element::GENERATOR * _rdr_sk;

    let commitment = PubPoly {
        commits: vec![dkg_pk],
    };

    let share = DistKeyShare {
        pri_share: PriShare { i: 1, v: dkg_sk },
    };

    let secret = b"test data";
    let (enc_cmt, encrypted_secret, _proof) =
        ThresholdDealerNode::encrypt_secret(&dkg_pk, secret, None, None).unwrap();

    let dealer = ThresholdDealerNode::new();
    let reply = dealer
        .reencrypt(&share, &encrypted_secret, &rdr_pk, None)
        .unwrap();

    let verify_result = dealer.verify(&rdr_pk, &commitment, &enc_cmt, &reply, None);

    assert!(verify_result.is_ok());
}

#[test]
fn test_verify_fails_with_wrong_proof() {
    let mut rng = OsRng;

    let dkg_sk = Fr::rand(&mut rng);
    let dkg_pk = Element::GENERATOR * dkg_sk;
    let _rdr_sk = Fr::rand(&mut rng);
    let rdr_pk = Element::GENERATOR * _rdr_sk;

    let commitment = PubPoly {
        commits: vec![dkg_pk],
    };

    let share = DistKeyShare {
        pri_share: PriShare { i: 1, v: dkg_sk },
    };

    let secret = b"test data";
    let (enc_cmt, encrypted_secret, _proof) =
        ThresholdDealerNode::encrypt_secret(&dkg_pk, secret, None, None).unwrap();

    let dealer = ThresholdDealerNode::new();
    let mut reply = dealer
        .reencrypt(&share, &encrypted_secret, &rdr_pk, None)
        .unwrap();

    // Tamper with the proof
    reply.proof = Fr::rand(&mut rng);

    let verify_result = dealer.verify(&rdr_pk, &commitment, &enc_cmt, &reply, None);

    assert!(verify_result.is_err());
}

#[test]
fn test_recover_insufficient_shares() {
    let dealer = ThresholdDealerNode::new();
    let shares = vec![PubShare {
        i: 1,
        v: Element::GENERATOR,
    }];

    let result = dealer.recover(&shares, 3, 5).unwrap();

    assert!(result.is_none());
}

#[test]
fn test_lagrange_interpolation() {
    let mut rng = OsRng;

    let secret = Fr::rand(&mut rng);

    let shares = vec![
        PubShare {
            i: 1,
            v: Element::GENERATOR * secret,
        },
        PubShare {
            i: 2,
            v: Element::GENERATOR * secret,
        },
        PubShare {
            i: 3,
            v: Element::GENERATOR * secret,
        },
    ];

    let dealer = ThresholdDealerNode::new();
    let recovered = dealer.recover(&shares, 3, 5).unwrap();

    assert!(recovered.is_some());
}

#[test]
fn test_key_derivation() {
    let mut rng = OsRng;
    let point = Element::GENERATOR * Fr::rand(&mut rng);

    let key1 = ThresholdDealerNode::derive_key_from_point(&point).unwrap();
    let key2 = ThresholdDealerNode::derive_key_from_point(&point).unwrap();

    assert_eq!(key1, key2);
    assert_eq!(key1.len(), 32);
}

#[test]
fn test_key_derivation_different_points() {
    let mut rng = OsRng;
    let point1 = Element::GENERATOR * Fr::rand(&mut rng);
    let point2 = Element::GENERATOR * Fr::rand(&mut rng);

    let key1 = ThresholdDealerNode::derive_key_from_point(&point1).unwrap();
    let key2 = ThresholdDealerNode::derive_key_from_point(&point2).unwrap();

    assert_ne!(key1, key2);
}

#[test]
fn test_dkg_encrypt_decrypt_integration() {
    let secret = b"This is a secret message that needs to be encrypted and decrypted using threshold re-encryption!";

    let n = 5;
    let t = 3;

    let mut coordinator = DKGCoordinator::new(
        |id: u32, threshold: usize, total_nodes: usize| {
            <crate::decaf377::dkg::DKGNode as crate::r#trait::Dkg>::new(id, threshold, total_nodes)
        },
        n,
        t,
    )
    .unwrap();
    let (aggregate_pk, secret_shares, pub_poly) = coordinator.run_dkg().unwrap();

    assert_ne!(aggregate_pk, Element::default());
    assert_eq!(secret_shares.len(), n);
    assert_eq!(pub_poly.commits.len(), t);

    // Verify shares match public polynomial
    for share in &secret_shares {
        let expected = Element::GENERATOR * share.v;
        let actual = pub_poly.eval(share.i);
        assert_eq!(
            expected, actual,
            "Share {} does not match public polynomial",
            share.i
        );
    }

    // Encrypt
    let (enc_cmt, encrypted_secret, _proof) =
        ThresholdDealerNode::encrypt_secret(&aggregate_pk, secret, None, None).unwrap();

    assert_ne!(enc_cmt, Element::default());
    assert!(!encrypted_secret.encrypted_data.is_empty());
    assert_eq!(encrypted_secret.nonce.len(), 12);

    // Setup reader
    let mut rng = OsRng;
    let rdr_sk = Fr::rand(&mut rng);
    let rdr_pk = Element::GENERATOR * rdr_sk;

    // Re-encrypt using threshold shares
    let dealer = ThresholdDealerNode::new();
    let mut reencrypt_replies = Vec::new();

    for share in secret_shares.iter().take(t) {
        let dist_key_share = DistKeyShare {
            pri_share: share.clone(),
        };

        let reply = dealer
            .reencrypt(&dist_key_share, &encrypted_secret, &rdr_pk, None)
            .unwrap();

        let verify_result = dealer.verify(&rdr_pk, &pub_poly, &enc_cmt, &reply, None);
        assert!(
            verify_result.is_ok(),
            "Re-encryption verification failed for share {}",
            share.i
        );

        reencrypt_replies.push(reply);
    }

    assert_eq!(reencrypt_replies.len(), t);

    // Recover
    let pub_shares: Vec<PubShare<Element>> =
        reencrypt_replies.iter().map(|r| r.share.clone()).collect();
    let recovered_xnc_cmt = dealer.recover(&pub_shares, t, n).unwrap();

    assert!(
        recovered_xnc_cmt.is_some(),
        "Failed to recover re-encrypted commitment"
    );
    let xnc_cmt = recovered_xnc_cmt.unwrap();
    assert_ne!(xnc_cmt, Element::default());

    // Decrypt
    let decrypted =
        ThresholdDealerNode::decrypt_secret(&aggregate_pk, &xnc_cmt, &rdr_sk, &encrypted_secret)
            .unwrap();

    assert_eq!(decrypted, secret);
    assert_eq!(decrypted.len(), secret.len());
}

#[test]
fn test_encryption_proof_valid() {
    let secret = b"test secret data";
    let mut rng = OsRng;

    let dkg_sk = Fr::rand(&mut rng);
    let dkg_pk = Element::GENERATOR * dkg_sk;

    let (enc_cmt, _encrypted_secret, proof) =
        ThresholdDealerNode::encrypt_secret(&dkg_pk, secret, None, None).unwrap();

    let result = ThresholdDealerNode::verify_encryption(&dkg_pk, &enc_cmt, &proof, None);
    assert!(result.is_ok(), "Valid encryption proof should verify");
}

#[test]
fn test_encryption_proof_wrong_dkg_pk() {
    let secret = b"test secret data";
    let mut rng = OsRng;

    let dkg_sk = Fr::rand(&mut rng);
    let dkg_pk = Element::GENERATOR * dkg_sk;

    let wrong_dkg_sk = Fr::rand(&mut rng);
    let wrong_dkg_pk = Element::GENERATOR * wrong_dkg_sk;

    let (enc_cmt, _encrypted_secret, proof) =
        ThresholdDealerNode::encrypt_secret(&dkg_pk, secret, None, None).unwrap();

    let result = ThresholdDealerNode::verify_encryption(&wrong_dkg_pk, &enc_cmt, &proof, None);
    assert!(
        result.is_err(),
        "Encryption proof should fail with wrong DKG public key"
    );
}

#[test]
fn test_encryption_proof_tampered_challenge() {
    let secret = b"test secret data";
    let mut rng = OsRng;

    let dkg_sk = Fr::rand(&mut rng);
    let dkg_pk = Element::GENERATOR * dkg_sk;

    let (enc_cmt, _encrypted_secret, mut proof) =
        ThresholdDealerNode::encrypt_secret(&dkg_pk, secret, None, None).unwrap();

    let tampered_challenge = Fr::rand(&mut rng);
    let mut tampered_bytes = Vec::new();
    tampered_challenge
        .serialize_compressed(&mut tampered_bytes)
        .unwrap();
    proof.challenge = tampered_bytes;

    let result = ThresholdDealerNode::verify_encryption(&dkg_pk, &enc_cmt, &proof, None);
    assert!(
        result.is_err(),
        "Encryption proof should fail with tampered challenge"
    );
}

#[test]
fn test_encryption_proof_tampered_response() {
    let secret = b"test secret data";
    let mut rng = OsRng;

    let dkg_sk = Fr::rand(&mut rng);
    let dkg_pk = Element::GENERATOR * dkg_sk;

    let (enc_cmt, _encrypted_secret, mut proof) =
        ThresholdDealerNode::encrypt_secret(&dkg_pk, secret, None, None).unwrap();

    let tampered_response = Fr::rand(&mut rng);
    let mut tampered_bytes = Vec::new();
    tampered_response
        .serialize_compressed(&mut tampered_bytes)
        .unwrap();
    proof.response = tampered_bytes;

    let result = ThresholdDealerNode::verify_encryption(&dkg_pk, &enc_cmt, &proof, None);
    assert!(
        result.is_err(),
        "Encryption proof should fail with tampered response"
    );
}

#[test]
fn test_encryption_proof_tampered_shared_point() {
    let secret = b"test secret data";
    let mut rng = OsRng;

    let dkg_sk = Fr::rand(&mut rng);
    let dkg_pk = Element::GENERATOR * dkg_sk;

    let (enc_cmt, _encrypted_secret, mut proof) =
        ThresholdDealerNode::encrypt_secret(&dkg_pk, secret, None, None).unwrap();

    let tampered_point = Element::GENERATOR * Fr::rand(&mut rng);
    let mut tampered_bytes = Vec::new();
    tampered_point
        .serialize_compressed(&mut tampered_bytes)
        .unwrap();
    proof.shared_point = tampered_bytes;

    let result = ThresholdDealerNode::verify_encryption(&dkg_pk, &enc_cmt, &proof, None);
    assert!(
        result.is_err(),
        "Encryption proof should fail with tampered shared point"
    );
}

// ============================================================================
// Capability Derivation Tests
// ============================================================================

#[test]
fn test_encrypt_decrypt_with_derivation() {
    let secret = b"test secret with capability derivation";
    let derivation = b"alice-capability-v1";
    let mut rng = OsRng;

    let dkg_sk = Fr::rand(&mut rng);
    let dkg_pk = Element::GENERATOR * dkg_sk;

    let rdr_sk = Fr::rand(&mut rng);
    let rdr_pk = Element::GENERATOR * rdr_sk;

    // 1. Encrypt with derivation
    let (enc_cmt, encrypted_secret, proof) =
        ThresholdDealerNode::encrypt_secret(&dkg_pk, secret, Some(derivation), None).unwrap();

    assert!(
        proof.derived_pk.is_some(),
        "Proof should contain derived_pk"
    );

    let derived_pk =
        Element::deserialize_compressed(&proof.derived_pk.as_ref().unwrap()[..]).unwrap();

    // 2. Simulate re-encryption with derivation applied
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"elgamal-derivation-v1\0\0");
    hasher.update(derivation);
    let hash = hasher.finalize();
    let d = Fr::from_le_bytes_mod_order(&hash);

    let xr_g = rdr_pk + enc_cmt;
    let xnc_cmt = xr_g * (d * dkg_sk);

    // 3. Decrypt using derived_pk (not dkg_pk)
    let decrypted =
        ThresholdDealerNode::decrypt_secret(&derived_pk, &xnc_cmt, &rdr_sk, &encrypted_secret)
            .unwrap();

    assert_eq!(decrypted, secret);
}

#[test]
fn test_reencrypt_with_derivation() {
    let mut rng = OsRng;
    let derivation = b"test-capability";

    let dkg_sk = Fr::rand(&mut rng);
    let dkg_pk = Element::GENERATOR * dkg_sk;
    let _rdr_sk = Fr::rand(&mut rng);
    let rdr_pk = Element::GENERATOR * _rdr_sk;

    let commitment = PubPoly {
        commits: vec![dkg_pk],
    };

    let share = DistKeyShare {
        pri_share: PriShare { i: 1, v: dkg_sk },
    };

    let secret = b"test data with derivation";
    let (enc_cmt, encrypted_secret, _proof) =
        ThresholdDealerNode::encrypt_secret(&dkg_pk, secret, Some(derivation), None).unwrap();

    let dealer = ThresholdDealerNode::new();
    let reply = dealer
        .reencrypt(&share, &encrypted_secret, &rdr_pk, Some(derivation))
        .unwrap();

    let verify_result = dealer.verify(&rdr_pk, &commitment, &enc_cmt, &reply, Some(derivation));
    assert!(verify_result.is_ok());
}

#[test]
fn test_reencrypt_wrong_derivation_fails_at_decrypt() {
    let mut rng = OsRng;
    let correct_derivation = b"correct-capability";
    let wrong_derivation = b"wrong-capability";

    let dkg_sk = Fr::rand(&mut rng);
    let dkg_pk = Element::GENERATOR * dkg_sk;
    let rdr_sk = Fr::rand(&mut rng);
    let rdr_pk = Element::GENERATOR * rdr_sk;

    let share = DistKeyShare {
        pri_share: PriShare { i: 1, v: dkg_sk },
    };

    let secret = b"test data";
    let (_enc_cmt, encrypted_secret, proof) =
        ThresholdDealerNode::encrypt_secret(&dkg_pk, secret, Some(correct_derivation), None)
            .unwrap();

    let dealer = ThresholdDealerNode::new();
    let reply = dealer
        .reencrypt(&share, &encrypted_secret, &rdr_pk, Some(wrong_derivation))
        .unwrap();

    let xnc_cmt = reply.share.v;

    let derived_pk =
        Element::deserialize_compressed(&proof.derived_pk.as_ref().unwrap()[..]).unwrap();

    let result =
        ThresholdDealerNode::decrypt_secret(&derived_pk, &xnc_cmt, &rdr_sk, &encrypted_secret);

    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("authentication failed"));
}

#[test]
fn test_reencrypt_missing_derivation_fails_at_decrypt() {
    let mut rng = OsRng;
    let derivation = b"some-capability";

    let dkg_sk = Fr::rand(&mut rng);
    let dkg_pk = Element::GENERATOR * dkg_sk;
    let rdr_sk = Fr::rand(&mut rng);
    let rdr_pk = Element::GENERATOR * rdr_sk;

    let share = DistKeyShare {
        pri_share: PriShare { i: 1, v: dkg_sk },
    };

    let secret = b"test data";
    let (_enc_cmt, encrypted_secret, proof) =
        ThresholdDealerNode::encrypt_secret(&dkg_pk, secret, Some(derivation), None).unwrap();

    let dealer = ThresholdDealerNode::new();
    let reply = dealer
        .reencrypt(&share, &encrypted_secret, &rdr_pk, None)
        .unwrap();

    let xnc_cmt = reply.share.v;

    let derived_pk =
        Element::deserialize_compressed(&proof.derived_pk.as_ref().unwrap()[..]).unwrap();

    let result =
        ThresholdDealerNode::decrypt_secret(&derived_pk, &xnc_cmt, &rdr_sk, &encrypted_secret);

    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("authentication failed"));
}

#[test]
fn test_reencrypt_extra_derivation_fails_at_decrypt() {
    let mut rng = OsRng;
    let derivation = b"some-capability";

    let dkg_sk = Fr::rand(&mut rng);
    let dkg_pk = Element::GENERATOR * dkg_sk;
    let rdr_sk = Fr::rand(&mut rng);
    let rdr_pk = Element::GENERATOR * rdr_sk;

    let share = DistKeyShare {
        pri_share: PriShare { i: 1, v: dkg_sk },
    };

    let secret = b"test data";
    let (_enc_cmt, encrypted_secret, _proof) =
        ThresholdDealerNode::encrypt_secret(&dkg_pk, secret, None, None).unwrap();

    let dealer = ThresholdDealerNode::new();
    let reply = dealer
        .reencrypt(&share, &encrypted_secret, &rdr_pk, Some(derivation))
        .unwrap();

    let xnc_cmt = reply.share.v;

    let result = ThresholdDealerNode::decrypt_secret(&dkg_pk, &xnc_cmt, &rdr_sk, &encrypted_secret);

    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("authentication failed"));
}

#[test]
fn test_dkg_encrypt_decrypt_with_derivation_integration() {
    let secret = b"Secret with capability-based derivation at re-encrypt time!";
    let derivation = b"alice-file-access-v1";

    let n = 5;
    let t = 3;

    let mut coordinator = DKGCoordinator::new(
        |id: u32, threshold: usize, total_nodes: usize| {
            <crate::decaf377::dkg::DKGNode as crate::r#trait::Dkg>::new(id, threshold, total_nodes)
        },
        n,
        t,
    )
    .unwrap();
    let (aggregate_pk, secret_shares, pub_poly) = coordinator.run_dkg().unwrap();

    let (enc_cmt, encrypted_secret, proof) =
        ThresholdDealerNode::encrypt_secret(&aggregate_pk, secret, Some(derivation), None).unwrap();

    let derived_pk =
        Element::deserialize_compressed(&proof.derived_pk.as_ref().unwrap()[..]).unwrap();

    let mut rng = OsRng;
    let rdr_sk = Fr::rand(&mut rng);
    let rdr_pk = Element::GENERATOR * rdr_sk;

    let dealer = ThresholdDealerNode::new();
    let mut reencrypt_replies = Vec::new();

    for share in secret_shares.iter().take(t) {
        let dist_key_share = DistKeyShare {
            pri_share: share.clone(),
        };

        let reply = dealer
            .reencrypt(
                &dist_key_share,
                &encrypted_secret,
                &rdr_pk,
                Some(derivation),
            )
            .unwrap();

        let verify_result = dealer.verify(&rdr_pk, &pub_poly, &enc_cmt, &reply, Some(derivation));
        assert!(
            verify_result.is_ok(),
            "Re-encryption verification failed for share {}",
            share.i
        );

        reencrypt_replies.push(reply);
    }

    let pub_shares: Vec<PubShare<Element>> =
        reencrypt_replies.iter().map(|r| r.share.clone()).collect();
    let xnc_cmt = dealer.recover(&pub_shares, t, n).unwrap().unwrap();

    let decrypted =
        ThresholdDealerNode::decrypt_secret(&derived_pk, &xnc_cmt, &rdr_sk, &encrypted_secret)
            .unwrap();

    assert_eq!(decrypted, secret);
}

#[test]
fn test_different_derivations_produce_different_keys() {
    let mut rng = OsRng;
    let dkg_sk = Fr::rand(&mut rng);
    let dkg_pk = Element::GENERATOR * dkg_sk;

    let secret = b"test";
    let derivation1 = b"alice";
    let derivation2 = b"bob";

    let (_, _, proof1) =
        ThresholdDealerNode::encrypt_secret(&dkg_pk, secret, Some(derivation1), None).unwrap();
    let (_, _, proof2) =
        ThresholdDealerNode::encrypt_secret(&dkg_pk, secret, Some(derivation2), None).unwrap();

    assert_ne!(proof1.derived_pk, proof2.derived_pk);

    let (_, _, proof1b) =
        ThresholdDealerNode::encrypt_secret(&dkg_pk, secret, Some(derivation1), None).unwrap();
    assert_eq!(proof1.derived_pk, proof1b.derived_pk);
}

// ============================================================================
// Metadata (Policy Binding) Tests
// ============================================================================

#[test]
fn test_encryption_proof_with_metadata_valid() {
    let secret = b"test secret data";
    let metadata = b"policy_id:123|resource:file.txt|permission:read";
    let mut rng = OsRng;

    let dkg_sk = Fr::rand(&mut rng);
    let dkg_pk = Element::GENERATOR * dkg_sk;

    let (enc_cmt, _encrypted_secret, proof) =
        ThresholdDealerNode::encrypt_secret(&dkg_pk, secret, None, Some(metadata)).unwrap();

    let result = ThresholdDealerNode::verify_encryption(&dkg_pk, &enc_cmt, &proof, Some(metadata));
    assert!(
        result.is_ok(),
        "Valid encryption proof with metadata should verify"
    );
}

#[test]
fn test_encryption_proof_wrong_metadata_fails() {
    let secret = b"test secret data";
    let correct_metadata = b"policy_id:123|resource:file.txt|permission:read";
    let wrong_metadata = b"policy_id:456|resource:other.txt|permission:write";
    let mut rng = OsRng;

    let dkg_sk = Fr::rand(&mut rng);
    let dkg_pk = Element::GENERATOR * dkg_sk;

    let (enc_cmt, _encrypted_secret, proof) =
        ThresholdDealerNode::encrypt_secret(&dkg_pk, secret, None, Some(correct_metadata)).unwrap();

    let result =
        ThresholdDealerNode::verify_encryption(&dkg_pk, &enc_cmt, &proof, Some(wrong_metadata));
    assert!(
        result.is_err(),
        "Encryption proof should fail with wrong metadata (policy tampering attempt)"
    );
}

#[test]
fn test_encryption_proof_missing_metadata_fails() {
    let secret = b"test secret data";
    let metadata = b"policy_id:123|resource:file.txt|permission:read";
    let mut rng = OsRng;

    let dkg_sk = Fr::rand(&mut rng);
    let dkg_pk = Element::GENERATOR * dkg_sk;

    let (enc_cmt, _encrypted_secret, proof) =
        ThresholdDealerNode::encrypt_secret(&dkg_pk, secret, None, Some(metadata)).unwrap();

    let result = ThresholdDealerNode::verify_encryption(&dkg_pk, &enc_cmt, &proof, None);
    assert!(
        result.is_err(),
        "Encryption proof should fail when metadata is missing but was used at encryption"
    );
}

#[test]
fn test_encryption_proof_extra_metadata_fails() {
    let secret = b"test secret data";
    let metadata = b"policy_id:123|resource:file.txt|permission:read";
    let mut rng = OsRng;

    let dkg_sk = Fr::rand(&mut rng);
    let dkg_pk = Element::GENERATOR * dkg_sk;

    let (enc_cmt, _encrypted_secret, proof) =
        ThresholdDealerNode::encrypt_secret(&dkg_pk, secret, None, None).unwrap();

    let result = ThresholdDealerNode::verify_encryption(&dkg_pk, &enc_cmt, &proof, Some(metadata));
    assert!(
        result.is_err(),
        "Encryption proof should fail when metadata is provided but was not used at encryption"
    );
}

#[test]
fn test_encryption_proof_metadata_with_derivation() {
    let secret = b"test secret with both metadata and derivation";
    let metadata = b"policy_id:789|resource:sensitive.doc|permission:decrypt";
    let derivation = b"alice-capability-v1";
    let mut rng = OsRng;

    let dkg_sk = Fr::rand(&mut rng);
    let dkg_pk = Element::GENERATOR * dkg_sk;

    let (enc_cmt, _encrypted_secret, proof) =
        ThresholdDealerNode::encrypt_secret(&dkg_pk, secret, Some(derivation), Some(metadata))
            .unwrap();

    assert!(
        proof.derived_pk.is_some(),
        "Proof should contain derived_pk when derivation is used"
    );

    let result = ThresholdDealerNode::verify_encryption(&dkg_pk, &enc_cmt, &proof, Some(metadata));
    assert!(
        result.is_ok(),
        "Proof should verify with correct metadata and derivation"
    );

    let wrong_metadata = b"policy_id:000|resource:other|permission:none";
    let result =
        ThresholdDealerNode::verify_encryption(&dkg_pk, &enc_cmt, &proof, Some(wrong_metadata));
    assert!(
        result.is_err(),
        "Proof should fail with wrong metadata even when derivation is correct"
    );
}

// ============================================================================
// AAD Binding Tests (Secret Component Mix-and-Match)
// ============================================================================

#[test]
fn test_swap_ciphertext_and_nonce_fails_decrypt() {
    let secret_a = b"secret A";
    let secret_b = b"secret B";
    let mut rng = OsRng;

    let dkg_sk = Fr::rand(&mut rng);
    let dkg_pk = Element::GENERATOR * dkg_sk;
    let rdr_sk = Fr::rand(&mut rng);
    let rdr_pk = Element::GENERATOR * rdr_sk;

    let (enc_cmt_a, encrypted_a, _proof_a) =
        ThresholdDealerNode::encrypt_secret(&dkg_pk, secret_a, None, None).unwrap();
    let (_enc_cmt_b, encrypted_b, _proof_b) =
        ThresholdDealerNode::encrypt_secret(&dkg_pk, secret_b, None, None).unwrap();

    let franken_secret = Secret {
        enc_cmt: encrypted_a.enc_cmt.clone(),
        encrypted_data: encrypted_b.encrypted_data.clone(),
        nonce: encrypted_b.nonce.clone(),
    };

    let xr_g = rdr_pk + enc_cmt_a;
    let xnc_cmt = xr_g * dkg_sk;

    let result = ThresholdDealerNode::decrypt_secret(&dkg_pk, &xnc_cmt, &rdr_sk, &franken_secret);
    assert!(
        result.is_err(),
        "Decryption should fail when encrypted_data and nonce are swapped from another encryption"
    );
}

#[test]
fn test_swap_enc_cmt_fails_decrypt() {
    let secret_a = b"secret A";
    let secret_b = b"secret B";
    let mut rng = OsRng;

    let dkg_sk = Fr::rand(&mut rng);
    let dkg_pk = Element::GENERATOR * dkg_sk;
    let rdr_sk = Fr::rand(&mut rng);
    let rdr_pk = Element::GENERATOR * rdr_sk;

    let (_enc_cmt_a, encrypted_a, _proof_a) =
        ThresholdDealerNode::encrypt_secret(&dkg_pk, secret_a, None, None).unwrap();
    let (enc_cmt_b, encrypted_b, _proof_b) =
        ThresholdDealerNode::encrypt_secret(&dkg_pk, secret_b, None, None).unwrap();

    let franken_secret = Secret {
        enc_cmt: encrypted_b.enc_cmt.clone(),
        encrypted_data: encrypted_a.encrypted_data.clone(),
        nonce: encrypted_a.nonce.clone(),
    };

    let xr_g = rdr_pk + enc_cmt_b;
    let xnc_cmt = xr_g * dkg_sk;

    let result = ThresholdDealerNode::decrypt_secret(&dkg_pk, &xnc_cmt, &rdr_sk, &franken_secret);
    assert!(
        result.is_err(),
        "Decryption should fail when enc_cmt is swapped from another encryption"
    );
}

#[test]
fn test_swap_nonce_only_fails_decrypt() {
    let secret_a = b"secret A";
    let secret_b = b"secret B";
    let mut rng = OsRng;

    let dkg_sk = Fr::rand(&mut rng);
    let dkg_pk = Element::GENERATOR * dkg_sk;
    let rdr_sk = Fr::rand(&mut rng);
    let rdr_pk = Element::GENERATOR * rdr_sk;

    let (enc_cmt_a, encrypted_a, _proof_a) =
        ThresholdDealerNode::encrypt_secret(&dkg_pk, secret_a, None, None).unwrap();
    let (_enc_cmt_b, encrypted_b, _proof_b) =
        ThresholdDealerNode::encrypt_secret(&dkg_pk, secret_b, None, None).unwrap();

    let franken_secret = Secret {
        enc_cmt: encrypted_a.enc_cmt.clone(),
        encrypted_data: encrypted_a.encrypted_data.clone(),
        nonce: encrypted_b.nonce.clone(),
    };

    let xr_g = rdr_pk + enc_cmt_a;
    let xnc_cmt = xr_g * dkg_sk;

    let result = ThresholdDealerNode::decrypt_secret(&dkg_pk, &xnc_cmt, &rdr_sk, &franken_secret);
    assert!(
        result.is_err(),
        "Decryption should fail when only the nonce is swapped"
    );
}

#[test]
fn test_swap_enc_cmt_and_proof_fails_decrypt() {
    let secret_a = b"secret A";
    let secret_b = b"secret B";
    let mut rng = OsRng;

    let dkg_sk = Fr::rand(&mut rng);
    let dkg_pk = Element::GENERATOR * dkg_sk;
    let rdr_sk = Fr::rand(&mut rng);
    let rdr_pk = Element::GENERATOR * rdr_sk;

    let (_enc_cmt_a, encrypted_a, _proof_a) =
        ThresholdDealerNode::encrypt_secret(&dkg_pk, secret_a, None, None).unwrap();
    let (enc_cmt_b, encrypted_b, proof_b) =
        ThresholdDealerNode::encrypt_secret(&dkg_pk, secret_b, None, None).unwrap();

    let verify_result = ThresholdDealerNode::verify_encryption(&dkg_pk, &enc_cmt_b, &proof_b, None);
    assert!(
        verify_result.is_ok(),
        "Proof B should verify against enc_cmt_b"
    );

    let franken_secret = Secret {
        enc_cmt: encrypted_b.enc_cmt.clone(),
        encrypted_data: encrypted_a.encrypted_data.clone(),
        nonce: encrypted_a.nonce.clone(),
    };

    let xr_g = rdr_pk + enc_cmt_b;
    let xnc_cmt = xr_g * dkg_sk;

    let result = ThresholdDealerNode::decrypt_secret(&dkg_pk, &xnc_cmt, &rdr_sk, &franken_secret);
    assert!(
        result.is_err(),
        "Decryption should fail when enc_cmt + proof are swapped but ciphertext is from another encryption"
    );
}
