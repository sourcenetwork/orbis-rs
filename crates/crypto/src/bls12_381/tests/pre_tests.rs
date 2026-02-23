use crate::bls12_381::common::PubPoly;
use crate::bls12_381::pre::ThresholdDealerNode;
use crate::r#trait::{
    DistKeyShare, PriShare, PubPoly as PubPolyTrait, PubShare, Secret, ThresholdDealer,
};
use crate::test_helper::DKGCoordinator;
use ark_bls12_381::{Fr, G1Affine, G1Projective};
use ark_ec::{AffineRepr, Group};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::UniformRand;
use rand_core::OsRng;

#[test]
fn test_threshold_dealer_creation() {
    assert_eq!(ThresholdDealerNode::name(), "elgamal/bls12_381");
}

#[test]
fn test_encrypt_decrypt_flow() {
    let secret = b"test secret data";
    let mut rng = OsRng;

    // Setup DKG key pair
    let dkg_sk = Fr::rand(&mut rng);
    let dkg_pk: G1Affine = (G1Projective::generator() * dkg_sk).into();

    // Setup reader key pair
    let rdr_sk = Fr::rand(&mut rng);
    let rdr_pk: G1Affine = (G1Projective::generator() * rdr_sk).into();

    // 1. Encrypt the secret (no derivation)
    let (enc_cmt, encrypted_secret, _proof) =
        ThresholdDealerNode::encrypt_secret(&dkg_pk, secret, None, None).unwrap();

    // Verify encryption produces valid output
    assert_ne!(enc_cmt, G1Affine::zero());
    assert!(!encrypted_secret.encrypted_data.is_empty());
    assert_eq!(encrypted_secret.nonce.len(), 12);

    // 2. Simulate re-encryption: compute xnc_cmt
    // In the real system, this comes from aggregating threshold shares
    // xnc_cmt = dkg_sk * (rdr_pk + enc_cmt)
    let xr_g = G1Projective::from(rdr_pk) + G1Projective::from(enc_cmt);
    let xnc_cmt: G1Affine = (xr_g * dkg_sk).into();

    // 3. Decrypt the secret
    let decrypted =
        ThresholdDealerNode::decrypt_secret(&dkg_pk, &xnc_cmt, &rdr_sk, &encrypted_secret).unwrap();

    // Verify decryption recovers original secret
    assert_eq!(decrypted, secret);
}

#[test]
fn test_encrypt_decrypt_large_data() {
    // Test with data larger than AES block size
    let secret = b"This is a much longer secret that contains multiple blocks of data. \
                   It should be properly encrypted and decrypted using AES-GCM, which \
                   handles arbitrary length data. This tests that our hybrid encryption \
                   scheme works correctly with larger payloads that exceed typical \
                   block sizes and ensures proper chunking and authentication.";

    let mut rng = OsRng;
    let dkg_sk = Fr::rand(&mut rng);
    let dkg_pk: G1Affine = (G1Projective::generator() * dkg_sk).into();
    let rdr_sk = Fr::rand(&mut rng);
    let rdr_pk: G1Affine = (G1Projective::generator() * rdr_sk).into();

    // Encrypt
    let (enc_cmt, encrypted_secret, _proof) =
        ThresholdDealerNode::encrypt_secret(&dkg_pk, secret, None, None).unwrap();

    assert_ne!(enc_cmt, G1Affine::zero());
    assert!(!encrypted_secret.encrypted_data.is_empty());

    // Simulate re-encryption commitment correctly
    // xnc_cmt = dkg_sk * (rdr_pk + enc_cmt)
    let xr_g = G1Projective::from(rdr_pk) + G1Projective::from(enc_cmt);
    let xnc_cmt: G1Affine = (xr_g * dkg_sk).into();

    // Decrypt
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
    let dkg_pk: G1Affine = (G1Projective::generator() * dkg_sk).into();
    let rdr_sk = Fr::rand(&mut rng);
    let rdr_pk: G1Affine = (G1Projective::generator() * rdr_sk).into();

    // Encrypt empty data
    let (enc_cmt, encrypted_secret, _proof) =
        ThresholdDealerNode::encrypt_secret(&dkg_pk, secret, None, None).unwrap();

    // Simulate re-encryption commitment correctly
    let xr_g = G1Projective::from(rdr_pk) + G1Projective::from(enc_cmt);
    let xnc_cmt: G1Affine = (xr_g * dkg_sk).into();

    // Decrypt
    let decrypted =
        ThresholdDealerNode::decrypt_secret(&dkg_pk, &xnc_cmt, &rdr_sk, &encrypted_secret).unwrap();

    assert_eq!(decrypted, secret);
}

#[test]
fn test_decryption_fails_with_wrong_key() {
    let secret = b"test secret";
    let mut rng = OsRng;
    let dkg_sk = Fr::rand(&mut rng);
    let dkg_pk: G1Affine = (G1Projective::generator() * dkg_sk).into();
    let rdr_sk = Fr::rand(&mut rng);
    let rdr_pk: G1Affine = (G1Projective::generator() * rdr_sk).into();

    // Wrong reader key
    let wrong_rdr_sk = Fr::rand(&mut rng);

    // Encrypt
    let (enc_cmt, encrypted_secret, _proof) =
        ThresholdDealerNode::encrypt_secret(&dkg_pk, secret, None, None).unwrap();

    // Simulate re-encryption commitment with CORRECT reader key
    let xr_g = G1Projective::from(rdr_pk) + G1Projective::from(enc_cmt);
    let xnc_cmt: G1Affine = (xr_g * dkg_sk).into();

    // Try to decrypt with WRONG key - should fail
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

    // Setup keys
    let dkg_sk = Fr::rand(&mut rng);
    let dkg_pk: G1Affine = (G1Projective::generator() * dkg_sk).into();
    let rdr_sk = Fr::rand(&mut rng);
    let rdr_pk: G1Affine = (G1Projective::generator() * rdr_sk).into();

    // Create a commitment (public polynomial) for verification
    let commitment = PubPoly {
        commits: vec![dkg_pk], // Simplified: single point
    };

    // Create a share
    let share = DistKeyShare {
        pri_share: PriShare { i: 1, v: dkg_sk },
    };

    // Encrypt a secret
    let secret = b"test data";
    let (enc_cmt, encrypted_secret, _proof) =
        ThresholdDealerNode::encrypt_secret(&dkg_pk, secret, None, None).unwrap();

    // Re-encrypt (no derivation)
    let dealer = ThresholdDealerNode::new();
    let reply = dealer
        .reencrypt(&share, &encrypted_secret, &rdr_pk, None)
        .unwrap();

    // Verify the reply (no derivation)
    let verify_result = dealer.verify(&rdr_pk, &commitment, &enc_cmt, &reply, None);

    assert!(verify_result.is_ok());
}

#[test]
fn test_verify_fails_with_wrong_proof() {
    let mut rng = OsRng;

    // Setup keys
    let dkg_sk = Fr::rand(&mut rng);
    let dkg_pk: G1Affine = (G1Projective::generator() * dkg_sk).into();
    let rdr_sk = Fr::rand(&mut rng);
    let rdr_pk: G1Affine = (G1Projective::generator() * rdr_sk).into();

    let commitment = PubPoly {
        commits: vec![dkg_pk],
    };

    let share = DistKeyShare {
        pri_share: PriShare { i: 1, v: dkg_sk },
    };

    let secret = b"test data";
    let (enc_cmt, encrypted_secret, _proof) =
        ThresholdDealerNode::encrypt_secret(&dkg_pk, secret, None, None).unwrap();

    // Re-encrypt
    let dealer = ThresholdDealerNode::new();
    let mut reply = dealer
        .reencrypt(&share, &encrypted_secret, &rdr_pk, None)
        .unwrap();

    // Tamper with the proof
    reply.proof = Fr::rand(&mut rng);

    // Verification should fail
    let verify_result = dealer.verify(&rdr_pk, &commitment, &enc_cmt, &reply, None);

    assert!(verify_result.is_err());
}

#[test]
fn test_recover_insufficient_shares() {
    let dealer = ThresholdDealerNode::new();
    let shares = vec![PubShare {
        i: 1,
        v: G1Affine::generator(),
    }];

    // Try to recover with only 1 share when threshold is 3
    let result = dealer.recover(&shares, 3, 5).unwrap();

    assert!(result.is_none());
}

#[test]
fn test_lagrange_interpolation() {
    let mut rng = OsRng;

    // Create a secret
    let secret = Fr::rand(&mut rng);

    // Create 3 shares (t=3, n=5)
    let shares = vec![
        PubShare {
            i: 1,
            v: (G1Projective::generator() * secret).into(),
        },
        PubShare {
            i: 2,
            v: (G1Projective::generator() * secret).into(),
        },
        PubShare {
            i: 3,
            v: (G1Projective::generator() * secret).into(),
        },
    ];

    // Recover (simplified test - in practice shares would be different)
    let dealer = ThresholdDealerNode::new();
    let recovered = dealer.recover(&shares, 3, 5).unwrap();

    assert!(recovered.is_some());
    // Note: This is a simplified test. In a real scenario with proper
    // polynomial shares, we'd verify the recovered point matches the original
}

#[test]
fn test_key_derivation() {
    let mut rng = OsRng;
    let point: G1Affine = (G1Projective::generator() * Fr::rand(&mut rng)).into();

    // Derive key twice - should be deterministic
    let key1 = ThresholdDealerNode::derive_key_from_point(&point).unwrap();
    let key2 = ThresholdDealerNode::derive_key_from_point(&point).unwrap();

    assert_eq!(key1, key2);
    assert_eq!(key1.len(), 32);
}

#[test]
fn test_key_derivation_different_points() {
    let mut rng = OsRng;
    let point1: G1Affine = (G1Projective::generator() * Fr::rand(&mut rng)).into();
    let point2: G1Affine = (G1Projective::generator() * Fr::rand(&mut rng)).into();

    let key1 = ThresholdDealerNode::derive_key_from_point(&point1).unwrap();
    let key2 = ThresholdDealerNode::derive_key_from_point(&point2).unwrap();

    // Different points should produce different keys
    assert_ne!(key1, key2);
}

#[test]
fn test_dkg_encrypt_decrypt_integration() {
    // This test demonstrates the complete flow:
    // 1. Run DKG to generate threshold keys
    // 2. Encrypt a secret using the aggregate public key
    // 3. Re-encrypt using threshold shares
    // 4. Decrypt the secret

    let secret = b"This is a secret message that needs to be encrypted and decrypted using threshold re-encryption!";

    // Setup: 3-of-5 threshold DKG
    let n = 5; // total nodes
    let t = 3; // threshold

    // Step 1: Run DKG to generate threshold keys
    // Workaround: Use a closure that explicitly calls the function to avoid type inference issues
    let mut coordinator = DKGCoordinator::new(
        |id: u32, threshold: usize, total_nodes: usize| {
            <crate::bls12_381::dkg::DKGNode as crate::r#trait::Dkg>::new(id, threshold, total_nodes)
        },
        n,
        t,
    )
    .unwrap();
    let (aggregate_pk, secret_shares, pub_poly) = coordinator.run_dkg().unwrap();

    // Verify DKG setup
    assert_ne!(aggregate_pk, G1Affine::zero());
    assert_eq!(secret_shares.len(), n);
    assert_eq!(pub_poly.commits.len(), t);

    // Verify shares match public polynomial (use pub_poly to avoid unused warning)
    for share in &secret_shares {
        let expected: G1Affine = (G1Projective::generator() * share.v).into();
        let actual = pub_poly.eval(share.i);
        assert_eq!(
            expected, actual,
            "Share {} does not match public polynomial",
            share.i
        );
    }

    // Step 2: Encrypt the secret using aggregate public key (no derivation)
    let (enc_cmt, encrypted_secret, _proof) =
        ThresholdDealerNode::encrypt_secret(&aggregate_pk, secret, None, None).unwrap();

    // Verify encryption
    assert_ne!(enc_cmt, G1Affine::zero());
    assert!(!encrypted_secret.encrypted_data.is_empty());
    assert_eq!(encrypted_secret.nonce.len(), 12);

    // Step 3: Setup reader (Bob) who wants to decrypt
    let mut rng = OsRng;
    let rdr_sk = Fr::rand(&mut rng);
    let rdr_pk: G1Affine = (G1Projective::generator() * rdr_sk).into();

    // Step 4: Re-encrypt using threshold shares (t = 3)
    // We need at least t nodes to participate in re-encryption
    let dealer = ThresholdDealerNode::new();
    let mut reencrypt_replies = Vec::new();

    // Use first t shares for re-encryption (no derivation)
    for share in secret_shares.iter().take(t) {
        let dist_key_share = DistKeyShare {
            pri_share: share.clone(),
        };

        let reply = dealer
            .reencrypt(&dist_key_share, &encrypted_secret, &rdr_pk, None)
            .unwrap();

        // Verify the re-encryption reply (no derivation)
        let verify_result = dealer.verify(&rdr_pk, &pub_poly, &enc_cmt, &reply, None);
        assert!(
            verify_result.is_ok(),
            "Re-encryption verification failed for share {}",
            share.i
        );

        reencrypt_replies.push(reply);
    }

    // Verify we have threshold shares
    assert_eq!(reencrypt_replies.len(), t);

    // Step 5: Recover the re-encrypted commitment from shares
    let pub_shares: Vec<PubShare<G1Affine>> =
        reencrypt_replies.iter().map(|r| r.share.clone()).collect();
    let recovered_xnc_cmt = dealer.recover(&pub_shares, t, n).unwrap();

    assert!(
        recovered_xnc_cmt.is_some(),
        "Failed to recover re-encrypted commitment"
    );
    let xnc_cmt = recovered_xnc_cmt.unwrap();
    assert_ne!(xnc_cmt, G1Affine::zero());

    // Step 6: Decrypt the secret using Bob's private key
    // effective_pk = aggregate_pk (no derivation)
    let decrypted =
        ThresholdDealerNode::decrypt_secret(&aggregate_pk, &xnc_cmt, &rdr_sk, &encrypted_secret)
            .unwrap();

    // Verify decryption recovered the original secret
    assert_eq!(decrypted, secret);
    assert_eq!(decrypted.len(), secret.len());
}

#[test]
fn test_encryption_proof_valid() {
    let secret = b"test secret data";
    let mut rng = OsRng;

    // Setup DKG key pair
    let dkg_sk = Fr::rand(&mut rng);
    let dkg_pk: G1Affine = (G1Projective::generator() * dkg_sk).into();

    // Encrypt the secret
    let (enc_cmt, _encrypted_secret, proof) =
        ThresholdDealerNode::encrypt_secret(&dkg_pk, secret, None, None).unwrap();

    // Verify the encryption proof
    let result = ThresholdDealerNode::verify_encryption(&dkg_pk, &enc_cmt, &proof, None);
    assert!(result.is_ok(), "Valid encryption proof should verify");
}

#[test]
fn test_encryption_proof_wrong_dkg_pk() {
    let secret = b"test secret data";
    let mut rng = OsRng;

    // Setup DKG key pair
    let dkg_sk = Fr::rand(&mut rng);
    let dkg_pk: G1Affine = (G1Projective::generator() * dkg_sk).into();

    // Different DKG public key
    let wrong_dkg_sk = Fr::rand(&mut rng);
    let wrong_dkg_pk: G1Affine = (G1Projective::generator() * wrong_dkg_sk).into();

    // Encrypt the secret
    let (enc_cmt, _encrypted_secret, proof) =
        ThresholdDealerNode::encrypt_secret(&dkg_pk, secret, None, None).unwrap();

    // Verify with wrong DKG public key - should fail
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

    // Setup DKG key pair
    let dkg_sk = Fr::rand(&mut rng);
    let dkg_pk: G1Affine = (G1Projective::generator() * dkg_sk).into();

    // Encrypt the secret
    let (enc_cmt, _encrypted_secret, mut proof) =
        ThresholdDealerNode::encrypt_secret(&dkg_pk, secret, None, None).unwrap();

    // Tamper with the challenge
    let tampered_challenge = Fr::rand(&mut rng);
    let mut tampered_bytes = Vec::new();
    tampered_challenge
        .serialize_compressed(&mut tampered_bytes)
        .unwrap();
    proof.challenge = tampered_bytes;

    // Verification should fail
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

    // Setup DKG key pair
    let dkg_sk = Fr::rand(&mut rng);
    let dkg_pk: G1Affine = (G1Projective::generator() * dkg_sk).into();

    // Encrypt the secret
    let (enc_cmt, _encrypted_secret, mut proof) =
        ThresholdDealerNode::encrypt_secret(&dkg_pk, secret, None, None).unwrap();

    // Tamper with the response
    let tampered_response = Fr::rand(&mut rng);
    let mut tampered_bytes = Vec::new();
    tampered_response
        .serialize_compressed(&mut tampered_bytes)
        .unwrap();
    proof.response = tampered_bytes;

    // Verification should fail
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

    // Setup DKG key pair
    let dkg_sk = Fr::rand(&mut rng);
    let dkg_pk: G1Affine = (G1Projective::generator() * dkg_sk).into();

    // Encrypt the secret
    let (enc_cmt, _encrypted_secret, mut proof) =
        ThresholdDealerNode::encrypt_secret(&dkg_pk, secret, None, None).unwrap();

    // Tamper with the shared point
    let tampered_point: G1Affine = (G1Projective::generator() * Fr::rand(&mut rng)).into();
    let mut tampered_bytes = Vec::new();
    tampered_point
        .serialize_compressed(&mut tampered_bytes)
        .unwrap();
    proof.shared_point = tampered_bytes;

    // Verification should fail
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

    // Setup DKG key pair
    let dkg_sk = Fr::rand(&mut rng);
    let dkg_pk: G1Affine = (G1Projective::generator() * dkg_sk).into();

    // Setup reader key pair
    let rdr_sk = Fr::rand(&mut rng);
    let rdr_pk: G1Affine = (G1Projective::generator() * rdr_sk).into();

    // 1. Encrypt with derivation
    let (enc_cmt, encrypted_secret, proof) =
        ThresholdDealerNode::encrypt_secret(&dkg_pk, secret, Some(derivation), None).unwrap();

    // Verify proof contains derived_pk
    assert!(
        proof.derived_pk.is_some(),
        "Proof should contain derived_pk"
    );

    // Extract derived_pk for later use
    let derived_pk =
        G1Affine::deserialize_compressed(&proof.derived_pk.as_ref().unwrap()[..]).unwrap();

    // 2. Simulate re-encryption with derivation applied
    // When derivation is applied: xnc_cmt = d * dkg_sk * (rdr_pk + enc_cmt)
    // We need to compute d from derivation bytes
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"elgamal-derivation-v1\0\0");
    hasher.update(derivation);
    let hash = hasher.finalize();
    let d = Fr::from_le_bytes_mod_order(&hash);

    let xr_g = G1Projective::from(rdr_pk) + G1Projective::from(enc_cmt);
    let xnc_cmt: G1Affine = (xr_g * (d * dkg_sk)).into();

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

    // Setup keys
    let dkg_sk = Fr::rand(&mut rng);
    let dkg_pk: G1Affine = (G1Projective::generator() * dkg_sk).into();
    let rdr_sk = Fr::rand(&mut rng);
    let rdr_pk: G1Affine = (G1Projective::generator() * rdr_sk).into();

    // Create a commitment (public polynomial) for verification
    let commitment = PubPoly {
        commits: vec![dkg_pk],
    };

    let share = DistKeyShare {
        pri_share: PriShare { i: 1, v: dkg_sk },
    };

    // Encrypt with derivation
    let secret = b"test data with derivation";
    let (enc_cmt, encrypted_secret, _proof) =
        ThresholdDealerNode::encrypt_secret(&dkg_pk, secret, Some(derivation), None).unwrap();

    // Re-encrypt with derivation
    let dealer = ThresholdDealerNode::new();
    let reply = dealer
        .reencrypt(&share, &encrypted_secret, &rdr_pk, Some(derivation))
        .unwrap();

    // Verify with derivation
    let verify_result = dealer.verify(&rdr_pk, &commitment, &enc_cmt, &reply, Some(derivation));
    assert!(verify_result.is_ok());
}

#[test]
fn test_reencrypt_wrong_derivation_fails_at_decrypt() {
    // With the simplified design, wrong derivation at re-encrypt succeeds
    // but decryption fails (AES-GCM auth failure).
    // Attacker cannot brute-force without reader's private key.
    let mut rng = OsRng;
    let correct_derivation = b"correct-capability";
    let wrong_derivation = b"wrong-capability";

    // Setup keys
    let dkg_sk = Fr::rand(&mut rng);
    let dkg_pk: G1Affine = (G1Projective::generator() * dkg_sk).into();
    let rdr_sk = Fr::rand(&mut rng);
    let rdr_pk: G1Affine = (G1Projective::generator() * rdr_sk).into();

    let share = DistKeyShare {
        pri_share: PriShare { i: 1, v: dkg_sk },
    };

    // Encrypt with correct derivation
    let secret = b"test data";
    let (_enc_cmt, encrypted_secret, proof) =
        ThresholdDealerNode::encrypt_secret(&dkg_pk, secret, Some(correct_derivation), None)
            .unwrap();

    // Re-encrypt with WRONG derivation - this succeeds (no verification)
    let dealer = ThresholdDealerNode::new();
    let reply = dealer
        .reencrypt(&share, &encrypted_secret, &rdr_pk, Some(wrong_derivation))
        .unwrap();

    // Recover xnc_cmt (in real system, from threshold of shares)
    let xnc_cmt = reply.share.v;

    // Extract derived_pk from proof (the CORRECT one used at encryption)
    let derived_pk =
        G1Affine::deserialize_compressed(&proof.derived_pk.as_ref().unwrap()[..]).unwrap();

    // Decrypt fails because re-encryption used wrong derivation scalar
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
    // Encrypt WITH derivation, re-encrypt WITHOUT - decryption fails
    let mut rng = OsRng;
    let derivation = b"some-capability";

    // Setup keys
    let dkg_sk = Fr::rand(&mut rng);
    let dkg_pk: G1Affine = (G1Projective::generator() * dkg_sk).into();
    let rdr_sk = Fr::rand(&mut rng);
    let rdr_pk: G1Affine = (G1Projective::generator() * rdr_sk).into();

    let share = DistKeyShare {
        pri_share: PriShare { i: 1, v: dkg_sk },
    };

    // Encrypt WITH derivation
    let secret = b"test data";
    let (_enc_cmt, encrypted_secret, proof) =
        ThresholdDealerNode::encrypt_secret(&dkg_pk, secret, Some(derivation), None).unwrap();

    // Re-encrypt WITHOUT derivation
    let dealer = ThresholdDealerNode::new();
    let reply = dealer
        .reencrypt(&share, &encrypted_secret, &rdr_pk, None)
        .unwrap();

    let xnc_cmt = reply.share.v;

    // Extract derived_pk from proof
    let derived_pk =
        G1Affine::deserialize_compressed(&proof.derived_pk.as_ref().unwrap()[..]).unwrap();

    // Decrypt fails - re-encryption didn't apply derivation but encryption did
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
    // Encrypt WITHOUT derivation, re-encrypt WITH - decryption fails
    let mut rng = OsRng;
    let derivation = b"some-capability";

    // Setup keys
    let dkg_sk = Fr::rand(&mut rng);
    let dkg_pk: G1Affine = (G1Projective::generator() * dkg_sk).into();
    let rdr_sk = Fr::rand(&mut rng);
    let rdr_pk: G1Affine = (G1Projective::generator() * rdr_sk).into();

    let share = DistKeyShare {
        pri_share: PriShare { i: 1, v: dkg_sk },
    };

    // Encrypt WITHOUT derivation
    let secret = b"test data";
    let (_enc_cmt, encrypted_secret, _proof) =
        ThresholdDealerNode::encrypt_secret(&dkg_pk, secret, None, None).unwrap();

    // Re-encrypt WITH derivation (extra)
    let dealer = ThresholdDealerNode::new();
    let reply = dealer
        .reencrypt(&share, &encrypted_secret, &rdr_pk, Some(derivation))
        .unwrap();

    let xnc_cmt = reply.share.v;

    // Decrypt fails - re-encryption applied derivation but encryption didn't
    // Use dkg_pk since there's no derived_pk
    let result = ThresholdDealerNode::decrypt_secret(&dkg_pk, &xnc_cmt, &rdr_sk, &encrypted_secret);

    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("authentication failed"));
}

#[test]
fn test_dkg_encrypt_decrypt_with_derivation_integration() {
    // Complete flow with derivation:
    // 1. Run DKG
    // 2. Encrypt with derivation
    // 3. Re-encrypt with derivation verification
    // 4. Decrypt using derived_pk

    let secret = b"Secret with capability-based derivation at re-encrypt time!";
    let derivation = b"alice-file-access-v1";

    let n = 5;
    let t = 3;

    // Step 1: Run DKG
    let mut coordinator = DKGCoordinator::new(
        |id: u32, threshold: usize, total_nodes: usize| {
            <crate::bls12_381::dkg::DKGNode as crate::r#trait::Dkg>::new(id, threshold, total_nodes)
        },
        n,
        t,
    )
    .unwrap();
    let (aggregate_pk, secret_shares, pub_poly) = coordinator.run_dkg().unwrap();

    // Step 2: Encrypt with derivation
    let (enc_cmt, encrypted_secret, proof) =
        ThresholdDealerNode::encrypt_secret(&aggregate_pk, secret, Some(derivation), None).unwrap();

    // Extract derived_pk for decryption
    let derived_pk =
        G1Affine::deserialize_compressed(&proof.derived_pk.as_ref().unwrap()[..]).unwrap();

    // Step 3: Setup reader
    let mut rng = OsRng;
    let rdr_sk = Fr::rand(&mut rng);
    let rdr_pk: G1Affine = (G1Projective::generator() * rdr_sk).into();

    // Step 4: Re-encrypt with derivation at each node
    let dealer = ThresholdDealerNode::new();
    let mut reencrypt_replies = Vec::new();

    for share in secret_shares.iter().take(t) {
        let dist_key_share = DistKeyShare {
            pri_share: share.clone(),
        };

        // Re-encrypt with derivation
        let reply = dealer
            .reencrypt(
                &dist_key_share,
                &encrypted_secret,
                &rdr_pk,
                Some(derivation),
            )
            .unwrap();

        // Verify with derivation
        let verify_result = dealer.verify(&rdr_pk, &pub_poly, &enc_cmt, &reply, Some(derivation));
        assert!(
            verify_result.is_ok(),
            "Re-encryption verification failed for share {}",
            share.i
        );

        reencrypt_replies.push(reply);
    }

    // Step 5: Recover
    let pub_shares: Vec<PubShare<G1Affine>> =
        reencrypt_replies.iter().map(|r| r.share.clone()).collect();
    let xnc_cmt = dealer.recover(&pub_shares, t, n).unwrap().unwrap();

    // Step 6: Decrypt using derived_pk (not aggregate_pk!)
    let decrypted =
        ThresholdDealerNode::decrypt_secret(&derived_pk, &xnc_cmt, &rdr_sk, &encrypted_secret)
            .unwrap();

    assert_eq!(decrypted, secret);
}

#[test]
fn test_different_derivations_produce_different_keys() {
    let mut rng = OsRng;
    let dkg_sk = Fr::rand(&mut rng);
    let dkg_pk: G1Affine = (G1Projective::generator() * dkg_sk).into();

    let secret = b"test";
    let derivation1 = b"alice";
    let derivation2 = b"bob";

    // Encrypt with different derivations
    let (_, _, proof1) =
        ThresholdDealerNode::encrypt_secret(&dkg_pk, secret, Some(derivation1), None).unwrap();
    let (_, _, proof2) =
        ThresholdDealerNode::encrypt_secret(&dkg_pk, secret, Some(derivation2), None).unwrap();

    // derived_pk should be different
    assert_ne!(proof1.derived_pk, proof2.derived_pk);

    // But encrypting with same derivation produces same derived_pk
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
    let metadata =
        ThresholdDealerNode::encode_metadata("123", "file.txt", "read", None, None, None);
    let mut rng = OsRng;

    let dkg_sk = Fr::rand(&mut rng);
    let dkg_pk: G1Affine = (G1Projective::generator() * dkg_sk).into();

    // Encrypt with metadata
    let (enc_cmt, _encrypted_secret, proof) =
        ThresholdDealerNode::encrypt_secret(&dkg_pk, secret, None, Some(&metadata)).unwrap();

    // Verify with same metadata - should succeed
    let result = ThresholdDealerNode::verify_encryption(&dkg_pk, &enc_cmt, &proof, Some(&metadata));
    assert!(
        result.is_ok(),
        "Valid encryption proof with metadata should verify"
    );
}

#[test]
fn test_encryption_proof_wrong_metadata_fails() {
    let secret = b"test secret data";
    let correct_metadata =
        ThresholdDealerNode::encode_metadata("123", "file.txt", "read", None, None, None);
    let wrong_metadata =
        ThresholdDealerNode::encode_metadata("456", "other.txt", "write", None, None, None);
    let mut rng = OsRng;

    let dkg_sk = Fr::rand(&mut rng);
    let dkg_pk: G1Affine = (G1Projective::generator() * dkg_sk).into();

    // Encrypt with correct metadata
    let (enc_cmt, _encrypted_secret, proof) =
        ThresholdDealerNode::encrypt_secret(&dkg_pk, secret, None, Some(&correct_metadata))
            .unwrap();

    // Verify with wrong metadata - should fail
    let result =
        ThresholdDealerNode::verify_encryption(&dkg_pk, &enc_cmt, &proof, Some(&wrong_metadata));
    assert!(
        result.is_err(),
        "Encryption proof should fail with wrong metadata (policy tampering attempt)"
    );
}

#[test]
fn test_encryption_proof_missing_metadata_fails() {
    let secret = b"test secret data";
    let metadata =
        ThresholdDealerNode::encode_metadata("123", "file.txt", "read", None, None, None);
    let mut rng = OsRng;

    let dkg_sk = Fr::rand(&mut rng);
    let dkg_pk: G1Affine = (G1Projective::generator() * dkg_sk).into();

    // Encrypt with metadata
    let (enc_cmt, _encrypted_secret, proof) =
        ThresholdDealerNode::encrypt_secret(&dkg_pk, secret, None, Some(&metadata)).unwrap();

    // Verify without metadata - should fail
    let result = ThresholdDealerNode::verify_encryption(&dkg_pk, &enc_cmt, &proof, None);
    assert!(
        result.is_err(),
        "Encryption proof should fail when metadata is missing but was used at encryption"
    );
}

#[test]
fn test_encryption_proof_extra_metadata_fails() {
    let secret = b"test secret data";
    let metadata =
        ThresholdDealerNode::encode_metadata("123", "file.txt", "read", None, None, None);
    let mut rng = OsRng;

    let dkg_sk = Fr::rand(&mut rng);
    let dkg_pk: G1Affine = (G1Projective::generator() * dkg_sk).into();

    // Encrypt WITHOUT metadata
    let (enc_cmt, _encrypted_secret, proof) =
        ThresholdDealerNode::encrypt_secret(&dkg_pk, secret, None, None).unwrap();

    // Verify WITH metadata - should fail
    let result = ThresholdDealerNode::verify_encryption(&dkg_pk, &enc_cmt, &proof, Some(&metadata));
    assert!(
        result.is_err(),
        "Encryption proof should fail when metadata is provided but was not used at encryption"
    );
}

#[test]
fn test_encryption_proof_metadata_with_derivation() {
    // Test that metadata binding works correctly when combined with capability derivation
    let secret = b"test secret with both metadata and derivation";
    let metadata =
        ThresholdDealerNode::encode_metadata("789", "sensitive.doc", "decrypt", None, None, None);
    let derivation = b"alice-capability-v1";
    let mut rng = OsRng;

    let dkg_sk = Fr::rand(&mut rng);
    let dkg_pk: G1Affine = (G1Projective::generator() * dkg_sk).into();

    // Encrypt with both metadata and derivation
    let (enc_cmt, _encrypted_secret, proof) =
        ThresholdDealerNode::encrypt_secret(&dkg_pk, secret, Some(derivation), Some(&metadata))
            .unwrap();

    // Verify proof contains derived_pk
    assert!(
        proof.derived_pk.is_some(),
        "Proof should contain derived_pk when derivation is used"
    );

    // verify_encryption expects the already-derived key (as verify_encryption_binding does)
    let derived_pk = ThresholdDealerNode::derive_public_key(&dkg_pk, derivation).unwrap();

    // Verify with correct metadata and derived key - should succeed
    let result =
        ThresholdDealerNode::verify_encryption(&derived_pk, &enc_cmt, &proof, Some(&metadata));
    assert!(
        result.is_ok(),
        "Proof should verify with correct metadata and derivation"
    );

    // Verify with wrong metadata - should fail even with correct derivation in proof
    let wrong_metadata =
        ThresholdDealerNode::encode_metadata("000", "other", "none", None, None, None);
    let result = ThresholdDealerNode::verify_encryption(
        &derived_pk,
        &enc_cmt,
        &proof,
        Some(&wrong_metadata),
    );
    assert!(
        result.is_err(),
        "Proof should fail with wrong metadata even when derivation is correct"
    );
}

#[test]
fn test_verify_encryption_wrong_derivation_fails_loudly() {
    // Verify that supplying the wrong derivation to verify_encryption fails immediately
    // with a derivation mismatch error, rather than silently producing an unusable result
    // that only fails at AES-GCM decrypt time.
    let secret = b"test secret";
    let metadata = ThresholdDealerNode::encode_metadata("123", "doc", "read", None, None, None);
    let correct_derivation = b"alice-capability-v1";
    let wrong_derivation = b"eve-capability-v1";
    let mut rng = OsRng;

    let dkg_sk = Fr::rand(&mut rng);
    let dkg_pk: G1Affine = (G1Projective::generator() * dkg_sk).into();

    let (enc_cmt, _encrypted_secret, proof) = ThresholdDealerNode::encrypt_secret(
        &dkg_pk,
        secret,
        Some(correct_derivation),
        Some(&metadata),
    )
    .unwrap();

    assert!(
        proof.derived_pk.is_some(),
        "Proof should contain derived_pk"
    );

    // Wrong derivation: verify_encryption should fail immediately
    let wrong_derived_pk =
        ThresholdDealerNode::derive_public_key(&dkg_pk, wrong_derivation).unwrap();
    let result = ThresholdDealerNode::verify_encryption(
        &wrong_derived_pk,
        &enc_cmt,
        &proof,
        Some(&metadata),
    );
    assert!(
        result.is_err(),
        "verify_encryption should fail with wrong derivation"
    );
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("Derivation mismatch"),
        "Error should be a derivation mismatch, not a NIZK or AES failure"
    );

    // No derivation when one was used: should also fail (derived_pk != dkg_pk)
    let result = ThresholdDealerNode::verify_encryption(&dkg_pk, &enc_cmt, &proof, Some(&metadata));
    assert!(
        result.is_err(),
        "verify_encryption should fail when derivation is omitted but proof has derived_pk"
    );

    // Correct derivation: should succeed
    let correct_derived_pk =
        ThresholdDealerNode::derive_public_key(&dkg_pk, correct_derivation).unwrap();
    let result = ThresholdDealerNode::verify_encryption(
        &correct_derived_pk,
        &enc_cmt,
        &proof,
        Some(&metadata),
    );
    assert!(
        result.is_ok(),
        "verify_encryption should succeed with correct derivation"
    );
}

// ============================================================================
// AAD Binding Tests (Secret Component Mix-and-Match)
// ============================================================================

#[test]
fn test_swap_ciphertext_and_nonce_fails_decrypt() {
    // Take encrypted_data + nonce from encryption B, keep enc_cmt from encryption A.
    // Re-encryption uses enc_cmt_A so the derived AES key and AAD won't match ciphertext_B.
    let secret_a = b"secret A";
    let secret_b = b"secret B";
    let mut rng = OsRng;

    let dkg_sk = Fr::rand(&mut rng);
    let dkg_pk: G1Affine = (G1Projective::generator() * dkg_sk).into();
    let rdr_sk = Fr::rand(&mut rng);
    let rdr_pk: G1Affine = (G1Projective::generator() * rdr_sk).into();

    // Two independent encryptions under the same DKG key
    let (enc_cmt_a, encrypted_a, _proof_a) =
        ThresholdDealerNode::encrypt_secret(&dkg_pk, secret_a, None, None).unwrap();
    let (_enc_cmt_b, encrypted_b, _proof_b) =
        ThresholdDealerNode::encrypt_secret(&dkg_pk, secret_b, None, None).unwrap();

    // Frankenstein secret: enc_cmt from A, ciphertext + nonce from B
    let franken_secret = Secret {
        enc_cmt: encrypted_a.enc_cmt.clone(),
        encrypted_data: encrypted_b.encrypted_data.clone(),
        nonce: encrypted_b.nonce.clone(),
    };

    // Re-encrypt using enc_cmt_a (which matches the franken secret's enc_cmt)
    let xr_g = G1Projective::from(rdr_pk) + G1Projective::from(enc_cmt_a);
    let xnc_cmt: G1Affine = (xr_g * dkg_sk).into();

    // Decryption must fail — ciphertext was encrypted with a different key and AAD
    let result = ThresholdDealerNode::decrypt_secret(&dkg_pk, &xnc_cmt, &rdr_sk, &franken_secret);
    assert!(
        result.is_err(),
        "Decryption should fail when encrypted_data and nonce are swapped from another encryption"
    );
}

#[test]
fn test_swap_enc_cmt_fails_decrypt() {
    // Keep encrypted_data + nonce from encryption A, swap in enc_cmt from encryption B.
    // The re-encryption will use enc_cmt_B, producing a different shared_point,
    // so the derived AES key won't match and AAD will differ.
    let secret_a = b"secret A";
    let secret_b = b"secret B";
    let mut rng = OsRng;

    let dkg_sk = Fr::rand(&mut rng);
    let dkg_pk: G1Affine = (G1Projective::generator() * dkg_sk).into();
    let rdr_sk = Fr::rand(&mut rng);
    let rdr_pk: G1Affine = (G1Projective::generator() * rdr_sk).into();

    let (_enc_cmt_a, encrypted_a, _proof_a) =
        ThresholdDealerNode::encrypt_secret(&dkg_pk, secret_a, None, None).unwrap();
    let (enc_cmt_b, encrypted_b, _proof_b) =
        ThresholdDealerNode::encrypt_secret(&dkg_pk, secret_b, None, None).unwrap();

    // Frankenstein secret: enc_cmt from B, ciphertext + nonce from A
    let franken_secret = Secret {
        enc_cmt: encrypted_b.enc_cmt.clone(),
        encrypted_data: encrypted_a.encrypted_data.clone(),
        nonce: encrypted_a.nonce.clone(),
    };

    // Re-encrypt using enc_cmt_b (which matches the franken secret's enc_cmt)
    let xr_g = G1Projective::from(rdr_pk) + G1Projective::from(enc_cmt_b);
    let xnc_cmt: G1Affine = (xr_g * dkg_sk).into();

    let result = ThresholdDealerNode::decrypt_secret(&dkg_pk, &xnc_cmt, &rdr_sk, &franken_secret);
    assert!(
        result.is_err(),
        "Decryption should fail when enc_cmt is swapped from another encryption"
    );
}

#[test]
fn test_swap_nonce_only_fails_decrypt() {
    // Keep enc_cmt and encrypted_data from A, swap in only the nonce from B.
    // AES-GCM authentication will fail with the wrong nonce.
    let secret_a = b"secret A";
    let secret_b = b"secret B";
    let mut rng = OsRng;

    let dkg_sk = Fr::rand(&mut rng);
    let dkg_pk: G1Affine = (G1Projective::generator() * dkg_sk).into();
    let rdr_sk = Fr::rand(&mut rng);
    let rdr_pk: G1Affine = (G1Projective::generator() * rdr_sk).into();

    let (enc_cmt_a, encrypted_a, _proof_a) =
        ThresholdDealerNode::encrypt_secret(&dkg_pk, secret_a, None, None).unwrap();
    let (_enc_cmt_b, encrypted_b, _proof_b) =
        ThresholdDealerNode::encrypt_secret(&dkg_pk, secret_b, None, None).unwrap();

    // Frankenstein secret: enc_cmt + ciphertext from A, nonce from B
    let franken_secret = Secret {
        enc_cmt: encrypted_a.enc_cmt.clone(),
        encrypted_data: encrypted_a.encrypted_data.clone(),
        nonce: encrypted_b.nonce.clone(),
    };

    let xr_g = G1Projective::from(rdr_pk) + G1Projective::from(enc_cmt_a);
    let xnc_cmt: G1Affine = (xr_g * dkg_sk).into();

    let result = ThresholdDealerNode::decrypt_secret(&dkg_pk, &xnc_cmt, &rdr_sk, &franken_secret);
    assert!(
        result.is_err(),
        "Decryption should fail when only the nonce is swapped"
    );
}

#[test]
fn test_swap_enc_cmt_and_proof_fails_decrypt() {
    // Swap enc_cmt + proof from encryption B, keep encrypted_data + nonce from A.
    // The proof verifies (it's valid for enc_cmt_B), but decryption fails because
    // the AES key derived from re-encrypting enc_cmt_B doesn't match ciphertext_A.
    let secret_a = b"secret A";
    let secret_b = b"secret B";
    let mut rng = OsRng;

    let dkg_sk = Fr::rand(&mut rng);
    let dkg_pk: G1Affine = (G1Projective::generator() * dkg_sk).into();
    let rdr_sk = Fr::rand(&mut rng);
    let rdr_pk: G1Affine = (G1Projective::generator() * rdr_sk).into();

    let (_enc_cmt_a, encrypted_a, _proof_a) =
        ThresholdDealerNode::encrypt_secret(&dkg_pk, secret_a, None, None).unwrap();
    let (enc_cmt_b, encrypted_b, proof_b) =
        ThresholdDealerNode::encrypt_secret(&dkg_pk, secret_b, None, None).unwrap();

    // The attacker's proof_b is valid for enc_cmt_b
    let verify_result = ThresholdDealerNode::verify_encryption(&dkg_pk, &enc_cmt_b, &proof_b, None);
    assert!(
        verify_result.is_ok(),
        "Proof B should verify against enc_cmt_b"
    );

    // Frankenstein secret: enc_cmt from B (matching proof_b), ciphertext + nonce from A
    let franken_secret = Secret {
        enc_cmt: encrypted_b.enc_cmt.clone(),
        encrypted_data: encrypted_a.encrypted_data.clone(),
        nonce: encrypted_a.nonce.clone(),
    };

    // Re-encrypt using enc_cmt_b
    let xr_g = G1Projective::from(rdr_pk) + G1Projective::from(enc_cmt_b);
    let xnc_cmt: G1Affine = (xr_g * dkg_sk).into();

    // Proof verification passes, but decryption must fail
    let result = ThresholdDealerNode::decrypt_secret(&dkg_pk, &xnc_cmt, &rdr_sk, &franken_secret);
    assert!(
        result.is_err(),
        "Decryption should fail when enc_cmt + proof are swapped but ciphertext is from another encryption"
    );
}
