use crate::bls12_381::common::PubPoly;
use crate::bls12_381::pre::ThresholdDealerNode;
use crate::r#trait::{DistKeyShare, PriShare, PubPoly as PubPolyTrait, PubShare, ThresholdDealer};
use crate::test_helper::DKGCoordinator;
use ark_bls12_381::{Fr, G1Affine, G1Projective};
use ark_ec::{AffineRepr, Group};
use ark_serialize::CanonicalSerialize;
use ark_std::UniformRand;
use rand_core::OsRng;

#[test]
fn test_threshold_dealer_creation() {
    let dealer = ThresholdDealerNode::new();
    assert_eq!(dealer.name(), "elgamal");
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

    // 1. Encrypt the secret
    let (enc_cmt, encrypted_secret, _proof) =
        ThresholdDealerNode::encrypt_secret(&dkg_pk, secret, None).unwrap();

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
        ThresholdDealerNode::decrypt_secret(&dkg_pk, &xnc_cmt, &rdr_sk, &encrypted_secret, None)
            .unwrap();

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
        ThresholdDealerNode::encrypt_secret(&dkg_pk, secret, None).unwrap();

    assert_ne!(enc_cmt, G1Affine::zero());
    assert!(!encrypted_secret.encrypted_data.is_empty());

    // Simulate re-encryption commitment correctly
    // xnc_cmt = dkg_sk * (rdr_pk + enc_cmt)
    let xr_g = G1Projective::from(rdr_pk) + G1Projective::from(enc_cmt);
    let xnc_cmt: G1Affine = (xr_g * dkg_sk).into();

    // Decrypt
    let decrypted =
        ThresholdDealerNode::decrypt_secret(&dkg_pk, &xnc_cmt, &rdr_sk, &encrypted_secret, None)
            .unwrap();

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
        ThresholdDealerNode::encrypt_secret(&dkg_pk, secret, None).unwrap();

    // Simulate re-encryption commitment correctly
    let xr_g = G1Projective::from(rdr_pk) + G1Projective::from(enc_cmt);
    let xnc_cmt: G1Affine = (xr_g * dkg_sk).into();

    // Decrypt
    let decrypted =
        ThresholdDealerNode::decrypt_secret(&dkg_pk, &xnc_cmt, &rdr_sk, &encrypted_secret, None)
            .unwrap();

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
        ThresholdDealerNode::encrypt_secret(&dkg_pk, secret, None).unwrap();

    // Simulate re-encryption commitment with CORRECT reader key
    let xr_g = G1Projective::from(rdr_pk) + G1Projective::from(enc_cmt);
    let xnc_cmt: G1Affine = (xr_g * dkg_sk).into();

    // Try to decrypt with WRONG key - should fail
    let result = ThresholdDealerNode::decrypt_secret(
        &dkg_pk,
        &xnc_cmt,
        &wrong_rdr_sk,
        &encrypted_secret,
        None,
    );

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
        ThresholdDealerNode::encrypt_secret(&dkg_pk, secret, None).unwrap();

    // Re-encrypt
    let dealer = ThresholdDealerNode::new();
    let reply = dealer
        .reencrypt(&share, &encrypted_secret, &rdr_pk)
        .unwrap();

    // Verify the reply
    let verify_result = dealer.verify(&rdr_pk, &commitment, &enc_cmt, &reply);

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
        ThresholdDealerNode::encrypt_secret(&dkg_pk, secret, None).unwrap();

    // Re-encrypt
    let dealer = ThresholdDealerNode::new();
    let mut reply = dealer
        .reencrypt(&share, &encrypted_secret, &rdr_pk)
        .unwrap();

    // Tamper with the proof
    reply.proof = Fr::rand(&mut rng);

    // Verification should fail
    let verify_result = dealer.verify(&rdr_pk, &commitment, &enc_cmt, &reply);

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

    // Step 2: Encrypt the secret using aggregate public key
    let (enc_cmt, encrypted_secret, _proof) =
        ThresholdDealerNode::encrypt_secret(&aggregate_pk, secret, None).unwrap();

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

    // Use first t shares for re-encryption
    for share in secret_shares.iter().take(t) {
        let dist_key_share = DistKeyShare {
            pri_share: share.clone(),
        };

        let reply = dealer
            .reencrypt(&dist_key_share, &encrypted_secret, &rdr_pk)
            .unwrap();

        // Verify the re-encryption reply
        let verify_result = dealer.verify(&rdr_pk, &pub_poly, &enc_cmt, &reply);
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
    let decrypted = ThresholdDealerNode::decrypt_secret(
        &aggregate_pk,
        &xnc_cmt,
        &rdr_sk,
        &encrypted_secret,
        None,
    )
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
        ThresholdDealerNode::encrypt_secret(&dkg_pk, secret, None).unwrap();

    // Verify the encryption proof
    let result = ThresholdDealerNode::verify_encryption(&dkg_pk, &enc_cmt, &proof);
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
        ThresholdDealerNode::encrypt_secret(&dkg_pk, secret, None).unwrap();

    // Verify with wrong DKG public key - should fail
    let result = ThresholdDealerNode::verify_encryption(&wrong_dkg_pk, &enc_cmt, &proof);
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
        ThresholdDealerNode::encrypt_secret(&dkg_pk, secret, None).unwrap();

    // Tamper with the challenge
    let tampered_challenge = Fr::rand(&mut rng);
    let mut tampered_bytes = Vec::new();
    tampered_challenge
        .serialize_compressed(&mut tampered_bytes)
        .unwrap();
    proof.challenge = tampered_bytes;

    // Verification should fail
    let result = ThresholdDealerNode::verify_encryption(&dkg_pk, &enc_cmt, &proof);
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
        ThresholdDealerNode::encrypt_secret(&dkg_pk, secret, None).unwrap();

    // Tamper with the response
    let tampered_response = Fr::rand(&mut rng);
    let mut tampered_bytes = Vec::new();
    tampered_response
        .serialize_compressed(&mut tampered_bytes)
        .unwrap();
    proof.response = tampered_bytes;

    // Verification should fail
    let result = ThresholdDealerNode::verify_encryption(&dkg_pk, &enc_cmt, &proof);
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
        ThresholdDealerNode::encrypt_secret(&dkg_pk, secret, None).unwrap();

    // Tamper with the shared point
    let tampered_point: G1Affine = (G1Projective::generator() * Fr::rand(&mut rng)).into();
    let mut tampered_bytes = Vec::new();
    tampered_point
        .serialize_compressed(&mut tampered_bytes)
        .unwrap();
    proof.shared_point = tampered_bytes;

    // Verification should fail
    let result = ThresholdDealerNode::verify_encryption(&dkg_pk, &enc_cmt, &proof);
    assert!(
        result.is_err(),
        "Encryption proof should fail with tampered shared point"
    );
}

// =============================================================================
// Capability Derivation Tests
// =============================================================================

#[test]
fn test_capability_derivation_encrypt_decrypt() {
    let secret = b"capability-protected secret";
    let derivation = b"my-capability-tag";
    let mut rng = OsRng;

    // Setup DKG key pair
    let dkg_sk = Fr::rand(&mut rng);
    let dkg_pk: G1Affine = (G1Projective::generator() * dkg_sk).into();

    // Setup reader key pair
    let rdr_sk = Fr::rand(&mut rng);
    let rdr_pk: G1Affine = (G1Projective::generator() * rdr_sk).into();

    // 1. Encrypt with derivation
    let (enc_cmt, encrypted_secret, proof) =
        ThresholdDealerNode::encrypt_secret(&dkg_pk, secret, Some(derivation)).unwrap();

    // Verify the derived_pk is stored in proof (allows verification without derivation)
    assert!(
        proof.derived_pk.is_some(),
        "derived_pk should be stored in proof"
    );

    // Verify encryption proof (no derivation needed - uses derived_pk from proof)
    let verify_result = ThresholdDealerNode::verify_encryption(&dkg_pk, &enc_cmt, &proof);
    assert!(
        verify_result.is_ok(),
        "Encryption proof should verify using derived_pk from proof"
    );

    // 2. Simulate re-encryption (unchanged by derivation)
    let xr_g = G1Projective::from(rdr_pk) + G1Projective::from(enc_cmt);
    let xnc_cmt: G1Affine = (xr_g * dkg_sk).into();

    // 3. Decrypt with correct derivation
    let decrypted = ThresholdDealerNode::decrypt_secret(
        &dkg_pk,
        &xnc_cmt,
        &rdr_sk,
        &encrypted_secret,
        Some(derivation),
    )
    .unwrap();

    assert_eq!(
        decrypted, secret,
        "Decryption should recover original secret"
    );
}

#[test]
fn test_capability_derivation_wrong_derivation_fails() {
    let secret = b"capability-protected secret";
    let derivation = b"my-capability-tag";
    let wrong_derivation = b"wrong-capability-tag";
    let mut rng = OsRng;

    // Setup keys
    let dkg_sk = Fr::rand(&mut rng);
    let dkg_pk: G1Affine = (G1Projective::generator() * dkg_sk).into();
    let rdr_sk = Fr::rand(&mut rng);
    let rdr_pk: G1Affine = (G1Projective::generator() * rdr_sk).into();

    // Encrypt with derivation
    let (enc_cmt, encrypted_secret, _proof) =
        ThresholdDealerNode::encrypt_secret(&dkg_pk, secret, Some(derivation)).unwrap();

    // Simulate re-encryption
    let xr_g = G1Projective::from(rdr_pk) + G1Projective::from(enc_cmt);
    let xnc_cmt: G1Affine = (xr_g * dkg_sk).into();

    // Try to decrypt with WRONG derivation - should fail (AES-GCM auth failure)
    let result = ThresholdDealerNode::decrypt_secret(
        &dkg_pk,
        &xnc_cmt,
        &rdr_sk,
        &encrypted_secret,
        Some(wrong_derivation),
    );

    assert!(
        result.is_err(),
        "Decryption with wrong derivation should fail"
    );
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("authentication failed"),
        "Error should indicate authentication failure"
    );
}

#[test]
fn test_capability_derivation_missing_derivation_fails() {
    let secret = b"capability-protected secret";
    let derivation = b"my-capability-tag";
    let mut rng = OsRng;

    // Setup keys
    let dkg_sk = Fr::rand(&mut rng);
    let dkg_pk: G1Affine = (G1Projective::generator() * dkg_sk).into();
    let rdr_sk = Fr::rand(&mut rng);
    let rdr_pk: G1Affine = (G1Projective::generator() * rdr_sk).into();

    // Encrypt WITH derivation
    let (enc_cmt, encrypted_secret, _proof) =
        ThresholdDealerNode::encrypt_secret(&dkg_pk, secret, Some(derivation)).unwrap();

    // Simulate re-encryption
    let xr_g = G1Projective::from(rdr_pk) + G1Projective::from(enc_cmt);
    let xnc_cmt: G1Affine = (xr_g * dkg_sk).into();

    // Try to decrypt WITHOUT derivation - should fail (AES-GCM auth failure)
    let result =
        ThresholdDealerNode::decrypt_secret(&dkg_pk, &xnc_cmt, &rdr_sk, &encrypted_secret, None);

    assert!(
        result.is_err(),
        "Decryption without derivation should fail when encrypted with derivation"
    );
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("authentication failed"),
        "Error should indicate authentication failure"
    );
}

#[test]
fn test_capability_derivation_unexpected_derivation_fails() {
    let secret = b"non-capability secret";
    let derivation = b"unexpected-capability";
    let mut rng = OsRng;

    // Setup keys
    let dkg_sk = Fr::rand(&mut rng);
    let dkg_pk: G1Affine = (G1Projective::generator() * dkg_sk).into();
    let rdr_sk = Fr::rand(&mut rng);
    let rdr_pk: G1Affine = (G1Projective::generator() * rdr_sk).into();

    // Encrypt WITHOUT derivation
    let (enc_cmt, encrypted_secret, proof) =
        ThresholdDealerNode::encrypt_secret(&dkg_pk, secret, None).unwrap();

    // Verify derived_pk is NOT in proof when no derivation used
    assert!(
        proof.derived_pk.is_none(),
        "derived_pk should be None when no derivation used"
    );

    // Simulate re-encryption
    let xr_g = G1Projective::from(rdr_pk) + G1Projective::from(enc_cmt);
    let xnc_cmt: G1Affine = (xr_g * dkg_sk).into();

    // Try to decrypt WITH derivation when none was used - should fail (AES-GCM auth failure)
    let result = ThresholdDealerNode::decrypt_secret(
        &dkg_pk,
        &xnc_cmt,
        &rdr_sk,
        &encrypted_secret,
        Some(derivation),
    );

    assert!(
        result.is_err(),
        "Decryption with derivation should fail when encrypted without derivation"
    );
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("authentication failed"),
        "Error should indicate authentication failure"
    );
}

#[test]
fn test_capability_derivation_verify_without_knowing_derivation() {
    // This test verifies that encryption proof can be verified without knowing
    // the derivation pre-image, because derived_pk is stored in the proof.
    let secret = b"test secret";
    let derivation = b"my-secret-capability";
    let mut rng = OsRng;

    let dkg_sk = Fr::rand(&mut rng);
    let dkg_pk: G1Affine = (G1Projective::generator() * dkg_sk).into();

    // Encrypt with derivation
    let (enc_cmt, _encrypted_secret, proof) =
        ThresholdDealerNode::encrypt_secret(&dkg_pk, secret, Some(derivation)).unwrap();

    // Verify that derived_pk is stored in proof
    assert!(
        proof.derived_pk.is_some(),
        "derived_pk should be stored in proof when derivation is used"
    );

    // Verification succeeds without knowing the derivation pre-image
    let result = ThresholdDealerNode::verify_encryption(&dkg_pk, &enc_cmt, &proof);
    assert!(
        result.is_ok(),
        "Verification should succeed using derived_pk from proof"
    );
}

#[test]
fn test_capability_derivation_different_capabilities_different_ciphertexts() {
    let secret = b"same secret";
    let derivation1 = b"capability-A";
    let derivation2 = b"capability-B";
    let mut rng = OsRng;

    let dkg_sk = Fr::rand(&mut rng);
    let dkg_pk: G1Affine = (G1Projective::generator() * dkg_sk).into();

    // Encrypt with different derivations
    let (_, _encrypted1, proof1) =
        ThresholdDealerNode::encrypt_secret(&dkg_pk, secret, Some(derivation1)).unwrap();
    let (_, _encrypted2, proof2) =
        ThresholdDealerNode::encrypt_secret(&dkg_pk, secret, Some(derivation2)).unwrap();

    // The shared_points should be different (different derived keys)
    assert_ne!(
        proof1.shared_point, proof2.shared_point,
        "Different derivations should produce different shared points"
    );

    // The derived_pk values should be different
    assert_ne!(
        proof1.derived_pk, proof2.derived_pk,
        "Different derivations should produce different derived public keys"
    );
}

#[test]
fn test_capability_derivation_full_pre_integration() {
    // This test demonstrates the complete capability-based PRE flow:
    // 1. Run DKG to generate threshold keys
    // 2. Encrypt a secret with capability derivation
    // 3. Re-encrypt using threshold shares (unchanged by derivation)
    // 4. Decrypt with correct capability - succeeds
    // 5. Decrypt with wrong capability - fails

    let secret = b"Capability-protected secret via threshold PRE!";
    let capability = b"resource:document:123:read";

    // Setup: 3-of-5 threshold DKG
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

    // Step 2: Encrypt with capability derivation
    let (enc_cmt, encrypted_secret, proof) =
        ThresholdDealerNode::encrypt_secret(&aggregate_pk, secret, Some(capability)).unwrap();

    // Verify encryption proof (no derivation needed - uses derived_pk from proof)
    assert!(ThresholdDealerNode::verify_encryption(&aggregate_pk, &enc_cmt, &proof).is_ok());

    // Step 3: Setup reader (Bob)
    let mut rng = OsRng;
    let rdr_sk = Fr::rand(&mut rng);
    let rdr_pk: G1Affine = (G1Projective::generator() * rdr_sk).into();

    // Step 4: Re-encrypt using threshold shares (derivation is transparent to this step)
    let dealer = ThresholdDealerNode::new();
    let mut reencrypt_replies = Vec::new();

    for share in secret_shares.iter().take(t) {
        let dist_key_share = DistKeyShare {
            pri_share: share.clone(),
        };
        let reply = dealer
            .reencrypt(&dist_key_share, &encrypted_secret, &rdr_pk)
            .unwrap();
        dealer
            .verify(&rdr_pk, &pub_poly, &enc_cmt, &reply)
            .expect("Re-encryption verification should succeed");
        reencrypt_replies.push(reply);
    }

    // Step 5: Recover re-encrypted commitment
    let pub_shares: Vec<PubShare<G1Affine>> =
        reencrypt_replies.iter().map(|r| r.share.clone()).collect();
    let xnc_cmt = dealer
        .recover(&pub_shares, t, n)
        .unwrap()
        .expect("Recovery should succeed");

    // Step 6: Decrypt WITH correct capability - should succeed
    let decrypted = ThresholdDealerNode::decrypt_secret(
        &aggregate_pk,
        &xnc_cmt,
        &rdr_sk,
        &encrypted_secret,
        Some(capability),
    )
    .expect("Decryption with correct capability should succeed");

    assert_eq!(decrypted, secret);

    // Step 7: Decrypt WITHOUT capability - should fail
    let wrong_result = ThresholdDealerNode::decrypt_secret(
        &aggregate_pk,
        &xnc_cmt,
        &rdr_sk,
        &encrypted_secret,
        None,
    );
    assert!(
        wrong_result.is_err(),
        "Decryption without capability should fail"
    );

    // Step 8: Decrypt with WRONG capability - should fail
    let wrong_cap_result = ThresholdDealerNode::decrypt_secret(
        &aggregate_pk,
        &xnc_cmt,
        &rdr_sk,
        &encrypted_secret,
        Some(b"wrong:capability"),
    );
    assert!(
        wrong_cap_result.is_err(),
        "Decryption with wrong capability should fail"
    );
}
