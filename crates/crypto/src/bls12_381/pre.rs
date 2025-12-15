use super::common::PubPoly;
use crate::{
    error::{CryptoError, Result},
    r#trait::{
        DistKeyShare, PubPoly as PubPolyTrait, PubShare, ReencryptReply, Secret, ThresholdDealer,
    },
};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use ark_bls12_381::{Fr, G1Affine, G1Projective};
use ark_ec::{AffineRepr, Group};
use ark_ff::{Field, One, PrimeField, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{vec::Vec, UniformRand};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

const NAME: &str = "elgamal";

#[derive(Clone, Debug)]
pub struct ThresholdDealerNode {}

impl ThresholdDealer for ThresholdDealerNode {
    type ShareValue = Fr;
    type PublicKey = G1Affine;
    type PubPoly = PubPoly;
    type DistKeyShare = DistKeyShare<Self::ShareValue>;
    type Secret = Secret;
    type ReencryptReply = ReencryptReply<Self::ShareValue, Self::PublicKey>;

    fn new() -> Self {
        ThresholdDealerNode {}
    }

    fn name(&self) -> &str {
        NAME
    }

    fn reencrypt(
        &self,
        dist_key_share: &Self::DistKeyShare,
        scrt: &Self::Secret,
        rdr_pk: &Self::PublicKey,
    ) -> Result<Self::ReencryptReply> {
        // Input validation
        if scrt.enc_cmt.is_empty() {
            return Err(CryptoError::ElGamalError(
                "Empty commitment in secret".to_string(),
            ));
        }

        let idx = dist_key_share.pri_share.i;
        let ski = dist_key_share.pri_share.v;

        // Validate index is positive
        if idx == 0 {
            return Err(CryptoError::ElGamalError(format!(
                "Invalid share index: {} (must not be 0)",
                idx
            )));
        }

        // Unmarshal the commitment
        let enc_cmt = Self::decompress_point(&scrt.enc_cmt)?;

        let (xnc_ski, chlgi, proofi) = Self::reencrypt(&ski, rdr_pk, &enc_cmt)?;

        Ok(ReencryptReply {
            share: PubShare { i: idx, v: xnc_ski },
            challenge: chlgi,
            proof: proofi,
        })
    }
    fn verify(
        &self,
        rdr_pk: &Self::PublicKey,
        dkg_cmt: &Self::PubPoly,
        enc_cmt: &Self::PublicKey,
        reply: &Self::ReencryptReply,
    ) -> Result<()> {
        let xnc_ski = reply.share.v;
        let idx = reply.share.i;
        let dkg_cmt_eval = dkg_cmt.eval(idx);

        Self::verify(
            rdr_pk,
            enc_cmt,
            &xnc_ski,
            &reply.challenge,
            &reply.proof,
            &dkg_cmt_eval,
        )?;

        Ok(())
    }

    fn recover(
        &self,
        xnc_ski: &[PubShare<Self::PublicKey>],
        t: usize,
        n: usize,
    ) -> Result<Option<Self::PublicKey>> {
        // Validate parameters
        if t == 0 {
            return Err(CryptoError::ElGamalError(
                "Threshold must be greater than zero".to_string(),
            ));
        }

        if t > n {
            return Err(CryptoError::ElGamalError(format!(
                "Threshold {} exceeds total shares {}",
                t, n
            )));
        }

        if xnc_ski.len() < t {
            return Ok(None);
        }

        Self::recover_commit(xnc_ski, t, n)
    }
    fn encrypt_secret(
        dkg_pk: &Self::PublicKey,
        data: &[u8],
    ) -> Result<(Self::PublicKey, Self::Secret)> {
        let mut rng = OsRng;
        // Generate random r
        let r = Fr::rand(&mut rng);
        let enc_cmt: G1Affine = (G1Projective::generator() * r).into(); // rG
        let rs_g: G1Affine = (G1Projective::from(*dkg_pk) * r).into(); // rsG

        // Derive AES key from rsG
        let aes_key = Self::derive_key_from_point(&rs_g)?;
        let cipher = Aes256Gcm::new(&aes_key.into());

        // Generate nonce using cryptographically secure RNG
        let mut nonce_bytes = [0u8; 12];
        rng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Encrypt data
        let ciphertext = cipher
            .encrypt(nonce, data)
            .map_err(|_| CryptoError::ElGamalError("Encryption failed".to_string()))?;

        let mut enc_cmt_bytes = Vec::new();
        enc_cmt.serialize_compressed(&mut enc_cmt_bytes)?;

        Ok((
            enc_cmt,
            Secret {
                enc_cmt: enc_cmt_bytes,
                encrypted_data: ciphertext,
                nonce: nonce_bytes.to_vec(),
                auth_tag: Vec::new(), // Included in ciphertext with AES-GCM
            },
        ))
    }
    fn decrypt_secret(
        dkg_pk: &Self::PublicKey,
        xnc_cmt: &Self::PublicKey, // Recovered from re-encryption
        rdr_sk: &Self::ShareValue,
        secret: &Self::Secret,
    ) -> Result<Vec<u8>> {
        // Input validation
        if secret.nonce.len() != 12 {
            return Err(CryptoError::ElGamalError(
                "Invalid nonce length: must be exactly 12 bytes".to_string(),
            ));
        }

        if secret.encrypted_data.is_empty() {
            return Err(CryptoError::ElGamalError(
                "Empty encrypted data".to_string(),
            ));
        }

        if secret.enc_cmt.is_empty() {
            return Err(CryptoError::ElGamalError("Empty commitment".to_string()));
        }

        // Recover rsG
        let xs_g = G1Projective::from(*dkg_pk) * rdr_sk; // xsG = x * sG
        let rs_g: G1Affine = (G1Projective::from(*xnc_cmt) - xs_g).into(); // rsG

        // Derive AES key
        let aes_key = Self::derive_key_from_point(&rs_g)?;
        let cipher = Aes256Gcm::new(&aes_key.into());

        // Decrypt
        let nonce = Nonce::from_slice(&secret.nonce);
        let plaintext = cipher
            .decrypt(nonce, secret.encrypted_data.as_ref())
            .map_err(|_| {
                CryptoError::ElGamalError("Decryption failed - authentication failed".to_string())
            })?;

        Ok(plaintext)
    }
}

impl ThresholdDealerNode {
    /// Decompress a point from bytes
    fn decompress_point(bytes: &[u8]) -> Result<G1Affine> {
        G1Affine::deserialize_compressed(bytes)
            .map_err(|e| CryptoError::ElGamalError(format!("failed to decompress point: {:?}", e)))
    }

    fn reencrypt(
        dkg_ski: &Fr,
        rdr_pk: &G1Affine,
        enc_cmt: &G1Affine,
    ) -> Result<(G1Affine, Fr, Fr)> {
        // Re-encrypted secret share (Ui)
        let xr_g = G1Projective::from(*rdr_pk) + G1Projective::from(*enc_cmt); // xrG = xG + rG
        let xnc_ski = (xr_g * dkg_ski).into(); // Ui = ski * (xG + rG)

        // Produce random oracle challenge (ei)
        // ei = Hash(Ui + UiHat + HiHat)
        let mut rng = OsRng;
        let ri = Fr::rand(&mut rng); // ri = Random scalar
        let ui_hat = (xr_g * ri).into(); // UiHat = ri * (xG + rG)
        let hi_hat = (G1Projective::generator() * ri).into(); // HiHat = ri * G

        let challenge_hash = Self::hash_points(&[xnc_ski, ui_hat, hi_hat])?;
        let chlgi = Fr::from_le_bytes_mod_order(&challenge_hash);

        // Produce NIZK proof of re-encryption (fi)
        // fi = ri + ei * ski
        let proofi = ri + (chlgi * dkg_ski);

        Ok((xnc_ski, chlgi, proofi))
    }

    fn verify(
        rdr_pk: &G1Affine,
        enc_cmt: &G1Affine,
        dkg_ski: &G1Affine,
        chlgi: &Fr,
        proofi: &Fr,
        dkg_cmt: &G1Affine,
    ) -> Result<()> {
        // Reconstruct UiHat
        let xr_g = G1Projective::from(*rdr_pk) + G1Projective::from(*enc_cmt); // xG + rG
        let fi_xr_g = xr_g * proofi; // fi * (xG + rG)
        let ei_ui = G1Projective::from(*dkg_ski) * chlgi; // ei * Ui
        let ui_hat = (fi_xr_g - ei_ui).into(); // UiHat = fi * (xG + rG) - ei * Ui

        // Reconstruct HiHat
        let fi_g = G1Projective::generator() * proofi; // FiG = fi * G
        let ei_ci = G1Projective::from(*dkg_cmt) * chlgi; // EiHi = ei * ci
        let hi_hat = (fi_g - ei_ci).into(); // HiHat = fi * G - ei * ci
                                            // Reconstruct random oracle challenge (ei)
                                            // ei = Hash(Ui + UiHat + HiHat)
        let challenge_hash = Self::hash_points(&[*dkg_ski, ui_hat, hi_hat])?;
        let chlg = Fr::from_le_bytes_mod_order(&challenge_hash);

        // Verify local challenge using constant-time comparison
        // Serialize both field elements to fixed-size byte arrays for constant-time comparison
        let mut chlg_bytes = Vec::new();
        let mut chlgi_bytes = Vec::new();
        chlg.serialize_compressed(&mut chlg_bytes)
            .map_err(|e| CryptoError::ElGamalError(format!("Serialization error: {:?}", e)))?;
        chlgi
            .serialize_compressed(&mut chlgi_bytes)
            .map_err(|e| CryptoError::ElGamalError(format!("Serialization error: {:?}", e)))?;

        // Pad to same length for constant-time comparison
        let max_len = chlg_bytes.len().max(chlgi_bytes.len());
        let mut chlg_padded = vec![0u8; max_len];
        let mut chlgi_padded = vec![0u8; max_len];
        chlg_padded[..chlg_bytes.len()].copy_from_slice(&chlg_bytes);
        chlgi_padded[..chlgi_bytes.len()].copy_from_slice(&chlgi_bytes);

        if chlg_padded.ct_ne(&chlgi_padded).into() {
            return Err(CryptoError::ElGamalError(
                "Cryptographic verification failed".to_string(),
            ));
        }

        Ok(())
    }

    fn recover_commit(
        shares: &[PubShare<G1Affine>],
        t: usize,
        n: usize,
    ) -> Result<Option<G1Affine>> {
        let shares_to_use = &shares[..t];
        // Validate all share indices are distinct and in valid range
        let mut indices: Vec<u32> = shares_to_use.iter().map(|s| s.i).collect();
        indices.sort();
        // Check for duplicates
        for i in 1..indices.len() {
            if indices[i] == indices[i - 1] {
                return Err(CryptoError::ElGamalError(format!(
                    "Duplicate share index: {}",
                    indices[i]
                )));
            }
        }

        // Validate indices are in valid range [1, n]
        for &idx in &indices {
            if idx < 1 || idx > n as u32 {
                return Err(CryptoError::ElGamalError(format!(
                    "Invalid share index: {} (must be in range [1, {}])",
                    idx, n
                )));
            }
        }

        let mut result = G1Projective::zero();

        for (i, share_i) in shares_to_use.iter().enumerate() {
            let mut num = Fr::one();
            let mut den = Fr::one();

            for (j, share_j) in shares_to_use.iter().enumerate() {
                if i != j {
                    let xi = Fr::from(share_i.i as u64);
                    let xj = Fr::from(share_j.i as u64);

                    num *= xj;
                    den *= xj - xi;
                }
            }

            // At this point, we've validated indices are distinct, so den should never be zero
            // But we still check for safety
            let lambda = num
            * den.inverse().ok_or_else(|| {
                CryptoError::ElGamalError(
                    "Division by zero in Lagrange interpolation - this should not happen after validation".to_string(),
                )
            })?;
            result += G1Projective::from(share_i.v) * lambda;
        }

        Ok(Some(result.into()))
    }

    /// Hash multiple points together
    fn hash_points(points: &[G1Affine]) -> Result<[u8; 32]> {
        let mut hasher = Sha256::new();

        for point in points {
            let mut bytes = Vec::new();
            point.serialize_compressed(&mut bytes)?;
            hasher.update(&bytes);
        }

        let result = hasher.finalize();
        let mut output = [0u8; 32];
        output.copy_from_slice(&result);

        Ok(output)
    }

    /// Derive AES key from elliptic curve point
    fn derive_key_from_point(point: &G1Affine) -> Result<[u8; 32]> {
        let mut point_bytes = Vec::new();
        point.serialize_compressed(&mut point_bytes)?;

        let hkdf = Hkdf::<Sha256>::new(None, &point_bytes);
        let mut key = [0u8; 32];
        hkdf.expand(b"elgamal-aes-key-v1", &mut key)
            .map_err(|_| CryptoError::ElGamalError("HKDF expansion failed".to_string()))?;

        Ok(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::r#trait::PriShare;
    use crate::test_helper::DKGCoordinator;
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
        let (enc_cmt, encrypted_secret) =
            ThresholdDealerNode::encrypt_secret(&dkg_pk, secret).unwrap();

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
            ThresholdDealerNode::decrypt_secret(&dkg_pk, &xnc_cmt, &rdr_sk, &encrypted_secret)
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
        let (enc_cmt, encrypted_secret) =
            ThresholdDealerNode::encrypt_secret(&dkg_pk, secret).unwrap();

        assert_ne!(enc_cmt, G1Affine::zero());
        assert!(!encrypted_secret.encrypted_data.is_empty());

        // Simulate re-encryption commitment correctly
        // xnc_cmt = dkg_sk * (rdr_pk + enc_cmt)
        let xr_g = G1Projective::from(rdr_pk) + G1Projective::from(enc_cmt);
        let xnc_cmt: G1Affine = (xr_g * dkg_sk).into();

        // Decrypt
        let decrypted =
            ThresholdDealerNode::decrypt_secret(&dkg_pk, &xnc_cmt, &rdr_sk, &encrypted_secret)
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
        let (enc_cmt, encrypted_secret) =
            ThresholdDealerNode::encrypt_secret(&dkg_pk, secret).unwrap();

        // Simulate re-encryption commitment correctly
        let xr_g = G1Projective::from(rdr_pk) + G1Projective::from(enc_cmt);
        let xnc_cmt: G1Affine = (xr_g * dkg_sk).into();

        // Decrypt
        let decrypted =
            ThresholdDealerNode::decrypt_secret(&dkg_pk, &xnc_cmt, &rdr_sk, &encrypted_secret)
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
        let (enc_cmt, encrypted_secret) =
            ThresholdDealerNode::encrypt_secret(&dkg_pk, secret).unwrap();

        // Simulate re-encryption commitment with CORRECT reader key
        let xr_g = G1Projective::from(rdr_pk) + G1Projective::from(enc_cmt);
        let xnc_cmt: G1Affine = (xr_g * dkg_sk).into();

        // Try to decrypt with WRONG key - should fail
        let result = ThresholdDealerNode::decrypt_secret(
            &dkg_pk,
            &xnc_cmt,
            &wrong_rdr_sk,
            &encrypted_secret,
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
        let (enc_cmt, encrypted_secret) =
            ThresholdDealerNode::encrypt_secret(&dkg_pk, secret).unwrap();

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
        let (enc_cmt, encrypted_secret) =
            ThresholdDealerNode::encrypt_secret(&dkg_pk, secret).unwrap();

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
                <crate::bls12_381::dkg::DKGNode as crate::r#trait::Dkg>::new(
                    id,
                    threshold,
                    total_nodes,
                )
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
        let (enc_cmt, encrypted_secret) =
            ThresholdDealerNode::encrypt_secret(&aggregate_pk, secret).unwrap();

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
        )
        .unwrap();

        // Verify decryption recovered the original secret
        assert_eq!(decrypted, secret);
        assert_eq!(decrypted.len(), secret.len());
    }
}
