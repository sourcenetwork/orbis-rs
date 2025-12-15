use super::common::{PolynomialCommitment, PubPoly};
use crate::{
    error::{CryptoError, Result},
    r#trait::{
        DistKeyShare, PolynomialCommitment as PolynomialCommitmentTrait, PriShare,
        PubPoly as PubPolyTrait, PubShare, ReencryptReply, Secret, ThresholdDealer,
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

#[derive(Clone, Debug)]
pub struct ThresholdDealerNode {}

impl ThresholdDealer for ThresholdDealerNode {
    type ShareValue = Fr;
    type PublicKey = G1Affine;
    type PubPoly = PubPoly;
    type DistKeyShare = DistKeyShare<Self::ShareValue>;
    type Secret = Secret;
    type ReencryptReply = ReencryptReply<Self::ShareValue, Self::PublicKey>;

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
