use super::common::PubPoly;
use crate::{
    error::{CryptoError, Result},
    r#trait::{
        DistKeyShare, EncryptionProof, PubPoly as PubPolyTrait, PubShare, ReencryptReply, Secret,
        ThresholdDealer,
    },
};
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use ark_bls12_381::{Fr, G1Affine, G1Projective};
use ark_ec::{AffineRepr, Group};
use ark_ff::{Field, One, PrimeField, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{collections::HashSet, vec::Vec, UniformRand};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

const NAME: &str = "elgamal";

const ENCRYPT_PROOF_DOMAIN: &[u8; 24] = b"elgamal-encrypt-proof-v1";
const PROTOCOL: &[u8; 30] = b"elgamal-reencrypt-challenge-v1";
const AAD_DOMAIN: &[u8; 15] = b"elgamal-aad-v1\0";

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
    ) -> Result<(Self::PublicKey, Self::Secret, EncryptionProof)> {
        let mut rng = OsRng;
        // Generate random r
        let r = Fr::rand(&mut rng);
        let enc_cmt: G1Affine = (G1Projective::generator() * r).into(); // rG
        let rs_g: G1Affine = (G1Projective::from(*dkg_pk) * r).into(); // rsG (shared point)

        // Generate Chaum-Pedersen NIZK proof
        // Proves that enc_cmt = r*G and rs_g = r*dkg_pk use the same r
        let (challenge, response) = Self::generate_encryption_proof(&r, dkg_pk, &enc_cmt, &rs_g)?;

        // Serialize proof components
        let mut shared_point_bytes = Vec::new();
        rs_g.serialize_compressed(&mut shared_point_bytes)?;
        let mut challenge_bytes = Vec::new();
        challenge.serialize_compressed(&mut challenge_bytes)?;
        let mut response_bytes = Vec::new();
        response.serialize_compressed(&mut response_bytes)?;

        let proof = EncryptionProof {
            shared_point: shared_point_bytes.clone(),
            challenge: challenge_bytes,
            response: response_bytes,
        };

        // Derive AES key from rsG
        let aes_key = Self::derive_key_from_point(&rs_g)?;
        let cipher = Aes256Gcm::new(&aes_key.into());

        // Generate nonce using cryptographically secure RNG
        let mut nonce_bytes = [0u8; 12];
        rng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Serialize commitment
        let mut enc_cmt_bytes = Vec::new();
        enc_cmt.serialize_compressed(&mut enc_cmt_bytes)?;

        // Build AAD using centralized helper for consistency with decryption
        let aad = Self::build_aad(&enc_cmt_bytes, &shared_point_bytes);

        // Encrypt data with AAD to bind ciphertext to commitment and shared point
        let payload = Payload {
            msg: data,
            aad: &aad,
        };
        let ciphertext = cipher
            .encrypt(nonce, payload)
            .map_err(|_| CryptoError::ElGamalError("Encryption failed".to_string()))?;

        Ok((
            enc_cmt,
            Secret {
                enc_cmt: enc_cmt_bytes,
                encrypted_data: ciphertext,
                nonce: nonce_bytes.to_vec(),
                auth_tag: Vec::new(), // Included in ciphertext with AES-GCM
            },
            proof,
        ))
    }

    /// Verify the Chaum-Pedersen NIZK proof for encryption.
    ///
    /// This verifies that `enc_cmt` and `shared_point` (in the proof) share the same
    /// discrete logarithm relative to G and dkg_pk respectively. In other words:
    ///   enc_cmt = r * G  AND  shared_point = r * dkg_pk  for some r
    ///
    /// ## What this DOES verify:
    /// - The mathematical relationship between enc_cmt and shared_point
    /// - That the encryptor knew the discrete log (randomness r)
    /// - Point validity (not identity, correct subgroup)
    ///
    /// ## What this does NOT verify:
    /// - That the ciphertext was actually encrypted using shared_point
    /// - Ciphertext integrity (that's verified at decrypt time via AES-GCM)
    ///
    /// The ciphertext binding is enforced via AAD in AES-GCM: if the wrong
    /// shared_point was used during encryption, decryption will fail with
    /// an authentication error.
    fn verify_encryption(
        dkg_pk: &Self::PublicKey,
        enc_cmt: &Self::PublicKey,
        proof: &EncryptionProof,
    ) -> Result<()> {
        // Validate enc_cmt from untrusted input
        if enc_cmt.is_zero() {
            return Err(CryptoError::ElGamalError(
                "Invalid enc_cmt: cannot be the identity element".to_string(),
            ));
        }
        if !enc_cmt.is_in_correct_subgroup_assuming_on_curve() {
            return Err(CryptoError::ElGamalError(
                "Invalid enc_cmt: not in correct subgroup".to_string(),
            ));
        }

        // Deserialize proof components
        let shared_point =
            G1Affine::deserialize_compressed(&proof.shared_point[..]).map_err(|e| {
                CryptoError::ElGamalError(format!("Failed to deserialize shared_point: {:?}", e))
            })?;

        // Validate shared_point is not the identity element and is in correct subgroup
        if shared_point.is_zero() {
            return Err(CryptoError::ElGamalError(
                "Invalid shared_point: cannot be the identity element".to_string(),
            ));
        }
        if !shared_point.is_in_correct_subgroup_assuming_on_curve() {
            return Err(CryptoError::ElGamalError(
                "Invalid shared_point: not in correct subgroup".to_string(),
            ));
        }

        let challenge = Fr::deserialize_compressed(&proof.challenge[..]).map_err(|e| {
            CryptoError::ElGamalError(format!("Failed to deserialize challenge: {:?}", e))
        })?;
        let response = Fr::deserialize_compressed(&proof.response[..]).map_err(|e| {
            CryptoError::ElGamalError(format!("Failed to deserialize response: {:?}", e))
        })?;

        // Verify: R1' = s*G - c*enc_cmt
        let r1_prime: G1Affine = (G1Projective::generator() * response
            - G1Projective::from(*enc_cmt) * challenge)
            .into();

        // Verify: R2' = s*dkg_pk - c*shared_point
        let r2_prime: G1Affine = (G1Projective::from(*dkg_pk) * response
            - G1Projective::from(shared_point) * challenge)
            .into();

        // Recompute challenge: c' = Hash(ENCRYPT_PROOF_DOMAIN, G, dkg_pk, enc_cmt, shared_point, R1', R2')
        let g = G1Affine::generator();
        let challenge_hash = Self::hash_encryption_proof_points(
            &g,
            dkg_pk,
            enc_cmt,
            &shared_point,
            &r1_prime,
            &r2_prime,
        )?;
        let recomputed_challenge = Fr::from_le_bytes_mod_order(&challenge_hash);

        // Compare challenges
        // Note: Fr field element comparison in arkworks is constant-time
        if challenge != recomputed_challenge {
            return Err(CryptoError::ElGamalError(
                "Encryption proof verification failed".to_string(),
            ));
        }

        Ok(())
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

        // Recover rsG (shared_point)
        // After correct re-encryption and recovery:
        // xnc_cmt = (x+r)*s*G, so rs_g = xnc_cmt - x*sG = r*sG = shared_point
        let xs_g = G1Projective::from(*dkg_pk) * rdr_sk; // xsG = x * sG
        let rs_g: G1Affine = (G1Projective::from(*xnc_cmt) - xs_g).into(); // rsG = shared_point

        // Derive AES key
        let aes_key = Self::derive_key_from_point(&rs_g)?;
        let cipher = Aes256Gcm::new(&aes_key.into());

        // Build AAD using centralized helper (must match encryption)
        let mut shared_point_bytes = Vec::new();
        rs_g.serialize_compressed(&mut shared_point_bytes)?;
        let aad = Self::build_aad(&secret.enc_cmt, &shared_point_bytes);

        // Decrypt with AAD to verify binding to commitment and shared point
        let nonce = Nonce::from_slice(&secret.nonce);
        let payload = Payload {
            msg: secret.encrypted_data.as_ref(),
            aad: &aad,
        };
        let plaintext = cipher.decrypt(nonce, payload).map_err(|_| {
            CryptoError::ElGamalError("Decryption failed - authentication failed".to_string())
        })?;

        Ok(plaintext)
    }
}

impl ThresholdDealerNode {
    /// Generate a new keypair for encryption/decryption (test-only).
    #[cfg(any(test, feature = "test-helpers"))]
    pub fn generate_keypair() -> (Fr, G1Affine) {
        let mut rng = OsRng;
        let sk = Fr::rand(&mut rng);
        let pk: G1Affine = (G1Projective::generator() * sk).into();
        (sk, pk)
    }

    /// Decompress a point from bytes and validate it's not the identity element
    fn decompress_point(bytes: &[u8]) -> Result<G1Affine> {
        let point = G1Affine::deserialize_compressed(bytes).map_err(|e| {
            CryptoError::ElGamalError(format!("failed to decompress point: {:?}", e))
        })?;

        // Verify point is not the identity element (security check)
        if point.is_zero() {
            return Err(CryptoError::ElGamalError(
                "Invalid point: cannot be the identity element".to_string(),
            ));
        }

        Ok(point)
    }

    fn reencrypt(
        dkg_ski: &Fr,
        rdr_pk: &G1Affine,
        enc_cmt: &G1Affine,
    ) -> Result<(G1Affine, Fr, Fr)> {
        // Validate inputs are not zero points
        if rdr_pk.is_zero() {
            return Err(CryptoError::ElGamalError(
                "Invalid reader public key: cannot be zero point".to_string(),
            ));
        }
        if enc_cmt.is_zero() {
            return Err(CryptoError::ElGamalError(
                "Invalid commitment: cannot be zero point".to_string(),
            ));
        }

        // Re-encrypted secret share (Ui)
        let xr_g = G1Projective::from(*rdr_pk) + G1Projective::from(*enc_cmt); // xrG = xG + rG
        let xnc_ski = (xr_g * dkg_ski).into(); // Ui = ski * (xG + rG)

        // Produce random oracle challenge (ei)
        // ei = Hash(Ui + UiHat + HiHat)
        let mut rng = OsRng;
        let ri = Fr::rand(&mut rng); // ri = Random scalar
        let ui_hat = (xr_g * ri).into(); // UiHat = ri * (xG + rG)
        let hi_hat = (G1Projective::generator() * ri).into(); // HiHat = ri * G

        let challenge_hash = Self::hash_reencrypt_proof_points(&[xnc_ski, ui_hat, hi_hat])?;
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
        let challenge_hash = Self::hash_reencrypt_proof_points(&[*dkg_ski, ui_hat, hi_hat])?;
        let chlg = Fr::from_le_bytes_mod_order(&challenge_hash);

        // Verify local challenge using constant-time comparison
        // Fr serializes to exactly 32 bytes for BLS12-381
        let mut chlg_bytes = [0u8; 32];
        let mut chlgi_bytes = [0u8; 32];
        chlg.serialize_compressed(&mut &mut chlg_bytes[..])
            .map_err(|e| CryptoError::ElGamalError(format!("Serialization error: {:?}", e)))?;
        chlgi
            .serialize_compressed(&mut &mut chlgi_bytes[..])
            .map_err(|e| CryptoError::ElGamalError(format!("Serialization error: {:?}", e)))?;

        // Constant-time comparison
        if chlg_bytes.ct_ne(&chlgi_bytes).into() {
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

        // Validate all share indices are distinct
        let mut seen_indices = HashSet::new();
        for share in shares_to_use {
            let idx = share.i;

            // Validate index is in valid range [1, n]
            if idx < 1 || idx > n as u32 {
                return Err(CryptoError::ElGamalError(format!(
                    "Invalid share index: {} (must be in range [1, {}])",
                    idx, n
                )));
            }

            // Check for duplicates
            if !seen_indices.insert(idx) {
                return Err(CryptoError::ElGamalError(format!(
                    "Duplicate share index: {}",
                    idx
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

    /// Hash multiple points together with domain separation
    fn hash_reencrypt_proof_points(points: &[G1Affine]) -> Result<[u8; 32]> {
        let mut hasher = Sha256::new();

        // Add domain separation to prevent cross-protocol attacks
        hasher.update(PROTOCOL);

        // Reuse buffer to avoid allocating for each point
        // Compressed G1 points are 48 bytes
        let mut bytes = Vec::with_capacity(48);
        for point in points {
            bytes.clear();
            point.serialize_compressed(&mut bytes)?;
            hasher.update(&bytes);
        }

        let result = hasher.finalize();
        let mut output = [0u8; 32];
        output.copy_from_slice(&result);

        Ok(output)
    }

    /// Build AAD (Additional Authenticated Data) for AES-GCM encryption/decryption.
    ///
    /// AAD format: H(AAD_DOMAIN || enc_cmt || shared_point)
    ///
    /// This binds the ciphertext to both the ElGamal commitment and the shared point,
    /// ensuring that:
    /// 1. The ciphertext cannot be transplanted to a different commitment
    /// 2. The shared_point used for key derivation matches what's in the proof
    ///
    /// Using a hash ensures consistent length and provides domain separation.
    fn build_aad(enc_cmt_bytes: &[u8], shared_point_bytes: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(AAD_DOMAIN);
        hasher.update(enc_cmt_bytes);
        hasher.update(shared_point_bytes);
        let result = hasher.finalize();
        let mut output = [0u8; 32];
        output.copy_from_slice(&result);
        output
    }

    /// Derive AES key from elliptic curve point
    pub fn derive_key_from_point(point: &G1Affine) -> Result<[u8; 32]> {
        let mut point_bytes = Vec::new();
        point.serialize_compressed(&mut point_bytes)?;

        let hkdf = Hkdf::<Sha256>::new(None, &point_bytes);
        let mut key = [0u8; 32];
        hkdf.expand(b"elgamal-aes-key-v1", &mut key)
            .map_err(|_| CryptoError::ElGamalError("HKDF expansion failed".to_string()))?;

        Ok(key)
    }

    /// Generate Chaum-Pedersen NIZK proof for encryption
    /// Proves that enc_cmt = r*G and shared_point = r*dkg_pk use the same randomness r
    fn generate_encryption_proof(
        r: &Fr,
        dkg_pk: &G1Affine,
        enc_cmt: &G1Affine,
        shared_point: &G1Affine,
    ) -> Result<(Fr, Fr)> {
        let mut rng = OsRng;

        // 1. k ← random scalar
        let k = Fr::rand(&mut rng);

        // 2. R1 = k * G, R2 = k * dkg_pk
        let r1: G1Affine = (G1Projective::generator() * k).into();
        let r2: G1Affine = (G1Projective::from(*dkg_pk) * k).into();

        // 3. c = Hash(ENCRYPT_PROOF_DOMAIN, G, dkg_pk, enc_cmt, shared_point, R1, R2)
        let g = G1Affine::generator();
        let challenge_hash =
            Self::hash_encryption_proof_points(&g, dkg_pk, enc_cmt, shared_point, &r1, &r2)?;
        let c = Fr::from_le_bytes_mod_order(&challenge_hash);

        // 4. s = k + c * r
        let s = k + (c * r);

        // 5. Output: (c, s)
        Ok((c, s))
    }

    /// Hash points for encryption proof with domain separation
    fn hash_encryption_proof_points(
        g: &G1Affine,
        dkg_pk: &G1Affine,
        enc_cmt: &G1Affine,
        shared_point: &G1Affine,
        r1: &G1Affine,
        r2: &G1Affine,
    ) -> Result<[u8; 32]> {
        let mut hasher = Sha256::new();

        // Add domain separation
        hasher.update(ENCRYPT_PROOF_DOMAIN);

        // Serialize and hash all points
        let mut bytes = Vec::with_capacity(48);
        for point in &[g, dkg_pk, enc_cmt, shared_point, r1, r2] {
            bytes.clear();
            point.serialize_compressed(&mut bytes)?;
            hasher.update(&bytes);
        }

        let result = hasher.finalize();
        let mut output = [0u8; 32];
        output.copy_from_slice(&result);

        Ok(output)
    }
}
