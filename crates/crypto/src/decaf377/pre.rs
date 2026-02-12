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
use ark_ff::{One, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{collections::HashSet, vec::Vec};
use decaf377::{Element, Fr};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

const NAME: &str = "elgamal/decaf377";

const ENCRYPT_PROOF_DOMAIN: &[u8; 24] = b"elgamal-encrypt-proof-v1";
const PROTOCOL: &[u8; 30] = b"elgamal-reencrypt-challenge-v1";
const AAD_DOMAIN: &[u8; 15] = b"elgamal-aad-v1\0";
const DERIVATION_DOMAIN: &[u8; 23] = b"elgamal-derivation-v1\0\0";

#[derive(Clone, Debug)]
pub struct ThresholdDealerNode {}

impl ThresholdDealer for ThresholdDealerNode {
    type ShareValue = Fr;
    type PublicKey = Element;
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
        derivation: Option<&[u8]>,
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

        // Compute derivation scalar if provided
        let derivation_scalar = derivation.map(Self::derive_capability_scalar);

        // Compute re-encrypted share with optional derivation
        let (xnc_ski, chlgi, proofi) =
            Self::reencrypt_internal(idx, &ski, rdr_pk, &enc_cmt, derivation_scalar)?;

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
        derivation: Option<&[u8]>,
    ) -> Result<()> {
        let xnc_ski = reply.share.v;
        let idx = reply.share.i;
        let dkg_cmt_eval = dkg_cmt.eval(idx);

        // If derivation is provided, apply it to the commitment for verification
        let effective_cmt = if let Some(deriv_bytes) = derivation {
            let d = Self::derive_capability_scalar(deriv_bytes);
            dkg_cmt_eval * d
        } else {
            dkg_cmt_eval
        };

        Self::verify_internal(
            idx,
            rdr_pk,
            enc_cmt,
            &xnc_ski,
            &reply.challenge,
            &reply.proof,
            &effective_cmt,
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
        derivation: Option<&[u8]>,
        metadata: Option<&[u8]>,
    ) -> Result<(Self::PublicKey, Self::Secret, EncryptionProof)> {
        // Validate dkg_pk is not the identity element
        if *dkg_pk == Element::default() {
            return Err(CryptoError::ElGamalError(
                "Invalid dkg_pk: cannot be the identity element".to_string(),
            ));
        }
        // decaf377: No subgroup check needed — the decaf construction guarantees
        // all deserialized points are in the prime-order group.

        let mut rng = OsRng;
        // Generate random non-zero r to avoid identity commitment and fixed AES key
        let r = loop {
            let candidate = Fr::rand(&mut rng);
            if candidate != Fr::zero() {
                break candidate;
            }
        };
        let enc_cmt = Element::GENERATOR * r; // rG

        // Compute derived public key if derivation is provided
        let (effective_pk, derived_pk_bytes) = if let Some(deriv_bytes) = derivation {
            let d = Self::derive_capability_scalar(deriv_bytes);
            if d == Fr::zero() {
                return Err(CryptoError::ElGamalError(
                    "Derivation produced zero scalar: use different derivation bytes".to_string(),
                ));
            }
            let derived_pk = *dkg_pk * d;
            if derived_pk == Element::default() {
                return Err(CryptoError::ElGamalError(
                    "Derived public key is the identity element".to_string(),
                ));
            }
            let mut bytes = Vec::new();
            derived_pk.serialize_compressed(&mut bytes)?;
            (derived_pk, Some(bytes))
        } else {
            (*dkg_pk, None)
        };

        // shared_point = r * effective_pk
        let shared_point = effective_pk * r;

        // Generate Chaum-Pedersen NIZK proof
        let (challenge, response) =
            Self::generate_encryption_proof(&r, &effective_pk, &enc_cmt, &shared_point, metadata)?;

        // Serialize proof components
        let mut shared_point_bytes = Vec::new();
        shared_point.serialize_compressed(&mut shared_point_bytes)?;
        let mut challenge_bytes = Vec::new();
        challenge.serialize_compressed(&mut challenge_bytes)?;
        let mut response_bytes = Vec::new();
        response.serialize_compressed(&mut response_bytes)?;

        let proof = EncryptionProof {
            shared_point: shared_point_bytes.clone(),
            challenge: challenge_bytes,
            response: response_bytes,
            derived_pk: derived_pk_bytes,
        };

        // Derive AES key from shared_point
        let aes_key = Self::derive_key_from_point(&shared_point)?;
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
            },
            proof,
        ))
    }

    fn verify_encryption(
        dkg_pk: &Self::PublicKey,
        enc_cmt: &Self::PublicKey,
        proof: &EncryptionProof,
        metadata: Option<&[u8]>,
    ) -> Result<()> {
        // Validate enc_cmt from untrusted input
        if *enc_cmt == Element::default() {
            return Err(CryptoError::ElGamalError(
                "Invalid enc_cmt: cannot be the identity element".to_string(),
            ));
        }
        // decaf377: No subgroup check needed.

        // Get effective public key from proof (derived_pk if present, otherwise dkg_pk)
        let effective_pk = if let Some(ref derived_pk_bytes) = proof.derived_pk {
            let derived_pk =
                Element::deserialize_compressed(&derived_pk_bytes[..]).map_err(|e| {
                    CryptoError::ElGamalError(format!("Failed to deserialize derived_pk: {:?}", e))
                })?;
            // Validate derived_pk
            if derived_pk == Element::default() {
                return Err(CryptoError::ElGamalError(
                    "Invalid derived_pk: cannot be the identity element".to_string(),
                ));
            }
            derived_pk
        } else {
            *dkg_pk
        };

        // Deserialize proof components
        let shared_point =
            Element::deserialize_compressed(&proof.shared_point[..]).map_err(|e| {
                CryptoError::ElGamalError(format!("Failed to deserialize shared_point: {:?}", e))
            })?;

        // Validate shared_point is not the identity element
        if shared_point == Element::default() {
            return Err(CryptoError::ElGamalError(
                "Invalid shared_point: cannot be the identity element".to_string(),
            ));
        }

        let challenge = Fr::deserialize_compressed(&proof.challenge[..]).map_err(|e| {
            CryptoError::ElGamalError(format!("Failed to deserialize challenge: {:?}", e))
        })?;
        let response = Fr::deserialize_compressed(&proof.response[..]).map_err(|e| {
            CryptoError::ElGamalError(format!("Failed to deserialize response: {:?}", e))
        })?;

        // Verify: R1' = s*G - c*enc_cmt
        let r1_prime = Element::GENERATOR * response - *enc_cmt * challenge;

        // Verify: R2' = s*effective_pk - c*shared_point
        let r2_prime = effective_pk * response - shared_point * challenge;

        // Recompute challenge
        let g = Element::GENERATOR;
        let challenge_hash = Self::hash_encryption_proof_points(
            &g,
            &effective_pk,
            enc_cmt,
            &shared_point,
            &r1_prime,
            &r2_prime,
            metadata,
        )?;
        let recomputed_challenge = Fr::from_le_bytes_mod_order(&challenge_hash);

        // Compare challenges using constant-time comparison
        let mut challenge_bytes = [0u8; 32];
        let mut recomputed_bytes = [0u8; 32];
        challenge
            .serialize_compressed(&mut &mut challenge_bytes[..])
            .map_err(|e| CryptoError::ElGamalError(format!("Serialization error: {:?}", e)))?;
        recomputed_challenge
            .serialize_compressed(&mut &mut recomputed_bytes[..])
            .map_err(|e| CryptoError::ElGamalError(format!("Serialization error: {:?}", e)))?;

        if challenge_bytes.ct_ne(&recomputed_bytes).into() {
            return Err(CryptoError::ElGamalError(
                "Encryption proof verification failed".to_string(),
            ));
        }

        Ok(())
    }

    fn decrypt_secret(
        effective_pk: &Self::PublicKey,
        xnc_cmt: &Self::PublicKey,
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

        // Recover shared_point from re-encryption result
        // shared_point = xnc_cmt - rdr_sk * effective_pk
        let xs_g = *effective_pk * rdr_sk;
        let shared_point = *xnc_cmt - xs_g;

        // Derive AES key
        let aes_key = Self::derive_key_from_point(&shared_point)?;
        let cipher = Aes256Gcm::new(&aes_key.into());

        // Build AAD using centralized helper (must match encryption)
        let mut shared_point_bytes = Vec::new();
        shared_point.serialize_compressed(&mut shared_point_bytes)?;
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

    fn derive_public_key(dkg_pk: &Self::PublicKey, derivation: &[u8]) -> Result<Self::PublicKey> {
        let d = Self::derive_capability_scalar(derivation);
        let derived_pk = *dkg_pk * d;
        Ok(derived_pk)
    }
}

impl ThresholdDealerNode {
    /// Generate a new keypair for encryption/decryption (test-only).
    #[cfg(any(test, feature = "test-helpers"))]
    pub fn generate_keypair() -> (Fr, Element) {
        let mut rng = OsRng;
        let sk = Fr::rand(&mut rng);
        let pk = Element::GENERATOR * sk;
        (sk, pk)
    }

    /// Derive a capability scalar from derivation bytes.
    fn derive_capability_scalar(derivation: &[u8]) -> Fr {
        let mut hasher = Sha256::new();
        hasher.update(DERIVATION_DOMAIN);
        hasher.update(derivation);
        let hash = hasher.finalize();
        Fr::from_le_bytes_mod_order(&hash)
    }

    /// Decompress a point from bytes and validate it's a valid curve point
    fn decompress_point(bytes: &[u8]) -> Result<Element> {
        let point = Element::deserialize_compressed(bytes).map_err(|e| {
            CryptoError::ElGamalError(format!("failed to decompress point: {:?}", e))
        })?;

        // Verify point is not the identity element (security check)
        if point == Element::default() {
            return Err(CryptoError::ElGamalError(
                "Invalid point: cannot be the identity element".to_string(),
            ));
        }

        // decaf377: No subgroup check needed — the decaf construction guarantees
        // all deserialized points are in the prime-order group.

        Ok(point)
    }

    /// Internal re-encryption with optional derivation scalar.
    fn reencrypt_internal(
        idx: u32,
        dkg_ski: &Fr,
        rdr_pk: &Element,
        enc_cmt: &Element,
        derivation_scalar: Option<Fr>,
    ) -> Result<(Element, Fr, Fr)> {
        // Validate inputs are not identity points
        if *rdr_pk == Element::default() {
            return Err(CryptoError::ElGamalError(
                "Invalid reader public key: cannot be zero point".to_string(),
            ));
        }
        if *enc_cmt == Element::default() {
            return Err(CryptoError::ElGamalError(
                "Invalid commitment: cannot be zero point".to_string(),
            ));
        }

        // Apply derivation scalar if provided
        let effective_ski = match derivation_scalar {
            Some(d) => d * dkg_ski,
            None => *dkg_ski,
        };

        // Re-encrypted secret share: Ui = effective_ski * (xG + rG)
        let xr_g = *rdr_pk + *enc_cmt;
        let xnc_ski = xr_g * effective_ski;

        // Compute effective commitment for binding into challenge hash
        let effective_cmt = Element::GENERATOR * effective_ski;

        // Produce random oracle challenge
        // ei = Hash(PROTOCOL, idx, rdr_pk, enc_cmt, effective_cmt, Ui, UiHat, HiHat)
        let mut rng = OsRng;
        let ri = Fr::rand(&mut rng);
        let ui_hat = xr_g * ri;
        let hi_hat = Element::GENERATOR * ri;

        let challenge_hash = Self::hash_reencrypt_proof_points(
            idx,
            rdr_pk,
            enc_cmt,
            &effective_cmt,
            &[xnc_ski, ui_hat, hi_hat],
        )?;
        let chlgi = Fr::from_le_bytes_mod_order(&challenge_hash);

        // Produce NIZK proof: fi = ri + ei * effective_ski
        let proofi = ri + (chlgi * effective_ski);

        Ok((xnc_ski, chlgi, proofi))
    }

    /// Internal verification of re-encryption proof.
    fn verify_internal(
        idx: u32,
        rdr_pk: &Element,
        enc_cmt: &Element,
        xnc_ski: &Element,
        chlgi: &Fr,
        proofi: &Fr,
        effective_cmt: &Element,
    ) -> Result<()> {
        // Reconstruct UiHat = fi * (xG + rG) - ei * Ui
        let xr_g = *rdr_pk + *enc_cmt;
        let fi_xr_g = xr_g * proofi;
        let ei_ui = *xnc_ski * chlgi;
        let ui_hat = fi_xr_g - ei_ui;

        // Reconstruct HiHat = fi * G - ei * effective_cmt
        let fi_g = Element::GENERATOR * proofi;
        let ei_ci = *effective_cmt * chlgi;
        let hi_hat = fi_g - ei_ci;

        // Reconstruct random oracle challenge
        // ei = Hash(PROTOCOL, idx, rdr_pk, enc_cmt, effective_cmt, Ui, UiHat, HiHat)
        let challenge_hash = Self::hash_reencrypt_proof_points(
            idx,
            rdr_pk,
            enc_cmt,
            effective_cmt,
            &[*xnc_ski, ui_hat, hi_hat],
        )?;
        let chlg = Fr::from_le_bytes_mod_order(&challenge_hash);

        // Verify using constant-time comparison
        let mut chlg_bytes = [0u8; 32];
        let mut chlgi_bytes = [0u8; 32];
        chlg.serialize_compressed(&mut &mut chlg_bytes[..])
            .map_err(|e| CryptoError::ElGamalError(format!("Serialization error: {:?}", e)))?;
        chlgi
            .serialize_compressed(&mut &mut chlgi_bytes[..])
            .map_err(|e| CryptoError::ElGamalError(format!("Serialization error: {:?}", e)))?;

        if chlg_bytes.ct_ne(&chlgi_bytes).into() {
            return Err(CryptoError::ElGamalError(
                "Cryptographic verification failed".to_string(),
            ));
        }

        Ok(())
    }

    fn recover_commit(shares: &[PubShare<Element>], t: usize, n: usize) -> Result<Option<Element>> {
        let shares_to_use = &shares[..t];

        // Validate all share indices are distinct
        let mut seen_indices = HashSet::new();
        for share in shares_to_use {
            let idx = share.i;

            if idx < 1 || idx > n as u32 {
                return Err(CryptoError::ElGamalError(format!(
                    "Invalid share index: {} (must be in range [1, {}])",
                    idx, n
                )));
            }

            if !seen_indices.insert(idx) {
                return Err(CryptoError::ElGamalError(format!(
                    "Duplicate share index: {}",
                    idx
                )));
            }
        }

        let mut result = Element::default();

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

            let lambda = num
                * den.inverse().ok_or_else(|| {
                    CryptoError::ElGamalError(
                        "Division by zero in Lagrange interpolation - this should not happen after validation".to_string(),
                    )
                })?;
            result += share_i.v * lambda;
        }

        Ok(Some(result))
    }

    /// Hash re-encryption proof with all public inputs bound into the challenge.
    ///
    /// Binds: PROTOCOL domain, share index, reader public key, encryption commitment,
    /// effective DKG commitment (with derivation applied), and the proof points
    /// (xnc_ski, UiHat, HiHat). This prevents proof replay across different
    /// ciphertexts, readers, DKG sessions, or share indices.
    fn hash_reencrypt_proof_points(
        idx: u32,
        rdr_pk: &Element,
        enc_cmt: &Element,
        effective_cmt: &Element,
        proof_points: &[Element],
    ) -> Result<[u8; 32]> {
        let mut hasher = Sha256::new();

        // Add domain separation to prevent cross-protocol attacks
        hasher.update(PROTOCOL);

        // Bind share index
        hasher.update(&idx.to_le_bytes());

        // Serialize and hash all public inputs then proof points
        // Compressed decaf377 points are 32 bytes
        let mut bytes = Vec::with_capacity(32);
        for point in [rdr_pk, enc_cmt, effective_cmt] {
            bytes.clear();
            point.serialize_compressed(&mut bytes)?;
            hasher.update(&bytes);
        }
        for point in proof_points {
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
    pub fn derive_key_from_point(point: &Element) -> Result<[u8; 32]> {
        let mut point_bytes = Vec::new();
        point.serialize_compressed(&mut point_bytes)?;

        let hkdf = Hkdf::<Sha256>::new(None, &point_bytes);
        let mut key = [0u8; 32];
        hkdf.expand(b"elgamal-aes-key-v1", &mut key)
            .map_err(|_| CryptoError::ElGamalError("HKDF expansion failed".to_string()))?;

        Ok(key)
    }

    /// Generate Chaum-Pedersen NIZK proof for encryption
    fn generate_encryption_proof(
        r: &Fr,
        dkg_pk: &Element,
        enc_cmt: &Element,
        shared_point: &Element,
        metadata: Option<&[u8]>,
    ) -> Result<(Fr, Fr)> {
        let mut rng = OsRng;

        // 1. k ← random scalar
        let k = Fr::rand(&mut rng);

        // 2. R1 = k * G, R2 = k * dkg_pk
        let r1 = Element::GENERATOR * k;
        let r2 = *dkg_pk * k;

        // 3. c = Hash(ENCRYPT_PROOF_DOMAIN, G, dkg_pk, enc_cmt, shared_point, R1, R2)
        let g = Element::GENERATOR;
        let challenge_hash = Self::hash_encryption_proof_points(
            &g,
            dkg_pk,
            enc_cmt,
            shared_point,
            &r1,
            &r2,
            metadata,
        )?;
        let c = Fr::from_le_bytes_mod_order(&challenge_hash);

        // 4. s = k + c * r
        let s = k + (c * r);

        Ok((c, s))
    }

    /// Hash points for encryption proof with domain separation
    fn hash_encryption_proof_points(
        g: &Element,
        dkg_pk: &Element,
        enc_cmt: &Element,
        shared_point: &Element,
        r1: &Element,
        r2: &Element,
        metadata_option: Option<&[u8]>,
    ) -> Result<[u8; 32]> {
        let mut hasher = Sha256::new();

        // Add domain separation
        hasher.update(ENCRYPT_PROOF_DOMAIN);

        if let Some(metadata) = metadata_option {
            hasher.update(&(metadata.len() as u64).to_le_bytes());
            hasher.update(metadata);
        }

        // Serialize and hash all points (32 bytes each for decaf377)
        let mut bytes = Vec::with_capacity(32);
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
