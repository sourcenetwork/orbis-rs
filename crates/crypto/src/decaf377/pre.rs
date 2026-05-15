use super::common::{PubPoly, ELEMENT_COMPRESSED_SIZE, FR_COMPRESSED_SIZE};
use crate::{
    error::{CryptoError, Result},
    r#trait::{
        CryptoDeserialize, DistKeyShare, EncryptionProof, PubPoly as PubPolyTrait, PubShare,
        ReencryptReply, Secret, ThresholdDealer,
    },
};
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use ark_ff::{BigInteger, One, PrimeField, Zero};
use ark_serialize::CanonicalSerialize;
use ark_std::{collections::HashSet, vec::Vec};
use decaf377::{Element, Fq, Fr};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

const NAME: &str = "elgamal/decaf377";

const ENCRYPT_PROOF_DOMAIN: &[u8; 24] = b"elgamal-encrypt-proof-v1";
const PROTOCOL: &[u8; 30] = b"elgamal-reencrypt-challenge-v1";
const AAD_DOMAIN: &[u8; 15] = b"elgamal-aad-v1\0";
const DERIVATION_DOMAIN: &[u8; 23] = b"elgamal-derivation-v1\0\0";
const POLICY_METADATA_DOMAIN: &[u8] = b"orbis-policy-metadata-v1";

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

    fn name() -> String {
        NAME.to_string()
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

        // Reject zero derivation scalar (same as encrypt_secret)
        if let Some(ref d) = derivation_scalar {
            if *d == Fr::zero() {
                return Err(CryptoError::ElGamalError(
                    "Derivation produced zero scalar: use different derivation bytes".to_string(),
                ));
            }
        }

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

        // Compute the effective public key if derivation is provided.
        let effective_pk = if let Some(deriv_bytes) = derivation {
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
            derived_pk
        } else {
            *dkg_pk
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
        effective_pk: &Self::PublicKey,
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

        // Validate the caller-supplied effective public key.
        if *effective_pk == Element::default() {
            return Err(CryptoError::ElGamalError(
                "Invalid effective_pk: cannot be the identity element".to_string(),
            ));
        }

        // Deserialize proof components
        if proof.shared_point.len() != ELEMENT_COMPRESSED_SIZE {
            return Err(CryptoError::ElGamalError(format!(
                "Invalid shared_point length: expected {}, got {}",
                ELEMENT_COMPRESSED_SIZE,
                proof.shared_point.len()
            )));
        }
        let shared_point = Element::from_bytes(&proof.shared_point[..]).map_err(|e| {
            CryptoError::ElGamalError(format!("Failed to deserialize shared_point: {:?}", e))
        })?;

        // Validate shared_point is not the identity element
        if shared_point == Element::default() {
            return Err(CryptoError::ElGamalError(
                "Invalid shared_point: cannot be the identity element".to_string(),
            ));
        }

        if proof.challenge.len() != FR_COMPRESSED_SIZE {
            return Err(CryptoError::ElGamalError(format!(
                "Invalid challenge length: expected {}, got {}",
                FR_COMPRESSED_SIZE,
                proof.challenge.len()
            )));
        }
        let challenge = Fr::from_bytes(&proof.challenge[..]).map_err(|e| {
            CryptoError::ElGamalError(format!("Failed to deserialize challenge: {:?}", e))
        })?;
        if proof.response.len() != FR_COMPRESSED_SIZE {
            return Err(CryptoError::ElGamalError(format!(
                "Invalid response length: expected {}, got {}",
                FR_COMPRESSED_SIZE,
                proof.response.len()
            )));
        }
        let response = Fr::from_bytes(&proof.response[..]).map_err(|e| {
            CryptoError::ElGamalError(format!("Failed to deserialize response: {:?}", e))
        })?;

        // Verify: R1' = s*G - c*enc_cmt
        let r1_prime = Element::GENERATOR * response - *enc_cmt * challenge;

        // Verify: R2' = s*effective_pk - c*shared_point
        let r2_prime = *effective_pk * response - shared_point * challenge;

        // Recompute challenge
        let metadata_arr: Option<[u8; 32]> = metadata
            .map(|m| {
                m.try_into().map_err(|_| {
                    CryptoError::ElGamalError("Metadata must be exactly 32 bytes".to_string())
                })
            })
            .transpose()?;
        let g = Element::GENERATOR;
        let recomputed_challenge = Self::hash_encryption_proof_points(
            &g,
            effective_pk,
            enc_cmt,
            &shared_point,
            &r1_prime,
            &r2_prime,
            metadata_arr.as_ref(),
        )?;

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

    fn derive_key_from_point(point: &Self::PublicKey) -> Result<[u8; 32]> {
        ThresholdDealerNode::derive_key_from_point(point)
    }

    fn encode_metadata(
        policy_id: &str,
        resource: &str,
        permission: &str,
        tier: Option<&str>,
        timestamp: Option<u64>,
        salt: Option<&str>,
    ) -> Vec<u8> {
        let domain = Fq::from_le_bytes_mod_order(POLICY_METADATA_DOMAIN);

        let ts_le = timestamp.map(|t| t.to_le_bytes());
        let ts_bytes: &[u8] = ts_le.as_ref().map_or(&[], |b| b.as_slice());

        // Each field is encoded as: Fq(len) followed by 31-byte chunks (each fits in Fq without reduction)
        let mut inputs: Vec<Fq> = Vec::new();
        for field in &[
            policy_id.as_bytes(),
            resource.as_bytes(),
            permission.as_bytes(),
            tier.unwrap_or("").as_bytes(),
            ts_bytes,
            salt.unwrap_or("").as_bytes(),
        ] {
            inputs.push(Fq::from(field.len() as u64));
            for chunk in field.chunks(31) {
                inputs.push(Fq::from_le_bytes_mod_order(chunk));
            }
        }

        // Sequential Poseidon chain: each step absorbs a pair of inputs
        let mut state = domain;
        for pair in inputs.chunks(2) {
            if pair.len() == 2 {
                state = poseidon377::hash_2(&state, (pair[0], pair[1]));
            } else {
                state = poseidon377::hash_1(&state, pair[0]);
            }
        }

        // Return LE bytes of the Fq result — 32 bytes, suitable for use as a
        // single Fq element in hash_encryption_proof_points
        state.into_bigint().to_bytes_le()
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
        if bytes.len() != ELEMENT_COMPRESSED_SIZE {
            return Err(CryptoError::ElGamalError(format!(
                "Invalid point length: expected {}, got {}",
                ELEMENT_COMPRESSED_SIZE,
                bytes.len()
            )));
        }
        let point = Element::from_bytes(bytes).map_err(|e| {
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

    /// Serialize a curve point to an Fq element for use as Poseidon input.
    ///
    /// Compressed decaf377 points are 32 bytes and encode a valid Fq representative,
    /// so from_le_bytes_mod_order performs no actual modular reduction here.
    fn point_to_fq(point: &Element) -> Result<Fq> {
        let mut bytes = Vec::with_capacity(32);
        point.serialize_compressed(&mut bytes)?;
        Ok(Fq::from_le_bytes_mod_order(&bytes))
    }

    /// Truncate a Poseidon output (Fq) to a Fiat-Shamir challenge scalar (Fr).
    ///
    /// Masks the top bits of the Fq element so the result is in [0, 2^{r-1}),
    /// which is strictly less than the Fr modulus. This avoids an in-circuit
    /// modular reduction (just bit wiring vs range check + subtraction).
    fn fq_to_challenge_scalar(fq: Fq) -> Fr {
        let mut bytes = fq.into_bigint().to_bytes_le();
        let keep_bits = Fr::MODULUS_BIT_SIZE - 1;
        let keep_bytes = (keep_bits as usize + 7) / 8;
        let spare_bits = keep_bytes * 8 - keep_bits as usize;
        bytes[keep_bytes - 1] &= 0xFF >> spare_bits;
        Fr::from_le_bytes_mod_order(&bytes)
    }

    /// Hash re-encryption proof with all public inputs bound into the challenge.
    ///
    /// Binds: PROTOCOL domain, share index, reader public key, encryption commitment,
    /// effective DKG commitment (with derivation applied), and the proof points
    /// (xnc_ski, UiHat, HiHat). This prevents proof replay across different
    /// ciphertexts, readers, DKG sessions, or share indices.
    ///
    /// Re-encryption is entirely off-circuit, so SHA256 is used here.
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
        hasher.update(idx.to_le_bytes());

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
        let metadata_arr: Option<[u8; 32]> = metadata
            .map(|m| {
                m.try_into().map_err(|_| {
                    CryptoError::ElGamalError("Metadata must be exactly 32 bytes".to_string())
                })
            })
            .transpose()?;

        let mut rng = OsRng;

        // 1. k ← random scalar
        let k = Fr::rand(&mut rng);

        // 2. R1 = k * G, R2 = k * dkg_pk
        let r1 = Element::GENERATOR * k;
        let r2 = *dkg_pk * k;

        // 3. c = Hash(ENCRYPT_PROOF_DOMAIN, G, dkg_pk, enc_cmt, shared_point, R1, R2)
        let g = Element::GENERATOR;
        let c = Self::hash_encryption_proof_points(
            &g,
            dkg_pk,
            enc_cmt,
            shared_point,
            &r1,
            &r2,
            metadata_arr.as_ref(),
        )?;

        // 4. s = k + c * r
        let s = k + (c * r);

        Ok((c, s))
    }

    /// Hash points for encryption proof with domain separation.
    ///
    /// Uses Poseidon377 so the verifier can be expressed efficiently inside a
    /// Groth16/BLS12-377 circuit. Metadata (if present) must be the output of
    /// `encode_metadata` — 32 bytes encoding a Poseidon Fq hash of the policy
    /// fields. It is absorbed as a single native Fq element in `hash_7`.
    fn hash_encryption_proof_points(
        g: &Element,
        dkg_pk: &Element,
        enc_cmt: &Element,
        shared_point: &Element,
        r1: &Element,
        r2: &Element,
        metadata_option: Option<&[u8; 32]>,
    ) -> Result<Fr> {
        // None  → Fq::zero() (no-metadata sentinel)
        // Some  → interpret bytes as a Fq element (output of encode_metadata)
        let meta_fq: Fq = match metadata_option {
            None => Fq::zero(),
            Some(metadata) => Fq::from_le_bytes_mod_order(metadata),
        };

        let domain = Fq::from_le_bytes_mod_order(ENCRYPT_PROOF_DOMAIN);
        let g_fq = Self::point_to_fq(g)?;
        let dkg_pk_fq = Self::point_to_fq(dkg_pk)?;
        let enc_cmt_fq = Self::point_to_fq(enc_cmt)?;
        let shared_point_fq = Self::point_to_fq(shared_point)?;
        let r1_fq = Self::point_to_fq(r1)?;
        let r2_fq = Self::point_to_fq(r2)?;

        let result = poseidon377::hash_7(
            &domain,
            (
                meta_fq,
                g_fq,
                dkg_pk_fq,
                enc_cmt_fq,
                shared_point_fq,
                r1_fq,
                r2_fq,
            ),
        );

        Ok(Self::fq_to_challenge_scalar(result))
    }
}
