use super::common::{Element, Fr, PubPoly, ELEMENT_COMPRESSED_SIZE, FR_COMPRESSED_SIZE};
use crate::{
    context::{self, CiphertextContext, ReaderAuthorizationContext},
    error::{CryptoError, Result},
    r#trait::{
        CryptoDeserialize, DistKeyShare, EncryptionProof, PubPoly as PubPolyTrait, PubShare,
        ReaderAuthorizationSignature, ReencryptReply, Secret, ThresholdDealer,
    },
};
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use blake2::Blake2b512;
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256, Sha512};
use std::collections::HashSet;
use subtle::ConstantTimeEq;

const NAME: &str = "elgamal/jubjub";

const PROTOCOL: &[u8] = b"elgamal-jubjub-reencrypt-challenge-v1";
const DERIVATION_DOMAIN: &[u8] = b"elgamal-jubjub-derivation-v1";
/// Domain separator for the encryption proof's Fiat-Shamir challenge.
const POLICY_BINDING_PROOF_DOMAIN: &[u8] = b"orbis-jubjub-policy-binding-proof-v1";
/// Domain separator for the reader-authorization signature's Fiat-Shamir
/// challenge. Distinct from the retired `READER_POP_DOMAIN` ("...-pop-proof-v1")
/// so a legacy, request-unbound proof can never be mistaken for one of these.
const READER_AUTHORIZATION_DOMAIN: &[u8] = b"orbis-jubjub-reader-authorization-v1";

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
        context: &ReaderAuthorizationContext,
        signature: &ReaderAuthorizationSignature,
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

        // Reject any rdr_pk the caller cannot prove knowledge of, or any
        // signature not bound to this exact request — see
        // `ReaderAuthorizationSignature`'s docs for why both are required
        // (xnc_ski = ski*(rdr_pk + enc_cmt) is otherwise linear and
        // unauthenticated in rdr_pk, and a context-free proof is replayable
        // across requests).
        Self::verify_reader_authorization(rdr_pk, context, signature)?;

        // Unmarshal the commitment
        let enc_cmt = Self::decompress_point(&scrt.enc_cmt)?;

        // Compute derivation scalar if provided — read from the signed
        // context, not a separate parameter, so "context says derivation X
        // but the share is computed under derivation Y" is structurally
        // impossible rather than merely checked.
        let derivation_scalar = context
            .derivation
            .as_deref()
            .map(Self::derive_capability_scalar);

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
        context: &CiphertextContext,
    ) -> Result<(Self::PublicKey, Self::Secret, EncryptionProof)> {
        // Validate dkg_pk is not the identity element
        if *dkg_pk == Element::default() {
            return Err(CryptoError::ElGamalError(
                "Invalid dkg_pk: cannot be the identity element".to_string(),
            ));
        }
        // `Element` wraps Jubjub's prime-order subgroup; decoding validates
        // canonical encoding and subgroup membership.

        let mut rng = OsRng;
        // Generate random non-zero r to avoid identity commitment and fixed AES key
        let r = loop {
            let candidate = Fr::rand(&mut rng);
            if candidate != Fr::zero() {
                break candidate;
            }
        };
        let enc_cmt = Element::generator() * r; // U = rG

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

        // KEM shared point V = r * effective_pk. Never serialized.
        let shared_point = effective_pk * r;
        let aes_key = Self::derive_key_from_point(&shared_point)?;
        let cipher = Aes256Gcm::new(&aes_key.into());

        // Serialize commitment U.
        let mut enc_cmt_bytes = Vec::new();
        enc_cmt.write_bytes(&mut enc_cmt_bytes)?;

        // AAD = context_digest(context, U). Encrypt first so the proof can bind
        // the ciphertext digest.
        let context_digest = context::context_digest(context, &enc_cmt_bytes);

        let mut nonce_bytes = [0u8; 12];
        rng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let payload = Payload {
            msg: data,
            aad: &context_digest,
        };
        let ciphertext = cipher
            .encrypt(nonce, payload)
            .map_err(|_| CryptoError::ElGamalError("Encryption failed".to_string()))?;

        let ciphertext_digest = context::ciphertext_digest(&nonce_bytes, &ciphertext);

        // Schnorr PoK of r for U = rG, bound to context_digest and ciphertext_digest.
        let (challenge, response) =
            Self::generate_encryption_proof(&r, &enc_cmt, &context_digest, &ciphertext_digest)?;

        let mut challenge_bytes = Vec::new();
        challenge.write_bytes(&mut challenge_bytes)?;
        let mut response_bytes = Vec::new();
        response.write_bytes(&mut response_bytes)?;

        let proof = EncryptionProof {
            challenge: challenge_bytes,
            response: response_bytes,
        };

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
        proof: &EncryptionProof,
        context: &CiphertextContext,
        secret: &Self::Secret,
    ) -> Result<()> {
        // Parse and validate U from the stored commitment.
        if secret.enc_cmt.len() != ELEMENT_COMPRESSED_SIZE {
            return Err(CryptoError::ElGamalError(format!(
                "Invalid enc_cmt length: expected {}, got {}",
                ELEMENT_COMPRESSED_SIZE,
                secret.enc_cmt.len()
            )));
        }
        let enc_cmt = Element::from_bytes(&secret.enc_cmt[..]).map_err(|e| {
            CryptoError::ElGamalError(format!("Failed to deserialize enc_cmt: {:?}", e))
        })?;
        if enc_cmt == Element::default() {
            return Err(CryptoError::ElGamalError(
                "Invalid enc_cmt: cannot be the identity element".to_string(),
            ));
        }

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

        // Deserialize proof scalars.
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

        // R1' = z*G - c*U
        let r1_prime = Element::generator() * response - enc_cmt * challenge;

        let context_digest = context::context_digest(context, &secret.enc_cmt);
        let ciphertext_digest = context::ciphertext_digest(&secret.nonce, &secret.encrypted_data);

        let recomputed_challenge = Self::encryption_proof_challenge(
            &enc_cmt,
            &r1_prime,
            &context_digest,
            &ciphertext_digest,
        )?;

        // Compare challenges using constant-time comparison
        let mut challenge_bytes = [0u8; 32];
        let mut recomputed_bytes = [0u8; 32];
        challenge
            .write_bytes(&mut &mut challenge_bytes[..])
            .map_err(|e| CryptoError::ElGamalError(format!("Serialization error: {:?}", e)))?;
        recomputed_challenge
            .write_bytes(&mut &mut recomputed_bytes[..])
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
        context: &CiphertextContext,
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

        // Recover the KEM shared point: V = xnc_cmt - rdr_sk * effective_pk.
        let xs_g = *effective_pk * rdr_sk;
        let shared_point = *xnc_cmt - xs_g;

        // Derive AES key
        let aes_key = Self::derive_key_from_point(&shared_point)?;
        let cipher = Aes256Gcm::new(&aes_key.into());

        // AAD = context_digest(context, U). A wrong context or commitment fails the open.
        let aad = context::context_digest(context, &secret.enc_cmt);

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

    fn sign_reader_authorization(
        rdr_sk: &Self::ShareValue,
        rdr_pk: &Self::PublicKey,
        context: &ReaderAuthorizationContext,
    ) -> Result<ReaderAuthorizationSignature> {
        let (challenge, response) =
            Self::generate_reader_authorization_signature(rdr_sk, rdr_pk, context)?;

        let mut challenge_bytes = Vec::new();
        challenge.write_bytes(&mut challenge_bytes)?;
        let mut response_bytes = Vec::new();
        response.write_bytes(&mut response_bytes)?;

        Ok(ReaderAuthorizationSignature {
            challenge: challenge_bytes,
            response: response_bytes,
        })
    }

    fn verify_reader_authorization(
        rdr_pk: &Self::PublicKey,
        context: &ReaderAuthorizationContext,
        signature: &ReaderAuthorizationSignature,
    ) -> Result<()> {
        // A rdr_pk of the identity element makes the discrete-log statement
        // vacuous (0 = 0*G): any (c, z) with c = H(rdr_pk, z*G, ...) trivially
        // verifies without the prover knowing anything, so it must be rejected
        // here independent of whatever `reencrypt`'s own checks do.
        if *rdr_pk == Element::default() {
            return Err(CryptoError::ElGamalError(
                "Invalid reader public key: cannot be zero point".to_string(),
            ));
        }

        if signature.challenge.len() != FR_COMPRESSED_SIZE {
            return Err(CryptoError::ElGamalError(format!(
                "Invalid reader-authorization-signature challenge length: expected {}, got {}",
                FR_COMPRESSED_SIZE,
                signature.challenge.len()
            )));
        }
        let challenge = Fr::from_bytes(&signature.challenge[..]).map_err(|e| {
            CryptoError::ElGamalError(format!(
                "Failed to deserialize reader-authorization-signature challenge: {:?}",
                e
            ))
        })?;
        if signature.response.len() != FR_COMPRESSED_SIZE {
            return Err(CryptoError::ElGamalError(format!(
                "Invalid reader-authorization-signature response length: expected {}, got {}",
                FR_COMPRESSED_SIZE,
                signature.response.len()
            )));
        }
        let response = Fr::from_bytes(&signature.response[..]).map_err(|e| {
            CryptoError::ElGamalError(format!(
                "Failed to deserialize reader-authorization-signature response: {:?}",
                e
            ))
        })?;

        // R1' = z*G - c*rdr_pk
        let r1_prime = Element::generator() * response - *rdr_pk * challenge;

        let context_digest = context::reader_authorization_context_digest(context);
        let recomputed_challenge =
            Self::reader_authorization_challenge(rdr_pk, &r1_prime, &context_digest)?;

        let mut challenge_bytes = [0u8; 32];
        let mut recomputed_bytes = [0u8; 32];
        challenge
            .write_bytes(&mut &mut challenge_bytes[..])
            .map_err(|e| CryptoError::ElGamalError(format!("Serialization error: {:?}", e)))?;
        recomputed_challenge
            .write_bytes(&mut &mut recomputed_bytes[..])
            .map_err(|e| CryptoError::ElGamalError(format!("Serialization error: {:?}", e)))?;

        if challenge_bytes.ct_ne(&recomputed_bytes).into() {
            return Err(CryptoError::ElGamalError(
                "Reader authorization signature verification failed".to_string(),
            ));
        }

        Ok(())
    }
}

impl ThresholdDealerNode {
    /// Generate a new keypair for encryption/decryption (test-only).
    #[cfg(any(test, feature = "test-helpers"))]
    pub fn generate_keypair() -> (Fr, Element) {
        let mut rng = OsRng;
        let sk = Fr::rand(&mut rng);
        let pk = Element::generator() * sk;
        (sk, pk)
    }

    /// Derive a capability scalar from derivation bytes.
    fn derive_capability_scalar(derivation: &[u8]) -> Fr {
        let mut hasher = Sha512::new();
        hasher.update(DERIVATION_DOMAIN);
        hasher.update(derivation);
        Fr::from_le_bytes_mod_order(&hasher.finalize())
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

        // `Element` wraps Jubjub's prime-order subgroup; decoding validates
        // canonical encoding and subgroup membership.

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
        // Validate inputs are not identity points. `Element` only represents
        // members of Jubjub's prime-order subgroup; its decoder rejects
        // points with a nontrivial cofactor component.
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
        let effective_cmt = Element::generator() * effective_ski;

        // Produce random oracle challenge
        // ei = Hash(PROTOCOL, idx, rdr_pk, enc_cmt, effective_cmt, Ui, UiHat, HiHat)
        let mut rng = OsRng;
        // Draw until non-zero: for a Schnorr-style response `f = r + e*x`,
        // `r = 0` would expose `x`. The shared sampling helper is bound to
        // arkworks field traits, so use the native Jubjub scalar sampler here.
        let ri = loop {
            let candidate = Fr::rand(&mut rng);
            if candidate != Fr::zero() {
                break candidate;
            }
        };
        let ui_hat = xr_g * ri;
        let hi_hat = Element::generator() * ri;

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
        let fi_g = Element::generator() * proofi;
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
        chlg.write_bytes(&mut &mut chlg_bytes[..])
            .map_err(|e| CryptoError::ElGamalError(format!("Serialization error: {:?}", e)))?;
        chlgi
            .write_bytes(&mut &mut chlgi_bytes[..])
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
    ///
    /// Uses unkeyed BLAKE2b-512. The full 64-byte digest is interpreted as a
    /// little-endian integer and reduced modulo the Jubjub scalar order.
    fn hash_reencrypt_proof_points(
        idx: u32,
        rdr_pk: &Element,
        enc_cmt: &Element,
        effective_cmt: &Element,
        proof_points: &[Element],
    ) -> Result<[u8; 64]> {
        let mut hasher = Blake2b512::new();

        // Add domain separation to prevent cross-protocol attacks
        hasher.update(PROTOCOL);

        // Bind share index
        hasher.update(idx.to_le_bytes());

        // Serialize and hash all public inputs then proof points
        // Compressed Jubjub points are 32 bytes
        let mut bytes = Vec::with_capacity(32);
        for point in [rdr_pk, enc_cmt, effective_cmt] {
            bytes.clear();
            point.write_bytes(&mut bytes)?;
            hasher.update(&bytes);
        }
        for point in proof_points {
            bytes.clear();
            point.write_bytes(&mut bytes)?;
            hasher.update(&bytes);
        }

        let result = hasher.finalize();
        let mut output = [0u8; 64];
        output.copy_from_slice(&result);
        Ok(output)
    }

    /// Derive AES key from elliptic curve point
    pub fn derive_key_from_point(point: &Element) -> Result<[u8; 32]> {
        let mut point_bytes = Vec::new();
        point.write_bytes(&mut point_bytes)?;

        let hkdf = Hkdf::<Sha256>::new(None, &point_bytes);
        let mut key = [0u8; 32];
        hkdf.expand(b"elgamal-jubjub-aes-key-v1", &mut key)
            .map_err(|_| CryptoError::ElGamalError("HKDF expansion failed".to_string()))?;

        Ok(key)
    }

    /// Generate the Schnorr PoK of `r` for `U = r*G`.
    ///
    /// `k <- random nonzero Fr`, `R1 = k*G`,
    /// `c = encryption_proof_challenge(U, R1, context_digest, ciphertext_digest)`,
    /// `z = k + c*r`. Returns `(c, z)`.
    fn generate_encryption_proof(
        r: &Fr,
        enc_cmt: &Element,
        context_digest: &[u8; 32],
        ciphertext_digest: &[u8; 32],
    ) -> Result<(Fr, Fr)> {
        let mut rng = OsRng;
        let k = loop {
            let candidate = Fr::rand(&mut rng);
            if candidate != Fr::zero() {
                break candidate;
            }
        };
        let r1 = Element::generator() * k;

        let c = Self::encryption_proof_challenge(enc_cmt, &r1, context_digest, ciphertext_digest)?;
        let z = k + (c * r);
        Ok((c, z))
    }

    /// Fiat-Shamir challenge:
    /// `Fr::from_le_bytes_mod_order(SHA512(POLICY_BINDING_PROOF_DOMAIN || compress(U)
    ///   || compress(R1) || context_digest || ciphertext_digest))`.
    ///
    /// SHA-512 is used (the encryption proof is entirely off-circuit) so the
    /// reduction bias into `Fr` is negligible.
    fn encryption_proof_challenge(
        enc_cmt: &Element,
        r1: &Element,
        context_digest: &[u8; 32],
        ciphertext_digest: &[u8; 32],
    ) -> Result<Fr> {
        let mut hasher = Sha512::new();
        hasher.update(POLICY_BINDING_PROOF_DOMAIN);

        let mut bytes = Vec::with_capacity(ELEMENT_COMPRESSED_SIZE);
        for point in [enc_cmt, r1] {
            bytes.clear();
            point.write_bytes(&mut bytes)?;
            hasher.update(&bytes);
        }
        hasher.update(context_digest);
        hasher.update(ciphertext_digest);

        Ok(Fr::from_le_bytes_mod_order(&hasher.finalize()))
    }

    /// Generate the Schnorr signature of `rdr_sk` for `rdr_pk = rdr_sk*G`,
    /// over `context`.
    ///
    /// `k <- random nonzero Fr`, `R1 = k*G`,
    /// `c = reader_authorization_challenge(rdr_pk, R1, reader_authorization_context_digest(context))`,
    /// `z = k + c*rdr_sk`. Returns `(c, z)`.
    fn generate_reader_authorization_signature(
        rdr_sk: &Fr,
        rdr_pk: &Element,
        context: &ReaderAuthorizationContext,
    ) -> Result<(Fr, Fr)> {
        let mut rng = OsRng;
        let k = loop {
            let candidate = Fr::rand(&mut rng);
            if candidate != Fr::zero() {
                break candidate;
            }
        };
        let r1 = Element::generator() * k;

        let context_digest = context::reader_authorization_context_digest(context);
        let c = Self::reader_authorization_challenge(rdr_pk, &r1, &context_digest)?;
        let z = k + (c * rdr_sk);
        Ok((c, z))
    }

    /// Fiat-Shamir challenge:
    /// `Fr::from_le_bytes_mod_order(SHA512(READER_AUTHORIZATION_DOMAIN || compress(rdr_pk)
    ///   || compress(R1) || reader_authorization_context_digest))`.
    fn reader_authorization_challenge(
        rdr_pk: &Element,
        r1: &Element,
        reader_authorization_context_digest: &[u8; 32],
    ) -> Result<Fr> {
        let mut hasher = Sha512::new();
        hasher.update(READER_AUTHORIZATION_DOMAIN);

        let mut bytes = Vec::with_capacity(ELEMENT_COMPRESSED_SIZE);
        for point in [rdr_pk, r1] {
            bytes.clear();
            point.write_bytes(&mut bytes)?;
            hasher.update(&bytes);
        }
        hasher.update(reader_authorization_context_digest);

        Ok(Fr::from_le_bytes_mod_order(&hasher.finalize()))
    }
}
