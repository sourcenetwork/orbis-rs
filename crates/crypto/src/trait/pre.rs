use super::codec::{CryptoDeserialize, CryptoSerialize};
use super::dkg::PubPoly;
use super::types::{EncryptionProof, PubShare, ReaderKeyProof};
use crate::context::CiphertextContext;
use crate::error::Result;

/// Trait for PRE
pub trait ThresholdDealer {
    type DistKeyShare;
    type Secret;
    type PublicKey: CryptoSerialize + CryptoDeserialize + Clone;
    type ShareValue: CryptoSerialize + CryptoDeserialize + Clone;
    type ReencryptReply;
    type PubPoly: PubPoly<PublicKey = Self::PublicKey>;

    fn new() -> Self;
    fn name() -> String;

    /// Re-encrypt a secret share using the receiver's public key.
    ///
    /// `rdr_proof` must be a valid [`ReaderKeyProof`] of knowledge of `rdr_pk`'s
    /// discrete log (see `prove_reader_key`/`verify_reader_key`); this is checked
    /// before any computation involving `rdr_pk`. Without it, `rdr_pk` is only
    /// checked for group membership, and `xnc_ski`'s linearity in `rdr_pk` lets a
    /// caller who is authorized for one ciphertext redirect the recovered
    /// commitment toward an unrelated one by submitting a difference of two
    /// published commitments as `rdr_pk` — see [`ReaderKeyProof`]'s docs.
    ///
    /// When derivation is provided, applies the derivation scalar to the share:
    ///   xnc_ski = d * ski * (xG + rG)  where d = H(DERIVATION_DOMAIN || derivation)
    ///
    /// Note: If the wrong derivation is provided, decryption will fail at the user
    /// level (AES-GCM authentication failure). An attacker cannot brute-force the
    /// correct derivation without the reader's private key.
    ///
    /// Input:
    ///   dist_key_share - Private share of secret key of DKG.
    ///   scrt           - The encrypted secret (contains enc_cmt = rG).
    ///   rdr_pk  (xG)   - Public key of the reader.
    ///   rdr_proof      - Proof the caller knows rdr_pk's discrete log.
    ///   derivation     - Optional capability derivation bytes.
    ///
    /// Output:
    ///   xnc_ski (Ui) - Re-encrypted secret share (with derivation applied if provided).
    ///   chlgi  (ei)  - Random oracle challenge.
    ///   proofi (fi)  - NIZK proof of re-encryption.
    fn reencrypt(
        &self,
        dist_key_share: &Self::DistKeyShare,
        scrt: &Self::Secret,
        rdr_pk: &Self::PublicKey,
        rdr_proof: &ReaderKeyProof,
        derivation: Option<&[u8]>,
    ) -> Result<Self::ReencryptReply>;

    /// Prove knowledge of `rdr_sk` for `rdr_pk = rdr_sk*G`.
    ///
    /// Called by the reader when building a PRE request, never by a node. The
    /// resulting [`ReaderKeyProof`] travels alongside `rdr_pk` on the wire and is
    /// checked by every responder inside `reencrypt`.
    fn prove_reader_key(
        rdr_sk: &Self::ShareValue,
        rdr_pk: &Self::PublicKey,
    ) -> Result<ReaderKeyProof>;

    /// Verify a [`ReaderKeyProof`] against `rdr_pk`.
    ///
    /// `reencrypt` calls this internally before touching the secret share;
    /// exposed separately so a service layer can fail fast (before a threshold
    /// round trip) on a malformed or missing proof.
    fn verify_reader_key(rdr_pk: &Self::PublicKey, proof: &ReaderKeyProof) -> Result<()>;

    /// Verify a re-encryption proof.
    ///
    /// When derivation is provided, verification uses d * dkg_cmt.eval(idx) as the
    /// expected commitment for the share, matching the derivation applied during re-encryption.
    ///
    /// Input:
    ///   rdr_pk     (xG)  - Public key of the reader.
    ///   dkg_cmt          - Public polynomial commitment of DKG.
    ///   enc_cmt    (rG)  - Schnorr commit of encoded keys.
    ///   reply            - Re-encryption reply containing share, challenge, and proof.
    ///   derivation       - Optional capability derivation bytes (must match reencrypt).
    fn verify(
        &self,
        rdr_pk: &Self::PublicKey,
        dkg_cmt: &Self::PubPoly,
        enc_cmt: &Self::PublicKey,
        reply: &Self::ReencryptReply,
        derivation: Option<&[u8]>,
    ) -> Result<()>;

    /// Recover the re-encrypted commitment from shares
    fn recover(
        &self,
        xnc_ski: &[PubShare<Self::PublicKey>],
        t: usize,
        n: usize,
    ) -> Result<Option<Self::PublicKey>>;

    // These functions are not called by the node, but are required here intentionally.
    // A complete curve implementation must provide the full client-side API (encrypt, verify, decrypt)
    // so that clients can use any supported curve. Keeping them in one trait ensures the compiler
    // enforces completeness — an implementer cannot ship a node-only impl and leave clients with a
    // half-implemented curve.

    /// Encrypt a secret using the aggregate public key of the DKG.
    ///
    /// Input:
    ///   dkg_pk (sG)   - Aggregate public key of the DKG.
    ///   data          - Data to be encrypted.
    ///   derivation    - Optional capability derivation bytes. When provided,
    ///                   a scalar d = H(derivation) is derived and applied
    ///                   multiplicatively: derived_pk = d * dkg_pk.
    ///                   The KEM shared point becomes r * derived_pk = r*d*s*G
    ///                   (never serialized — only the AES key is derived from it).
    ///   context   - Policy/ring inputs bound to the ciphertext and the proof.
    ///               `context.enc_cmt` is not a field; the fresh `U` is folded in
    ///               internally.
    ///
    /// Output:
    ///   enc_cmt  - Schnorr commit (rG), i.e. `U`
    ///   secret   - Encrypted data (AAD = context_digest(context, U))
    ///   proof    - Schnorr PoK of `r` bound to context_digest and ciphertext_digest
    fn encrypt_secret(
        dkg_pk: &Self::PublicKey,
        data: &[u8],
        derivation: Option<&[u8]>,
        context: &CiphertextContext,
    ) -> Result<(Self::PublicKey, Self::Secret, EncryptionProof)>;

    /// Verify the encryption proof against a rebuilt [`CiphertextContext`] and the
    /// stored [`Secret`](super::types::Secret).
    ///
    /// Checks knowledge of `r` for `U = secret.enc_cmt` and that the same
    /// `context_digest(context, secret.enc_cmt)` and
    /// `ciphertext_digest(secret.nonce, secret.encrypted_data)` were bound at
    /// encryption time. Any mismatch in a context field, the commitment, the
    /// nonce, or the ciphertext fails verification.
    fn verify_encryption(
        proof: &EncryptionProof,
        context: &CiphertextContext,
        secret: &Self::Secret,
    ) -> Result<()>;

    /// Decrypt a secret using the reader's secret key.
    ///
    /// Input:
    ///   effective_pk       - The public key used for decryption:
    ///                        - If derivation was used: derive_public_key(dkg_pk, derivation)
    ///                        - Otherwise: dkg_pk (aggregate public key of DKG)
    ///   xnc_cmt            - Re-encrypted commitment: d*(x+r)*sG (with derivation)
    ///                        or (x+r)*sG (without derivation).
    ///   rdr_sk  (x)        - Secret key of the reader.
    ///   secret             - The encrypted secret.
    ///   context            - The same context bound at encryption time; rebuilds
    ///                        the AES-GCM AAD. A wrong context fails the GCM open.
    ///
    /// Output:
    ///   Decrypted data.
    ///
    /// Note: When derivation was used during encryption/re-encryption:
    ///   - xnc_cmt = d * (x+r) * sG
    ///   - effective_pk = d * sG
    ///   - recovered KEM point = xnc_cmt - x * effective_pk = d*r*sG
    fn decrypt_secret(
        effective_pk: &Self::PublicKey,
        xnc_cmt: &Self::PublicKey,
        rdr_sk: &Self::ShareValue,
        secret: &Self::Secret,
        context: &CiphertextContext,
    ) -> Result<Vec<u8>>;

    /// Derive the effective public key from the DKG public key and derivation bytes.
    ///
    /// Input:
    ///   dkg_pk     - Aggregate public key of the DKG (sG).
    ///   derivation - Capability derivation bytes.
    ///
    /// Output:
    ///   derived_pk = d * dkg_pk where d = H(DERIVATION_DOMAIN || derivation)
    ///
    /// This is used by the decryptor to compute the effective_pk needed for decryption
    /// when capability derivation was used during encryption.
    fn derive_public_key(dkg_pk: &Self::PublicKey, derivation: &[u8]) -> Result<Self::PublicKey>;

    /// Derive a symmetric AES key from an elliptic-curve point via HKDF-SHA256.
    ///
    /// Used internally after re-encryption share recovery to derive the AES key
    /// that decrypts the ciphertext. Exposed on the trait so generic tests can
    /// verify determinism and point-distinctness without curve-specific imports.
    fn derive_key_from_point(point: &Self::PublicKey) -> Result<[u8; 32]>;
}
