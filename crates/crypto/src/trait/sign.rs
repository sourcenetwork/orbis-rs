use super::codec::{CryptoDeserialize, CryptoSerialize};
use crate::error::Result;

pub trait ThresholdSigner {
    /// Whether this scheme requires interactive nonce commitment rounds (FROST = true, BLS = false)
    const INTERACTIVE: bool;

    /// Scalar field (Fr for BLS12-381)
    type ShareValue;

    /// Signature type (usually G1Affine)
    type Signature;

    /// Public key type (usually G2Affine)
    type PublicKey;

    /// Public polynomial from DKG (commitments)
    type PubPoly;

    /// Distributed secret key share
    type DistKeyShare;

    /// Signature share type
    type SigShare;

    /// Nonce commitment broadcast in Round 1 (BLS: `()`, FROST: nonce pair)
    type NonceCommitment: CryptoSerialize + CryptoDeserialize + Clone + Send + Sync;

    /// Secret state held between Round 1 and Round 2 (BLS: `()`, FROST: secret nonces)
    type SigningState: CryptoSerialize + CryptoDeserialize + Send + Sync;

    /// Construct a new signer
    fn new() -> Self;

    /// Domain-separated name for the protocol
    fn name() -> String;

    /// Hash a public-key-augmented message to the signing group (BLS only;
    /// FROST returns Err).
    ///
    /// The public key is part of the hash input so signatures made by publicly
    /// related keys cannot be converted from one key to another by scaling the
    /// signature point.
    fn hash_message(&self, pk: &Self::PublicKey, msg: &[u8]) -> Result<Self::Signature>;

    /// Generate nonce commitments and secret signing state for Round 1
    fn generate_nonces(
        &self,
        dist_key_share: &Self::DistKeyShare,
    ) -> Result<(Self::NonceCommitment, Self::SigningState)>;

    /// Locally sign a message using a DKG share.
    ///
    /// When `derivation` is `Some(bytes)`, each node multiplies its secret share by
    /// `d = H(SIGN_DERIVATION_DOMAIN || derivation)` before signing, producing a signature
    /// that verifies under the derived public key `d * agg_pk`.
    ///
    /// When `metadata` is also provided, it is folded into the derivation scalar:
    /// `d = H(SIGN_DERIVATION_DOMAIN || derivation || \x00 || len(metadata) || metadata)`.
    /// The metadata is thus cryptographically bound to every signature share. BLS additionally
    /// hashes the effective public key with the message (the augmented ciphersuite), preventing
    /// signatures from being converted between publicly related derived keys. FROST binds the
    /// effective public key into its transcript challenge.
    fn sign(
        &self,
        dist_key_share: &Self::DistKeyShare,
        msg: &[u8],
        pub_poly: &Self::PubPoly,
        signing_state: Option<&Self::SigningState>,
        all_commitments: &[(u32, Self::NonceCommitment)],
        derivation: Option<&[u8]>,
        metadata: Option<&[u8]>,
    ) -> Result<Self::SigShare>;

    /// Verify a single signature share against the DKG commitments.
    ///
    /// `derivation` and `metadata` must match the values passed to `sign`.
    fn verify_share(
        &self,
        msg: &[u8],
        pub_poly: &Self::PubPoly,
        sig_share: &Self::SigShare,
        all_commitments: &[(u32, Self::NonceCommitment)],
        derivation: Option<&[u8]>,
        metadata: Option<&[u8]>,
    ) -> Result<()>;

    /// Recover a full signature from shares.
    fn recover(
        &self,
        shares: &[Self::SigShare],
        t: usize,
        n: usize,
        group_public_key: &Self::PublicKey,
        msg: &[u8],
        all_commitments: &[(u32, Self::NonceCommitment)],
    ) -> Result<Option<Self::Signature>>;

    /// Verify the final signature
    fn verify(&self, pk: &Self::PublicKey, msg: &[u8], sig: &Self::Signature) -> Result<()>;

    /// Encode signing policy fields into a metadata commitment for derivation binding.
    ///
    /// Both the signer and any verifier must call this function with the same inputs
    /// to produce the same bytes for `sign`, `verify_share`, and `derive_public_key`.
    ///
    /// Uses SHA-256 with length-prefixed fields and a domain separator so the output
    /// is collision-free across different `(policy_id, permission, resource)` pairs.
    fn encode_metadata(policy_id: &str, resource: &str, permission: &str) -> Vec<u8>;

    /// Derive a deterministic public key from the DKG aggregate public key.
    ///
    /// Computes `pk' = d * dkg_pk` where:
    ///   - Without metadata: `d = H(SIGN_DERIVATION_DOMAIN || derivation)`
    ///   - With metadata:    `d = H(SIGN_DERIVATION_DOMAIN || derivation || \x00 || len(metadata) || metadata)`
    ///
    /// Signing with a share multiplied by `d` produces a signature that verifies under `pk'`.
    ///
    /// Returns an error if `d` is zero (negligible probability).
    fn derive_public_key(
        dkg_pk: &Self::PublicKey,
        derivation: &[u8],
        metadata: Option<&[u8]>,
    ) -> Result<Self::PublicKey>;
}
