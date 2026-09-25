use super::codec::{CryptoDeserialize, CryptoSerialize};
use super::types::{PetTag, PubShare, TagKnowledgeProof};
use crate::error::Result;

/// PET (ownership-tag) primitives, defined once per curve backend alongside the
/// existing PRE ([`super::pre::ThresholdDealer`]) and signing
/// ([`super::sign::ThresholdSigner`]) abstractions.
///
/// A PET tag masks a fingerprint of the claimed owner's identity under an
/// independently generated PET public key: `T = F(owner_id) + r_tag * pet_pk`.
/// [`Pet::owner_fingerprint`] computes `F`, the deterministic mapping from an
/// owner identifier to a group element.
///
/// `F` is defined and owned here, on the Orbis side, not supplied by the tag
/// producer (Bankd): every PET participant reconstructs the expected
/// fingerprint for an authenticated audit target from this same function
/// rather than trusting a caller-supplied value.
pub trait Pet {
    /// Group element type (matches the curve's `ThresholdDealer::PublicKey`).
    type PublicKey: CryptoSerialize + CryptoDeserialize + Clone;
    /// Scalar field type (matches the curve's `ThresholdDealer::ShareValue`).
    type ShareValue: CryptoSerialize + CryptoDeserialize + Clone;

    fn new() -> Self;
    fn name() -> String;

    /// `F(owner_id) = hash_to_scalar(FINGERPRINT_DOMAIN || owner_id) * G`.
    ///
    /// Deterministic and public. Every verifier recomputes this directly from
    /// the authenticated audit target id; it is never taken as a caller-supplied
    /// value.
    fn owner_fingerprint(owner_id: &[u8]) -> Result<Self::PublicKey>;

    /// Generate the tag-knowledge proof for a tag whose `ephemeral_point = r_tag*G`.
    ///
    /// Called once by the tag producer/encryptor, never by a verifier or
    /// auditor. `tag_transcript_digest` must be
    /// [`crate::pet_context::tag_proof_digest`] computed over the tag, the
    /// authoritative PET public key and ring identity, and the complete payload
    /// envelope — see that function's docs for the exact binding.
    fn prove_tag_knowledge(
        r_tag: &Self::ShareValue,
        tag: &PetTag,
        tag_transcript_digest: &[u8; 32],
    ) -> Result<TagKnowledgeProof>;

    /// Verify a [`TagKnowledgeProof`] against `tag` and an independently
    /// reconstructed `tag_transcript_digest`.
    ///
    /// Every PET participant, including the initiator, must call this — after
    /// rebuilding `tag_transcript_digest` itself from the resolved document and
    /// authoritative ring state — before joining PET. A coordinator-supplied
    /// verification flag does not satisfy this requirement.
    fn verify_tag_knowledge(
        tag: &PetTag,
        proof: &TagKnowledgeProof,
        tag_transcript_digest: &[u8; 32],
    ) -> Result<()>;

    /// A committee member's raw contribution to the threshold PET check:
    /// `share_i * R`, where `share_i` is this node's DKG share of the ring's
    /// PET secret key and `R = tag.ephemeral_point`. Structurally the same
    /// "apply my secret share to a public group element" shape as
    /// [`super::pre::ThresholdDealer::reencrypt`]'s `ski * (xG + rG)`, just
    /// against a single point instead of a sum of two.
    ///
    /// Never reveals `share_i` or the PET secret key: recovering either from
    /// this output alone requires solving discrete log. Combine
    /// `threshold`-many of these via [`Pet::combine_pet_check_shares`] to
    /// recover `pet_sk * R`.
    fn partial_pet_check(share_i: &Self::ShareValue, tag: &PetTag) -> Result<Self::PublicKey>;

    /// Lagrange-combine `shares` (each indexed by its contributor's DKG
    /// share index, 1-based) into `pet_sk * R`. Requires at least
    /// `threshold` shares with distinct indices in `[1, n]`; only the first
    /// `threshold` are used, mirroring the same truncate-to-threshold
    /// convention as PRE's own share recovery.
    fn combine_pet_check_shares(
        shares: &[PubShare<Self::PublicKey>],
        threshold: usize,
        n: usize,
    ) -> Result<Self::PublicKey>;

    /// Verify a combined threshold check (from
    /// [`Pet::combine_pet_check_shares`]) against `tag` and the
    /// independently reconstructed fingerprint of the authenticated audit
    /// target (from [`Pet::owner_fingerprint`]):
    /// `tag.masked_fingerprint == target_fingerprint + combined_check`,
    /// i.e. `T == F(target) + pet_sk*R`, the tag's own defining equation
    /// with `r_tag*pet_pk` recovered as `pet_sk*R = pet_sk*(r_tag*G) =
    /// r_tag*pet_pk`. Returns `Err` on any mismatch — a non-matching target,
    /// a forged tag, or a wrong/incomplete threshold combination all fail
    /// identically here, since the equation only balances for the real
    /// owner.
    fn verify_pet_match(
        tag: &PetTag,
        combined_check: &Self::PublicKey,
        target_fingerprint: &Self::PublicKey,
    ) -> Result<()>;
}
