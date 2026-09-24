use super::codec::{CryptoDeserialize, CryptoSerialize};
use super::types::{PetTag, TagKnowledgeProof};
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
}
