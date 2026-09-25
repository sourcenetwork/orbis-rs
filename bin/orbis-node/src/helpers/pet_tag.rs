//! Converts a wire-level PET tag attachment (four raw byte fields, shared by
//! the `pre` and `store_secret` proto packages as their own `PetTagAttachment`
//! message) into the internal `DocumentPayload` shape: two JSON strings,
//! matching how the payload's own `EncryptionProof` is carried separately from
//! its ciphertext.
//!
//! This is structural conversion only — it does not validate curve membership,
//! point encoding, or proof correctness. That happens wherever the tag is
//! actually verified (not yet implemented; no PET ring can exist yet).

use crypto::r#trait::{PetTag, TagKnowledgeProof};

/// Returns the `(pet_tag, pet_tag_proof)` JSON strings for `DocumentPayload`
/// from a decoded attachment's four raw byte fields.
pub fn pet_tag_attachment_to_document_fields(
    ephemeral_point: Vec<u8>,
    masked_fingerprint: Vec<u8>,
    knowledge_proof_challenge: Vec<u8>,
    knowledge_proof_response: Vec<u8>,
) -> Result<(String, String), String> {
    let pet_tag: String = PetTag {
        ephemeral_point,
        masked_fingerprint,
    }
    .try_into()
    .map_err(|e: crypto::error::CryptoError| format!("Failed to serialize pet_tag: {}", e))?;

    let pet_tag_proof: String = TagKnowledgeProof {
        challenge: knowledge_proof_challenge,
        response: knowledge_proof_response,
    }
    .try_into()
    .map_err(|e: crypto::error::CryptoError| format!("Failed to serialize pet_tag_proof: {}", e))?;

    Ok((pet_tag, pet_tag_proof))
}
