//! Binding context for the PET tag-knowledge proof.
//!
//! [`tag_proof_digest`] folds the tag ciphertext (`R`, `T`), the authoritative
//! PET public key and stable ring identity, and the complete payload envelope
//! — its [`CiphertextContext`] (the *same* context bound into the payload
//! encryption proof: ring_pk, policy fields, salt — not a second,
//! caller-selectable tag policy), its [`Secret`], and its already-created
//! [`EncryptionProof`] — into a single digest. The tag-knowledge proof's
//! Fiat-Shamir challenge binds this digest, so changing any of these inputs
//! invalidates a copied proof.
//!
//! This digest deliberately excludes the tag-knowledge proof itself (generated
//! afterwards, from this digest) and the final document ID (calculated after
//! the proof is attached), matching the non-circular construction order in the
//! PET design.

use crate::context::{self, CiphertextContext};
use crate::r#trait::{EncryptionProof, Secret};
use sha2::{Digest, Sha256};

/// Domain separator for [`tag_proof_digest`].
pub const TAG_PROOF_DIGEST_DOMAIN: &[u8] = b"orbis-pet-tag-proof-v1";

/// Append `bytes` with a 4-byte big-endian length prefix.
fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// Compute the tag-knowledge-proof transcript digest.
///
/// * `ephemeral_point` / `masked_fingerprint` — the tag ciphertext `(R, T)`,
///   compressed.
/// * `pet_pk` — the authoritative PET public key from live ring state,
///   compressed.
/// * `ring_id` — the stable ring identity (`DocumentPayload.ring_id`).
/// * `ciphertext_context` / `secret` / `payload_proof` — the exact payload
///   envelope: the context already bound into the payload's own encryption
///   proof, the encrypted `Secret`, and that `EncryptionProof`.
///
/// Every verifier reconstructs this digest independently from the resolved
/// document and authoritative ring state; a separately supplied digest is
/// never sufficient evidence of the binding.
pub fn tag_proof_digest(
    ephemeral_point: &[u8],
    masked_fingerprint: &[u8],
    pet_pk: &[u8],
    ring_id: &str,
    ciphertext_context: &CiphertextContext,
    secret: &Secret,
    payload_proof: &EncryptionProof,
) -> [u8; 32] {
    let mut out = Vec::new();
    put_bytes(&mut out, ephemeral_point);
    put_bytes(&mut out, masked_fingerprint);
    put_bytes(&mut out, pet_pk);
    put_bytes(&mut out, ring_id.as_bytes());
    put_bytes(&mut out, &context::canonical_encode(ciphertext_context));
    put_bytes(&mut out, &secret.enc_cmt);
    put_bytes(&mut out, &secret.nonce);
    put_bytes(&mut out, &secret.encrypted_data);
    put_bytes(&mut out, &payload_proof.challenge);
    put_bytes(&mut out, &payload_proof.response);

    let mut hasher = Sha256::new();
    hasher.update(TAG_PROOF_DIGEST_DOMAIN);
    hasher.update(&out);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_ctx() -> CiphertextContext {
        CiphertextContext {
            ring_pk: vec![9, 9, 9],
            policy_id: "policy".into(),
            resource: "resource".into(),
            permission: "read".into(),
            tier: None,
            timestamp: None,
            salt: None,
        }
    }

    fn sample_secret() -> Secret {
        Secret {
            enc_cmt: vec![1, 2, 3],
            encrypted_data: vec![4, 5, 6],
            nonce: vec![0; 12],
        }
    }

    fn sample_proof() -> EncryptionProof {
        EncryptionProof {
            challenge: vec![7, 8],
            response: vec![9, 10],
        }
    }

    #[test]
    fn digest_is_deterministic() {
        let a = tag_proof_digest(
            b"R",
            b"T",
            b"pet-pk",
            "ring-1",
            &sample_ctx(),
            &sample_secret(),
            &sample_proof(),
        );
        let b = tag_proof_digest(
            b"R",
            b"T",
            b"pet-pk",
            "ring-1",
            &sample_ctx(),
            &sample_secret(),
            &sample_proof(),
        );
        assert_eq!(a, b);
    }

    #[test]
    fn every_input_changes_the_digest() {
        let base = tag_proof_digest(
            b"R",
            b"T",
            b"pet-pk",
            "ring-1",
            &sample_ctx(),
            &sample_secret(),
            &sample_proof(),
        );

        assert_ne!(
            base,
            tag_proof_digest(
                b"R-other",
                b"T",
                b"pet-pk",
                "ring-1",
                &sample_ctx(),
                &sample_secret(),
                &sample_proof()
            ),
            "changing R must change the digest"
        );
        assert_ne!(
            base,
            tag_proof_digest(
                b"R",
                b"T-other",
                b"pet-pk",
                "ring-1",
                &sample_ctx(),
                &sample_secret(),
                &sample_proof()
            ),
            "changing T must change the digest"
        );
        assert_ne!(
            base,
            tag_proof_digest(
                b"R",
                b"T",
                b"pet-pk-other",
                "ring-1",
                &sample_ctx(),
                &sample_secret(),
                &sample_proof()
            ),
            "changing the PET public key must change the digest"
        );
        assert_ne!(
            base,
            tag_proof_digest(
                b"R",
                b"T",
                b"pet-pk",
                "ring-2",
                &sample_ctx(),
                &sample_secret(),
                &sample_proof()
            ),
            "changing the ring id must change the digest"
        );
        let mut other_ctx = sample_ctx();
        other_ctx.policy_id = "other-policy".into();
        assert_ne!(
            base,
            tag_proof_digest(
                b"R",
                b"T",
                b"pet-pk",
                "ring-1",
                &other_ctx,
                &sample_secret(),
                &sample_proof()
            ),
            "changing the ciphertext context must change the digest"
        );
        let mut other_secret = sample_secret();
        other_secret.encrypted_data = vec![99];
        assert_ne!(
            base,
            tag_proof_digest(
                b"R",
                b"T",
                b"pet-pk",
                "ring-1",
                &sample_ctx(),
                &other_secret,
                &sample_proof()
            ),
            "changing the encrypted payload must change the digest"
        );
        let mut other_proof = sample_proof();
        other_proof.response = vec![255];
        assert_ne!(
            base,
            tag_proof_digest(
                b"R",
                b"T",
                b"pet-pk",
                "ring-1",
                &sample_ctx(),
                &sample_secret(),
                &other_proof
            ),
            "changing the payload encryption proof must change the digest"
        );
    }
}
