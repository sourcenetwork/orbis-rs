//! Ciphertext-binding context for the PRE encryption proof.
//!
//! [`CiphertextContext`] carries the policy/ring inputs that an encryptor commits
//! to when producing a document. Its deterministic [`canonical_encode`]
//! serialization is folded — together with the encryption commitment `U` — into
//! [`context_digest`], which is used both as the AES-GCM AAD and (via the
//! per-curve Schnorr proof) as a Fiat-Shamir input. This binds the ciphertext to
//! exactly one `(ring_pk, policy_id, resource, permission, tier, timestamp,
//! salt)` tuple: tampering with any field, the commitment, or the ciphertext
//! makes both proof verification and decryption fail.
//!
//! The context is never stored on the wire. Both the encryptor and every
//! verifier rebuild it from parts (the on-chain `DocumentPayload` fields, the
//! ring public key, and the reader-supplied `salt`), so the proof binds the
//! *semantic* fields rather than any particular JSON byte layout.

use sha2::{Digest, Sha256};

/// Domain separator for [`context_digest`].
pub const CONTEXT_DIGEST_DOMAIN: &[u8] = b"orbis-context-v1";
/// Domain separator for [`ciphertext_digest`].
pub const CIPHERTEXT_DIGEST_DOMAIN: &[u8] = b"orbis-ciphertext-v1";

/// Binds a payload's encryption to the exact PET ownership tag it was
/// created for.
///
/// Without this, a copied ciphertext + encryption proof (both public, on the
/// bulletin) could be reattached to a *fresh* tag pointing at a different
/// owner, generated with an attacker's own randomness — both the original
/// payload proof and the new tag's own knowledge proof would still verify,
/// since neither previously committed to the other. Folding this into
/// [`CiphertextContext`] (and hence into both the AES-GCM AAD and the
/// payload's Fiat-Shamir challenge via [`context_digest`]) means a verifier
/// who rebuilds the context from a *different* tag gets a different digest:
/// AEAD decryption fails, and the original Schnorr proof no longer verifies.
/// Forging a new, consistent proof for the new tag would require
/// re-encrypting from the plaintext, which a ciphertext-only attacker
/// doesn't have. See the PET audit fix checklist, finding #5.
///
/// `None` for a ring that doesn't `requires_pet`.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PetTagBinding {
    /// Stable ring identity (`DocumentPayload.ring_id`) — the same value
    /// bound into `pet_context::tag_proof_digest`.
    pub ring_id: String,
    /// The ring's authoritative PET checking public key (compressed point
    /// bytes) — distinct from [`CiphertextContext::ring_pk`], the main ring
    /// key.
    pub pet_pk: Vec<u8>,
    /// The tag ciphertext `(R, T)`, compressed. Generated *before* this
    /// payload is encrypted — see `cli_tool::generate_pet_tag`/
    /// `prepare_secret`'s required noncircular construction order.
    pub ephemeral_point: Vec<u8>,
    pub masked_fingerprint: Vec<u8>,
}

/// Policy/ring inputs bound to a PRE-encrypted document.
///
/// Contains only values the caller knows up front. The encryption commitment
/// `U` is *not* a field here — it is passed alongside the context to
/// [`context_digest`] (the fresh `U` at encryption time, `secret.enc_cmt` at
/// verification / decryption time).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CiphertextContext {
    /// Serialized ring / DKG aggregate public key (compressed point bytes).
    pub ring_pk: Vec<u8>,
    /// ACP policy id the document is filed under.
    pub policy_id: String,
    /// ACP resource type.
    pub resource: String,
    /// ACP permission required to read.
    pub permission: String,
    /// Optional ACP tier.
    pub tier: Option<String>,
    /// Optional ACP timestamp.
    pub timestamp: Option<u64>,
    /// Optional reader-supplied capability salt.
    pub salt: Option<String>,
    /// PET ownership-tag binding — see [`PetTagBinding`].
    pub pet_tag: Option<PetTagBinding>,
}

/// Append `bytes` with a 4-byte big-endian length prefix.
fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// Append an optional string: `0x00` for `None`, `0x01` + length-prefixed bytes
/// for `Some`.
fn put_opt_str(out: &mut Vec<u8>, value: Option<&str>) {
    match value {
        None => out.push(0),
        Some(s) => {
            out.push(1);
            put_bytes(out, s.as_bytes());
        }
    }
}

/// Append an optional `u64`: `0x00` for `None`, `0x01` + 8 big-endian bytes for
/// `Some`.
fn put_opt_u64(out: &mut Vec<u8>, value: Option<u64>) {
    match value {
        None => out.push(0),
        Some(n) => {
            out.push(1);
            out.extend_from_slice(&n.to_be_bytes());
        }
    }
}

/// Append an optional [`PetTagBinding`]: `0x00` for `None`, `0x01` +
/// length-prefixed sub-fields (in declaration order) for `Some`.
fn put_opt_pet_tag(out: &mut Vec<u8>, value: Option<&PetTagBinding>) {
    match value {
        None => out.push(0),
        Some(binding) => {
            out.push(1);
            put_bytes(out, binding.ring_id.as_bytes());
            put_bytes(out, &binding.pet_pk);
            put_bytes(out, &binding.ephemeral_point);
            put_bytes(out, &binding.masked_fingerprint);
        }
    }
}

/// Deterministic length-prefixed encoding of a [`CiphertextContext`].
///
/// Field order is fixed as declared on the struct. Every variable-length field
/// is length-prefixed and every optional field carries a presence tag, so no two
/// distinct contexts share an encoding.
pub fn canonical_encode(context: &CiphertextContext) -> Vec<u8> {
    let mut out = Vec::new();
    put_bytes(&mut out, &context.ring_pk);
    put_bytes(&mut out, context.policy_id.as_bytes());
    put_bytes(&mut out, context.resource.as_bytes());
    put_bytes(&mut out, context.permission.as_bytes());
    put_opt_str(&mut out, context.tier.as_deref());
    put_opt_u64(&mut out, context.timestamp);
    put_opt_str(&mut out, context.salt.as_deref());
    put_opt_pet_tag(&mut out, context.pet_tag.as_ref());
    out
}

/// `SHA256(CONTEXT_DIGEST_DOMAIN || canonical_encode(context) || len_prefix(enc_cmt))`.
///
/// Used as the AES-GCM AAD and as a Fiat-Shamir input in the encryption proof.
/// `enc_cmt` is the compressed encryption commitment `U` (the fresh value at
/// encryption time, `secret.enc_cmt` at verification / decryption time).
pub fn context_digest(context: &CiphertextContext, enc_cmt: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(CONTEXT_DIGEST_DOMAIN);
    hasher.update(canonical_encode(context));
    let mut framed = Vec::with_capacity(4 + enc_cmt.len());
    put_bytes(&mut framed, enc_cmt);
    hasher.update(framed);
    hasher.finalize().into()
}

/// `SHA256(CIPHERTEXT_DIGEST_DOMAIN || nonce || encrypted_data)`.
///
/// `encrypted_data` is the full AES-GCM output (ciphertext followed by the
/// authentication tag). Bound into the encryption proof so the proof commits to
/// the exact `(nonce, ciphertext)` pair.
pub fn ciphertext_digest(nonce: &[u8], encrypted_data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(CIPHERTEXT_DIGEST_DOMAIN);
    hasher.update(nonce);
    hasher.update(encrypted_data);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> CiphertextContext {
        CiphertextContext {
            ring_pk: vec![1, 2, 3, 4],
            policy_id: "policy".into(),
            resource: "resource".into(),
            permission: "read".into(),
            tier: Some("gold".into()),
            timestamp: Some(42),
            salt: None,
            pet_tag: None,
        }
    }

    fn sample_pet_tag() -> PetTagBinding {
        PetTagBinding {
            ring_id: "ring-1".into(),
            pet_pk: vec![9, 9, 9],
            ephemeral_point: vec![1, 1, 1],
            masked_fingerprint: vec![2, 2, 2],
        }
    }

    #[test]
    fn canonical_encode_is_deterministic() {
        assert_eq!(canonical_encode(&sample()), canonical_encode(&sample()));
    }

    #[test]
    fn distinct_fields_produce_distinct_encodings() {
        let base = sample();
        let mut other = base.clone();
        other.permission = "write".into();
        assert_ne!(canonical_encode(&base), canonical_encode(&other));

        // Ambiguity guard: moving a byte across the policy_id/resource boundary
        // must not collide thanks to the length prefixes.
        let mut a = base.clone();
        a.policy_id = "ab".into();
        a.resource = "c".into();
        let mut b = base.clone();
        b.policy_id = "a".into();
        b.resource = "bc".into();
        assert_ne!(canonical_encode(&a), canonical_encode(&b));
    }

    #[test]
    fn option_presence_changes_encoding() {
        let mut none_salt = sample();
        none_salt.salt = None;
        let mut empty_salt = sample();
        empty_salt.salt = Some(String::new());
        assert_ne!(
            canonical_encode(&none_salt),
            canonical_encode(&empty_salt),
            "None and Some(\"\") must not collide"
        );
    }

    /// Finding #5 (PET audit fix checklist): a context with no PET tag must
    /// never encode identically to one with a tag, and two contexts with
    /// *different* tags must never collide either — otherwise a reattached
    /// tag could slip through unnoticed.
    #[test]
    fn pet_tag_presence_and_content_change_the_encoding() {
        let untagged = sample();
        let mut tagged = sample();
        tagged.pet_tag = Some(sample_pet_tag());
        assert_ne!(
            canonical_encode(&untagged),
            canonical_encode(&tagged),
            "presence of a PET tag binding must change the encoding"
        );

        let mut other_tag = tagged.clone();
        other_tag.pet_tag = Some(PetTagBinding {
            masked_fingerprint: vec![99, 99, 99],
            ..sample_pet_tag()
        });
        assert_ne!(
            canonical_encode(&tagged),
            canonical_encode(&other_tag),
            "a different tag's masked_fingerprint must change the encoding"
        );
    }

    #[test]
    fn context_digest_binds_enc_cmt() {
        let ctx = sample();
        assert_ne!(
            context_digest(&ctx, &[0u8; 32]),
            context_digest(&ctx, &[1u8; 32])
        );
    }

    #[test]
    fn ciphertext_digest_binds_nonce_and_data() {
        assert_ne!(
            ciphertext_digest(&[0u8; 12], b"ct"),
            ciphertext_digest(&[1u8; 12], b"ct")
        );
        assert_ne!(
            ciphertext_digest(&[0u8; 12], b"ct"),
            ciphertext_digest(&[0u8; 12], b"cu")
        );
    }
}
