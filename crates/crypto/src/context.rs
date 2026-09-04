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
