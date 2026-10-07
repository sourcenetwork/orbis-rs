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
/// Domain separator for [`reader_authorization_context_digest`].
pub const READER_AUTHORIZATION_CONTEXT_DIGEST_DOMAIN: &[u8] =
    b"orbis-reader-authorization-context-v1";

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
/// doesn't have.
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
pub(crate) fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// Append an optional string: `0x00` for `None`, `0x01` + length-prefixed bytes
/// for `Some`.
pub(crate) fn put_opt_str(out: &mut Vec<u8>, value: Option<&str>) {
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
pub(crate) fn put_opt_u64(out: &mut Vec<u8>, value: Option<u64>) {
    match value {
        None => out.push(0),
        Some(n) => {
            out.push(1);
            out.extend_from_slice(&n.to_be_bytes());
        }
    }
}

/// Append optional bytes: `0x00` for `None`, `0x01` + length-prefixed bytes for
/// `Some`.
pub(crate) fn put_opt_bytes(out: &mut Vec<u8>, value: Option<&[u8]>) {
    match value {
        None => out.push(0),
        Some(b) => {
            out.push(1);
            put_bytes(out, b);
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

/// Crypto-local mirror of `authz::vera::ValidWindow` — this crate has no
/// dependency on `authz` and shouldn't gain one just for this field, so the
/// node layer maps `ValidWindow { start, end }` to this identical shape when
/// building a [`ReaderAuthorizationContext`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ValidWindowBinding {
    pub start: u64,
    pub end: u64,
}

/// Append an optional [`ValidWindowBinding`]: `0x00` for `None`, `0x01` + the
/// two `u64` fields (big-endian, declaration order) for `Some`.
fn put_opt_valid_window(out: &mut Vec<u8>, value: Option<&ValidWindowBinding>) {
    match value {
        None => out.push(0),
        Some(w) => {
            out.push(1);
            out.extend_from_slice(&w.start.to_be_bytes());
            out.extend_from_slice(&w.end.to_be_bytes());
        }
    }
}

/// Request-bound recipient-authorization transcript — the message a PRE
/// recipient's Schnorr signature over their own key actually signs, replacing
/// the old context-free proof-of-possession. A plain data-bag populated by the
/// node layer from already-verified claims and already-resolved ring/document
/// state: this type itself knows nothing about JWTs, the bulletin, or ACP,
/// exactly like [`CiphertextContext`] doesn't.
///
/// Deliberately does **not** bind the ciphertext (`enc_cmt`/a digest of
/// `nonce`+`encrypted_data`): binding `object_id` already closes the
/// cross-ciphertext replay this exists to prevent (a signature for one
/// `object_id` cannot be reused for a request naming a different one, since
/// it's baked into the Fiat-Shamir challenge), and the correspondence between
/// a resolved `object_id` and the `Secret` actually used is already a
/// node-layer invariant (stage 3 resolves the document once; both this
/// context and the `Secret` passed to `reencrypt` derive from that same
/// resolution) backed by the same honest-threshold-of-nodes assumption this
/// protocol's other per-node checks (ACP, PET admission, encryption-binding)
/// already rest on — not something that needs independent crypto-layer
/// enforcement on top of that.
///
/// `ring_id` is similarly excluded: it's immutable per `object_id` and
/// independently, authoritatively resolved by the server regardless of any
/// client input, so binding `object_id` already implies it.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ReaderAuthorizationContext {
    /// Vera chain id — static per deployment.
    pub chain_id: String,
    /// Authoritative ring / DKG aggregate public key (compressed point
    /// bytes), server-resolved — never the client's own claim.
    pub ring_pk: Vec<u8>,
    /// Authenticated JWT issuer (`iss`).
    pub jwt_issuer: String,
    /// Delegated subject (`sub`), if the issuer is a trusted relay.
    pub jwt_subject: Option<String>,
    /// The actor the token actually resolves to (issuer, or the delegated
    /// subject when delegation is permitted) — bound in addition to the raw
    /// issuer/subject so the transcript is unambiguous even if delegation
    /// trust configuration ever changes between signing and verification.
    pub resolved_actor: String,
    /// JWT id (`jti`) — the logical request identifier. Callers must reject
    /// an empty value before constructing this context; there is no legacy
    /// tolerance for a token minted before `jti` existed.
    pub jwt_id: String,
    pub jwt_issued_time: u64,
    pub jwt_expiration_time: u64,
    pub jwt_not_before: Option<u64>,
    /// The document id this authorization is for, bound only once it has
    /// been used to successfully resolve a document server-side.
    pub object_id: String,
    /// The recipient public key itself, folded into the transcript (rather
    /// than hashed alongside it) so the transcript alone is fully
    /// self-describing — useful for the external, reproducible test-vector
    /// this type's signing scheme is expected to support.
    pub recipient_pk: Vec<u8>,
    pub derivation: Option<Vec<u8>>,
    pub salt: Option<String>,
    pub valid_window: Option<ValidWindowBinding>,
    pub audit_target_object_id: Option<String>,
}

/// Deterministic length-prefixed encoding of a [`ReaderAuthorizationContext`],
/// following [`canonical_encode`]'s exact conventions: fixed field order,
/// every variable-length field length-prefixed, every optional field
/// presence-tagged.
pub fn canonical_encode_reader_authorization(ctx: &ReaderAuthorizationContext) -> Vec<u8> {
    let mut out = Vec::new();
    put_bytes(&mut out, ctx.chain_id.as_bytes());
    put_bytes(&mut out, &ctx.ring_pk);
    put_bytes(&mut out, ctx.jwt_issuer.as_bytes());
    put_opt_str(&mut out, ctx.jwt_subject.as_deref());
    put_bytes(&mut out, ctx.resolved_actor.as_bytes());
    put_bytes(&mut out, ctx.jwt_id.as_bytes());
    out.extend_from_slice(&ctx.jwt_issued_time.to_be_bytes());
    out.extend_from_slice(&ctx.jwt_expiration_time.to_be_bytes());
    put_opt_u64(&mut out, ctx.jwt_not_before);
    put_bytes(&mut out, ctx.object_id.as_bytes());
    put_bytes(&mut out, &ctx.recipient_pk);
    put_opt_bytes(&mut out, ctx.derivation.as_deref());
    put_opt_str(&mut out, ctx.salt.as_deref());
    put_opt_valid_window(&mut out, ctx.valid_window.as_ref());
    put_opt_str(&mut out, ctx.audit_target_object_id.as_deref());
    out
}

/// `SHA256(READER_AUTHORIZATION_CONTEXT_DIGEST_DOMAIN || canonical_encode_reader_authorization(ctx))`.
///
/// Folded into the reader-authorization Schnorr signature's Fiat-Shamir
/// challenge alongside the recipient key and nonce commitment. No
/// ciphertext-binding term — see [`ReaderAuthorizationContext`]'s doc comment
/// for why that's a deliberate choice, not an omission.
pub fn reader_authorization_context_digest(ctx: &ReaderAuthorizationContext) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(READER_AUTHORIZATION_CONTEXT_DIGEST_DOMAIN);
    hasher.update(canonical_encode_reader_authorization(ctx));
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

    /// a context with no PET tag must
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

    fn sample_reader_auth_context() -> ReaderAuthorizationContext {
        ReaderAuthorizationContext {
            chain_id: "vera-test".into(),
            ring_pk: vec![1, 2, 3, 4],
            jwt_issuer: "did:key:issuer".into(),
            jwt_subject: None,
            resolved_actor: "did:key:issuer".into(),
            jwt_id: "jti-1".into(),
            jwt_issued_time: 1000,
            jwt_expiration_time: 2000,
            jwt_not_before: None,
            object_id: "object-1".into(),
            recipient_pk: vec![9, 9, 9],
            derivation: None,
            salt: None,
            valid_window: None,
            audit_target_object_id: None,
        }
    }

    #[test]
    fn reader_authorization_canonical_encode_is_deterministic() {
        assert_eq!(
            canonical_encode_reader_authorization(&sample_reader_auth_context()),
            canonical_encode_reader_authorization(&sample_reader_auth_context())
        );
    }

    #[test]
    fn reader_authorization_distinct_object_ids_produce_distinct_encodings() {
        let base = sample_reader_auth_context();
        let mut other = base.clone();
        other.object_id = "object-2".into();
        assert_ne!(
            canonical_encode_reader_authorization(&base),
            canonical_encode_reader_authorization(&other)
        );

        // Ambiguity guard: moving a byte across the jwt_issuer/resolved_actor
        // boundary must not collide thanks to the length prefixes.
        let mut a = base.clone();
        a.jwt_issuer = "ab".into();
        a.resolved_actor = "c".into();
        let mut b = base.clone();
        b.jwt_issuer = "a".into();
        b.resolved_actor = "bc".into();
        assert_ne!(
            canonical_encode_reader_authorization(&a),
            canonical_encode_reader_authorization(&b)
        );
    }

    #[test]
    fn reader_authorization_option_presence_changes_encoding() {
        let mut none_salt = sample_reader_auth_context();
        none_salt.salt = None;
        let mut empty_salt = sample_reader_auth_context();
        empty_salt.salt = Some(String::new());
        assert_ne!(
            canonical_encode_reader_authorization(&none_salt),
            canonical_encode_reader_authorization(&empty_salt),
            "None and Some(\"\") must not collide"
        );

        let mut no_window = sample_reader_auth_context();
        no_window.valid_window = None;
        let mut with_window = sample_reader_auth_context();
        with_window.valid_window = Some(ValidWindowBinding { start: 0, end: 0 });
        assert_ne!(
            canonical_encode_reader_authorization(&no_window),
            canonical_encode_reader_authorization(&with_window),
            "presence of a valid_window must change the encoding even when start=end=0"
        );
    }

    #[test]
    fn reader_authorization_context_digest_binds_every_field() {
        let base = sample_reader_auth_context();
        let base_digest = reader_authorization_context_digest(&base);

        let mut different_chain = base.clone();
        different_chain.chain_id = "vera-other".into();
        assert_ne!(
            base_digest,
            reader_authorization_context_digest(&different_chain)
        );

        let mut different_recipient = base.clone();
        different_recipient.recipient_pk = vec![0, 0, 0];
        assert_ne!(
            base_digest,
            reader_authorization_context_digest(&different_recipient)
        );

        let mut different_jti = base;
        different_jti.jwt_id = "jti-2".into();
        assert_ne!(
            base_digest,
            reader_authorization_context_digest(&different_jti)
        );
    }
}
