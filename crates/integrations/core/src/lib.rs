//! Shared operation and authentication evidence model for Orbis flows.
//!
//! An operation (e.g. [`SignOperation`]) canonically encodes exactly what's
//! being authorized. Encoding is one-way by design: a verifier reconstructs
//! the *expected* operation from the live request it already has in hand
//! (ring id, derivation id, message digest, plus the evidence's own
//! expiry/nonce), re-encodes it, and compares the result against whatever
//! the evidence actually committed to — it never parses an untrusted
//! encoding back apart.
//!
//! This crate stays independent of HTTP frameworks, databases, mail
//! delivery, and node startup. ACP permission evaluation and threshold
//! cryptography belong to their existing layers. A verification result
//! produced in one process is not proof for another — every participating
//! Orbis node must independently verify the original evidence itself.

/// An operation some authentication evidence's challenge must commit to.
/// Implemented by each protocol's own operation type (`SignOperation`,
/// `PreOperation`, `StoreSecretOperation`); lets a single generic verifier
/// (see `orbis_webauthn::verify_and_build_token`, dispatched per endpoint
/// via `authn::endpoints::EndpointAuth`) work across every protocol
/// without knowing their individual field shapes.
pub trait CanonicalOperation {
    fn canonical_bytes(&self) -> Vec<u8>;
}

/// Produces authentication evidence for an operation `Op`, authorizing it in
/// place of a JWT. Each mechanism's own crate (`orbis-webauthn`, and in the
/// future an email/DKIM crate) implements this for its own evidence type;
/// a generic caller (`orbis-sdk`'s `submit_*_with_evidence` functions) never
/// needs to know which mechanism it's holding.
///
/// `Wire` is the mechanism's own evidence payload shape — e.g.
/// `orbis_webauthn::WebAuthnEvidence` — independent of any one protocol's
/// generated proto type, since every service's request message is a
/// distinct Rust type even where their fields are identical. A caller maps
/// `Wire` into the right wire format at its own boundary.
///
/// `produce` takes `operation` so a mechanism that must bind its evidence to
/// the operation's own canonical encoding (anything challenge-based) can do
/// so; a mechanism that already produced self-contained evidence elsewhere
/// (e.g. a WebAuthn assertion a browser already signed over the exact
/// challenge bytes) just repackages it and ignores `operation`.
pub trait ChallengeEvidence<Op: CanonicalOperation> {
    type Wire;
    type Error: std::fmt::Display;

    fn produce(self, operation: &Op) -> Result<Self::Wire, Self::Error>;
}

/// Domain separator for the Sign operation encoding. Bump the version
/// suffix on any incompatible change to the encoded fields or their order.
pub const SIGN_OPERATION_DOMAIN: &[u8] = b"orbis-integration-sign-operation-v1";

/// The exact Sign request a piece of authentication evidence must commit to
/// — e.g. embedded as a WebAuthn assertion's `challenge`. A verified
/// assertion is itself the request-binding proof; nothing else carries it.
///
/// Deliberately the same scope as `SignClaims` (`derivation_id` +
/// `message_sha256`, no `ring_id`): `derivation_id` already determines
/// `ring_id` via a trusted, non-spoofable bulletin lookup, so binding it
/// again here would add nothing — the existing JWT-based claims don't
/// either.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignOperation {
    pub derivation_id: String,
    pub message_sha256: Vec<u8>,
    /// Unix seconds; evidence for this operation is rejected once `now`
    /// passes this. Chosen by whoever builds the operation, not derived.
    pub expiry: u64,
    /// Per-request randomness. Not a security boundary by itself — the
    /// fields above already bind the request to one exact operation — but
    /// it lets a caller that wants single-use semantics track consumed
    /// nonces itself. This crate holds no state of its own.
    pub nonce: [u8; 16],
}

impl CanonicalOperation for SignOperation {
    /// Canonical, deterministic, domain-separated encoding. Each
    /// variable-length field is length-prefixed so no concatenation of two
    /// fields can collide with a different split of the same bytes (e.g.
    /// `ring_id="AB", derivation_id="C"` vs `ring_id="A", derivation_id="BC"`).
    fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            SIGN_OPERATION_DOMAIN.len()
                + 8
                + self.derivation_id.len()
                + 8
                + self.message_sha256.len()
                + 8
                + self.nonce.len(),
        );
        out.extend_from_slice(SIGN_OPERATION_DOMAIN);
        write_len_prefixed(&mut out, self.derivation_id.as_bytes());
        write_len_prefixed(&mut out, &self.message_sha256);
        out.extend_from_slice(&self.expiry.to_be_bytes());
        out.extend_from_slice(&self.nonce);
        out
    }
}

fn write_len_prefixed(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// A present-but-empty field must not encode identically to an absent one,
/// so this writes a presence byte before the length-prefixed bytes rather
/// than treating `None` as a zero-length `Some`.
fn write_optional(out: &mut Vec<u8>, bytes: Option<&[u8]>) {
    match bytes {
        Some(bytes) => {
            out.push(1);
            write_len_prefixed(out, bytes);
        }
        None => out.push(0),
    }
}

/// Domain separator for the PRE operation encoding. Bump the version suffix
/// on any incompatible change to the encoded fields or their order.
pub const PRE_OPERATION_DOMAIN: &[u8] = b"orbis-integration-pre-operation-v1";

/// The exact PRE decrypt request a piece of authentication evidence must
/// commit to — e.g. embedded as a WebAuthn assertion's `challenge`. Same
/// scope as `PreClaims` (`rdr_pk`/`object_id`/`derivation`/`salt`), plus the
/// fields evidence alone needs to add.
///
/// `issued_at` is not a convenience timestamp like `SignOperation` doesn't
/// need one for: PRE's reader-key proof-of-possession
/// (`ReaderAuthorizationContext`) binds the authenticating token's
/// `issued_time` into a signature the *client* produces before the server
/// ever sees the request. The server must reconstruct an identical
/// transcript to verify that signature, so this value has to be something
/// both sides already agree on — client-chosen and carried here, never
/// "now" at verification time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreOperation {
    pub object_id: String,
    pub rdr_pk: Vec<u8>,
    pub derivation: Option<Vec<u8>>,
    pub salt: Option<String>,
    pub issued_at: u64,
    /// Unix seconds; evidence for this operation is rejected once `now`
    /// passes this. Chosen by whoever builds the operation, not derived.
    pub expiry: u64,
    /// Per-request randomness. Not a security boundary by itself — the
    /// fields above already bind the request to one exact operation — but
    /// it lets a caller that wants single-use semantics track consumed
    /// nonces itself. This crate holds no state of its own.
    pub nonce: [u8; 16],
}

impl CanonicalOperation for PreOperation {
    /// Canonical, deterministic, domain-separated encoding. See
    /// [`SignOperation::canonical_bytes`] for why every variable-length
    /// field is length-prefixed, and [`write_optional`] for why an absent
    /// optional field can't just encode as a zero-length one.
    fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(PRE_OPERATION_DOMAIN);
        write_len_prefixed(&mut out, self.object_id.as_bytes());
        write_len_prefixed(&mut out, &self.rdr_pk);
        write_optional(&mut out, self.derivation.as_deref());
        write_optional(&mut out, self.salt.as_deref().map(str::as_bytes));
        out.extend_from_slice(&self.issued_at.to_be_bytes());
        out.extend_from_slice(&self.expiry.to_be_bytes());
        out.extend_from_slice(&self.nonce);
        out
    }
}

/// Domain separator for the StoreSecret operation encoding. Bump the
/// version suffix on any incompatible change to the encoded fields or
/// their order.
pub const STORE_SECRET_OPERATION_DOMAIN: &[u8] = b"orbis-integration-store-secret-operation-v1";

/// The exact StoreSecret request a piece of authentication evidence must
/// commit to. Same scope as `StoreSecretClaims` — no `issued_at` the way
/// `PreOperation` needs one: nothing downstream cryptographically binds
/// this request's `issued_time` into a further signature the way PRE's
/// reader-key proof-of-possession does, so (like `SignOperation`)
/// verification-time "now" is fine for the synthetic token's
/// `issued_time`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreSecretOperation {
    pub encrypted_document_sha256: Vec<u8>,
    pub enc_cmt: Vec<u8>,
    pub ring_id: String,
    pub policy_id: String,
    pub resource: String,
    pub permission: String,
    pub challenge: Vec<u8>,
    pub response: Vec<u8>,
    pub with_proof: bool,
    pub tier: Option<String>,
    pub timestamp: Option<u64>,
    /// Unix seconds; evidence for this operation is rejected once `now`
    /// passes this. Chosen by whoever builds the operation, not derived.
    pub expiry: u64,
    /// Per-request randomness — see `SignOperation::nonce`'s doc comment.
    pub nonce: [u8; 16],
}

impl CanonicalOperation for StoreSecretOperation {
    /// Canonical, deterministic, domain-separated encoding — see
    /// [`SignOperation::canonical_bytes`] for why every variable-length
    /// field is length-prefixed, and [`write_optional`] for why an absent
    /// optional field can't just encode as a zero-length one.
    fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(STORE_SECRET_OPERATION_DOMAIN);
        write_len_prefixed(&mut out, &self.encrypted_document_sha256);
        write_len_prefixed(&mut out, &self.enc_cmt);
        write_len_prefixed(&mut out, self.ring_id.as_bytes());
        write_len_prefixed(&mut out, self.policy_id.as_bytes());
        write_len_prefixed(&mut out, self.resource.as_bytes());
        write_len_prefixed(&mut out, self.permission.as_bytes());
        write_len_prefixed(&mut out, &self.challenge);
        write_len_prefixed(&mut out, &self.response);
        out.push(self.with_proof as u8);
        write_optional(&mut out, self.tier.as_deref().map(str::as_bytes));
        match self.timestamp {
            Some(timestamp) => {
                out.push(1);
                out.extend_from_slice(&timestamp.to_be_bytes());
            }
            None => out.push(0),
        }
        out.extend_from_slice(&self.expiry.to_be_bytes());
        out.extend_from_slice(&self.nonce);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> SignOperation {
        SignOperation {
            derivation_id: "deriv-1".to_string(),
            message_sha256: vec![1, 2, 3],
            expiry: 1_700_000_000,
            nonce: [7; 16],
        }
    }

    #[test]
    fn canonical_bytes_is_deterministic() {
        assert_eq!(sample().canonical_bytes(), sample().canonical_bytes());
    }

    #[test]
    fn differing_field_split_does_not_collide() {
        // Same concatenated bytes (b"ABC"), split differently between
        // derivation_id and message_sha256 — length-prefixing must keep
        // these from encoding identically.
        let a = SignOperation {
            derivation_id: "AB".to_string(),
            message_sha256: vec![b'C'],
            ..sample()
        };
        let b = SignOperation {
            derivation_id: "A".to_string(),
            message_sha256: vec![b'B', b'C'],
            ..sample()
        };
        assert_ne!(a.canonical_bytes(), b.canonical_bytes());
    }

    #[test]
    fn differing_nonce_or_expiry_changes_encoding() {
        let base = sample();

        let mut different_nonce = base.clone();
        different_nonce.nonce = [8; 16];
        assert_ne!(base.canonical_bytes(), different_nonce.canonical_bytes());

        let mut different_expiry = base.clone();
        different_expiry.expiry += 1;
        assert_ne!(base.canonical_bytes(), different_expiry.canonical_bytes());
    }

    fn sample_pre() -> PreOperation {
        PreOperation {
            object_id: "object-1".to_string(),
            rdr_pk: vec![1, 2, 3],
            derivation: None,
            salt: None,
            issued_at: 1_700_000_000,
            expiry: 1_700_000_300,
            nonce: [9; 16],
        }
    }

    #[test]
    fn pre_canonical_bytes_is_deterministic() {
        assert_eq!(
            sample_pre().canonical_bytes(),
            sample_pre().canonical_bytes()
        );
    }

    #[test]
    fn pre_absent_optional_differs_from_present_empty() {
        let absent = PreOperation {
            salt: None,
            ..sample_pre()
        };
        let present_empty = PreOperation {
            salt: Some(String::new()),
            ..sample_pre()
        };
        assert_ne!(absent.canonical_bytes(), present_empty.canonical_bytes());
    }

    #[test]
    fn pre_differing_issued_at_changes_encoding() {
        let base = sample_pre();
        let mut different = base.clone();
        different.issued_at += 1;
        assert_ne!(base.canonical_bytes(), different.canonical_bytes());
    }

    fn sample_store_secret() -> StoreSecretOperation {
        StoreSecretOperation {
            encrypted_document_sha256: vec![1, 2, 3],
            enc_cmt: vec![4, 5, 6],
            ring_id: "ring-1".to_string(),
            policy_id: "policy-1".to_string(),
            resource: "document".to_string(),
            permission: "read".to_string(),
            challenge: vec![7, 8],
            response: vec![9, 10],
            with_proof: true,
            tier: None,
            timestamp: None,
            expiry: 1_700_000_300,
            nonce: [11; 16],
        }
    }

    #[test]
    fn store_secret_canonical_bytes_is_deterministic() {
        assert_eq!(
            sample_store_secret().canonical_bytes(),
            sample_store_secret().canonical_bytes()
        );
    }

    #[test]
    fn store_secret_with_proof_changes_encoding() {
        let base = sample_store_secret();
        let mut different = base.clone();
        different.with_proof = !different.with_proof;
        assert_ne!(base.canonical_bytes(), different.canonical_bytes());
    }

    #[test]
    fn store_secret_absent_timestamp_differs_from_present_zero() {
        let absent = StoreSecretOperation {
            timestamp: None,
            ..sample_store_secret()
        };
        let present_zero = StoreSecretOperation {
            timestamp: Some(0),
            ..sample_store_secret()
        };
        assert_ne!(absent.canonical_bytes(), present_zero.canonical_bytes());
    }
}
