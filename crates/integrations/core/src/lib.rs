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

impl SignOperation {
    /// Canonical, deterministic, domain-separated encoding. Each
    /// variable-length field is length-prefixed so no concatenation of two
    /// fields can collide with a different split of the same bytes (e.g.
    /// `ring_id="AB", derivation_id="C"` vs `ring_id="A", derivation_id="BC"`).
    pub fn canonical_bytes(&self) -> Vec<u8> {
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
}
