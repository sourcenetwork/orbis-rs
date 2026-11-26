//! The operation-commitment binding a DKIM-signed reply must carry.
//!
//! WebAuthn embeds `operation.canonical_bytes()` directly as an exact-match
//! binary challenge, signed by a dedicated key under the browser's control.
//! Email has no equivalent signing key under this system's control — the
//! only signature in the whole flow is the reader's own mail provider's
//! DKIM key, applied to whatever text happens to be in the reply. So
//! instead of a binary challenge, the binding here is
//! [`orbis_integration_core::CanonicalDisplay::canonical_display`]: a
//! deterministic, human-legible rendering of the *entire* operation (for
//! PRE, that necessarily includes `rdr_pk` — the exact reader key, not just
//! "an email from this address") that a challenge email asks the reader to
//! read, approve, and reply to, and that [`body_contains_text`] looks for
//! as a substring of the DKIM-verified body.
//!
//! This is an *exact* match, not a hash comparison: the full rendering is
//! embedded (or quoted back) verbatim, so there is no collision space to
//! reason about the way there would be with a short derived code — the
//! match either is there, byte-for-byte (modulo the whitespace a mail
//! client's line-wrapping might introduce), or it isn't. The tradeoff is
//! size: this text is the entire operation, not a short token, so a
//! challenge email's reply is expected to quote or paste it back in full
//! rather than a human typing it from memory.

use orbis_integration_core::CanonicalDisplay;

/// The exact text a challenge email asks the reader to have present,
/// verbatim, in their DKIM-signed reply, and the one
/// [`crate::verify_email_message`] looks for.
pub fn challenge_text(operation: &impl CanonicalDisplay) -> String {
    operation.canonical_display()
}

/// Whether `body` contains `text`, ignoring whitespace and hyphens —
/// deliberately not a byte-exact match: mail clients re-wrap lines and
/// mail/text editors sometimes insert soft hyphens at wrap points, both of
/// which would otherwise break an exact substring check on a long,
/// multi-line block of text. Case is preserved (not folded): unlike a
/// short, meaningless derived code, this text carries real identifying
/// data (hex-encoded hashes and keys, IDs), so case-insensitive matching
/// would risk treating two distinct values that differ only in case as the
/// same — a risk worth avoiding now that nothing forces every field to be
/// case-normalized hex.
pub fn body_contains_text(body: &[u8], text: &str) -> bool {
    let body_text = String::from_utf8_lossy(body);
    normalize(&body_text).contains(&normalize(text))
}

fn normalize(value: &str) -> String {
    value
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use orbis_integration_core::CanonicalOperation;

    struct ToyOperation(Vec<u8>);

    impl CanonicalOperation for ToyOperation {
        fn canonical_bytes(&self) -> Vec<u8> {
            self.0.clone()
        }
    }

    impl CanonicalDisplay for ToyOperation {
        fn canonical_display(&self) -> String {
            format!("toy-operation: {}\n", hex::encode(&self.0))
        }
    }

    #[test]
    fn challenge_text_is_deterministic() {
        let op = ToyOperation(b"same-operation".to_vec());
        assert_eq!(challenge_text(&op), challenge_text(&op));
    }

    #[test]
    fn challenge_text_differs_for_different_operations() {
        let a = ToyOperation(b"operation-a".to_vec());
        let b = ToyOperation(b"operation-b".to_vec());
        assert_ne!(challenge_text(&a), challenge_text(&b));
    }

    #[test]
    fn body_contains_text_survives_wrapping_and_blank_lines() {
        let text = "toy-operation: deadbeef\nexpiry: 123\n";
        let body = "Hi, replying to confirm:\n\ntoy-operation: dead-\nbeef\nexpiry: 123\n\nthanks!";
        assert!(body_contains_text(body.as_bytes(), text));
    }

    #[test]
    fn body_contains_text_is_case_sensitive() {
        let text = "toy-operation: deadbeef\n";
        let body = "TOY-OPERATION: DEADBEEF\n";
        assert!(!body_contains_text(body.as_bytes(), text));
    }

    #[test]
    fn body_missing_text_is_rejected() {
        let text = "toy-operation: deadbeef\n";
        let body = "no matching content in here";
        assert!(!body_contains_text(body.as_bytes(), text));
    }
}
