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

/// Whether `body` contains `text`, tolerating mail-reply artifacts at
/// exactly two places: leading `>` quote markers (RFC 3676) plus
/// incidental leading/trailing whitespace, stripped per *line*, never
/// from the middle of one — and *where* a line break falls at all, which
/// [`normalize`] treats as unconstrained rather than trying to detect and
/// undo any one specific wrapping convention (a mail client's own hard
/// wrap with no signal it happened at all, or RFC 3676 `format=flowed`'s
/// trailing-space-marked soft wrap, are both covered by this one rule,
/// with no wrapping-convention-specific logic needed for either). This is
/// deliberately not a blanket character filter — an earlier version of
/// this function deleted every `-`, whitespace, and `>` character
/// anywhere in both strings, which tolerated mail-client reformatting but
/// also silently collapsed *distinct* field values into the same
/// normalized string (`"ab-cd"` and `"abcd"`, or `"foo bar"` and
/// `"foobar"`, compared equal) — turning the exact-text binding this
/// module exists to provide into something a captured reply for one
/// operation could satisfy for a different one, as long as the rest of
/// the rendering happened to match.
///
/// Discarding line breaks entirely doesn't reopen that hole, because a
/// newline is never semantic content to begin with: every
/// [`orbis_integration_core::CanonicalDisplay`] implementation escapes a
/// literal `\n`/`\r` inside a value into the two-character text `\n`/`\r`
/// (see that trait's own doc comment), so a real line-break byte only
/// ever appears as this module's own structural filler, never as part of
/// a value — nothing is lost by ignoring where it falls. Field boundaries
/// stay unambiguous on their own: a quoted field's value can never
/// contain a bare `"` (any literal quote inside it is escaped to `\"`),
/// and a hex-encoded field's alphabet (`[0-9a-f]`) can never be confused
/// with the next field's label, since no label here is composed entirely
/// of hex digits. Quoted-printable soft line breaks (mid-token wraps
/// within a single line) are handled upstream by actually decoding the
/// message (`crate::message_contains_text`), not by anything here.
///
/// Case is preserved (not folded): unlike a short, meaningless derived
/// code, this text carries real identifying data (hex-encoded hashes and
/// keys, IDs), so case-insensitive matching would risk treating two
/// distinct values that differ only in case as the same.
pub fn body_contains_text(body: &[u8], text: &str) -> bool {
    let body_text = String::from_utf8_lossy(body);
    normalize(&body_text).contains(&normalize(text))
}

/// Strips each line's leading `>`/whitespace and trailing whitespace,
/// then concatenates every line directly with no separator — not even a
/// `\n` — so a line break's exact position (and whether the mail client
/// that put it there used a hard wrap, `format=flowed`, or anything
/// else) never affects the comparison. See [`body_contains_text`]'s own
/// doc comment for why this is safe to do unconditionally rather than a
/// renewed version of the blanket-stripping bug it already fixed once.
fn normalize(value: &str) -> String {
    value
        .lines()
        .map(|line| {
            line.trim_start_matches(|c: char| c == '>' || c.is_whitespace())
                .trim_end()
        })
        .collect::<String>()
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
    fn body_contains_text_survives_surrounding_content_and_blank_lines() {
        let text = "toy-operation: deadbeef\nexpiry: 123\n";
        let body = "Hi, replying to confirm:\n\ntoy-operation: deadbeef\nexpiry: 123\n\nthanks!";
        assert!(body_contains_text(body.as_bytes(), text));
    }

    #[test]
    fn body_contains_text_survives_trailing_whitespace_per_line() {
        // Some mail clients/editors leave trailing spaces on lines — not a
        // position-anchored artifact `normalize` needs to invent tolerance
        // for; `trim_end()` per line already covers it for free.
        let text = "toy-operation: deadbeef\nexpiry: 123\n";
        let body = "toy-operation: deadbeef  \nexpiry: 123   \n";
        assert!(body_contains_text(body.as_bytes(), text));
    }

    /// The exact flaw this module's own doc comment calls out: a blanket
    /// character filter would delete the hyphen from both sides and treat
    /// these as the same operation. They must not match — a captured
    /// reply for one derivation must never authorize the other.
    #[test]
    fn body_contains_text_does_not_collapse_hyphenated_and_unhyphenated_values() {
        let text = "derivation: \"ab-cd\"\n";
        let body = "derivation: \"abcd\"\n";
        assert!(!body_contains_text(body.as_bytes(), text));
    }

    /// Same flaw, for whitespace instead of a hyphen: a value containing a
    /// real space must not match a different value with that space
    /// removed.
    #[test]
    fn body_contains_text_does_not_collapse_values_differing_only_by_a_space() {
        let text = "derivation: \"foo bar\"\n";
        let body = "derivation: \"foobar\"\n";
        assert!(!body_contains_text(body.as_bytes(), text));
    }

    /// A `>` that's part of a value's own content (not a line-leading
    /// quote marker) must not be stripped — only `>` at the *start* of a
    /// line is quote-reply syntax.
    #[test]
    fn body_contains_text_does_not_strip_a_mid_line_angle_bracket() {
        let text = "derivation: \"a>b\"\n";
        let body = "derivation: \"ab\"\n";
        assert!(!body_contains_text(body.as_bytes(), text));
    }

    #[test]
    fn body_contains_text_survives_reply_quoting() {
        let text = "toy-operation: deadbeef\nexpiry: 123\n";
        let body =
            "> toy-operation: deadbeef\n> expiry: 123\n>\n> On Mon, Jan 1, 2026, Ring wrote:";
        assert!(body_contains_text(body.as_bytes(), text));
    }

    /// Reproduces a real production failure: Gmail's own reply-quoting
    /// split a single-line `derivation: "<64 hex chars>"` field between
    /// the label and its value — not because the value itself was
    /// mid-token wrapped, but because the whole line, once quoted, didn't
    /// fit, and Gmail chose to push the unbreakable value entirely onto
    /// its own line. No RFC 3676 `format=flowed` marker was present to
    /// signal this had happened. This must match regardless of whether
    /// the *sent* text ever had this split — the point of this test (as
    /// opposed to the one in `orbis_integration_core` that checks
    /// `canonical_display` itself never renders a line long enough to
    /// risk this) is that the matching side tolerates it even if some
    /// future field, or some other client, wraps somewhere this crate's
    /// own rendering didn't anticipate.
    #[test]
    fn body_contains_text_survives_a_line_wrapped_between_a_label_and_its_value() {
        // Matches the shape `label_and_long_value` actually renders:
        // label, then colon, then a line break — no space before it.
        let text = "derivation:\n\"deadbeefcafe\"\nexpiry: 123\n";
        let body = "> derivation:\n> \"deadbeefcafe\"\n> expiry: 123\n>\n> wrote:";
        assert!(body_contains_text(body.as_bytes(), text));
    }

    /// Same general tolerance, but for a wrap landing *inside* a single
    /// unbreakable value (mid-hex-string), with no quote markers at all —
    /// the shape a naive hard-wrap (not reply-quoting) produces.
    #[test]
    fn body_contains_text_survives_a_line_wrapped_mid_value() {
        let text = "rdr_pk: deadbeefcafef00dfeedface\n";
        let body = "rdr_pk: deadbeefcafe\nf00dfeedface\n";
        assert!(body_contains_text(body.as_bytes(), text));
    }

    /// RFC 3676 `format=flowed`'s own soft-wrap signal — a single
    /// trailing space before the line break, meaning "rejoin this with
    /// the next line" — needs no special-case handling: the existing
    /// per-line `trim_end()` already strips that trailing space, and the
    /// newline itself is discarded unconditionally regardless of why it's
    /// there.
    #[test]
    fn body_contains_text_survives_a_format_flowed_soft_wrap() {
        let text = "rdr_pk: deadbeefcafef00dfeedface\n";
        let body = "rdr_pk: deadbeefcafe \r\nf00dfeedface\r\n";
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
