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

/// Human-legible, deterministic rendering of an operation — for mechanisms
/// where a person, not a dedicated signing key, is the one approving a
/// request (today, `orbis-email`'s DKIM-signed-reply binding). A verifier
/// reconstructs this exact text from the live request the same way it
/// reconstructs [`CanonicalOperation::canonical_bytes`], and checks that
/// authenticated evidence's content contains it. Unlike `canonical_bytes`,
/// this is designed to be *read*, not just compared byte-for-byte: a
/// person approving a request can see exactly what they're approving
/// (what-you-sign-is-what-you-see), which an opaque hash or binary blob
/// doesn't give them.
///
/// Deliberately a separate trait from [`CanonicalOperation`], not an
/// additional required method on it: a mechanism like WebAuthn signs
/// opaque bytes directly with no person reading a textual commitment, so
/// it has no need to implement this, and no existing `CanonicalOperation`
/// implementor (including test-only toy types elsewhere in this
/// workspace) is forced to grow a method it never uses.
pub trait CanonicalDisplay: CanonicalOperation {
    fn canonical_display(&self) -> String;
}

/// Minimally escapes `value`'s special characters, without yet adding the
/// surrounding quotes [`label_and_long_value`] puts around it — kept
/// separate from quoting so chunking (see [`chunk_long_value`]) operates
/// on the escaped content alone and the quote marks land exactly at the
/// start and end of the whole value, never shifted by one character the
/// way chunking an already-quoted string would (a real failure mode this
/// was built to avoid, not a hypothetical one — see
/// [`label_and_long_value`]'s own doc comment).
fn escape_display_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            _ => out.push(ch),
        }
    }
    out
}

/// The widest a chunk of a long value (see [`chunk_long_value`]) is
/// allowed to render as, in characters. Chosen with a comfortable margin
/// below the ~76-78 character width most mail clients wrap plain text
/// at — not just enough for one `> ` reply-quote prefix (2 characters),
/// but several, in case a reply is itself quoted again, and the one or
/// two bytes [`label_and_long_quoted_value`] adds for its surrounding
/// quote marks.
const CHUNK_WIDTH: usize = 64;

/// Splits `value` into fixed-width (at most [`CHUNK_WIDTH`] characters,
/// never bytes — a caller-controlled string can contain multi-byte UTF-8)
/// lines, each followed by `\n`. An empty value still renders as one
/// (empty) line, never zero lines, so a caller formatting it between two
/// labeled fields never loses the line break between them. A value
/// already at or under `CHUNK_WIDTH` renders as a single such line, so
/// this is always safe to call unconditionally.
fn chunk_long_value(value: &str) -> String {
    if value.is_empty() {
        return "\n".to_string();
    }
    let mut out = String::with_capacity(value.len() + value.len() / CHUNK_WIDTH + 1);
    let mut chars = value.chars().peekable();
    while chars.peek().is_some() {
        let chunk: String = chars.by_ref().take(CHUNK_WIDTH).collect();
        out.push_str(&chunk);
        out.push('\n');
    }
    out
}

/// Renders `label` and `value` on their own line(s) (`"{label}:\n{value}\n"`,
/// `value` itself chunked via [`chunk_long_value`] if it's long) instead
/// of sharing one line with the label — for any [`CanonicalDisplay`]
/// field whose rendered value is bare (never quoted: hex, or the
/// unquoted `(none)` sentinel) but variable-length or always long, where
/// label-plus-value, or even the value alone, risks crossing the width
/// most mail clients wrap plain text at. [`label_and_long_quoted_value`]
/// is the equivalent for a value that needs surrounding quotes.
///
/// Confirmed against a real-world failure, not a theoretical one: a
/// single-line `derivation: "<64 hex chars>"` (78 characters — right at
/// that width) got split by Gmail's reply-quoting between the label and
/// the value, with no RFC 3676 `format=flowed` marker to signal it had
/// been wrapped, so [`crate::CanonicalDisplay`]'s own matching side (see
/// `orbis_email::challenge_text`'s doc comment on tolerating a mail
/// client's line-wrapping) had nothing to reconstruct from — quoting adds
/// its own `> ` prefix on top of whatever margin the original line had,
/// so even a line that looked safely short when first sent can still get
/// wrapped once quoted back in a reply. A long value alone can cross that
/// width too (a compressed BLS12-381 G1 point is 96 hex characters) —
/// chunking isn't just for the label/value split. Rendering everything
/// comfortably short up front means a mail client never needs to touch
/// any of these lines at all — closing the gap rather than trying to
/// detect and undo whatever a specific client's wrapping happened to do.
fn label_and_long_value(label: &str, value: &str) -> String {
    format!("{label}:\n{}", chunk_long_value(value))
}

/// Same as [`label_and_long_value`], but for a value that needs
/// [`escape_display_value`]'s quoting (any legitimately-present string
/// field, to stay visibly distinct from the unquoted `(none)` sentinel
/// an absent optional field renders as). Escapes and chunks `raw_value`
/// first, *then* adds the opening and closing quote to the very start
/// and very end of the (possibly multi-line) result — never quotes
/// first and chunks second, which would shift chunk boundaries by the
/// width of the leading quote mark and could split the value one
/// character later than a clean rendering would, right before the
/// closing quote.
fn label_and_long_quoted_value(label: &str, raw_value: &str) -> String {
    let mut chunked = chunk_long_value(&escape_display_value(raw_value));
    chunked.insert(0, '"');
    let before_final_newline = chunked.len() - 1;
    chunked.insert(before_final_newline, '"');
    format!("{label}:\n{chunked}")
}

/// Same as [`label_and_long_quoted_value`], but for an optional string
/// field ([`display_optional_string`]'s own shape): quoted when present,
/// the bare `(none)` sentinel — never quoted, never chunked, always
/// short — when absent.
fn label_and_long_optional_string(label: &str, value: Option<&str>) -> String {
    match value {
        Some(value) => label_and_long_quoted_value(label, value),
        None => format!("{label}:\n(none)\n"),
    }
}

/// Same as [`label_and_long_value`], but for an optional bytes field
/// ([`display_optional_bytes`]'s own shape): hex-encoded and chunked
/// when present, the bare `(none)` sentinel when absent.
fn label_and_long_optional_bytes(label: &str, value: Option<&[u8]>) -> String {
    match value {
        Some(bytes) => label_and_long_value(label, &hex::encode(bytes)),
        None => format!("{label}:\n(none)\n"),
    }
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

impl CanonicalDisplay for SignOperation {
    /// Each field labeled, in the same order as
    /// [`SignOperation::canonical_bytes`] — see that method and
    /// [`CanonicalDisplay`]'s own doc comments. A variable-length or
    /// always-long value gets its own line, label above it — see
    /// [`label_and_long_value`]'s own doc comment for why.
    fn canonical_display(&self) -> String {
        format!(
            "{}\n{}{}expiry_unix: {}\nnonce: {}\n",
            std::str::from_utf8(SIGN_OPERATION_DOMAIN).expect("domain separator is ASCII"),
            label_and_long_quoted_value("derivation", &self.derivation_id),
            label_and_long_value("message_sha256", &hex::encode(&self.message_sha256)),
            self.expiry,
            hex::encode(self.nonce),
        )
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

impl CanonicalDisplay for PreOperation {
    /// Each field labeled, in the same order as
    /// [`PreOperation::canonical_bytes`] — see that method and
    /// [`CanonicalDisplay`]'s own doc comment. A variable-length or
    /// always-long value gets its own line, label above it — see
    /// [`label_and_long_value`]'s own doc comment for why.
    fn canonical_display(&self) -> String {
        format!(
            "{}\n{}{}{}{}issued_at_unix: {}\nexpiry_unix: {}\nnonce: {}\n",
            std::str::from_utf8(PRE_OPERATION_DOMAIN).expect("domain separator is ASCII"),
            label_and_long_quoted_value("object_id", &self.object_id),
            label_and_long_value("rdr_pk", &hex::encode(&self.rdr_pk)),
            label_and_long_optional_bytes("derivation", self.derivation.as_deref()),
            label_and_long_optional_string("salt", self.salt.as_deref()),
            self.issued_at,
            self.expiry,
            hex::encode(self.nonce),
        )
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

impl CanonicalDisplay for StoreSecretOperation {
    /// Each field labeled, in the same order as
    /// [`StoreSecretOperation::canonical_bytes`] — see that method and
    /// [`CanonicalDisplay`]'s own doc comment. A variable-length or
    /// always-long value gets its own line, label above it — see
    /// [`label_and_long_value`]'s own doc comment for why.
    fn canonical_display(&self) -> String {
        format!(
            "{}\n{}{}{}{}{}{}{}{}with_proof: {}\n{}timestamp_unix: {}\nexpiry_unix: {}\nnonce: {}\n",
            std::str::from_utf8(STORE_SECRET_OPERATION_DOMAIN).expect("domain separator is ASCII"),
            label_and_long_value(
                "encrypted_document_sha256",
                &hex::encode(&self.encrypted_document_sha256)
            ),
            label_and_long_value("enc_cmt", &hex::encode(&self.enc_cmt)),
            label_and_long_quoted_value("ring_id", &self.ring_id),
            label_and_long_quoted_value("policy_id", &self.policy_id),
            label_and_long_quoted_value("resource", &self.resource),
            label_and_long_quoted_value("permission", &self.permission),
            label_and_long_value("challenge", &hex::encode(&self.challenge)),
            label_and_long_value("response", &hex::encode(&self.response)),
            self.with_proof,
            label_and_long_optional_string("tier", self.tier.as_deref()),
            match self.timestamp {
                Some(timestamp) => timestamp.to_string(),
                None => "(none)".to_string(),
            },
            self.expiry,
            hex::encode(self.nonce),
        )
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

    #[test]
    fn canonical_display_is_deterministic_and_sensitive_to_every_field() {
        let base = sample();
        assert_eq!(base.canonical_display(), base.canonical_display());

        let mut different_derivation = base.clone();
        different_derivation.derivation_id = "deriv-2".to_string();
        assert_ne!(
            base.canonical_display(),
            different_derivation.canonical_display()
        );

        let mut different_message = base.clone();
        different_message.message_sha256 = vec![9, 9, 9];
        assert_ne!(
            base.canonical_display(),
            different_message.canonical_display()
        );

        let mut different_nonce = base.clone();
        different_nonce.nonce = [8; 16];
        assert_ne!(
            base.canonical_display(),
            different_nonce.canonical_display()
        );

        let mut different_expiry = base.clone();
        different_expiry.expiry += 1;
        assert_ne!(
            base.canonical_display(),
            different_expiry.canonical_display()
        );
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

    #[test]
    fn pre_canonical_display_is_deterministic_and_distinguishes_absent_from_sentinel_value() {
        let base = sample_pre();
        assert_eq!(base.canonical_display(), base.canonical_display());

        let mut different_rdr_pk = base.clone();
        different_rdr_pk.rdr_pk = vec![9, 9, 9];
        assert_ne!(
            base.canonical_display(),
            different_rdr_pk.canonical_display()
        );

        // A present salt whose value is literally the unquoted sentinel text
        // must still render distinctly from a genuinely absent salt.
        let absent = PreOperation {
            salt: None,
            ..base.clone()
        };
        let sentinel_value = PreOperation {
            salt: Some("(none)".to_string()),
            ..base
        };
        assert_ne!(
            absent.canonical_display(),
            sentinel_value.canonical_display()
        );
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

    /// Reproduces a real production failure: a single-line
    /// `derivation: "<64 hex chars>"` (78 characters total) got split by
    /// Gmail's own reply-quoting between the label and the value, with no
    /// RFC 3676 `format=flowed` marker to signal it had been wrapped —
    /// so there was nothing for the matching side to reconstruct. Every
    /// line `canonical_display()` renders must stay short enough to
    /// survive at least one level of `> ` quoting (2 extra characters)
    /// without crossing the ~76-78 character width most mail clients wrap
    /// plain text at, for every operation type and realistically-sized
    /// field value — not just the short fixtures the other tests above
    /// use, which were never close to that width in the first place.
    #[test]
    fn canonical_display_lines_survive_one_level_of_reply_quoting() {
        const MAIL_CLIENT_WRAP_WIDTH: usize = 78;
        const QUOTE_PREFIX_LEN: usize = "> ".len();
        const SAFE_WIDTH: usize = MAIL_CLIENT_WRAP_WIDTH - QUOTE_PREFIX_LEN;

        fn assert_every_line_is_safe(label: &str, text: &str) {
            for line in text.lines() {
                assert!(
                    line.len() <= SAFE_WIDTH,
                    "{label}: line {line:?} is {} chars, too long to survive a single \
                     level of `> ` quoting (max {SAFE_WIDTH})",
                    line.len()
                );
            }
        }

        let sign = SignOperation {
            derivation_id: "a".repeat(64),
            message_sha256: vec![0u8; 32],
            expiry: 1_795_793_967,
            nonce: [0u8; 16],
        };
        assert_every_line_is_safe("SignOperation", &sign.canonical_display());

        let pre = PreOperation {
            object_id: "b".repeat(64),
            // Realistic: a compressed BLS12-381 G1 point is 48 bytes.
            rdr_pk: vec![0u8; 48],
            derivation: Some(vec![0u8; 32]),
            salt: Some("c".repeat(64)),
            issued_at: 1_795_793_000,
            expiry: 1_795_793_967,
            nonce: [0u8; 16],
        };
        assert_every_line_is_safe("PreOperation", &pre.canonical_display());

        let store_secret = StoreSecretOperation {
            encrypted_document_sha256: vec![0u8; 32],
            enc_cmt: vec![0u8; 48],
            ring_id: "d".repeat(64),
            policy_id: "e".repeat(64),
            resource: "document".to_string(),
            permission: "read".to_string(),
            challenge: vec![0u8; 32],
            response: vec![0u8; 64],
            with_proof: true,
            tier: Some("f".repeat(64)),
            timestamp: Some(1_795_793_000),
            expiry: 1_795_793_967,
            nonce: [0u8; 16],
        };
        assert_every_line_is_safe("StoreSecretOperation", &store_secret.canonical_display());
    }
}
