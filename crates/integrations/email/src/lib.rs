//! DKIM email evidence integration for Orbis flows.
//!
//! A reader proves control of a mailbox by producing a DKIM-signed email;
//! every participating ring node independently verifies that proof before
//! treating the reader as an authenticated actor, exactly the way
//! `orbis-webauthn` lets a passkey assertion stand in for a JWT — see that
//! crate's own doc comment for the shared design (an exact,
//! canonically-encoded [`orbis_integration_core::CanonicalOperation`],
//! independently reconstructed and verified by every node, never trusted
//! from any one party).
//!
//! DKIM alone only proves *who sent this message*; it says nothing about
//! *which request* it authorizes. [`challenge_text`] closes that gap: a
//! deterministic, human-legible rendering of the operation's *entire*
//! canonical state (so, for PRE, necessarily including `rdr_pk` — the
//! exact reader key, not just "an email from this address") that a
//! challenge email asks the reader to read, approve, and reply to
//! verbatim, and that [`verify_email_message`] looks for as a substring of
//! the DKIM-verified body. Unlike a short derived code, this is an *exact*
//! match on the full text — no hash, no collision space — and it doubles
//! as informed consent: the reader can see exactly what they're approving
//! before replying, not just an opaque token. See [`challenge_text`]'s own
//! doc comment for why this is a textual rendering rather than the same
//! binary `canonical_bytes()` WebAuthn uses.
//!
//! The actual DKIM cryptography and message parsing are reused directly
//! from `mail-auth` (built on its pure-Rust `rust-crypto` backend) —
//! this crate only orchestrates the checks `mail-auth` doesn't do itself:
//! DMARC-style `d=`/`From:` alignment (mandatory — skipping it lets any
//! domain forge a validly-signed message claiming to be any address), the
//! challenge-text binding, and the identity/claims resolution every
//! protocol needs identically.
//!
//! Node-side verification must call this directly and independently; a
//! verification result produced by one party is never proof for another.

use authn::BearerToken;
use mail_auth::dkim::VerifySignature;
use mail_auth::dns::ResolverCache;
use mail_auth::{AuthenticatedMessage, DkimOutput, DkimResult, MessageAuthenticator, Parameters};
use orbis_integration_core::{CanonicalDisplay, CanonicalOperation, ChallengeEvidence};
use sha2::{Digest, Sha256};

mod challenge_text;
mod dns_map_cache;
mod error;
mod pinned_keys;
pub mod test_support;

pub use challenge_text::{body_contains_text, challenge_text};
pub use error::{EmailAuthError, VerifyError};
pub use pinned_keys::{PinnedDnsCache, PinnedKeysError};

pub mod endpoints;

/// Authentication evidence authorizing a request in place of a JWT: a
/// DKIM-signed email reply, plus the fields needed to resolve an identity
/// from it and bind it to an exact operation. The ACP subject is
/// `did:key:sha256(normalized address)` — the address a node independently
/// extracts from the DKIM-verified message, never `claimed_address` alone
/// (see [`verify_email_message`]). See this crate's own `build_token` for
/// why this reuses the `did:key:` scheme rather than a dedicated one.
///
/// Plain fields, not a generated proto type — see
/// `orbis_webauthn::WebAuthnEvidence`'s own doc comment for why.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EmailEvidence {
    /// The caller's own claim about which address this evidence proves —
    /// checked against, but never a substitute for, the address
    /// [`verify_email_message`] independently extracts from the signed
    /// message itself.
    pub claimed_address: String,
    /// The entire captured, DKIM-signed MIME reply.
    pub raw_message: Vec<u8>,
    /// Unix seconds, client-chosen — see `orbis_webauthn::WebAuthnEvidence`'s
    /// own doc comment on why this is never "now" at verification time.
    pub issued_at: u64,
    /// Unix seconds; rejected once `now` passes this.
    pub expiry: u64,
    pub nonce: Vec<u8>,
}

/// A DKIM-signed email reply a caller already captured, paired with the
/// fields needed to turn it into an [`EmailEvidence`] — an
/// `orbis_integration_core::ChallengeEvidence` producer for any operation.
///
/// The reply's own DKIM signature already covers the body containing the
/// operation's reply code, so, like `orbis_webauthn::PasskeyAssertion`,
/// `produce` never needs to inspect the operation itself — it only
/// repackages what was already captured. It does not verify anything;
/// verification is node-side and independent per node.
#[derive(Debug, Clone)]
pub struct SignedEmailAssertion {
    pub claimed_address: String,
    pub raw_message: Vec<u8>,
    pub issued_at: u64,
    pub expiry: u64,
    pub nonce: [u8; 16],
}

impl<Op: CanonicalOperation> ChallengeEvidence<Op> for SignedEmailAssertion {
    type Wire = EmailEvidence;
    type Error = std::convert::Infallible;

    fn produce(self, _operation: &Op) -> Result<EmailEvidence, Self::Error> {
        Ok(EmailEvidence {
            claimed_address: self.claimed_address,
            raw_message: self.raw_message,
            issued_at: self.issued_at,
            expiry: self.expiry,
            nonce: self.nonce.to_vec(),
        })
    }
}

/// Verifies a raw DKIM-signed message against `expected_text` using live
/// DNS for key resolution (`authenticator`'s own configured resolver) —
/// the production path. Returns the independently-extracted `From:`
/// address on success; `claimed_address` is checked against it but never
/// trusted on its own.
///
/// Checks, in order: at least one `DKIM-Signature` both verifies and is
/// DMARC-aligned (`d=` equals the `From:` header's domain exactly — see
/// this crate's own doc comment for why that's mandatory), `expected_text`
/// (the full operation rendering — see [`challenge_text`]) appears in the
/// verified body, and `claimed_address` (if non-empty) matches the
/// extracted address.
pub async fn verify_email_message(
    authenticator: &MessageAuthenticator,
    raw_message: &[u8],
    claimed_address: &str,
    expected_text: &str,
) -> Result<String, VerifyError> {
    let parsed = AuthenticatedMessage::parse(raw_message).ok_or(VerifyError::MalformedMessage)?;
    let results = authenticator.verify_dkim(&parsed).await;
    check_verified_results(&results, &parsed, claimed_address, expected_text)
}

/// Same as [`verify_email_message`], but resolves DKIM keys through
/// `cache` instead of live DNS — the seam a fully offline test (see
/// [`test_support`]), the production pinned-key path
/// ([`PinnedDnsCache`]), or, later, a chain-backed pinned-key store
/// attaches through.
///
/// Unlike `mail-auth`'s own cache-then-network pattern (confirmed in its
/// `txt_lookup`: "consulted before and updated after the query" — a cache
/// *miss* still falls through to live DNS and writes that answer straight
/// back into whatever cache it was given), this function never lets that
/// fallback run at all: every `(d=, s=)` pair the message's own
/// `DKIM-Signature` header(s) name must already be present in `cache`
/// ([`unpinned_signing_keys_present`]), or verification is rejected before
/// `authenticator` is ever asked to resolve anything. This is what
/// actually makes a pinned key set closed, rather than merely preferred —
/// without it, any domain not in the pin file would still silently verify
/// over live, unauthenticated DNS.
pub async fn verify_email_message_with_cache<C: mail_auth::DnsCache>(
    authenticator: &MessageAuthenticator,
    cache: &C,
    raw_message: &[u8],
    claimed_address: &str,
    expected_text: &str,
) -> Result<String, VerifyError> {
    let parsed = AuthenticatedMessage::parse(raw_message).ok_or(VerifyError::MalformedMessage)?;
    if unpinned_signing_keys_present(cache, &parsed) {
        return Err(VerifyError::UnpinnedSigningKey);
    }
    let results = authenticator
        .verify_dkim(Parameters::new(&parsed).with_cache(cache))
        .await;
    check_verified_results(&results, &parsed, claimed_address, expected_text)
}

/// Whether any `DKIM-Signature` header the message carries names a
/// `(d=, s=)` pair `cache` doesn't already hold a key for. A message with
/// no signature at all (`dkim_signatures()` empty) is not flagged here —
/// that's [`VerifyError::NoSignature`]'s job, raised downstream once
/// `verify_dkim` runs and finds nothing to verify; this check exists
/// purely to keep that run from ever touching the network for a domain
/// nobody pinned.
fn unpinned_signing_keys_present<C: mail_auth::DnsCache>(
    cache: &C,
    parsed: &AuthenticatedMessage<'_>,
) -> bool {
    let Some(txt_cache) = cache.txt() else {
        return !parsed.dkim_signatures().is_empty();
    };
    parsed.dkim_signatures().iter().any(|header| {
        let fqdn = crate::dns_map_cache::domain_key_fqdn(&header.header.d, &header.header.s);
        txt_cache.get::<str>(&fqdn).is_none()
    })
}

fn check_verified_results(
    results: &[DkimOutput<'_>],
    parsed: &AuthenticatedMessage<'_>,
    claimed_address: &str,
    expected_text: &str,
) -> Result<String, VerifyError> {
    if results.is_empty() {
        return Err(VerifyError::NoSignature);
    }

    // RFC 5322 §3.6 requires exactly one `From:` field. A second one is
    // either a malformed message or an attempt to exploit DKIM's own
    // header-counting rule (RFC 6376 §5.4.2: a header name listed once in
    // `h=` covers only the header block's *last* instance of it, counted
    // from the bottom): an extra `From:` prepended above the genuinely
    // signed one leaves the signature passing while `first_from_address()`
    // below would return the unsigned, attacker-chosen header instead of
    // the one DKIM actually covered. Rejecting outright — rather than
    // trying to bind to "whichever instance the signature covered" — is
    // simpler and matches RFC 5322's own cardinality rule directly.
    if parsed.from_addresses().len() != 1 {
        return Err(VerifyError::MalformedMessage);
    }

    let from_address = parsed.first_from_address();
    let from_domain = from_address
        .rsplit_once('@')
        .map(|(_, domain)| domain)
        .ok_or(VerifyError::MalformedMessage)?;

    let aligned_pass = results.iter().any(|output| {
        output.result() == &DkimResult::Pass
            && output.signature().is_some_and(|signature| {
                // Alignment alone isn't enough: a signature whose `h=`
                // never lists `from` doesn't cover the `From:` header at
                // all, so nothing here stops it from reading anything —
                // DKIM only canonicalizes/hashes the header names `h=`
                // actually lists.
                signature.domain().eq_ignore_ascii_case(from_domain)
                    && signature
                        .h
                        .iter()
                        .any(|header| header.eq_ignore_ascii_case("from"))
            })
    });
    if !aligned_pass {
        return Err(VerifyError::NoAlignedPassingSignature);
    }

    if !message_contains_text(parsed, expected_text) {
        return Err(VerifyError::TextNotFound);
    }

    if !claimed_address.is_empty() && !claimed_address.eq_ignore_ascii_case(from_address) {
        return Err(VerifyError::ClaimedAddressMismatch);
    }

    Ok(from_address.to_string())
}

/// Whether `expected_text` is present anywhere a human reading the message
/// would actually see it. `parsed.raw_body()` (mail-auth's own view) is the
/// *transport* body: for a real mail client's reply, that's routinely
/// quoted-printable- or base64-encoded, or an HTML-only part with no
/// matching text/plain sibling — a literal substring search against those
/// raw bytes fails even when the text is right there, unencoded, once a
/// mail reader decodes it. So this independently re-parses the same raw
/// bytes with `mail-parser` (never mail-auth's own verification path,
/// which must keep hashing the untouched transport bytes DKIM actually
/// signed) and checks every decoded text body RFC 8621 defines as the
/// message's `textBody` — HTML automatically converted to text when
/// that's the only version present. The raw-bytes check stays as a cheap
/// first attempt and safety net for the case `mail-parser` fails to parse
/// something `mail-auth`'s own parser accepted.
fn message_contains_text(parsed: &AuthenticatedMessage<'_>, expected_text: &str) -> bool {
    if body_contains_text(parsed.raw_body(), expected_text) {
        return true;
    }
    mail_parser::MessageParser::new()
        .parse(parsed.raw_message())
        .is_some_and(|message| {
            message
                .text_bodies()
                .any(|text| body_contains_text(text.as_bytes(), expected_text))
        })
}

/// Independently verifies `evidence` against `operation` and returns a
/// `BearerToken` carrying `claims` on success — the same shape a verified
/// JWT or WebAuthn evidence already produces, so every downstream check in
/// a protocol's request pipeline runs unchanged regardless of which
/// authentication method was used. See `orbis_webauthn::verify_and_build_token`
/// for the shared shape this mirrors.
///
/// `issuer_id` is `did:key:sha256(normalized address)` (lowercased,
/// trimmed) — not a real decoded key, see this crate's own `build_token`
/// for why it still wears the `did:key:` prefix: that's the one actor-id
/// scheme the chain's ACP module accepts for a `set_relationship` grant
/// without decoding the suffix as an actual key. `authn::resolve_actor_id`
/// and `Authz::check` both already accept an arbitrary subject string, so
/// neither needed to change for this.
///
/// `max_lifetime_secs` bounds how far past `current_time` a caller-chosen
/// `evidence.expiry` may sit — see `orbis_webauthn::verify_and_build_token`'s
/// own doc comment for why (`JtiReplayGuard`'s retention cap).
pub async fn verify_and_build_token<Op, Claims>(
    authenticator: &MessageAuthenticator,
    evidence: &EmailEvidence,
    operation: Op,
    claims: Claims,
    current_time: u64,
    max_lifetime_secs: u64,
) -> Result<BearerToken<Claims>, EmailAuthError>
where
    Op: CanonicalDisplay,
{
    check_evidence_freshness(evidence, current_time, max_lifetime_secs)?;
    let expected_text = challenge_text(&operation);
    let address = verify_email_message(
        authenticator,
        &evidence.raw_message,
        &evidence.claimed_address,
        &expected_text,
    )
    .await?;
    Ok(build_token(&address, evidence, claims))
}

/// Same as [`verify_and_build_token`], but resolves DKIM keys through
/// `cache` instead of live DNS — see
/// [`verify_email_message_with_cache`]'s own doc comment.
pub async fn verify_and_build_token_with_cache<Op, Claims, C: mail_auth::DnsCache>(
    authenticator: &MessageAuthenticator,
    cache: &C,
    evidence: &EmailEvidence,
    operation: Op,
    claims: Claims,
    current_time: u64,
    max_lifetime_secs: u64,
) -> Result<BearerToken<Claims>, EmailAuthError>
where
    Op: CanonicalDisplay,
{
    check_evidence_freshness(evidence, current_time, max_lifetime_secs)?;
    let expected_text = challenge_text(&operation);
    let address = verify_email_message_with_cache(
        authenticator,
        cache,
        &evidence.raw_message,
        &evidence.claimed_address,
        &expected_text,
    )
    .await?;
    Ok(build_token(&address, evidence, claims))
}

/// Expiry/lifetime/nonce-shape checks shared by both `verify_and_build_token*`
/// entry points — identical in shape to `orbis_webauthn::verify_and_build_token`'s
/// own checks.
fn check_evidence_freshness(
    evidence: &EmailEvidence,
    current_time: u64,
    max_lifetime_secs: u64,
) -> Result<(), EmailAuthError> {
    if current_time > evidence.expiry {
        return Err(EmailAuthError::Expired);
    }
    if evidence.expiry.saturating_sub(current_time) > max_lifetime_secs {
        return Err(EmailAuthError::LifetimeTooLong);
    }
    if evidence.nonce.len() != 16 {
        return Err(EmailAuthError::InvalidNonce);
    }
    Ok(())
}

fn build_token<Claims>(
    verified_address: &str,
    evidence: &EmailEvidence,
    claims: Claims,
) -> BearerToken<Claims> {
    let normalized = verified_address.trim().to_lowercase();
    // `did:key:` — not a real decoded key, just a stable hash wearing the
    // one actor-id scheme the chain's ACP module accepts without any
    // further structural validation (confirmed empirically: both backends
    // reject any other prefix, including a plain `email:` one, with "is
    // not a valid did" — see `vera-identity::Did::new`, which checks only
    // `starts_with("did:key:")` for this scheme, never decodes the
    // suffix). A real did:key value always starts with `z` (multibase
    // base58btc); a hex digest never does, so this can't collide with an
    // actual passkey-derived DID.
    let issuer_id = format!(
        "did:key:{}",
        hex::encode(Sha256::digest(normalized.as_bytes()))
    );
    BearerToken {
        issuer_id,
        subject_id: None,
        issued_time: evidence.issued_at,
        expiration_time: evidence.expiry,
        not_before: None,
        jwt_id: hex::encode(&evidence.nonce),
        claims,
    }
}

/// Extends an endpoint's normal (JWT) authentication shape
/// (`authn::endpoints::EndpointAuth`) with what email evidence specifically
/// needs — mirrors `orbis_webauthn::WebAuthnEndpoint` exactly; see that
/// trait's own doc comment for why this lives here and not in `authn`.
pub trait EmailEndpoint: authn::endpoints::EndpointAuth {
    /// The operation this endpoint's challenge text must render and
    /// commit to. Bound by [`CanonicalDisplay`], not just
    /// [`CanonicalOperation`] — unlike WebAuthn's binary challenge, the
    /// email mechanism needs a human-legible rendering, not just a
    /// canonical byte encoding (see this crate's own doc comment).
    type Operation: CanonicalDisplay;

    /// Builds the claims an email-authorized request's synthetic token
    /// carries, from `fields` alone.
    fn claims(fields: &Self::Fields) -> Self::Claims;

    /// Builds the operation this exact request's challenge text must
    /// commit to. `issued_at` only matters to an endpoint whose claims get
    /// cryptographically bound into a further signature the client
    /// produces before the server sees the request (PRE's reader-key
    /// proof-of-possession) — see `orbis_webauthn::WebAuthnEndpoint::operation`'s
    /// own doc comment.
    fn operation(
        fields: &Self::Fields,
        issued_at: u64,
        expiry: u64,
        nonce: [u8; 16],
    ) -> Self::Operation;
}

/// Verifies email evidence for one endpoint `E` and returns a `BearerToken`
/// carrying its synthesized claims — the complete email authentication
/// path for one endpoint, self-contained in this crate. Mirrors
/// `orbis_webauthn::verify_endpoint_auth` exactly.
pub async fn verify_endpoint_auth<E: EmailEndpoint>(
    authenticator: &MessageAuthenticator,
    fields: &E::Fields,
    evidence: &EmailEvidence,
    current_time: u64,
    max_lifetime_secs: u64,
) -> Result<BearerToken<E::Claims>, EmailAuthError> {
    let (operation, claims) = endpoint_operation_and_claims::<E>(fields, evidence)?;
    verify_and_build_token(
        authenticator,
        evidence,
        operation,
        claims,
        current_time,
        max_lifetime_secs,
    )
    .await
}

/// Same as [`verify_endpoint_auth`], but resolves DKIM keys through `cache`
/// instead of live DNS — see [`verify_email_message_with_cache`]'s own doc
/// comment.
pub async fn verify_endpoint_auth_with_cache<E: EmailEndpoint, C: mail_auth::DnsCache>(
    authenticator: &MessageAuthenticator,
    cache: &C,
    fields: &E::Fields,
    evidence: &EmailEvidence,
    current_time: u64,
    max_lifetime_secs: u64,
) -> Result<BearerToken<E::Claims>, EmailAuthError> {
    let (operation, claims) = endpoint_operation_and_claims::<E>(fields, evidence)?;
    verify_and_build_token_with_cache(
        authenticator,
        cache,
        evidence,
        operation,
        claims,
        current_time,
        max_lifetime_secs,
    )
    .await
}

fn endpoint_operation_and_claims<E: EmailEndpoint>(
    fields: &E::Fields,
    evidence: &EmailEvidence,
) -> Result<(E::Operation, E::Claims), EmailAuthError> {
    let nonce: [u8; 16] = evidence
        .nonce
        .as_slice()
        .try_into()
        .map_err(|_| EmailAuthError::InvalidNonce)?;
    let operation = E::operation(fields, evidence.issued_at, evidence.expiry, nonce);
    let claims = E::claims(fields);
    Ok((operation, claims))
}

#[cfg(test)]
mod tests;
