use super::*;
use crate::test_support::{TestDnsCache, TestSigningKey};
use mail_auth::MessageAuthenticator;

const DOMAIN: &str = "example.test";
const SELECTOR: &str = "orbistest";
const FROM: &str = "alice@example.test";
const TO: &str = "ring@orbis.test";

struct Fixture {
    authenticator: MessageAuthenticator,
    cache: TestDnsCache,
    key: TestSigningKey,
}

/// A real mail client's quoted-printable encoder wraps long lines with a
/// soft `=\r\n` line break partway through — exactly what a long
/// hex-encoded field (PRE's `rdr_pk`, in practice) looks like once a real
/// reply (Gmail included) gets re-encoded on the wire. No DKIM signature
/// needed here: `message_contains_text` doesn't look at one, only at
/// `AuthenticatedMessage`'s own parsed structure.
#[test]
fn message_contains_text_decodes_quoted_printable_soft_line_break() {
    let hex_value = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899";
    let text = format!("rdr_pk: {hex_value}\n");
    let (first, second) = hex_value.split_at(20);
    let raw = format!(
        "From: alice@example.test\r\nSubject: test\r\nTo: ring@orbis.test\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\
         Content-Transfer-Encoding: quoted-printable\r\n\r\nrdr_pk: {first}=\r\n{second}\r\n"
    );
    let parsed = AuthenticatedMessage::parse(raw.as_bytes()).expect("message parses");
    assert!(
        !body_contains_text(parsed.raw_body(), &text),
        "sanity check: the raw transport bytes contain a soft line break \
         splitting the hex value, so a literal substring search must fail \
         — this is the bug message_contains_text exists to fix"
    );
    assert!(message_contains_text(&parsed, &text));
}

/// A reply with no text/plain part at all — only HTML, as some mail
/// clients send by default. `mail_parser::Message::text_bodies` converts
/// the HTML part to text automatically when it's the only version present
/// (RFC 8621's `textBody`), so this still has to match.
#[test]
fn message_contains_text_decodes_html_only_body() {
    let text = "confirming:\nORBIS SIGN REQUEST\nderivation: test\n";
    let raw = b"From: alice@example.test\r\nSubject: test\r\nTo: ring@orbis.test\r\n\
Content-Type: text/html; charset=utf-8\r\n\r\n\
<div>confirming:<br>ORBIS SIGN REQUEST<br>derivation: test<br></div>\r\n";
    let parsed = AuthenticatedMessage::parse(raw).expect("message parses");
    assert!(!body_contains_text(parsed.raw_body(), text));
    assert!(message_contains_text(&parsed, text));
}

fn fixture() -> Fixture {
    let key = TestSigningKey::generate(DOMAIN, SELECTOR);
    let cache = TestDnsCache::default();
    key.register(&cache);
    Fixture {
        authenticator: MessageAuthenticator::new_system_conf().expect("authenticator"),
        cache,
        key,
    }
}

#[tokio::test]
async fn verifies_a_well_formed_signed_reply() {
    let f = fixture();
    let text = "ORBIS SIGN REQUEST\nderivation: test\n";
    let message = f
        .key
        .sign_message(FROM, TO, &format!("confirming:\n{text}"));

    let address = verify_email_message_with_cache(&f.authenticator, &f.cache, &message, FROM, text)
        .await
        .expect("well-formed signed reply must verify");
    assert_eq!(address, FROM);
}

/// DKIM's own header-counting rule (RFC 6376 §5.4.2) binds a signed header
/// name to the header block's *last* instance of it, counted from the
/// bottom — so a `From:` header prepended *above* the one the signature
/// actually covers leaves the signature passing while naively reading
/// "the first `From:` header" would return the attacker's unsigned one.
/// Must be rejected outright, not attributed to either address.
#[tokio::test]
async fn rejects_message_with_multiple_from_headers() {
    let f = fixture();
    let text = "ORBIS SIGN REQUEST\nderivation: test\n";
    let message = f
        .key
        .sign_message(FROM, TO, &format!("confirming:\n{text}"));
    let message = String::from_utf8(message).expect("test message is ASCII");

    // Prepend an extra, unsigned `From:` header above the one DKIM's
    // bottom-counting rule actually covers.
    let spoofed = message.replacen(
        "From: alice@example.test\r\n",
        "From: other@example.test\r\nFrom: alice@example.test\r\n",
        1,
    );
    assert_ne!(spoofed, message, "sanity check: the replacement must apply");

    let result =
        verify_email_message_with_cache(&f.authenticator, &f.cache, spoofed.as_bytes(), FROM, text)
            .await;
    assert!(matches!(result, Err(VerifyError::MalformedMessage)));
}

/// A signature whose `h=` doesn't list `From` at all never canonicalizes
/// or hashes that header — DKIM passing says nothing about its content,
/// so alignment against it must not be trusted either, even with only one
/// `From:` header present (no header-duplication trick needed at all).
#[tokio::test]
async fn rejects_signature_that_does_not_cover_from_header() {
    let f = fixture();
    let text = "ORBIS SIGN REQUEST\nderivation: test\n";
    let message = f.key.sign_message_with_headers(
        FROM,
        TO,
        &format!("confirming:\n{text}"),
        &["Subject", "To"],
    );

    let result =
        verify_email_message_with_cache(&f.authenticator, &f.cache, &message, FROM, text).await;
    assert!(matches!(
        result,
        Err(VerifyError::NoAlignedPassingSignature)
    ));
}

#[tokio::test]
async fn rejects_missing_text() {
    let f = fixture();
    let message = f
        .key
        .sign_message(FROM, TO, "nothing relevant in this body");

    let result = verify_email_message_with_cache(
        &f.authenticator,
        &f.cache,
        &message,
        FROM,
        "ORBIS SIGN REQUEST\nderivation: test\n",
    )
    .await;
    assert!(matches!(result, Err(VerifyError::TextNotFound)));
}

#[tokio::test]
async fn rejects_dkim_domain_misaligned_with_from_header() {
    // Signed validly by `attacker.test`, but claims to be `alice@example.test`
    // in the From header — the DMARC-style alignment check this crate adds
    // on top of mail-auth's own `verify_dkim` must catch this; a bare
    // DkimResult::Pass alone would not.
    let f = fixture();
    let attacker_key = TestSigningKey::generate("attacker.test", SELECTOR);
    attacker_key.register(&f.cache);
    let text = "ORBIS SIGN REQUEST\nderivation: test\n";
    let message = attacker_key.sign_message(FROM, TO, text);

    let result =
        verify_email_message_with_cache(&f.authenticator, &f.cache, &message, FROM, text).await;
    assert!(matches!(
        result,
        Err(VerifyError::NoAlignedPassingSignature)
    ));
}

#[tokio::test]
async fn rejects_claimed_address_mismatch() {
    let f = fixture();
    let text = "ORBIS SIGN REQUEST\nderivation: test\n";
    let message = f.key.sign_message(FROM, TO, text);

    let result = verify_email_message_with_cache(
        &f.authenticator,
        &f.cache,
        &message,
        "someone-else@example.test",
        text,
    )
    .await;
    assert!(matches!(result, Err(VerifyError::ClaimedAddressMismatch)));
}

#[tokio::test]
async fn unsigned_message_is_rejected_cleanly() {
    let f = fixture();
    let raw = format!("From: {FROM}\r\nTo: {TO}\r\n\r\nno signature here\r\n");

    let result = verify_email_message_with_cache(
        &f.authenticator,
        &f.cache,
        raw.as_bytes(),
        FROM,
        "irrelevant",
    )
    .await;
    assert!(matches!(result, Err(VerifyError::NoSignature)));
}

/// The whole point of pinned-key mode: a domain/selector the cache was
/// never told about must be rejected outright, never silently resolved
/// over live DNS. Deliberately signs with a key whose domain
/// (`unpinned.test`) was never registered anywhere, against a *real*
/// live-DNS-capable authenticator — if this fell through to the network
/// the way `mail-auth`'s own `txt_lookup` does on a cache miss, this
/// would either hang/timeout or return a live (NXDOMAIN) answer instead
/// of the deterministic rejection asserted here.
#[tokio::test]
async fn rejects_unpinned_signing_key_without_touching_live_dns() {
    let key = TestSigningKey::generate("unpinned.test", SELECTOR);
    let cache = TestDnsCache::default(); // deliberately never registered
    let authenticator = MessageAuthenticator::new_system_conf().expect("authenticator");
    let text = "ORBIS SIGN REQUEST\nderivation: test\n";
    let message = key.sign_message("alice@unpinned.test", TO, &format!("confirming:\n{text}"));

    let result = verify_email_message_with_cache(
        &authenticator,
        &cache,
        &message,
        "alice@unpinned.test",
        text,
    )
    .await;
    assert!(matches!(result, Err(VerifyError::UnpinnedSigningKey)));
}

/// `mail-auth`'s own `txt_lookup` calls `ResolverCache::insert` with a
/// real expiry after a live-DNS fallback. An earlier version of
/// `MapCache::insert` ignored that expiry entirely, caching whatever came
/// back (correct or spoofed) for the life of the process — this proves
/// an already-past expiry is honored and treated as a miss, not a hit.
#[test]
fn map_cache_respects_ttl_and_expires_entries() {
    use crate::dns_map_cache::MapCache;
    use mail_auth::dkim::DomainKey;
    use mail_auth::dns::{ResolverCache, TxtRecordParser};
    use mail_auth::TxtRecord;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    let signing_key = TestSigningKey::generate(DOMAIN, SELECTOR);
    let domain_key =
        DomainKey::parse(signing_key.txt_record()).expect("valid test DKIM key record");
    let record = TxtRecord::DomainKey(Arc::new(domain_key));

    let cache = MapCache::default();
    let key: Box<str> = "orbistest._domainkey.example.test.".into();
    cache.insert(key.clone(), record, Instant::now() - Duration::from_secs(1));

    assert!(
        cache.get::<str>(&key).is_none(),
        "an expired entry must not be served as a cache hit"
    );
}

struct ToyOperation(&'static str);

impl CanonicalOperation for ToyOperation {
    fn canonical_bytes(&self) -> Vec<u8> {
        self.0.as_bytes().to_vec()
    }
}

impl CanonicalDisplay for ToyOperation {
    fn canonical_display(&self) -> String {
        format!("TOY OPERATION\nvalue: {}\n", self.0)
    }
}

fn evidence_for(raw_message: Vec<u8>, expiry: u64, nonce: [u8; 16]) -> EmailEvidence {
    EmailEvidence {
        claimed_address: FROM.to_string(),
        raw_message,
        issued_at: 1_700_000_000,
        expiry,
        nonce: nonce.to_vec(),
    }
}

#[tokio::test]
async fn verify_and_build_token_succeeds_and_binds_issuer_to_the_verified_address() {
    let f = fixture();
    let operation = ToyOperation("op-1");
    let text = challenge_text(&operation);
    let message = f
        .key
        .sign_message(FROM, TO, &format!("confirming:\n{text}"));
    let evidence = evidence_for(message, 1_700_000_300, [1; 16]);

    let token = verify_and_build_token_with_cache(
        &f.authenticator,
        &f.cache,
        &evidence,
        operation,
        (),
        1_700_000_100,
        10_000,
    )
    .await
    .expect("verification must succeed");

    let expected_issuer = authn::did_from_email_address(FROM);
    assert_eq!(token.issuer_id, expected_issuer);
    assert_eq!(token.jwt_id, hex::encode([1u8; 16]));
}

/// Proves the binding can't be misdirected: a validly signed reply quoting
/// one operation's exact challenge text must not authorize a *different*
/// operation (e.g. PRE's challenge text for a different `rdr_pk`), even
/// though the DKIM signature and From address are both perfectly valid.
#[tokio::test]
async fn reply_cannot_be_redirected_to_a_different_operation() {
    let f = fixture();
    let original_operation = ToyOperation("rdr_pk=AAAA");
    let text = challenge_text(&original_operation);
    let message = f
        .key
        .sign_message(FROM, TO, &format!("confirming:\n{text}"));
    let evidence = evidence_for(message, 1_700_000_300, [2; 16]);

    let different_operation = ToyOperation("rdr_pk=BBBB");
    let result = verify_and_build_token_with_cache(
        &f.authenticator,
        &f.cache,
        &evidence,
        different_operation,
        (),
        1_700_000_100,
        10_000,
    )
    .await;
    assert!(matches!(
        result,
        Err(EmailAuthError::Verification(VerifyError::TextNotFound))
    ));
}

#[tokio::test]
async fn expired_evidence_is_rejected_before_any_dkim_check() {
    // No cache registered for this key, and the plain (no-cache,
    // live-DNS-capable) entry point is used — proving the expiry check
    // short-circuits before any DKIM/network work would even be attempted.
    let unregistered_key = TestSigningKey::generate("unregistered.test", SELECTOR);
    let operation = ToyOperation("op-expired");
    let text = challenge_text(&operation);
    let message = unregistered_key.sign_message(FROM, TO, &text);
    let evidence = evidence_for(message, 1_700_000_300, [3; 16]);

    let authenticator = MessageAuthenticator::new_system_conf().expect("authenticator");
    let result = verify_and_build_token(
        &authenticator,
        &evidence,
        operation,
        (),
        1_700_000_301, // one second past expiry
        10_000,
    )
    .await;
    assert!(matches!(result, Err(EmailAuthError::Expired)));
}

#[tokio::test]
async fn lifetime_too_long_is_rejected_before_any_dkim_check() {
    let unregistered_key = TestSigningKey::generate("unregistered2.test", SELECTOR);
    let operation = ToyOperation("op-lifetime");
    let text = challenge_text(&operation);
    let message = unregistered_key.sign_message(FROM, TO, &text);
    let evidence = evidence_for(message, 1_700_100_000, [4; 16]); // expiry far in the future

    let authenticator = MessageAuthenticator::new_system_conf().expect("authenticator");
    let result = verify_and_build_token(
        &authenticator,
        &evidence,
        operation,
        (),
        1_700_000_100,
        10_000, // max allowed lifetime, far shorter than evidence.expiry - current_time
    )
    .await;
    assert!(matches!(result, Err(EmailAuthError::LifetimeTooLong)));
}

#[test]
fn invalid_nonce_length_is_rejected() {
    let evidence = EmailEvidence {
        claimed_address: FROM.to_string(),
        raw_message: Vec::new(),
        issued_at: 0,
        expiry: 100,
        nonce: vec![0; 8], // not 16 bytes
    };
    let result = check_evidence_freshness(&evidence, 50, 10_000);
    assert!(matches!(result, Err(EmailAuthError::InvalidNonce)));
}
