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

    let expected_issuer = format!(
        "did:key:{}",
        hex::encode(Sha256::digest(FROM.to_lowercase().as_bytes()))
    );
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
