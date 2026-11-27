//! Builds a synthetic, fully offline, DKIM-signed test message and a
//! matching [`TestDnsCache`] pre-seeded with its key record — mirroring
//! `orbis_webauthn::build_test_assertion`'s own "never use this in place of
//! a real mail provider" disclaimer. Used by this crate's own tests and
//! available to other crates' tests that need a real, verifiable signed
//! message without a mailbox or a network.
//!
//! The cache this module builds mirrors `mail_auth::dns::cache`'s own
//! documented `MapCache`/`Caches` example exactly (a `HashMap` behind a
//! `Mutex`, one cache per record type, only `Txt` populated) — it is not a
//! bespoke abstraction, just that pattern pre-seeded instead of populated
//! lazily from live lookups.

use crate::dns_map_cache::MapCache;
use mail_auth::crypto::{RsaKey, Sha256 as DkimSha256};
use mail_auth::dkim::{DkimSigner, DomainKey};
use mail_auth::dns::{DnsCache, NoCache, TxtRecordParser};
use mail_auth::headers::HeaderWriter;
use mail_auth::TxtRecord;
use rsa::pkcs1::EncodeRsaPrivateKey;
use rsa::pkcs8::EncodePublicKey;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{PrivateKeyDer, PrivatePkcs1KeyDer};
use std::sync::Arc;

/// In-memory TXT-record cache for [`mail_auth::MessageAuthenticator`],
/// implementing the same `DnsCache`/`ResolverCache` seam a future
/// chain-backed pinned-key store would use — see this crate's own README.
/// Only the `Txt` record type is ever populated; the other four accessors
/// return `None` (disabled), since DKIM verification never looks them up.
#[derive(Default)]
pub struct TestDnsCache {
    txt: MapCache,
}

impl DnsCache for TestDnsCache {
    type Txt = MapCache;
    type Mx = NoCache;
    type Ipv4 = NoCache;
    type Ipv6 = NoCache;
    type Ptr = NoCache;

    fn txt(&self) -> Option<&Self::Txt> {
        Some(&self.txt)
    }
    fn mx(&self) -> Option<&Self::Mx> {
        None
    }
    fn ipv4(&self) -> Option<&Self::Ipv4> {
        None
    }
    fn ipv6(&self) -> Option<&Self::Ipv6> {
        None
    }
    fn ptr(&self) -> Option<&Self::Ptr> {
        None
    }
}

impl TestDnsCache {
    /// Inserts the DKIM key record found at `<selector>._domainkey.<domain>`
    /// — `raw_txt_record` is the exact TXT value text a real zone would
    /// publish (`v=DKIM1; k=rsa; p=...`). Panics on a malformed record: this
    /// is test setup, not something that should fail softly.
    pub fn insert_dkim_key(&self, domain: &str, selector: &str, raw_txt_record: &[u8]) {
        let key = DomainKey::parse(raw_txt_record).expect("valid test DKIM key record");
        self.txt.insert_record(
            crate::dns_map_cache::domain_key_fqdn(domain, selector),
            TxtRecord::DomainKey(Arc::new(key)),
        );
    }
}

/// A synthetic RSA signing identity for one `(domain, selector)` pair, plus
/// the exact TXT record text a real zone would publish for it.
pub struct TestSigningKey {
    rsa_key: rsa::RsaPrivateKey,
    domain: String,
    selector: String,
    txt_record: Vec<u8>,
}

impl TestSigningKey {
    /// Generates a fresh 2048-bit RSA key. Slow-ish (RSA keygen) — call
    /// once per test, not per assertion.
    pub fn generate(domain: impl Into<String>, selector: impl Into<String>) -> Self {
        let rsa_key = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048).expect("rsa keygen");

        let public_key_der = rsa::RsaPublicKey::from(&rsa_key)
            .to_public_key_der()
            .expect("spki der");
        let txt_record = format!(
            "v=DKIM1; k=rsa; p={}",
            base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                public_key_der.as_bytes()
            )
        )
        .into_bytes();

        Self {
            rsa_key,
            domain: domain.into(),
            selector: selector.into(),
            txt_record,
        }
    }

    /// Builds the mail-auth signing key fresh from the stored RSA key —
    /// `mail_auth::crypto::RsaKey` doesn't implement `Clone`, so this is
    /// re-derived per call rather than cached.
    fn mail_auth_signing_key(&self) -> RsaKey<DkimSha256> {
        let pem = self
            .rsa_key
            .to_pkcs1_pem(rsa::pkcs8::LineEnding::LF)
            .expect("pkcs1 pem encode");
        RsaKey::<DkimSha256>::from_key_der(PrivateKeyDer::Pkcs1(
            PrivatePkcs1KeyDer::from_pem_slice(pem.as_bytes()).expect("parse generated pem"),
        ))
        .expect("signing key from der")
    }

    /// The exact TXT record text this key's domain/selector would publish.
    pub fn txt_record(&self) -> &[u8] {
        &self.txt_record
    }

    /// Registers this key's record into `cache`, so a
    /// [`crate::verify_email_message_for_test`] call against the resulting
    /// signed message can verify fully offline.
    pub fn register(&self, cache: &TestDnsCache) {
        cache.insert_dkim_key(&self.domain, &self.selector, &self.txt_record);
    }

    /// Signs a minimal RFC 5322 message (`From`/`Subject`/`To` + `body`) and
    /// returns the complete raw bytes (`DKIM-Signature` header prepended),
    /// exactly as a captured mail reply would look. `from_address`'s domain
    /// does not have to equal this key's signing domain — tests that need a
    /// signature/From-domain mismatch (the DMARC-alignment failure case)
    /// construct it that way deliberately. Signs all three headers
    /// (`h=From,Subject,To`); use [`Self::sign_message_with_headers`] for a
    /// test that needs a signature not covering one of them.
    pub fn sign_message(&self, from_address: &str, to_address: &str, body: &str) -> Vec<u8> {
        self.sign_message_with_headers(from_address, to_address, body, &["From", "Subject", "To"])
    }

    /// Same as [`Self::sign_message`], but with an explicit `h=` header
    /// list — for a test that needs a signature whose `h=` doesn't cover
    /// `From` at all, which `mail-auth`'s own header-canonicalization
    /// faithfully honors: a header name absent from `h=` is simply never
    /// hashed, so its content isn't protected by the signature no matter
    /// what it says.
    pub fn sign_message_with_headers(
        &self,
        from_address: &str,
        to_address: &str,
        body: &str,
        headers: &[&str],
    ) -> Vec<u8> {
        let message = format!(
            "From: {from_address}\r\nSubject: orbis-email test\r\nTo: {to_address}\r\n\r\n{body}\r\n"
        );
        let signature = DkimSigner::from_key(self.mail_auth_signing_key())
            .domain(self.domain.clone())
            .selector(self.selector.clone())
            .headers(headers.iter().copied())
            .sign(message.as_bytes())
            .expect("sign test message");

        let mut signed = signature.to_header().into_bytes();
        signed.extend_from_slice(message.as_bytes());
        signed
    }
}
