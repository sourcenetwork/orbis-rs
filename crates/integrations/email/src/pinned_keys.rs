//! A fixed, operator-curated alternative to live DNS for DKIM key
//! resolution, built on `mail_auth`'s own public `DnsCache`/`ResolverCache`
//! seam — the same one [`crate::test_support::TestDnsCache`] uses for fully
//! offline tests (see this crate's own README for that seam's shared
//! shape). Unlike that type, [`PinnedDnsCache`] is meant for production
//! use: it loads from a file an operator controls, never panics on bad
//! input, and is the natural first step toward the DNSSEC gap logged
//! elsewhere in this crate (`check_verified_results`'s own doc comment) —
//! trusting a pinned key an operator vetted out of band is strictly
//! stronger than trusting whatever a live, unauthenticated DNS lookup
//! returns for the sending domain's `_domainkey` TXT record.
//!
//! An operator chooses this over the live-DNS default
//! ([`crate::verify_email_message`]/[`crate::verify_endpoint_auth`]) when
//! they only ever expect mail from a small, known set of signing domains
//! (so curating their keys ahead of time is practical) and would rather
//! not have every verification depend on DNS availability/integrity at
//! request time.

use crate::dns_map_cache::MapCache;
use mail_auth::dkim::DomainKey;
use mail_auth::dns::{DnsCache, NoCache, TxtRecordParser};
use mail_auth::TxtRecord;
use serde::Deserialize;
use std::path::Path;
use std::sync::Arc;

#[derive(Debug, Clone, Deserialize)]
struct PinnedKeyEntry {
    domain: String,
    selector: String,
    txt_record: String,
}

#[derive(Debug, Clone, Deserialize)]
struct PinnedKeysFile {
    keys: Vec<PinnedKeyEntry>,
}

/// Error loading or parsing a pinned-keys file
/// ([`PinnedDnsCache::load_from_file`]).
#[derive(Debug, thiserror::Error)]
pub enum PinnedKeysError {
    #[error("failed to read pinned DKIM keys file: {0}")]
    Io(#[from] std::io::Error),
    #[error("failed to parse pinned DKIM keys file: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid DKIM TXT record for {selector}._domainkey.{domain}: {source}")]
    InvalidRecord {
        domain: String,
        selector: String,
        #[source]
        source: mail_auth::Error,
    },
}

/// A fixed, operator-curated set of DKIM keys, used in place of live DNS —
/// see this module's own doc comment for why. Implements the same
/// `DnsCache`/`ResolverCache` seam [`crate::test_support::TestDnsCache`]
/// uses, so it plugs into [`crate::verify_endpoint_auth_with_cache`] (and
/// the lower-level [`crate::verify_email_message_with_cache`]) exactly the
/// way that type does — only the Txt record type is ever populated,
/// matching every DKIM lookup this crate performs.
#[derive(Debug, Default)]
pub struct PinnedDnsCache {
    txt: MapCache,
}

impl DnsCache for PinnedDnsCache {
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

impl PinnedDnsCache {
    /// Registers one `(domain, selector)` key. `raw_txt_record` is the
    /// exact TXT value text a real zone would publish for it
    /// (`v=DKIM1; k=rsa; p=...`). Returns an error on a malformed record
    /// instead of panicking — unlike `TestDnsCache`'s own version of this
    /// method, this one runs against operator-supplied, not test-authored,
    /// input.
    pub fn insert_dkim_key(
        &self,
        domain: &str,
        selector: &str,
        raw_txt_record: &[u8],
    ) -> Result<(), PinnedKeysError> {
        let key =
            DomainKey::parse(raw_txt_record).map_err(|source| PinnedKeysError::InvalidRecord {
                domain: domain.to_string(),
                selector: selector.to_string(),
                source,
            })?;
        self.txt.insert_record(
            crate::dns_map_cache::domain_key_fqdn(domain, selector),
            TxtRecord::DomainKey(Arc::new(key)),
        );
        Ok(())
    }

    /// Loads a pinned-keys file into a fresh cache:
    /// ```json
    /// { "keys": [ { "domain": "example.com", "selector": "default", "txt_record": "v=DKIM1; k=rsa; p=..." } ] }
    /// ```
    /// Fails on any read/parse error or any single malformed record — a bad
    /// config file should stop node startup, not silently serve a cache
    /// with gaps in it.
    pub fn load_from_file(path: &Path) -> Result<Self, PinnedKeysError> {
        let contents = std::fs::read_to_string(path)?;
        let file: PinnedKeysFile = serde_json::from_str(&contents)?;
        let cache = Self::default();
        for entry in file.keys {
            cache.insert_dkim_key(&entry.domain, &entry.selector, entry.txt_record.as_bytes())?;
        }
        Ok(cache)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mail_auth::dns::ResolverCache;
    use std::io::Write;

    fn write_temp_file(contents: &str) -> tempfile::NamedTempFile {
        let mut file = tempfile::NamedTempFile::new().expect("create temp file");
        file.write_all(contents.as_bytes())
            .expect("write temp file");
        file
    }

    #[test]
    fn load_from_file_rejects_malformed_json() {
        let file = write_temp_file("not json");
        let error = PinnedDnsCache::load_from_file(file.path()).unwrap_err();
        assert!(matches!(error, PinnedKeysError::Json(_)));
    }

    #[test]
    fn load_from_file_rejects_malformed_txt_record() {
        let file = write_temp_file(
            r#"{"keys": [{"domain": "example.test", "selector": "s1", "txt_record": "not a dkim record"}]}"#,
        );
        let error = PinnedDnsCache::load_from_file(file.path()).unwrap_err();
        assert!(matches!(error, PinnedKeysError::InvalidRecord { .. }));
    }

    #[test]
    fn load_from_file_rejects_missing_file() {
        let error =
            PinnedDnsCache::load_from_file(Path::new("/nonexistent/path.json")).unwrap_err();
        assert!(matches!(error, PinnedKeysError::Io(_)));
    }

    #[test]
    fn load_from_file_populates_a_queryable_record() {
        let signing_key =
            crate::test_support::TestSigningKey::generate("example.test", "orbistest");
        let txt_record = String::from_utf8(signing_key.txt_record().to_vec()).unwrap();
        let contents = serde_json::json!({
            "keys": [
                { "domain": "example.test", "selector": "orbistest", "txt_record": txt_record },
            ]
        })
        .to_string();
        let file = write_temp_file(&contents);

        let cache = PinnedDnsCache::load_from_file(file.path()).expect("valid pinned keys file");
        let record = cache
            .txt
            .get("orbistest._domainkey.example.test.")
            .expect("record must be present under its FQDN key");
        assert!(matches!(record, TxtRecord::DomainKey(_)));
    }
}
