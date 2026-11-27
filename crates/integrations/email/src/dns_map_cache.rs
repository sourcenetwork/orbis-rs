//! A `HashMap`-backed [`mail_auth::ResolverCache`], the one piece shared by
//! [`crate::test_support::TestDnsCache`] (fully offline tests) and
//! [`crate::PinnedDnsCache`] (the production pinned-key alternative to live
//! DNS) — both are otherwise just this cache wrapped in a `DnsCache` impl
//! that only ever populates the `Txt` slot. Mirrors `mail_auth::dns::cache`'s
//! own documented `MapCache`/`Caches` example exactly (a `HashMap` behind a
//! `Mutex`), not a bespoke abstraction.

use mail_auth::dns::ResolverCache;
use mail_auth::TxtRecord;
use std::borrow::Borrow;
use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Mutex;
use std::time::Instant;

// `pub`, not `pub(crate)`: it's only reachable from outside this crate
// through the `Txt` associated type on the public `DnsCache for
// TestDnsCache`/`DnsCache for PinnedDnsCache` impls (both of which are
// public types), which requires this item's own visibility to be at least
// as public — `dns_map_cache` itself stays a private module either way.
#[derive(Default)]
pub struct MapCache(Mutex<HashMap<Box<str>, (TxtRecord, Option<Instant>)>>);

// `TxtRecord` itself has no `Debug` impl; this just names the type so
// callers that need `Debug` for error-handling/test-assertion purposes
// (e.g. `Result::unwrap_err`) can get it without inspecting cache contents.
impl std::fmt::Debug for MapCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MapCache").finish_non_exhaustive()
    }
}

impl MapCache {
    /// Inserts a record with no expiry — used for operator/file-provided
    /// entries (`PinnedDnsCache::insert_dkim_key`,
    /// `TestDnsCache::insert_dkim_key`), which have no DNS TTL to begin
    /// with; they're meant to last for the life of the process by design,
    /// not because expiry is being ignored (see `ResolverCache::insert`
    /// below for the case that distinction actually matters).
    pub(crate) fn insert_record(&self, key: Box<str>, value: TxtRecord) {
        self.0
            .lock()
            .expect("dns map cache mutex poisoned")
            .insert(key, (value, None));
    }
}

impl ResolverCache<Box<str>, TxtRecord> for MapCache {
    fn get<Q>(&self, name: &Q) -> Option<TxtRecord>
    where
        Box<str>: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let mut map = self.0.lock().expect("dns map cache mutex poisoned");
        let expired =
            matches!(map.get(name), Some((_, Some(expires))) if Instant::now() >= *expires);
        if expired {
            map.remove(name);
            return None;
        }
        map.get(name).map(|(value, _)| value.clone())
    }

    fn remove<Q>(&self, name: &Q) -> Option<TxtRecord>
    where
        Box<str>: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.0
            .lock()
            .expect("dns map cache mutex poisoned")
            .remove(name)
            .map(|(value, _)| value)
    }

    // This is the one path a *live* DNS answer (correct or spoofed) ever
    // reaches this cache through — `mail-auth`'s own `txt_lookup` calls it
    // after falling back to the network on a miss (see this crate's own
    // `unpinned_signing_keys_present`, which exists specifically so
    // `PinnedDnsCache` never reaches this path at all in production). An
    // earlier version of this method ignored `valid_until` entirely,
    // caching whatever came back for the life of the process regardless
    // of its real TTL — now corrected to actually expire it, both as a
    // defensive fix in its own right and because a future chain-backed
    // pinned-key store (see this crate's README) plans to populate a
    // deliberately *short-lived* cache through this exact seam, which
    // needs expiry to work to mean anything.
    fn insert(&self, key: Box<str>, value: TxtRecord, valid_until: Instant) {
        self.0
            .lock()
            .expect("dns map cache mutex poisoned")
            .insert(key, (value, Some(valid_until)));
    }
}

/// The fully qualified, lowercased name (trailing dot) a DKIM key lookup
/// uses for `<selector>._domainkey.<domain>` — mirrors
/// `VerifySignature::domain_key`/`ToFqdn::to_fqdn` exactly (confirmed
/// against mail-auth 0.16's own source), shared by every caller that needs
/// to insert into or check membership in a [`MapCache`] by domain/selector
/// rather than by the raw FQDN string.
pub(crate) fn domain_key_fqdn(domain: &str, selector: &str) -> Box<str> {
    format!("{selector}._domainkey.{domain}.")
        .to_lowercase()
        .into()
}
