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
pub struct MapCache(Mutex<HashMap<Box<str>, TxtRecord>>);

// `TxtRecord` itself has no `Debug` impl; this just names the type so
// callers that need `Debug` for error-handling/test-assertion purposes
// (e.g. `Result::unwrap_err`) can get it without inspecting cache contents.
impl std::fmt::Debug for MapCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MapCache").finish_non_exhaustive()
    }
}

impl MapCache {
    pub(crate) fn insert_record(&self, key: Box<str>, value: TxtRecord) {
        self.0
            .lock()
            .expect("dns map cache mutex poisoned")
            .insert(key, value);
    }
}

impl ResolverCache<Box<str>, TxtRecord> for MapCache {
    fn get<Q>(&self, name: &Q) -> Option<TxtRecord>
    where
        Box<str>: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.0
            .lock()
            .expect("dns map cache mutex poisoned")
            .get(name)
            .cloned()
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
    }

    fn insert(&self, key: Box<str>, value: TxtRecord, _valid_until: Instant) {
        self.insert_record(key, value);
    }
}
