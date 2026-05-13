//! Benchmarks for the `local-storage` crate.
//!
//! Posted on issue #83 to decide whether a cache layer over redb is justified.
//! The KDF (Argon2) cost is intentionally paid once during harness setup, not
//! per iteration — that matches production, where `RedbStorage::new` runs once
//! at node start and the derived `Aes256Gcm` cipher is reused for every call.

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use local_storage::r#trait::{LocalStorage, LocalStorageKeys};
use local_storage::redb::RedbStorage;
use serde::{Deserialize, Serialize};
use std::hint::black_box;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

/// Mirror of `bin/orbis-node/src/ring_state.rs::RingIndexEntry`.
/// Duplicated rather than depended on to keep the bench crate self-contained.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct RingIndexEntry {
    ring_pk_str: String,
    bulletin_post_id: String,
}

/// Matches `bin/orbis-node/src/constants.rs::MAX_LOCAL_RINGS_PER_NODE`.
const MAX_LOCAL_RINGS_PER_NODE: usize = 256;

/// Typical decrypted `RingShareBundle` size — see `bin/orbis-node/src/ring_state.rs`.
const RING_SHARE_BUNDLE_BYTES: usize = 1024;

static BENCH_COUNTER: AtomicU64 = AtomicU64::new(0);

fn unique_db_path(tag: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let n = BENCH_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut p = std::env::temp_dir();
    p.push(format!("orbis-local-storage-bench-{tag}-{nanos}-{n}.redb"));
    p
}

struct DbHandle {
    storage: RedbStorage,
    path: PathBuf,
}

impl DbHandle {
    fn open_with_password(tag: &str) -> Self {
        let path = unique_db_path(tag);
        let storage =
            RedbStorage::new(Some("bench_password".to_string()), path.display().to_string())
                .expect("open db");
        Self { storage, path }
    }
}

impl Drop for DbHandle {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn make_ring_index(n: usize) -> Vec<RingIndexEntry> {
    (0..n)
        .map(|i| RingIndexEntry {
            // ~64 hex chars to mirror `aggregate_pk.to_string()` length.
            ring_pk_str: format!("{:0>64x}", i as u128),
            // Content-hash post ids are also ~64 hex chars.
            bulletin_post_id: format!("{:0>64x}", (i as u128).wrapping_mul(0x9E37_79B9)),
        })
        .collect()
}

fn bench_redb_get_plain(c: &mut Criterion) {
    let db = DbHandle::open_with_password("get_plain");
    let key = LocalStorageKeys::RingKey("hot".to_string());
    db.storage
        .set(key.clone(), vec![0xABu8; RING_SHARE_BUNDLE_BYTES])
        .unwrap();

    let mut g = c.benchmark_group("redb_get_plain");
    g.throughput(Throughput::Bytes(RING_SHARE_BUNDLE_BYTES as u64));
    g.bench_function("warm_1KB", |b| {
        b.iter(|| {
            let v = db.storage.get(black_box(key.clone())).unwrap();
            black_box(v);
        });
    });
    g.finish();
}

fn bench_redb_get_encrypted(c: &mut Criterion) {
    let db = DbHandle::open_with_password("get_encrypted");

    let small_key = LocalStorageKeys::RingKey("share".to_string());
    db.storage
        .set_encrypted(
            small_key.clone(),
            Zeroizing::new(vec![0xCDu8; RING_SHARE_BUNDLE_BYTES]),
        )
        .unwrap();

    let index = make_ring_index(MAX_LOCAL_RINGS_PER_NODE);
    let index_json = serde_json::to_vec(&index).unwrap();
    let index_bytes_len = index_json.len();
    db.storage
        .set_encrypted(LocalStorageKeys::RingIndex, Zeroizing::new(index_json))
        .unwrap();

    let mut g = c.benchmark_group("redb_get_encrypted");
    g.throughput(Throughput::Bytes(RING_SHARE_BUNDLE_BYTES as u64));
    g.bench_function("ring_share_bundle_1KB", |b| {
        b.iter(|| {
            let v = db.storage.get_encrypted(black_box(small_key.clone())).unwrap();
            black_box(v);
        });
    });
    g.throughput(Throughput::Bytes(index_bytes_len as u64));
    g.bench_function(format!("ring_index_{}_entries", MAX_LOCAL_RINGS_PER_NODE), |b| {
        b.iter(|| {
            let v = db
                .storage
                .get_encrypted(black_box(LocalStorageKeys::RingIndex))
                .unwrap();
            black_box(v);
        });
    });
    g.finish();
}

fn bench_redb_set_encrypted(c: &mut Criterion) {
    let db = DbHandle::open_with_password("set_encrypted");
    let payload = vec![0x11u8; RING_SHARE_BUNDLE_BYTES];

    let mut g = c.benchmark_group("redb_set_encrypted");
    g.throughput(Throughput::Bytes(RING_SHARE_BUNDLE_BYTES as u64));
    g.bench_function("ring_share_bundle_1KB", |b| {
        let mut i = 0u64;
        b.iter(|| {
            // Distinct key each iter to avoid measuring same-key overwrite cost only.
            let key = LocalStorageKeys::RingKey(format!("k{i}"));
            i = i.wrapping_add(1);
            db.storage
                .set_encrypted(black_box(key), Zeroizing::new(payload.clone()))
                .unwrap();
        });
    });
    g.finish();
}

fn bench_ring_index_decode(c: &mut Criterion) {
    let mut g = c.benchmark_group("ring_index_decode");
    for &n in &[1usize, 16, 64, MAX_LOCAL_RINGS_PER_NODE] {
        let json = serde_json::to_vec(&make_ring_index(n)).unwrap();
        g.throughput(Throughput::Bytes(json.len() as u64));
        g.bench_with_input(BenchmarkId::from_parameter(n), &json, |b, json| {
            b.iter(|| {
                let v: Vec<RingIndexEntry> = serde_json::from_slice(black_box(json)).unwrap();
                black_box(v);
            });
        });
    }
    g.finish();
}

fn bench_managed_ring_count(c: &mut Criterion) {
    // End-to-end shape of `bin/orbis-node/src/info/service.rs:103` —
    // get_encrypted(RingIndex) + JSON-decode + count.
    let db = DbHandle::open_with_password("managed_ring_count");

    let mut g = c.benchmark_group("managed_ring_count");
    for &n in &[1usize, 16, 64, MAX_LOCAL_RINGS_PER_NODE] {
        let json = serde_json::to_vec(&make_ring_index(n)).unwrap();
        db.storage
            .set_encrypted(LocalStorageKeys::RingIndex, Zeroizing::new(json))
            .unwrap();
        g.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, _| {
            b.iter(|| {
                let bytes = db
                    .storage
                    .get_encrypted(black_box(LocalStorageKeys::RingIndex))
                    .unwrap()
                    .expect("present");
                let entries: Vec<RingIndexEntry> = serde_json::from_slice(&bytes).unwrap();
                black_box(entries.len());
            });
        });
    }
    g.finish();
}

criterion_group!(
    benches,
    bench_redb_get_plain,
    bench_redb_get_encrypted,
    bench_redb_set_encrypted,
    bench_ring_index_decode,
    bench_managed_ring_count,
);
criterion_main!(benches);
