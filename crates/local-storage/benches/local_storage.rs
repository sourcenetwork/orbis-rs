//! Benchmarks for the `local-storage` crate.
//!
//! Generic over the `LocalStorage` trait so any backend implementation gets the
//! same harness. The active backend is picked at compile time by the
//! `memory` / `redb` feature flags (mutually exclusive — see `lib.rs`). To
//! compare backends, run the suite twice with the appropriate `--features`.
//!
//! The KDF (Argon2) cost is intentionally paid once during harness setup, not
//! per iteration — that matches production, where the storage handle is
//! constructed once at node start and the derived `Aes256Gcm` cipher is reused
//! for every call.

#[cfg(not(any(feature = "redb", feature = "memory")))]
compile_error!("local-storage benches require either the `redb` or `memory` feature to be enabled");

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use local_storage::r#trait::{LocalStorage, LocalStorageKeys};
use serde::{Deserialize, Serialize};
use std::hint::black_box;
#[cfg(feature = "redb")]
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(feature = "redb")]
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

const BENCH_PASSWORD: &str = "bench_password";

#[cfg(feature = "redb")]
static BENCH_COUNTER: AtomicU64 = AtomicU64::new(0);

#[cfg(feature = "redb")]
fn unique_db_path(tag: &str) -> std::path::PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let n = BENCH_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut p = std::env::temp_dir();
    p.push(format!("orbis-local-storage-bench-{tag}-{nanos}-{n}.redb"));
    p
}

/// Construction + cleanup wrapper for whichever `LocalStorage` impl is active.
trait BenchBackend: Sized {
    type Storage: LocalStorage;
    fn open(tag: &str) -> Self;
    fn storage(&self) -> &Self::Storage;
}

#[cfg(feature = "redb")]
mod redb_backend {
    use super::*;
    use local_storage::redb::RedbStorage;
    use std::path::PathBuf;

    pub struct RedbBackend {
        storage: RedbStorage,
        path: PathBuf,
    }

    impl BenchBackend for RedbBackend {
        type Storage = RedbStorage;

        fn open(tag: &str) -> Self {
            let path = unique_db_path(tag);
            let storage =
                RedbStorage::new(Some(BENCH_PASSWORD.to_string()), path.display().to_string())
                    .expect("open redb storage");
            Self { storage, path }
        }

        fn storage(&self) -> &Self::Storage {
            &self.storage
        }
    }

    impl Drop for RedbBackend {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

#[cfg(feature = "memory")]
mod memory_backend {
    use super::*;
    use local_storage::memory::MemoryStorage;

    pub struct MemoryBackend {
        storage: MemoryStorage,
    }

    impl BenchBackend for MemoryBackend {
        type Storage = MemoryStorage;

        fn open(_tag: &str) -> Self {
            let storage = MemoryStorage::new(Some(BENCH_PASSWORD.to_string()), String::new())
                .expect("open memory storage");
            Self { storage }
        }

        fn storage(&self) -> &Self::Storage {
            &self.storage
        }
    }
}

#[cfg(feature = "redb")]
type ActiveBackend = redb_backend::RedbBackend;
#[cfg(feature = "memory")]
type ActiveBackend = memory_backend::MemoryBackend;

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

fn bench_storage_get_plain(c: &mut Criterion) {
    let backend = ActiveBackend::open("get_plain");
    let storage = backend.storage();
    let key = LocalStorageKeys::RingKey("hot".to_string());
    storage
        .set(key.clone(), vec![0xABu8; RING_SHARE_BUNDLE_BYTES])
        .unwrap();

    let mut g = c.benchmark_group("storage_get_plain");
    g.throughput(Throughput::Bytes(RING_SHARE_BUNDLE_BYTES as u64));
    g.bench_function("warm_1KB", |b| {
        b.iter(|| {
            let v = storage.get(black_box(key.clone())).unwrap();
            black_box(v);
        });
    });
    g.finish();
}

fn bench_storage_get_encrypted(c: &mut Criterion) {
    let backend = ActiveBackend::open("get_encrypted");
    let storage = backend.storage();

    let small_key = LocalStorageKeys::RingKey("share".to_string());
    storage
        .set_encrypted(
            small_key.clone(),
            Zeroizing::new(vec![0xCDu8; RING_SHARE_BUNDLE_BYTES]),
        )
        .unwrap();

    let index = make_ring_index(MAX_LOCAL_RINGS_PER_NODE);
    let index_json = serde_json::to_vec(&index).unwrap();
    let index_bytes_len = index_json.len();
    storage
        .set_encrypted(LocalStorageKeys::RingIndex, Zeroizing::new(index_json))
        .unwrap();

    let mut g = c.benchmark_group("storage_get_encrypted");
    g.throughput(Throughput::Bytes(RING_SHARE_BUNDLE_BYTES as u64));
    g.bench_function("ring_share_bundle_1KB", |b| {
        b.iter(|| {
            let v = storage.get_encrypted(black_box(small_key.clone())).unwrap();
            black_box(v);
        });
    });
    g.throughput(Throughput::Bytes(index_bytes_len as u64));
    g.bench_function(
        format!("ring_index_{}_entries", MAX_LOCAL_RINGS_PER_NODE),
        |b| {
            b.iter(|| {
                let v = storage
                    .get_encrypted(black_box(LocalStorageKeys::RingIndex))
                    .unwrap();
                black_box(v);
            });
        },
    );
    g.finish();
}

fn bench_storage_set_encrypted(c: &mut Criterion) {
    let backend = ActiveBackend::open("set_encrypted");
    let storage = backend.storage();
    let payload = vec![0x11u8; RING_SHARE_BUNDLE_BYTES];

    let mut g = c.benchmark_group("storage_set_encrypted");
    g.throughput(Throughput::Bytes(RING_SHARE_BUNDLE_BYTES as u64));
    g.bench_function("ring_share_bundle_1KB", |b| {
        let mut i = 0u64;
        b.iter(|| {
            // Distinct key each iter to avoid measuring same-key overwrite cost only.
            let key = LocalStorageKeys::RingKey(format!("k{i}"));
            i = i.wrapping_add(1);
            storage
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
    let backend = ActiveBackend::open("managed_ring_count");
    let storage = backend.storage();

    let mut g = c.benchmark_group("managed_ring_count");
    for &n in &[1usize, 16, 64, MAX_LOCAL_RINGS_PER_NODE] {
        let json = serde_json::to_vec(&make_ring_index(n)).unwrap();
        storage
            .set_encrypted(LocalStorageKeys::RingIndex, Zeroizing::new(json))
            .unwrap();
        g.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, _| {
            b.iter(|| {
                let bytes = storage
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

fn print_backend_banner() {
    // One-time backend identity print so output is unambiguous when running
    // the same suite under different feature flags.
    type S = <ActiveBackend as BenchBackend>::Storage;
    eprintln!(
        "local-storage bench backend: {}",
        <S as LocalStorage>::name()
    );
}

fn benches_group(c: &mut Criterion) {
    print_backend_banner();
    bench_storage_get_plain(c);
    bench_storage_get_encrypted(c);
    bench_storage_set_encrypted(c);
    bench_ring_index_decode(c);
    bench_managed_ring_count(c);
}

criterion_group!(benches, benches_group);
criterion_main!(benches);
