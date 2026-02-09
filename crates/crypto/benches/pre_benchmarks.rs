use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};

use crypto::r#trait::{EncryptionProof, PubShare, ThresholdDealer};

#[path = "bls12_381/pre.rs"]
mod bls12_381_pre;

// ---------------------------------------------------------------------------
// Generic benchmark infrastructure
// ---------------------------------------------------------------------------

/// Pre-computed data for benchmarking any ThresholdDealer implementation.
pub struct BenchFixture<D: ThresholdDealer> {
    pub dealer: D,
    pub aggregate_pk: D::PublicKey,
    pub pub_poly: D::PubPoly,
    pub dist_key_shares: Vec<D::DistKeyShare>,
    pub rdr_sk: D::ShareValue,
    pub rdr_pk: D::PublicKey,
    pub enc_cmt: D::PublicKey,
    pub secret: D::Secret,
    pub proof: EncryptionProof,
    pub reencrypt_reply: D::ReencryptReply,
    pub pub_shares: Vec<PubShare<D::PublicKey>>,
    pub xnc_cmt: D::PublicKey,
    pub t: usize,
    pub n: usize,
}

/// Implement this trait to plug a ThresholdDealer implementation into the
/// generic benchmark suite.
pub trait BenchSetup {
    type Dealer: ThresholdDealer;

    /// Run DKG, encrypt a test secret, pre-compute reencrypt shares and
    /// recovered commitment — everything the benchmarks need.
    fn create_fixture(t: usize, n: usize) -> BenchFixture<Self::Dealer>;

    /// Extract a `PubShare` from an opaque `ReencryptReply`.
    fn extract_pub_share(
        reply: &<Self::Dealer as ThresholdDealer>::ReencryptReply,
    ) -> PubShare<<Self::Dealer as ThresholdDealer>::PublicKey>;
}

/// Register all PRE benchmarks for a given `BenchSetup` implementation.
fn run_pre_benchmarks<S: BenchSetup>(c: &mut Criterion, prefix: &str) {
    let fixture = S::create_fixture(3, 5);
    let data: &[u8] = b"benchmark secret payload - 32 bytes!";

    // -- encrypt_secret -------------------------------------------------------
    {
        let mut group = c.benchmark_group(format!("{prefix}/encrypt_secret"));

        group.bench_function("no_derivation", |b| {
            b.iter(|| {
                <S::Dealer as ThresholdDealer>::encrypt_secret(
                    black_box(&fixture.aggregate_pk),
                    black_box(data),
                    None,
                    None,
                )
                .unwrap()
            })
        });

        let derivation: &[u8] = b"capability/resource/read";
        group.bench_function("with_derivation", |b| {
            b.iter(|| {
                <S::Dealer as ThresholdDealer>::encrypt_secret(
                    black_box(&fixture.aggregate_pk),
                    black_box(data),
                    Some(black_box(derivation)),
                    None,
                )
                .unwrap()
            })
        });

        let metadata: &[u8] = b"document-id:12345";
        group.bench_function("with_metadata", |b| {
            b.iter(|| {
                <S::Dealer as ThresholdDealer>::encrypt_secret(
                    black_box(&fixture.aggregate_pk),
                    black_box(data),
                    None,
                    Some(black_box(metadata)),
                )
                .unwrap()
            })
        });

        group.finish();
    }

    // -- decrypt_secret -------------------------------------------------------
    c.bench_function(&format!("{prefix}/decrypt_secret"), |b| {
        b.iter(|| {
            <S::Dealer as ThresholdDealer>::decrypt_secret(
                black_box(&fixture.aggregate_pk),
                black_box(&fixture.xnc_cmt),
                black_box(&fixture.rdr_sk),
                black_box(&fixture.secret),
            )
            .unwrap()
        })
    });

    // -- verify_encryption ----------------------------------------------------
    c.bench_function(&format!("{prefix}/verify_encryption"), |b| {
        b.iter(|| {
            <S::Dealer as ThresholdDealer>::verify_encryption(
                black_box(&fixture.aggregate_pk),
                black_box(&fixture.enc_cmt),
                black_box(&fixture.proof),
                None,
            )
            .unwrap()
        })
    });

    // -- reencrypt ------------------------------------------------------------
    {
        let mut group = c.benchmark_group(format!("{prefix}/reencrypt"));

        group.bench_function("no_derivation", |b| {
            b.iter(|| {
                fixture
                    .dealer
                    .reencrypt(
                        black_box(&fixture.dist_key_shares[0]),
                        black_box(&fixture.secret),
                        black_box(&fixture.rdr_pk),
                        None,
                    )
                    .unwrap()
            })
        });

        let derivation: &[u8] = b"capability/resource/read";
        group.bench_function("with_derivation", |b| {
            b.iter(|| {
                fixture
                    .dealer
                    .reencrypt(
                        black_box(&fixture.dist_key_shares[0]),
                        black_box(&fixture.secret),
                        black_box(&fixture.rdr_pk),
                        Some(black_box(derivation)),
                    )
                    .unwrap()
            })
        });

        group.finish();
    }

    // -- verify_reencrypt -----------------------------------------------------
    c.bench_function(&format!("{prefix}/verify_reencrypt"), |b| {
        b.iter(|| {
            fixture
                .dealer
                .verify(
                    black_box(&fixture.rdr_pk),
                    black_box(&fixture.pub_poly),
                    black_box(&fixture.enc_cmt),
                    black_box(&fixture.reencrypt_reply),
                    None,
                )
                .unwrap()
        })
    });

    // -- recover (varying t-of-n) ---------------------------------------------
    {
        let mut group = c.benchmark_group(format!("{prefix}/recover"));

        for &(t, n) in &[(2, 3), (3, 5), (5, 9)] {
            let f = S::create_fixture(t, n);

            group.bench_with_input(
                BenchmarkId::new("lagrange_interpolation", format!("{t}_of_{n}")),
                &f.pub_shares,
                |b, shares| {
                    b.iter(|| {
                        f.dealer
                            .recover(black_box(shares), black_box(t), black_box(n))
                            .unwrap()
                    })
                },
            );
        }

        group.finish();
    }

    // -- end_to_end -----------------------------------------------------------
    {
        let mut group = c.benchmark_group(format!("{prefix}/end_to_end"));
        group.measurement_time(std::time::Duration::from_secs(10));
        group.bench_function("3_of_5", |b| {
            b.iter(|| {
                // Encrypt
                let (_enc_cmt, secret, _proof) = <S::Dealer as ThresholdDealer>::encrypt_secret(
                    &fixture.aggregate_pk,
                    data,
                    None,
                    None,
                )
                .unwrap();

                // Re-encrypt with t shares
                let mut pub_shares = Vec::with_capacity(fixture.t);
                for dks in fixture.dist_key_shares.iter().take(fixture.t) {
                    let reply = fixture
                        .dealer
                        .reencrypt(dks, &secret, &fixture.rdr_pk, None)
                        .unwrap();
                    pub_shares.push(S::extract_pub_share(&reply));
                }

                // Recover
                let xnc_cmt = fixture
                    .dealer
                    .recover(&pub_shares, fixture.t, fixture.n)
                    .unwrap()
                    .unwrap();

                // Decrypt
                <S::Dealer as ThresholdDealer>::decrypt_secret(
                    &fixture.aggregate_pk,
                    &xnc_cmt,
                    &fixture.rdr_sk,
                    &secret,
                )
                .unwrap()
            })
        });
        group.finish();
    }
}

// ---------------------------------------------------------------------------
// Benchmark registration
// ---------------------------------------------------------------------------
fn bls12_381_benchmarks(c: &mut Criterion) {
    run_pre_benchmarks::<bls12_381_pre::Bls12381Bench>(c, "bls12_381");
}

criterion_group!(benches, bls12_381_benchmarks);
criterion_main!(benches);
