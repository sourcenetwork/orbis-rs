use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use std::time::Duration;

use crypto::r#trait::ThresholdSigner;

#[cfg(feature = "bls12-381")]
#[path = "bls12_381/sign.rs"]
mod bls12_381_sign;

#[cfg(feature = "decaf377")]
#[path = "decaf377/sign.rs"]
mod decaf377_sign;

// ---------------------------------------------------------------------------
// Message shared between the benchmark runner and each implementation's fixture
// ---------------------------------------------------------------------------

pub const MSG: &[u8] = b"benchmark signing payload - 36 bytes!!";

// ---------------------------------------------------------------------------
// Generic benchmark infrastructure
// ---------------------------------------------------------------------------

/// Pre-computed state for benchmarking any `ThresholdSigner` implementation.
///
/// For non-interactive signers (BLS): `commitments` and `signing_states` are
/// empty — they are unused by the signing logic.
/// For interactive signers (FROST): `commitments` holds t nonce commitments
/// and `signing_states` holds the corresponding secret nonce pairs.
pub struct SignBenchFixture<S: ThresholdSigner> {
    pub signer: S,
    pub aggregate_pk: S::PublicKey,
    pub pub_poly: S::PubPoly,
    /// First `t` dist-key shares (one per participating signer).
    pub dist_key_shares: Vec<S::DistKeyShare>,
    /// Participant IDs parallel to `dist_key_shares`.
    pub participant_ids: Vec<u32>,
    /// Round-1 nonce commitments (empty for non-interactive schemes).
    pub commitments: Vec<(u32, S::NonceCommitment)>,
    /// Round-1 secret nonce state (empty for non-interactive schemes).
    pub signing_states: Vec<S::SigningState>,
    /// Pre-computed signature shares (one per participant, for t participants).
    pub sig_shares: Vec<S::SigShare>,
    /// Recovered full signature.
    pub full_sig: S::Signature,
    pub t: usize,
    pub n: usize,
}

/// Implement this trait to plug a `ThresholdSigner` implementation into the
/// generic benchmark suite.
pub trait SignBenchSetup {
    type Signer: ThresholdSigner;

    /// Build a full fixture: run DKG, optionally run Round 1 nonce exchange,
    /// sign with t shares, and recover the full signature.
    fn create_fixture(t: usize, n: usize) -> SignBenchFixture<Self::Signer>;
}

/// Register all signing benchmarks for a given `SignBenchSetup` implementation.
fn run_sign_benchmarks<S: SignBenchSetup>(c: &mut Criterion, prefix: &str) {
    // -- hash_message (non-interactive / BLS only) ----------------------------
    // FROST's hash_message always returns Err, so only run for BLS.
    if !<S::Signer as ThresholdSigner>::INTERACTIVE {
        let fixture = S::create_fixture(2, 3);
        c.bench_function(&format!("{prefix}/hash_message"), |b| {
            b.iter(|| fixture.signer.hash_message(black_box(MSG)).unwrap())
        });
    }

    // -- generate_nonces ------------------------------------------------------
    {
        let mut group = c.benchmark_group(format!("{prefix}/generate_nonces"));

        for &(t, n) in &[(2, 3), (3, 5), (5, 9)] {
            let fixture = S::create_fixture(t, n);

            group.bench_function(BenchmarkId::new("t_of_n", format!("{t}_of_{n}")), |b| {
                b.iter(|| {
                    fixture
                        .signer
                        .generate_nonces(black_box(&fixture.dist_key_shares[0]))
                        .unwrap()
                })
            });
        }

        group.finish();
    }

    // -- sign -----------------------------------------------------------------
    {
        let mut group = c.benchmark_group(format!("{prefix}/sign"));

        for &(t, n) in &[(2, 3), (3, 5), (5, 9)] {
            let fixture = S::create_fixture(t, n);

            group.bench_function(BenchmarkId::new("t_of_n", format!("{t}_of_{n}")), |b| {
                b.iter(|| {
                    fixture
                        .signer
                        .sign(
                            black_box(&fixture.dist_key_shares[0]),
                            black_box(MSG),
                            black_box(&fixture.pub_poly),
                            // None for BLS (empty vec → first() = None);
                            // Some(&state) for FROST.
                            black_box(fixture.signing_states.first()),
                            black_box(&fixture.commitments),
                        )
                        .unwrap()
                })
            });
        }

        group.finish();
    }

    // -- verify_share ---------------------------------------------------------
    {
        let mut group = c.benchmark_group(format!("{prefix}/verify_share"));

        for &(t, n) in &[(2, 3), (3, 5), (5, 9)] {
            let fixture = S::create_fixture(t, n);

            group.bench_function(BenchmarkId::new("t_of_n", format!("{t}_of_{n}")), |b| {
                b.iter(|| {
                    fixture
                        .signer
                        .verify_share(
                            black_box(MSG),
                            black_box(&fixture.pub_poly),
                            black_box(&fixture.sig_shares[0]),
                            black_box(&fixture.commitments),
                        )
                        .unwrap()
                })
            });
        }

        group.finish();
    }

    // -- recover (varying t-of-n) ---------------------------------------------
    {
        let mut group = c.benchmark_group(format!("{prefix}/recover"));

        for &(t, n) in &[(2, 3), (3, 5), (5, 9)] {
            let fixture = S::create_fixture(t, n);

            group.bench_function(BenchmarkId::new("t_of_n", format!("{t}_of_{n}")), |b| {
                b.iter(|| {
                    fixture
                        .signer
                        .recover(
                            black_box(&fixture.sig_shares),
                            black_box(t),
                            black_box(n),
                            black_box(MSG),
                            black_box(&fixture.commitments),
                        )
                        .unwrap()
                })
            });
        }

        group.finish();
    }

    // -- verify ---------------------------------------------------------------
    {
        let fixture = S::create_fixture(3, 5);

        c.bench_function(&format!("{prefix}/verify"), |b| {
            b.iter(|| {
                fixture
                    .signer
                    .verify(
                        black_box(&fixture.aggregate_pk),
                        black_box(MSG),
                        black_box(&fixture.full_sig),
                    )
                    .unwrap()
            })
        });
    }

    // -- end_to_end -----------------------------------------------------------
    {
        let mut group = c.benchmark_group(format!("{prefix}/end_to_end"));
        group.measurement_time(Duration::from_secs(10));

        for &(t, n) in &[(2, 3), (3, 5), (5, 9)] {
            let fixture = S::create_fixture(t, n);

            group.bench_function(BenchmarkId::new("t_of_n", format!("{t}_of_{n}")), |b| {
                b.iter(|| {
                    // Round 1: each participant generates nonces
                    let mut commitments = Vec::with_capacity(fixture.t);
                    let mut states = Vec::with_capacity(fixture.t);
                    for (i, dks) in fixture.dist_key_shares.iter().enumerate() {
                        let (commitment, state) =
                            fixture.signer.generate_nonces(black_box(dks)).unwrap();
                        commitments.push((fixture.participant_ids[i], commitment));
                        states.push(state);
                    }

                    // Round 2: each participant signs
                    let mut sig_shares = Vec::with_capacity(fixture.t);
                    for (i, dks) in fixture.dist_key_shares.iter().enumerate() {
                        let share = fixture
                            .signer
                            .sign(
                                black_box(dks),
                                black_box(MSG),
                                black_box(&fixture.pub_poly),
                                black_box(states.get(i)),
                                black_box(&commitments),
                            )
                            .unwrap();
                        sig_shares.push(share);
                    }

                    // Recover the full signature
                    let full_sig = fixture
                        .signer
                        .recover(
                            black_box(&sig_shares),
                            black_box(fixture.t),
                            black_box(fixture.n),
                            black_box(MSG),
                            black_box(&commitments),
                        )
                        .unwrap()
                        .unwrap();

                    // Verify
                    black_box(
                        fixture
                            .signer
                            .verify(
                                black_box(&fixture.aggregate_pk),
                                black_box(MSG),
                                black_box(&full_sig),
                            )
                            .unwrap(),
                    )
                })
            });
        }

        group.finish();
    }
}

// ---------------------------------------------------------------------------
// Benchmark registration (one curve per build; features are mutually exclusive)
// ---------------------------------------------------------------------------
fn run_all_sign_benchmarks(c: &mut Criterion) {
    #[cfg(feature = "bls12-381")]
    run_sign_benchmarks::<bls12_381_sign::Bls12381SignBench>(c, "bls12_381");
    #[cfg(feature = "decaf377")]
    run_sign_benchmarks::<decaf377_sign::Decaf377SignBench>(c, "decaf377");
}

criterion_group!(benches, run_all_sign_benchmarks);
criterion_main!(benches);
