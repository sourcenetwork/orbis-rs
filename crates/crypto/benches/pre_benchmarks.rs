use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};

use crypto::r#trait::{EncryptionProof, PubShare, ThresholdDealer};

// ---------------------------------------------------------------------------
// Generic benchmark infrastructure
// ---------------------------------------------------------------------------

/// Pre-computed data for benchmarking any ThresholdDealer implementation.
struct BenchFixture<D: ThresholdDealer> {
    dealer: D,
    aggregate_pk: D::PublicKey,
    pub_poly: D::PubPoly,
    dist_key_shares: Vec<D::DistKeyShare>,
    rdr_sk: D::ShareValue,
    rdr_pk: D::PublicKey,
    enc_cmt: D::PublicKey,
    secret: D::Secret,
    proof: EncryptionProof,
    reencrypt_reply: D::ReencryptReply,
    pub_shares: Vec<PubShare<D::PublicKey>>,
    xnc_cmt: D::PublicKey,
    t: usize,
    n: usize,
}

/// Implement this trait to plug a ThresholdDealer implementation into the
/// generic benchmark suite.
trait BenchSetup {
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
    c.bench_function(&format!("{prefix}/end_to_end_3_of_5"), |b| {
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
}

// ---------------------------------------------------------------------------
// BLS12-381 implementation
// ---------------------------------------------------------------------------

use ark_bls12_381::{Fr, G1Affine, G1Projective};
use ark_ec::Group;
use ark_std::UniformRand;
use rand_core::OsRng;

use crypto::bls12_381::pre::ThresholdDealerNode;
use crypto::r#trait::DistKeyShare;
use crypto::test_helper::DKGCoordinator;

struct Bls12381Bench;

impl BenchSetup for Bls12381Bench {
    type Dealer = ThresholdDealerNode;

    fn create_fixture(t: usize, n: usize) -> BenchFixture<ThresholdDealerNode> {
        let mut coordinator = DKGCoordinator::new(
            |id: u32, threshold: usize, total_nodes: usize| {
                <crypto::bls12_381::dkg::DKGNode as crypto::r#trait::Dkg>::new(
                    id,
                    threshold,
                    total_nodes,
                )
            },
            n,
            t,
        )
        .unwrap();
        let (aggregate_pk, secret_shares, pub_poly) = coordinator.run_dkg().unwrap();

        let mut rng = OsRng;
        let rdr_sk = Fr::rand(&mut rng);
        let rdr_pk: G1Affine = (G1Projective::generator() * rdr_sk).into();

        let data = b"benchmark secret payload - 32 bytes!";
        let (enc_cmt, secret, proof) =
            ThresholdDealerNode::encrypt_secret(&aggregate_pk, data, None, None).unwrap();

        let dealer = ThresholdDealerNode::new();
        let dist_key_shares: Vec<DistKeyShare<Fr>> = secret_shares
            .into_iter()
            .map(|s| DistKeyShare { pri_share: s })
            .collect();

        // Pre-compute reencrypt replies and pub_shares
        let mut pub_shares = Vec::with_capacity(t);
        let mut replies = Vec::with_capacity(t);
        for dks in dist_key_shares.iter().take(t) {
            let reply = dealer.reencrypt(dks, &secret, &rdr_pk, None).unwrap();
            pub_shares.push(reply.share.clone());
            replies.push(reply);
        }
        let reencrypt_reply = replies.swap_remove(0);

        let xnc_cmt = dealer.recover(&pub_shares, t, n).unwrap().unwrap();

        BenchFixture {
            dealer,
            aggregate_pk,
            pub_poly,
            dist_key_shares,
            rdr_sk,
            rdr_pk,
            enc_cmt,
            secret,
            proof,
            reencrypt_reply,
            pub_shares,
            xnc_cmt,
            t,
            n,
        }
    }

    fn extract_pub_share(
        reply: &<ThresholdDealerNode as ThresholdDealer>::ReencryptReply,
    ) -> PubShare<G1Affine> {
        reply.share.clone()
    }
}

fn bls12_381_benchmarks(c: &mut Criterion) {
    run_pre_benchmarks::<Bls12381Bench>(c, "bls12_381");
}

criterion_group!(benches, bls12_381_benchmarks);
criterion_main!(benches);
