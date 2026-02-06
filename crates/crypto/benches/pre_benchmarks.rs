use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};

use ark_bls12_381::{Fr, G1Affine, G1Projective};
use ark_ec::Group;
use ark_std::UniformRand;
use rand_core::OsRng;

use crypto::bls12_381::pre::ThresholdDealerNode;
use crypto::r#trait::{DistKeyShare, PriShare, PubShare, ThresholdDealer};
use crypto::test_helper::DKGCoordinator;

/// Run DKG and return everything needed to benchmark PRE operations.
fn setup_dkg(
    t: usize,
    n: usize,
) -> (
    G1Affine,                           // aggregate_pk
    Vec<PriShare<Fr>>,                  // secret_shares
    crypto::bls12_381::common::PubPoly, // pub_poly
    Fr,                                 // rdr_sk
    G1Affine,                           // rdr_pk
    G1Affine,                           // enc_cmt
    crypto::r#trait::Secret,            // encrypted_secret
    crypto::r#trait::EncryptionProof,   // proof
) {
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

    let secret_data = b"benchmark secret payload - 32 bytes!";
    let (enc_cmt, encrypted_secret, proof) =
        ThresholdDealerNode::encrypt_secret(&aggregate_pk, secret_data, None, None).unwrap();

    (
        aggregate_pk,
        secret_shares,
        pub_poly,
        rdr_sk,
        rdr_pk,
        enc_cmt,
        encrypted_secret,
        proof,
    )
}

fn bench_encrypt_secret(c: &mut Criterion) {
    let mut rng = OsRng;
    let dkg_sk = Fr::rand(&mut rng);
    let dkg_pk: G1Affine = (G1Projective::generator() * dkg_sk).into();
    let data = b"benchmark secret payload - 32 bytes!";

    let mut group = c.benchmark_group("encrypt_secret");

    group.bench_function("no_derivation", |b| {
        b.iter(|| {
            ThresholdDealerNode::encrypt_secret(black_box(&dkg_pk), black_box(data), None, None)
                .unwrap()
        })
    });

    let derivation = b"capability/resource/read";
    group.bench_function("with_derivation", |b| {
        b.iter(|| {
            ThresholdDealerNode::encrypt_secret(
                black_box(&dkg_pk),
                black_box(data),
                Some(black_box(derivation)),
                None,
            )
            .unwrap()
        })
    });

    let metadata = b"document-id:12345";
    group.bench_function("with_metadata", |b| {
        b.iter(|| {
            ThresholdDealerNode::encrypt_secret(
                black_box(&dkg_pk),
                black_box(data),
                None,
                Some(black_box(metadata)),
            )
            .unwrap()
        })
    });

    group.finish();
}

fn bench_decrypt_secret(c: &mut Criterion) {
    let mut rng = OsRng;
    let dkg_sk = Fr::rand(&mut rng);
    let dkg_pk: G1Affine = (G1Projective::generator() * dkg_sk).into();
    let rdr_sk = Fr::rand(&mut rng);
    let rdr_pk: G1Affine = (G1Projective::generator() * rdr_sk).into();

    let data = b"benchmark secret payload - 32 bytes!";
    let (enc_cmt, encrypted_secret, _proof) =
        ThresholdDealerNode::encrypt_secret(&dkg_pk, data, None, None).unwrap();

    // Simulate full re-encryption: xnc_cmt = dkg_sk * (rdr_pk + enc_cmt)
    let xr_g = G1Projective::from(rdr_pk) + G1Projective::from(enc_cmt);
    let xnc_cmt: G1Affine = (xr_g * dkg_sk).into();

    c.bench_function("decrypt_secret", |b| {
        b.iter(|| {
            ThresholdDealerNode::decrypt_secret(
                black_box(&dkg_pk),
                black_box(&xnc_cmt),
                black_box(&rdr_sk),
                black_box(&encrypted_secret),
            )
            .unwrap()
        })
    });
}

fn bench_verify_encryption(c: &mut Criterion) {
    let mut rng = OsRng;
    let dkg_sk = Fr::rand(&mut rng);
    let dkg_pk: G1Affine = (G1Projective::generator() * dkg_sk).into();

    let data = b"benchmark secret payload - 32 bytes!";
    let (enc_cmt, _secret, proof) =
        ThresholdDealerNode::encrypt_secret(&dkg_pk, data, None, None).unwrap();

    c.bench_function("verify_encryption", |b| {
        b.iter(|| {
            ThresholdDealerNode::verify_encryption(
                black_box(&dkg_pk),
                black_box(&enc_cmt),
                black_box(&proof),
                None,
            )
            .unwrap()
        })
    });
}

fn bench_reencrypt(c: &mut Criterion) {
    let t = 3;
    let n = 5;
    let (
        _aggregate_pk,
        secret_shares,
        _pub_poly,
        _rdr_sk,
        rdr_pk,
        _enc_cmt,
        encrypted_secret,
        _proof,
    ) = setup_dkg(t, n);

    let dealer = ThresholdDealerNode::new();
    let dist_key_share = DistKeyShare {
        pri_share: secret_shares[0].clone(),
    };

    let mut group = c.benchmark_group("reencrypt");

    group.bench_function("no_derivation", |b| {
        b.iter(|| {
            dealer
                .reencrypt(
                    black_box(&dist_key_share),
                    black_box(&encrypted_secret),
                    black_box(&rdr_pk),
                    None,
                )
                .unwrap()
        })
    });

    let derivation = b"capability/resource/read";
    group.bench_function("with_derivation", |b| {
        b.iter(|| {
            dealer
                .reencrypt(
                    black_box(&dist_key_share),
                    black_box(&encrypted_secret),
                    black_box(&rdr_pk),
                    Some(black_box(derivation)),
                )
                .unwrap()
        })
    });

    group.finish();
}

fn bench_verify_reencrypt(c: &mut Criterion) {
    let t = 3;
    let n = 5;
    let (
        _aggregate_pk,
        secret_shares,
        pub_poly,
        _rdr_sk,
        rdr_pk,
        enc_cmt,
        encrypted_secret,
        _proof,
    ) = setup_dkg(t, n);

    let dealer = ThresholdDealerNode::new();
    let dist_key_share = DistKeyShare {
        pri_share: secret_shares[0].clone(),
    };

    let reply = dealer
        .reencrypt(&dist_key_share, &encrypted_secret, &rdr_pk, None)
        .unwrap();

    c.bench_function("verify_reencrypt", |b| {
        b.iter(|| {
            dealer
                .verify(
                    black_box(&rdr_pk),
                    black_box(&pub_poly),
                    black_box(&enc_cmt),
                    black_box(&reply),
                    None,
                )
                .unwrap()
        })
    });
}

fn bench_recover(c: &mut Criterion) {
    let mut group = c.benchmark_group("recover");

    for &(t, n) in &[(2, 3), (3, 5), (5, 9)] {
        let (
            _aggregate_pk,
            secret_shares,
            _pub_poly,
            _rdr_sk,
            rdr_pk,
            _enc_cmt,
            encrypted_secret,
            _proof,
        ) = setup_dkg(t, n);

        let dealer = ThresholdDealerNode::new();

        // Generate re-encryption shares from t nodes
        let mut pub_shares: Vec<PubShare<G1Affine>> = Vec::new();
        for share in secret_shares.iter().take(t) {
            let dist_key_share = DistKeyShare {
                pri_share: share.clone(),
            };
            let reply = dealer
                .reencrypt(&dist_key_share, &encrypted_secret, &rdr_pk, None)
                .unwrap();
            pub_shares.push(reply.share);
        }

        group.bench_with_input(
            BenchmarkId::new("lagrange_interpolation", format!("{}_of_{}", t, n)),
            &(pub_shares, t, n),
            |b, (shares, t, n)| {
                b.iter(|| {
                    dealer
                        .recover(black_box(shares), black_box(*t), black_box(*n))
                        .unwrap()
                })
            },
        );
    }

    group.finish();
}

fn bench_end_to_end(c: &mut Criterion) {
    let t = 3;
    let n = 5;
    let (
        aggregate_pk,
        secret_shares,
        _pub_poly,
        rdr_sk,
        rdr_pk,
        _enc_cmt,
        _encrypted_secret,
        _proof,
    ) = setup_dkg(t, n);

    let data = b"benchmark secret payload - 32 bytes!";
    let dealer = ThresholdDealerNode::new();

    c.bench_function("end_to_end_3_of_5", |b| {
        b.iter(|| {
            // Encrypt
            let (_enc_cmt, encrypted_secret, _proof) =
                ThresholdDealerNode::encrypt_secret(&aggregate_pk, data, None, None).unwrap();

            // Re-encrypt with t shares
            let mut pub_shares: Vec<PubShare<G1Affine>> = Vec::new();
            for share in secret_shares.iter().take(t) {
                let dist_key_share = DistKeyShare {
                    pri_share: share.clone(),
                };
                let reply = dealer
                    .reencrypt(&dist_key_share, &encrypted_secret, &rdr_pk, None)
                    .unwrap();
                pub_shares.push(reply.share);
            }

            // Recover
            let xnc_cmt = dealer.recover(&pub_shares, t, n).unwrap().unwrap();

            // Decrypt
            ThresholdDealerNode::decrypt_secret(&aggregate_pk, &xnc_cmt, &rdr_sk, &encrypted_secret)
                .unwrap()
        })
    });
}

criterion_group!(
    benches,
    bench_encrypt_secret,
    bench_decrypt_secret,
    bench_verify_encryption,
    bench_reencrypt,
    bench_verify_reencrypt,
    bench_recover,
    bench_end_to_end,
);
criterion_main!(benches);
