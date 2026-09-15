//! Synthetic MPC-share interoperability test, not a deployed Orbis service.
use ark_ff::PrimeField;
use crypto::r#trait::{DistKeyShare, PriShare, PubPoly, ThresholdDealer};
use crypto::{CiphertextContext, CryptoSerialize, PreImpl, PubPolyImpl};
use decaf377::{Element, Fr};
use rand_core::OsRng;
use serde_json::json;
use std::{fs, path::Path, time::Instant};

fn public_polynomial(shares: &[Fr]) -> PubPolyImpl {
    let mut commits = vec![Element::default(); shares.len()];
    for (i, share) in shares.iter().enumerate() {
        let x = Fr::from(i as u64 + 1);
        let mut coeff = vec![Fr::from(1u64)];
        let mut denom = Fr::from(1u64);
        for j in 0..shares.len() {
            if i == j {
                continue;
            }
            let y = Fr::from(j as u64 + 1);
            let mut next = vec![Fr::from(0u64); coeff.len() + 1];
            for (k, c) in coeff.iter().enumerate() {
                next[k] -= *c * y;
                next[k + 1] += c;
            }
            coeff = next;
            denom *= x - y;
        }
        let point = Element::GENERATOR * (*share * denom.inverse().unwrap());
        for (target, c) in commits.iter_mut().zip(coeff) {
            *target += point * c;
        }
    }
    PubPolyImpl { commits }
}

fn main() {
    let args: Vec<_> = std::env::args().collect();
    assert!(args.len() == 5, "usage: lakey_pre <synthetic Persistence directory> <nodes> <threshold> <public-reference.json>");
    let dir = Path::new(&args[1]);
    let n: usize = args[2].parse().unwrap();
    let t: usize = args[3].parse().unwrap();
    let reference = Path::new(&args[4]);
    assert!(t >= 2 && t <= n && n <= 32);
    // Files are synthetic local test fixtures. This process can read all nodes;
    // production must keep each share with its node and use authenticated handoff.
    let mut by_node = Vec::new();
    let mut masters = Vec::new();
    let mut rbytes = [0u8; 33];
    rbytes[32] = 1;
    let r_inv = Fr::from_le_bytes_mod_order(&rbytes).inverse().unwrap();
    for i in 0..n {
        let path = dir.join(format!("Transactions-P{i}.data"));
        let bytes = fs::read(&path).unwrap();
        let header = 8 + u64::from_le_bytes(bytes[..8].try_into().unwrap()) as usize;
        assert_eq!(
            bytes.len(),
            header + (512 + 4) * 32,
            "unexpected fixture format"
        );
        let mut shares = Vec::new();
        masters.push(
            (0..512)
                .map(|j| {
                    Fr::from_le_bytes_mod_order(&bytes[header + j * 32..header + (j + 1) * 32])
                        * r_inv
                })
                .collect::<Vec<_>>(),
        );
        for j in 0..4 {
            let off = header + (512 + j) * 32;
            shares.push(Fr::from_le_bytes_mod_order(&bytes[off..off + 32]) * r_inv);
        }
        by_node.push(shares);
        // Remove the bounded synthetic handoff slots. Only 512 master shares remain.
        fs::OpenOptions::new()
            .write(true)
            .open(path)
            .unwrap()
            .set_len((header + 512 * 32) as u64)
            .unwrap();
    }
    let polys: Vec<_> = (0..4)
        .map(|slot| {
            let shares: Vec<_> = by_node.iter().map(|v| v[slot]).collect();
            let p = public_polynomial(&shares[..t]);
            for (i, s) in shares.iter().enumerate() {
                assert_eq!(p.eval(i as u32 + 1), Element::GENERATOR * (*s));
            }
            p
        })
        .collect();
    // Independent clear reference on synthetic fixtures ONLY: catches incorrect
    // modulus, Montgomery decoding, byte ordering, and public-matrix expansion.
    let mut master = vec![Fr::from(0u64); 512];
    for i in 0..t {
        let x = Fr::from(i as u64 + 1);
        let mut coeff = Fr::from(1u64);
        for j in 0..t {
            if i != j {
                let y = Fr::from(j as u64 + 1);
                coeff *= -y * (x - y).inverse().unwrap();
            }
        }
        for j in 0..512 {
            master[j] += masters[i][j] * coeff;
        }
    }
    let logq: usize = 32;
    let stat: usize = 128;
    let logp = if logq == 12 { 8 } else { 24 };
    let rows = (251 + stat + logp - 1) / logp;
    let ints: Vec<u128> = master
        .iter()
        .map(|v| {
            let limbs = v.into_bigint();
            assert!(limbs.0[1..].iter().all(|v| *v == 0));
            let value = limbs.0[0] as u128;
            assert!(value < (1u128 << logq));
            value
        })
        .collect();
    for (slot, identity) in [
        "chain1/ring1/epoch1/named/Alice/amount",
        "chain1/ring1/epoch1/named/Bob/amount",
        "chain1/ring1/epoch1/named/Alice/sender",
        "chain1/ring1/epoch1/general/amount",
    ]
    .iter()
    .enumerate()
    {
        use sha3::digest::{ExtendableOutput, Update, XofReader};
        let mut h = sha3::Shake256::default();
        h.update(b"orbis-lakey-poc-v1\0");
        h.update(identity.as_bytes());
        let mut data = vec![0u8; rows * 512 * 4];
        h.finalize_xof().read(&mut data);
        let mut expected = Fr::from(0u64);
        let mut weight = Fr::from(1u64);
        for row in 0..rows {
            let mut dot = 0u128;
            for j in 0..512 {
                let off = (row * 512 + j) * 4;
                let a = u32::from_le_bytes(data[off..off + 4].try_into().unwrap()) as u128
                    & ((1u128 << logq) - 1);
                dot += a * ints[j];
            }
            let rounded = (dot & ((1u128 << logq) - 1)) >> (logq - logp);
            expected += Fr::from(rounded as u64) * weight;
            weight *= Fr::from(1u64 << logp);
        }
        assert_eq!(
            polys[slot].commits[0],
            Element::GENERATOR * expected,
            "independent LaKey reference mismatch"
        );
    }
    for i in 0..4 {
        for j in i + 1..4 {
            assert_ne!(polys[i].commits[0], polys[j].commits[0]);
        }
    }
    let public_keys: Vec<_> = polys
        .iter()
        .map(|p| p.commits[0].to_bytes().unwrap())
        .collect();
    if reference.exists() {
        assert_eq!(
            public_keys,
            serde_json::from_slice::<Vec<Vec<u8>>>(&fs::read(reference).unwrap()).unwrap(),
            "derived keys changed across restart/refresh"
        );
    } else {
        fs::write(reference, serde_json::to_vec(&public_keys).unwrap()).unwrap();
    }
    let pre = PreImpl::new();
    let reader = Fr::rand(&mut OsRng);
    let reader_pk = Element::GENERATOR * reader;
    let pop = PreImpl::prove_reader_key(&reader, &reader_pk).unwrap();
    let start = Instant::now();
    for encrypted_scope in 0..4 {
        let context = CiphertextContext {
            ring_pk: public_keys[encrypted_scope].clone(),
            policy_id: "synthetic-policy".into(),
            resource: "synthetic-payment".into(),
            permission: "audit".into(),
            tier: Some(encrypted_scope.to_string()),
            timestamp: None,
            salt: None,
        };
        let plaintext = b"synthetic disclosed value";
        let (epk, secret, encryption_proof) = PreImpl::encrypt_secret(
            &polys[encrypted_scope].commits[0],
            plaintext,
            None,
            &context,
        )
        .unwrap();
        PreImpl::verify_encryption(&encryption_proof, &context, &secret).unwrap();
        let mut opened = Vec::new();
        // Audit the same ciphertext under each scope, including unrelated people.
        for scope in 0..4 {
            let mut replies = Vec::new();
            for (i, shares) in by_node.iter().take(t).enumerate() {
                let key = DistKeyShare {
                    pri_share: PriShare {
                        i: i as u32 + 1,
                        v: shares[scope],
                    },
                };
                // The LaKey output is already the effective key. No public derivation.
                let reply = pre
                    .reencrypt(&key, &secret, &reader_pk, &pop, None)
                    .unwrap();
                pre.verify(&reader_pk, &polys[scope], &epk, &reply, None)
                    .unwrap();
                assert!(pre
                    .verify(&reader_pk, &polys[(scope + 1) % 4], &epk, &reply, None)
                    .is_err());
                assert!(pre
                    .verify(
                        &reader_pk,
                        &polys[scope],
                        &(epk + Element::GENERATOR),
                        &reply,
                        None
                    )
                    .is_err());
                replies.push(reply.share.clone());
            }
            assert!(pre.recover(&replies[..t - 1], t, n).unwrap().is_none());
            let result = pre.recover(&replies, t, n).unwrap().unwrap();
            let decrypted = PreImpl::decrypt_secret(
                &polys[scope].commits[0],
                &result,
                &reader,
                &secret,
                &context,
            );
            if scope == encrypted_scope {
                assert_eq!(decrypted.unwrap(), plaintext);
            } else {
                assert!(decrypted.is_err(), "unrelated person or field decrypted");
            }
            opened.push(result - polys[scope].commits[0] * reader);
        }
        for i in 1..4 {
            assert_ne!(opened[0], opened[i]);
        }
    }
    println!(
        "{}",
        json!({"case":"LaKey MPC shares into pinned Orbis Decaf377 PRE","nodes":n,"threshold":t,"ciphertexts":4,"independent_scopes":4,"seconds":start.elapsed().as_secs_f64(),"persistent_master_scalar_shares_per_node":512,"clear_key_output":false,"fixture_reference_reconstructs_synthetic_master_in_test_process":true,"checks":"independent clear LaKey reference, polynomial consistency, restart/refresh public keys, DLEQ, wrong key/field/ephemeral point, insufficient shares, wrong-scope plaintext decryption"})
    );
}
