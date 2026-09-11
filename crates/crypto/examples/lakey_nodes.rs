//! Five-node process test; workers see only their own initialized node state.
use crypto::r#trait::{PubPoly, ThresholdDealer};
use crypto::{
    lakey::{self, Field, Identity, PreShare, Scope},
    CryptoDeserialize, GroupAffine, PreImpl, ScalarField,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    io::Write,
    path::Path,
    process::{Command, Stdio},
};

#[derive(Deserialize)]
struct PublicShare {
    index: u32,
    public_share: Vec<u8>,
}
fn run(root: &str, binary: &str, requests: Vec<Value>) -> Vec<Value> {
    std::thread::scope(|scope| {
        let jobs: Vec<_> = requests
            .into_iter()
            .enumerate()
            .map(|(i, request)| {
                scope.spawn(move || {
                    let mut child = Command::new(binary)
                        .arg(Path::new(root).join(format!("{i}.json")))
                        .stdin(Stdio::piped())
                        .stdout(Stdio::piped())
                        .stderr(Stdio::piped())
                        .spawn()
                        .unwrap();
                    let mut input = child.stdin.take().unwrap();
                    input
                        .write_all(&serde_json::to_vec(&request).unwrap())
                        .unwrap();
                    input.write_all(b"\n").unwrap();
                    drop(input);
                    let result = child.wait_with_output().unwrap();
                    assert!(
                        result.status.success(),
                        "node {} failed: {}",
                        i,
                        String::from_utf8_lossy(&result.stderr)
                    );
                    serde_json::from_slice(&result.stdout).unwrap()
                })
            })
            .collect();
        jobs.into_iter().map(|job| job.join().unwrap()).collect()
    })
}
fn request(identity: &Identity, session: u8, operation: Value) -> Value {
    let session = vec![session; 32];
    json!({"identity":identity,"session":session,"operation":operation})
}
fn main() {
    let args: Vec<_> = std::env::args().collect();
    assert_eq!(
        args.len(),
        3,
        "usage: lakey_nodes <node configuration directory> <worker binary>"
    );
    let identity = Identity {
        chain: "fixture-chain".into(),
        ring: "fixture-ring".into(),
        epoch: 1,
        scope: Scope::Person {
            identity: vec![7; 48],
        },
        field: Field::Amount,
    };
    let round = |id: &Identity, session| {
        let values = run(
            &args[1],
            &args[2],
            vec![request(id, session, json!({"kind":"public_key"})); 5],
        );
        let points: Vec<_> = values
            .into_iter()
            .enumerate()
            .map(|(i, value)| {
                let item: PublicShare = serde_json::from_value(value).unwrap();
                assert_eq!(item.index, i as u32 + 1);
                GroupAffine::from_bytes(&item.public_share).unwrap()
            })
            .collect();
        lakey::public_polynomial(&points, 3).unwrap().eval(0)
    };
    let key = round(&identity, 1);
    assert_eq!(key, round(&identity, 2), "restart changed key");
    let mut other = identity.clone();
    other.scope = Scope::Person {
        identity: vec![8; 48],
    };
    let other_key = round(&other, 3);
    assert_ne!(key, other_key);
    let mut other_field = identity.clone();
    other_field.field = Field::Sender;
    assert_ne!(key, round(&other_field, 5), "field scopes share a key");
    let mut general = identity.clone();
    general.scope = Scope::General;
    assert_ne!(
        key,
        round(&general, 6),
        "person and general scopes share a key"
    );
    let reader_sk = ScalarField::rand(&mut rand_core::OsRng);
    let reader = GroupAffine::GENERATOR * reader_sk;
    let pop = PreImpl::prove_reader_key(&reader_sk, &reader).unwrap();
    let r = ScalarField::from(11u64);
    let epk = GroupAffine::GENERATOR * r;
    let operation = json!({"kind":"pre", "epk":epk.vartime_compress().0, "reader":reader.vartime_compress().0,"reader_proof":pop});
    let values = run(
        &args[1],
        &args[2],
        vec![request(&identity, 4, operation); 5],
    );
    let shares: Vec<PreShare> = values
        .into_iter()
        .map(|v| serde_json::from_value(v).unwrap())
        .collect();
    let result = lakey::recover(&shares, 3, 5, &key, &epk, &reader).unwrap();
    let dh = result - key * reader_sk;
    assert_eq!(dh, key * r);
    let alice_scalar = PreImpl::derive_capability_scalar(&[7; 48]);
    let bob_scalar = PreImpl::derive_capability_scalar(&[8; 48]);
    assert_ne!(
        dh * (bob_scalar * alice_scalar.inverse().unwrap()),
        other_key * r,
        "public scalar ratio converted Alice's result into Bob's"
    );
    assert!(lakey::recover(&shares, 3, 5, &other_key, &epk, &reader).is_err());
    assert!(lakey::recover(&shares[..2], 3, 5, &key, &epk, &reader).is_err());
    println!("five isolated MPC workers: stable keys, person isolation, fresh-share PRE and negatives passed");
}
