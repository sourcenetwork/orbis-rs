//! Jubjub proof transcript hash. Parameters match the BLS12-381 scalar-field
//! Poseidon permutation (alpha 5, 8 full and 57 partial rounds).
use ::jubjub::Fq;
use ff::Field;
use serde::Deserialize;
use std::sync::LazyLock;

#[derive(Deserialize)]
struct Encoded {
    ark: Vec<Vec<String>>,
    mds: Vec<Vec<String>>,
}
struct Parameters {
    ark: Vec<Vec<Fq>>,
    mds: Vec<Vec<Fq>>,
}
static PARAMETERS: LazyLock<std::collections::BTreeMap<usize, Parameters>> = LazyLock::new(|| {
    let encoded: std::collections::BTreeMap<String, Encoded> =
        serde_json::from_str(include_str!("poseidon.json")).expect("embedded Poseidon parameters");
    let rows = |rows: Vec<Vec<String>>| {
        rows.into_iter()
            .map(|row| {
                row.into_iter()
                    .map(|s| {
                        let mut bytes: [u8; 32] = hex::decode(s).unwrap().try_into().unwrap();
                        bytes.reverse();
                        Option::<Fq>::from(Fq::from_bytes(&bytes))
                            .expect("canonical Poseidon constant")
                    })
                    .collect()
            })
            .collect()
    };
    encoded
        .into_iter()
        .map(|(width, p)| {
            (
                width.parse().unwrap(),
                Parameters {
                    ark: rows(p.ark),
                    mds: rows(p.mds),
                },
            )
        })
        .collect()
});

/// Injective byte packing: byte length followed by zero-padded 31-byte LE limbs.
/// Domain 240 is reserved for Orbis proof transcripts; each caller also prefixes
/// its distinct protocol domain. Output is a canonical field element, not a scalar.
pub fn digest(bytes: &[u8]) -> [u8; 32] {
    let mut input = vec![Fq::from(
        u64::try_from(bytes.len()).expect("transcript length"),
    )];
    input.extend(bytes.chunks(31).map(|chunk| {
        let mut packed = [0; 32];
        packed[..chunk.len()].copy_from_slice(chunk);
        Option::<Fq>::from(Fq::from_bytes(&packed)).unwrap()
    }));
    let width = match input.len() {
        0..=2 => 3,
        3..=5 | 13..=15 => 6,
        _ => 13,
    };
    let p = &PARAMETERS[&width];
    let permute = |state: &mut Vec<Fq>| {
        for (round, constants) in p.ark.iter().enumerate() {
            for (i, value) in state.iter_mut().enumerate() {
                *value += constants[i];
                if round < 4 || round >= 61 || i == 0 {
                    *value = value.square().square() * *value;
                }
            }
            *state = p
                .mds
                .iter()
                .map(|row| {
                    row.iter()
                        .zip(state.iter())
                        .fold(Fq::ZERO, |sum, (a, b)| sum + a * b)
                })
                .collect();
        }
    };
    let mut state = vec![Fq::ZERO; width];
    state[0] = Fq::from(input.len() as u64 * 256 + 240);
    for chunk in input.chunks(width - 1) {
        for (i, value) in chunk.iter().enumerate() {
            state[i + 1] += value;
        }
        permute(&mut state);
    }
    state[1].to_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    // Independently evaluated with Python integer arithmetic and the dense round schedule.
    #[test]
    fn independent_dense_vectors_cover_packing_and_widths() {
        for (len, expected) in [
            (
                0,
                "31753b45671c13bf2b77704753675f8ffe4341ebbdb2546bb5ebf181caf04338",
            ),
            (
                1,
                "eb60f92b626fcf23ace5740ee6b2c6b5fcd71c702cd54e79dbae1c13a3a0d81b",
            ),
            (
                31,
                "3655d6768acb7405abdb03e05d6f02c94aeb18bae9185ceb0cdd28f41bec243e",
            ),
            (
                32,
                "f7aa85015eda81c277b9e8be038c7c32f5f13d9dc7a444812784e7689eaac641",
            ),
            (
                64,
                "1b8ee20419c2acf5f81b2a908197ecbc383330dfb15a0532d24197c7d9c93f0d",
            ),
            (
                128,
                "f1df2ff0c889e67ad3f158c9cbcdb74bf741b82b733e442170b82fb9db06e44e",
            ),
            (
                373,
                "4ed462b55dac7c73bb2ccabb407dd7542b74be37536abdfcb89306e6b8f6c909",
            ),
            (
                1024,
                "04991a2a907d71a551c293d584ad1b165d454b9ab5fa793826e3bc2af3a4e83c",
            ),
        ] {
            let bytes: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            assert_eq!(hex::encode(digest(&bytes)), expected);
        }
    }
    #[test]
    fn framing_distinguishes_trailing_zero_and_limb_boundaries() {
        for n in [0, 1, 30, 31, 32, 61, 62, 63, 372, 373] {
            let a = vec![0; n];
            let mut b = a.clone();
            b.push(0);
            assert_ne!(digest(&a), digest(&b));
        }
    }
}
