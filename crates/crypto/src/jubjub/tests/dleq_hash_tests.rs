//! DLEQ transcript fixtures computed independently with Python's
//! `hashlib.blake2b(transcript, digest_size=64)` (unkeyed, no personalization).
//! Point encodings were produced with affine twisted-Edwards arithmetic,
//! d = -10240/10241, starting from zkcrypto's full generator with v = 11 and
//! clearing its cofactor by multiplying by 8. Scalar reduction used Python's
//! `int.from_bytes(digest, "little") % r`, where
//! r = 0x0e7db4ea6533afa906673b0101343b00a6682093ccc81082d0970e5ed6f72cb7.
//! Witness 7 and nonce 11 are public test values, never production secrets.

use crate::jubjub::{
    common::{Element, Fr, PubPoly},
    pet::PetNode,
    pre::ThresholdDealerNode,
};
use crate::r#trait::{
    BlindingReply, CryptoDeserialize, CryptoSerialize, Pet, PetCheckReply, PetTag, PubShare,
    ReencryptReply, ThresholdDealer,
};
use blake2::{Blake2b512, Digest};
use sha2::Sha512;

const NODE_ID: u32 = 0x0102_0304;

fn decode_hex<const N: usize>(hex: &str) -> [u8; N] {
    assert_eq!(hex.len(), N * 2);
    std::array::from_fn(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap())
}

fn point(multiple: u64) -> Element {
    Element::generator() * Fr::from(multiple)
}

fn append_points(transcript: &mut Vec<u8>, multiples: &[u64]) {
    for multiple in multiples {
        transcript.extend_from_slice(&point(*multiple).to_bytes().unwrap());
    }
}

/// Pin both the full hash and its reduction independently of production helpers.
/// Return the expected BLAKE2b challenge and a SHA-512 challenge over the exact
/// same transcript, so rejection cannot be explained by different proof inputs.
fn fixture_challenges(transcript: &[u8], digest_hex: &str, scalar_hex: &str) -> (Fr, Fr) {
    let expected_digest = decode_hex::<64>(digest_hex);
    let actual_digest: [u8; 64] = Blake2b512::digest(transcript).into();
    assert_eq!(actual_digest, expected_digest);

    let challenge = Fr::from_bytes(&decode_hex::<32>(scalar_hex)).unwrap();
    assert_eq!(Fr::from_le_bytes_mod_order(&expected_digest), challenge);

    let sha_challenge = Fr::from_le_bytes_mod_order(&Sha512::digest(transcript));
    assert_ne!(sha_challenge, challenge);
    (challenge, sha_challenge)
}

#[test]
fn pre_dleq_accepts_blake2b512_vector_and_rejects_sha512() {
    // Reader key = 3G, encryption commitment = 5G, public share = 7G.
    // With witness 7 and nonce 11: U = 56G, U_hat = 88G, H_hat = 11G.
    let mut transcript = b"elgamal-jubjub-reencrypt-challenge-v1".to_vec();
    transcript.extend_from_slice(&NODE_ID.to_le_bytes());
    append_points(&mut transcript, &[3, 5, 7, 56, 88, 11]);
    let (challenge, sha_challenge) = fixture_challenges(
        &transcript,
        concat!(
            "0cec0a9333e8467e952006cf2e6a3ca394479bc3218e68762fc2f9a0b934d6f76",
            "1b52ece9d1fb0648bfd1b3dc0e31fd4dac7de871134b0e0de401b3cadb38da1"
        ),
        "3c3dad1f0678776edb1e78160dbb84d1b80d4348928da3e6fbdaba61a08fec0b",
    );
    let public_shares = PubPoly {
        commits: vec![point(7)],
    };
    let dealer = ThresholdDealerNode::new();
    let make_reply = |challenge| ReencryptReply {
        share: PubShare {
            i: NODE_ID,
            v: point(56),
        },
        challenge,
        proof: Fr::from(11u64) + challenge * Fr::from(7u64),
    };

    dealer
        .verify(
            &point(3),
            &public_shares,
            &point(5),
            &make_reply(challenge),
            None,
        )
        .expect("the independent BLAKE2b-512 PRE DLEQ vector must verify");
    assert!(
        dealer
            .verify(
                &point(3),
                &public_shares,
                &point(5),
                &make_reply(sha_challenge),
                None
            )
            .is_err(),
        "a PRE DLEQ proof using SHA-512 must be rejected"
    );
}

#[test]
fn pet_check_dleq_accepts_blake2b512_vector_and_rejects_sha512() {
    // R = 3G, public share = 7G, partial = 21G; nonce commitments 33G/11G.
    let mut transcript = b"orbis-jubjub-pet-check-dleq-proof-v1".to_vec();
    transcript.extend_from_slice(&NODE_ID.to_le_bytes());
    append_points(&mut transcript, &[3, 7, 21, 33, 11]);
    let (challenge, sha_challenge) = fixture_challenges(
        &transcript,
        concat!(
            "282dea117c185ea3449d6dd9dd5b928b1e5a492ce10efef2315abdd70169b0d3",
            "fe0cbc22351121a0087b8c02e84bac02d5e18fe79d16ff517729d112f0227ac9"
        ),
        "09184131eadadd5805f5ffe41e789ca46646b094b047990ea0467710c9623204",
    );
    let public_shares = PubPoly {
        commits: vec![point(7)],
    };
    let tag = PetTag {
        ephemeral_point: point(3).to_bytes().unwrap(),
        masked_fingerprint: point(18).to_bytes().unwrap(),
    };
    let make_reply = |challenge| PetCheckReply {
        partial: PubShare {
            i: NODE_ID,
            v: point(21),
        },
        challenge,
        proof: Fr::from(11u64) + challenge * Fr::from(7u64),
    };

    PetNode::verify_partial_pet_check(&public_shares, &tag, &make_reply(challenge))
        .expect("the independent BLAKE2b-512 PET-check DLEQ vector must verify");
    assert!(
        PetNode::verify_partial_pet_check(&public_shares, &tag, &make_reply(sha_challenge))
            .is_err(),
        "a PET-check DLEQ proof using SHA-512 must be rejected"
    );
}

#[test]
fn pet_blinding_dleq_accepts_blake2b512_vector_and_rejects_sha512() {
    // R = 3G, T = 18G, target = 13G, so D = 5G. Blinding by witness 7
    // yields A/B = 21G/35G; nonce 11 yields U/V = 33G/55G.
    let digest = [0x42; 32];
    let mut transcript = b"orbis-jubjub-pet-blind-proof-v1".to_vec();
    append_points(&mut transcript, &[3, 5, 21, 35, 33, 55]);
    transcript.extend_from_slice(&digest);
    let (challenge, sha_challenge) = fixture_challenges(
        &transcript,
        concat!(
            "d432dc0bf43d6392c103057577b4e6cf2319e9583bd0fe4ab401a4fbd8aa17b3",
            "9e8ec3b9399547d094b03ab87375233d3f4c37125c1bc9ac9ebdab7d07a96341"
        ),
        "8d55ea301e9dcd6d5998cf6337b633ed66e932704cf1184f1b0b7f48ac830401",
    );
    let tag = PetTag {
        ephemeral_point: point(3).to_bytes().unwrap(),
        masked_fingerprint: point(18).to_bytes().unwrap(),
    };
    let make_reply = |challenge| BlindingReply {
        blinded_r: point(21),
        blinded_diff: point(35),
        challenge,
        proof: Fr::from(11u64) + challenge * Fr::from(7u64),
    };

    PetNode::verify_blinding_correctness(&tag, &point(13), &make_reply(challenge), &digest)
        .expect("the independent BLAKE2b-512 PET-blinding DLEQ vector must verify");
    assert!(
        PetNode::verify_blinding_correctness(&tag, &point(13), &make_reply(sha_challenge), &digest)
            .is_err(),
        "a PET-blinding DLEQ proof using SHA-512 must be rejected"
    );
}
