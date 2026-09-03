//! Generic PRE test suite
//!
//! Contains generic tests that can be applied to any [`ThresholdDealer`] implementation.
//! Call [`run_all_tests`] from your implementation's test module.
//!
//! # Type parameters
//!
//! Rather than writing `T::ShareValue` or `T::PublicKey` inside associated-type equality
//! bounds (which causes a compiler cycle), each function accepts explicit type parameters:
//!
//! * `T`  — the `ThresholdDealer` implementor.
//! * `SV` — the share-value / scalar type (`= T::ShareValue`).
//! * `PK` — the public-key / group-element type (`= T::PublicKey`).
//! * `PP` — the public-polynomial type (`= T::PubPoly`).
//!
//! # Required closures
//!
//! * `make_keypair` — returns a random `(SV, PK)` pair (scalar, group element).
//! * `make_pub_poly` — constructs `PP` from a `Vec<PK>`.
//! * `run_dkg` — runs a full DKG ceremony with `(n, t)`, returning `(agg_pk, shares, pub_poly)`.

use crate::context::{context_digest, CiphertextContext};
use crate::error::{CryptoError, Result};
use crate::r#trait::{
    CryptoDeserialize, DistKeyShare, PriShare, PubPoly as PubPolyTrait, PubShare, ReencryptReply,
    Secret, ThresholdDealer,
};
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};

/// Fixed [`CiphertextContext`] for the generic PRE tests.
///
/// `ring_pk` is opaque bytes (never parsed as a point), so the generic test
/// bounds need no serialization trait. `enc_cmt` is not a context field, so a
/// fresh identical value is valid at encrypt, verify, and decrypt time.
fn test_ctx() -> CiphertextContext {
    CiphertextContext {
        ring_pk: b"pre-tests-ring-pk".to_vec(),
        policy_id: "policy".to_string(),
        resource: "resource".to_string(),
        permission: "read".to_string(),
        tier: None,
        timestamp: None,
        salt: None,
    }
}

/// A [`CiphertextContext`] with every field distinct from [`test_ctx`], for
/// "wrong context" negative tests.
fn other_ctx() -> CiphertextContext {
    CiphertextContext {
        ring_pk: b"a-different-ring-pk".to_vec(),
        policy_id: "other-policy".to_string(),
        resource: "other-resource".to_string(),
        permission: "write".to_string(),
        tier: Some("gold".to_string()),
        timestamp: Some(42),
        salt: Some("s".to_string()),
    }
}

/// Run all generic PRE tests for a given [`ThresholdDealer`] implementation.
///
/// The `make_identity_pk` closure must return the group identity element for `PK`
/// (e.g. `G1Affine::identity()` for BLS12-381, `Element::default()` for decaf377).
pub fn run_all_tests<T, SV, PK, PP, MK, MP, RD, MI>(
    make_keypair: MK,
    make_pub_poly: MP,
    run_dkg: RD,
    make_identity_pk: MI,
) -> Result<()>
where
    T: ThresholdDealer<
        ShareValue = SV,
        PublicKey = PK,
        PubPoly = PP,
        Secret = Secret,
        DistKeyShare = DistKeyShare<SV>,
        ReencryptReply = ReencryptReply<SV, PK>,
    >,
    SV: Clone + zeroize::Zeroize,
    PK: PartialEq + std::fmt::Debug + Clone,
    PP: PubPolyTrait<PublicKey = PK>,
    MK: Fn() -> (SV, PK) + Clone,
    MP: Fn(Vec<PK>) -> PP + Clone,
    RD: Fn(usize, usize) -> Result<(PK, Vec<PriShare<SV>>, PP)> + Clone,
    MI: Fn() -> PK,
{
    test_encrypt_decrypt_flow::<T, SV, PK, PP, _>(make_keypair.clone())?;
    test_encrypt_decrypt_large_data::<T, SV, PK, PP, _>(make_keypair.clone())?;
    test_encrypt_decrypt_empty_data::<T, SV, PK, PP, _>(make_keypair.clone())?;
    test_decryption_fails_with_wrong_key::<T, SV, PK, PP, _>(make_keypair.clone())?;
    test_reencrypt_and_verify::<T, SV, PK, PP, _, _>(make_keypair.clone(), make_pub_poly.clone())?;
    test_verify_fails_with_wrong_proof::<T, SV, PK, PP, _, _>(
        make_keypair.clone(),
        make_pub_poly.clone(),
    )?;
    test_recover_insufficient_shares::<T, SV, PK, PP, _>(make_keypair.clone())?;
    test_lagrange_interpolation::<T, SV, PK, PP, _>(make_keypair.clone())?;
    test_key_derivation::<T, SV, PK, PP, _>(make_keypair.clone())?;
    test_key_derivation_different_points::<T, SV, PK, PP, _>(make_keypair.clone())?;
    test_encryption_proof_valid::<T, SV, PK, PP, _>(make_keypair.clone())?;
    test_encryption_proof_wrong_dkg_pk::<T, SV, PK, PP, _>(make_keypair.clone())?;
    test_encryption_proof_tampered_challenge::<T, SV, PK, PP, _>(make_keypair.clone())?;
    test_encryption_proof_tampered_response::<T, SV, PK, PP, _>(make_keypair.clone())?;
    test_encryption_proof_tampered_context::<T, SV, PK, PP, _>(make_keypair.clone())?;
    test_encryption_proof_tampered_ciphertext::<T, SV, PK, PP, _>(make_keypair.clone())?;
    test_encrypt_decrypt_with_derivation::<T, SV, PK, PP, _>(make_keypair.clone())?;
    test_reencrypt_with_derivation::<T, SV, PK, PP, _, _>(
        make_keypair.clone(),
        make_pub_poly.clone(),
    )?;
    test_reencrypt_wrong_derivation_fails_at_decrypt::<T, SV, PK, PP, _>(make_keypair.clone())?;
    test_reencrypt_missing_derivation_fails_at_decrypt::<T, SV, PK, PP, _>(make_keypair.clone())?;
    test_reencrypt_extra_derivation_fails_at_decrypt::<T, SV, PK, PP, _>(make_keypair.clone())?;
    test_different_derivations_produce_different_keys::<T, SV, PK, PP, _>(make_keypair.clone())?;
    test_encryption_proof_with_context_valid::<T, SV, PK, PP, _>(make_keypair.clone())?;
    test_encryption_proof_wrong_context_fails::<T, SV, PK, PP, _>(make_keypair.clone())?;
    test_encryption_proof_context_with_derivation::<T, SV, PK, PP, _>(make_keypair.clone())?;
    test_swap_ciphertext_and_nonce_fails_decrypt::<T, SV, PK, PP, _>(make_keypair.clone())?;
    test_swap_enc_cmt_fails_decrypt::<T, SV, PK, PP, _>(make_keypair.clone())?;
    test_swap_nonce_only_fails_decrypt::<T, SV, PK, PP, _>(make_keypair.clone())?;
    test_swap_enc_cmt_and_proof_fails_decrypt::<T, SV, PK, PP, _>(make_keypair.clone())?;
    test_context_individual_field_tampering_fails::<T, SV, PK, PP, _>(make_keypair.clone())?;
    test_dkg_encrypt_decrypt_integration::<T, SV, PK, PP, _, _>(
        make_keypair.clone(),
        run_dkg.clone(),
    )?;
    test_dkg_encrypt_decrypt_with_derivation_integration::<T, SV, PK, PP, _, _>(
        make_keypair.clone(),
        run_dkg,
    )?;
    test_reencrypt_rejects_identity_rdr_pk::<T, SV, PK, PP, _, _>(make_keypair, make_identity_pk)?;
    Ok(())
}

/// Verifies that `reencrypt` rejects the group identity element as `rdr_pk`.
///
/// A zero `rdr_pk` makes every re-encrypted share equal to the identity, leaking no
/// key material to the reader while appearing to succeed — the check must reject it
/// before any computation.
pub fn test_reencrypt_rejects_identity_rdr_pk<T, SV, PK, PP, MK, MI>(
    make_keypair: MK,
    make_identity_pk: MI,
) -> Result<()>
where
    T: ThresholdDealer<
        ShareValue = SV,
        PublicKey = PK,
        PubPoly = PP,
        Secret = Secret,
        DistKeyShare = DistKeyShare<SV>,
        ReencryptReply = ReencryptReply<SV, PK>,
    >,
    SV: Clone + zeroize::Zeroize,
    PK: PartialEq + std::fmt::Debug + Clone,
    PP: PubPolyTrait<PublicKey = PK>,
    MK: Fn() -> (SV, PK),
    MI: Fn() -> PK,
{
    let (dkg_sk, dkg_pk) = make_keypair();
    let (_, encrypted_secret, _) = T::encrypt_secret(&dkg_pk, b"test data", None, &test_ctx())?;

    let share = DistKeyShare {
        pri_share: PriShare { i: 1, v: dkg_sk },
    };
    let dealer = T::new();
    let identity = make_identity_pk();

    let result = dealer.reencrypt(&share, &encrypted_secret, &identity, None);
    assert!(
        result.is_err(),
        "reencrypt must reject the identity element as rdr_pk"
    );
    Ok(())
}

// ============================================================================
// Internal helper
// ============================================================================

/// Compute `xnc_cmt` in a 1-of-1 scenario via `reencrypt + recover`, staying
/// within the trait boundary rather than doing raw curve arithmetic.
fn single_node_xnc_cmt<T, SV, PK, PP>(
    dkg_sk: SV,
    encrypted_secret: &Secret,
    rdr_pk: &PK,
    derivation: Option<&[u8]>,
) -> Result<PK>
where
    T: ThresholdDealer<
        ShareValue = SV,
        PublicKey = PK,
        PubPoly = PP,
        Secret = Secret,
        DistKeyShare = DistKeyShare<SV>,
        ReencryptReply = ReencryptReply<SV, PK>,
    >,
    SV: Clone + zeroize::Zeroize,
    PK: Clone,
    PP: PubPolyTrait<PublicKey = PK>,
{
    let share = DistKeyShare {
        pri_share: PriShare { i: 1, v: dkg_sk },
    };
    let dealer = T::new();
    let reply = dealer.reencrypt(&share, encrypted_secret, rdr_pk, derivation)?;
    let xnc_cmt = dealer
        .recover(std::slice::from_ref(&reply.share), 1, 1)?
        .expect("recover with 1 share at t=1 must succeed");
    Ok(xnc_cmt)
}

// ============================================================================
// Basic encrypt / decrypt
// ============================================================================

/// A party that sees only what is published — the serialized [`EncryptionProof`]
/// and [`Secret`] — cannot recover the plaintext. Recovery requires threshold PRE
/// participation (a re-encryption to the reader's key).
///
/// The AES key is `derive_key_from_point(shared_point)`, where
/// `shared_point = r · effective_pk` is the KEM secret; it is computed only by the
/// encryptor and never serialized. This checks that invariant directly: for every
/// group element that can be parsed out of the published bytes, a key derived from
/// it does not open the ciphertext. If a future change serialized the KEM secret
/// (or any other point that derives the AES key), this test fails.
pub fn test_public_encryption_artifacts_cannot_decrypt<T, SV, PK, MK>(
    make_keypair: MK,
) -> Result<()>
where
    T: ThresholdDealer<ShareValue = SV, PublicKey = PK, Secret = Secret>,
    PK: CryptoDeserialize,
    MK: Fn() -> (SV, PK),
{
    let plaintext = b"threshold PRE participation is required to recover this plaintext";
    let (_dkg_sk, dkg_pk) = make_keypair();
    let ctx = CiphertextContext {
        ring_pk: b"ring-pk".to_vec(),
        policy_id: "policy".to_string(),
        resource: "documents/report".to_string(),
        permission: "read".to_string(),
        tier: Some("restricted".to_string()),
        timestamp: Some(1_725_321_600),
        salt: Some("salt".to_string()),
    };

    let (_enc_cmt, secret, proof) = T::encrypt_secret(&dkg_pk, plaintext, None, &ctx)?;

    // Serialize exactly what a bulletin reader receives and gather every byte
    // string in it — walking the JSON keeps this correct if a field is added to
    // either struct later.
    let mut published: Vec<Vec<u8>> = Vec::new();
    for value in [
        serde_json::to_value(&proof)
            .map_err(|e| CryptoError::ParseError(format!("serialize proof: {e}")))?,
        serde_json::to_value(&secret)
            .map_err(|e| CryptoError::ParseError(format!("serialize secret: {e}")))?,
    ] {
        collect_byte_strings(&value, &mut published);
    }

    let aad = context_digest(&ctx, &secret.enc_cmt);
    for bytes in published {
        // A field that is not a valid group element cannot yield a point-derived
        // key; `enc_cmt` (= r·G) is a point but is not the KEM secret, so a key
        // derived from it must not open the ciphertext either.
        let Ok(point) = PK::from_bytes(&bytes) else {
            continue;
        };
        let Ok(key) = T::derive_key_from_point(&point) else {
            continue;
        };
        let opened = Aes256Gcm::new_from_slice(&key).ok().and_then(|cipher| {
            cipher
                .decrypt(
                    Nonce::from_slice(&secret.nonce),
                    Payload {
                        msg: &secret.encrypted_data,
                        aad: &aad,
                    },
                )
                .ok()
        });
        assert!(
            opened.is_none(),
            "a published field yields a working symmetric key — the KEM secret must never be serialized"
        );
    }
    Ok(())
}

/// Collect every JSON byte string — an array of `0..=255` integers, which is how
/// `serde` encodes `Vec<u8>` — reachable from `value`.
fn collect_byte_strings(value: &serde_json::Value, out: &mut Vec<Vec<u8>>) {
    match value {
        serde_json::Value::Array(items) => {
            let as_bytes: Option<Vec<u8>> = items
                .iter()
                .map(|item| {
                    item.as_u64()
                        .filter(|n| *n <= u8::MAX as u64)
                        .map(|n| n as u8)
                })
                .collect();
            match as_bytes {
                Some(bytes) => out.push(bytes),
                None => items
                    .iter()
                    .for_each(|item| collect_byte_strings(item, out)),
            }
        }
        serde_json::Value::Object(map) => {
            map.values()
                .for_each(|item| collect_byte_strings(item, out));
        }
        _ => {}
    }
}

pub fn test_encrypt_decrypt_flow<T, SV, PK, PP, MK>(make_keypair: MK) -> Result<()>
where
    T: ThresholdDealer<
        ShareValue = SV,
        PublicKey = PK,
        PubPoly = PP,
        Secret = Secret,
        DistKeyShare = DistKeyShare<SV>,
        ReencryptReply = ReencryptReply<SV, PK>,
    >,
    SV: Clone + zeroize::Zeroize,
    PK: PartialEq + std::fmt::Debug + Clone,
    PP: PubPolyTrait<PublicKey = PK>,
    MK: Fn() -> (SV, PK),
{
    let secret = b"test secret data";
    let (dkg_sk, dkg_pk) = make_keypair();
    let (rdr_sk, rdr_pk) = make_keypair();

    let (_, encrypted_secret, _) = T::encrypt_secret(&dkg_pk, secret, None, &test_ctx())?;
    assert!(!encrypted_secret.encrypted_data.is_empty());
    assert_eq!(encrypted_secret.nonce.len(), 12);

    let xnc_cmt = single_node_xnc_cmt::<T, SV, PK, PP>(dkg_sk, &encrypted_secret, &rdr_pk, None)?;
    let decrypted = T::decrypt_secret(&dkg_pk, &xnc_cmt, &rdr_sk, &encrypted_secret, &test_ctx())?;
    assert_eq!(decrypted, secret);
    Ok(())
}

pub fn test_encrypt_decrypt_large_data<T, SV, PK, PP, MK>(make_keypair: MK) -> Result<()>
where
    T: ThresholdDealer<
        ShareValue = SV,
        PublicKey = PK,
        PubPoly = PP,
        Secret = Secret,
        DistKeyShare = DistKeyShare<SV>,
        ReencryptReply = ReencryptReply<SV, PK>,
    >,
    SV: Clone + zeroize::Zeroize,
    PK: PartialEq + std::fmt::Debug + Clone,
    PP: PubPolyTrait<PublicKey = PK>,
    MK: Fn() -> (SV, PK),
{
    let secret = b"This is a much longer secret that contains multiple blocks of data. \
                   It should be properly encrypted and decrypted using AES-GCM, which \
                   handles arbitrary length data. This tests that our hybrid encryption \
                   scheme works correctly with larger payloads that exceed typical \
                   block sizes and ensures proper chunking and authentication.";

    let (dkg_sk, dkg_pk) = make_keypair();
    let (rdr_sk, rdr_pk) = make_keypair();

    let (_, encrypted_secret, _) = T::encrypt_secret(&dkg_pk, secret, None, &test_ctx())?;
    assert!(!encrypted_secret.encrypted_data.is_empty());

    let xnc_cmt = single_node_xnc_cmt::<T, SV, PK, PP>(dkg_sk, &encrypted_secret, &rdr_pk, None)?;
    let decrypted = T::decrypt_secret(&dkg_pk, &xnc_cmt, &rdr_sk, &encrypted_secret, &test_ctx())?;
    assert_eq!(decrypted.len(), secret.len());
    assert_eq!(decrypted, secret);
    Ok(())
}

pub fn test_encrypt_decrypt_empty_data<T, SV, PK, PP, MK>(make_keypair: MK) -> Result<()>
where
    T: ThresholdDealer<
        ShareValue = SV,
        PublicKey = PK,
        PubPoly = PP,
        Secret = Secret,
        DistKeyShare = DistKeyShare<SV>,
        ReencryptReply = ReencryptReply<SV, PK>,
    >,
    SV: Clone + zeroize::Zeroize,
    PK: PartialEq + std::fmt::Debug + Clone,
    PP: PubPolyTrait<PublicKey = PK>,
    MK: Fn() -> (SV, PK),
{
    let secret = b"";
    let (dkg_sk, dkg_pk) = make_keypair();
    let (rdr_sk, rdr_pk) = make_keypair();

    let (_, encrypted_secret, _) = T::encrypt_secret(&dkg_pk, secret, None, &test_ctx())?;
    let xnc_cmt = single_node_xnc_cmt::<T, SV, PK, PP>(dkg_sk, &encrypted_secret, &rdr_pk, None)?;
    let decrypted = T::decrypt_secret(&dkg_pk, &xnc_cmt, &rdr_sk, &encrypted_secret, &test_ctx())?;
    assert_eq!(decrypted, secret);
    Ok(())
}

pub fn test_decryption_fails_with_wrong_key<T, SV, PK, PP, MK>(make_keypair: MK) -> Result<()>
where
    T: ThresholdDealer<
        ShareValue = SV,
        PublicKey = PK,
        PubPoly = PP,
        Secret = Secret,
        DistKeyShare = DistKeyShare<SV>,
        ReencryptReply = ReencryptReply<SV, PK>,
    >,
    SV: Clone + zeroize::Zeroize,
    PK: PartialEq + std::fmt::Debug + Clone,
    PP: PubPolyTrait<PublicKey = PK>,
    MK: Fn() -> (SV, PK),
{
    let secret = b"test secret";
    let (dkg_sk, dkg_pk) = make_keypair();
    let (_, rdr_pk) = make_keypair();
    let (wrong_rdr_sk, _) = make_keypair();

    let (_, encrypted_secret, _) = T::encrypt_secret(&dkg_pk, secret, None, &test_ctx())?;
    let xnc_cmt = single_node_xnc_cmt::<T, SV, PK, PP>(dkg_sk, &encrypted_secret, &rdr_pk, None)?;

    let result = T::decrypt_secret(
        &dkg_pk,
        &xnc_cmt,
        &wrong_rdr_sk,
        &encrypted_secret,
        &test_ctx(),
    );
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("authentication failed"),
        "expected AES-GCM authentication failure"
    );
    Ok(())
}

// ============================================================================
// Re-encryption and verification
// ============================================================================

pub fn test_reencrypt_and_verify<T, SV, PK, PP, MK, MP>(
    make_keypair: MK,
    make_pub_poly: MP,
) -> Result<()>
where
    T: ThresholdDealer<
        ShareValue = SV,
        PublicKey = PK,
        PubPoly = PP,
        Secret = Secret,
        DistKeyShare = DistKeyShare<SV>,
        ReencryptReply = ReencryptReply<SV, PK>,
    >,
    SV: Clone + zeroize::Zeroize,
    PK: PartialEq + std::fmt::Debug + Clone,
    PP: PubPolyTrait<PublicKey = PK>,
    MK: Fn() -> (SV, PK),
    MP: Fn(Vec<PK>) -> PP,
{
    let (dkg_sk, dkg_pk) = make_keypair();
    let (_, rdr_pk) = make_keypair();

    let commitment = make_pub_poly(vec![dkg_pk.clone()]);
    let share = DistKeyShare {
        pri_share: PriShare { i: 1, v: dkg_sk },
    };

    let (enc_cmt, encrypted_secret, _) =
        T::encrypt_secret(&dkg_pk, b"test data", None, &test_ctx())?;

    let dealer = T::new();
    let reply = dealer.reencrypt(&share, &encrypted_secret, &rdr_pk, None)?;
    dealer.verify(&rdr_pk, &commitment, &enc_cmt, &reply, None)?;
    Ok(())
}

pub fn test_verify_fails_with_wrong_proof<T, SV, PK, PP, MK, MP>(
    make_keypair: MK,
    make_pub_poly: MP,
) -> Result<()>
where
    T: ThresholdDealer<
        ShareValue = SV,
        PublicKey = PK,
        PubPoly = PP,
        Secret = Secret,
        DistKeyShare = DistKeyShare<SV>,
        ReencryptReply = ReencryptReply<SV, PK>,
    >,
    SV: Clone + zeroize::Zeroize,
    PK: PartialEq + std::fmt::Debug + Clone,
    PP: PubPolyTrait<PublicKey = PK>,
    MK: Fn() -> (SV, PK),
    MP: Fn(Vec<PK>) -> PP,
{
    let (dkg_sk, dkg_pk) = make_keypair();
    let (_, rdr_pk) = make_keypair();

    let commitment = make_pub_poly(vec![dkg_pk.clone()]);
    let share = DistKeyShare {
        pri_share: PriShare { i: 1, v: dkg_sk },
    };

    let (enc_cmt, encrypted_secret, _) =
        T::encrypt_secret(&dkg_pk, b"test data", None, &test_ctx())?;

    let dealer = T::new();
    let mut reply = dealer.reencrypt(&share, &encrypted_secret, &rdr_pk, None)?;

    // Replace the proof scalar with a different one from a fresh keypair
    reply.proof = make_keypair().0;

    let verify_result = dealer.verify(&rdr_pk, &commitment, &enc_cmt, &reply, None);
    assert!(verify_result.is_err());
    Ok(())
}

// ============================================================================
// Recovery (Lagrange interpolation)
// ============================================================================

pub fn test_recover_insufficient_shares<T, SV, PK, PP, MK>(make_keypair: MK) -> Result<()>
where
    T: ThresholdDealer<
        ShareValue = SV,
        PublicKey = PK,
        PubPoly = PP,
        Secret = Secret,
        DistKeyShare = DistKeyShare<SV>,
        ReencryptReply = ReencryptReply<SV, PK>,
    >,
    SV: Clone + zeroize::Zeroize,
    PK: PartialEq + std::fmt::Debug + Clone,
    PP: PubPolyTrait<PublicKey = PK>,
    MK: Fn() -> (SV, PK),
{
    let (_, point) = make_keypair();
    let shares = vec![PubShare { i: 1, v: point }];

    let dealer = T::new();
    let result = dealer.recover(&shares, 3, 5)?;
    assert!(result.is_none());
    Ok(())
}

pub fn test_lagrange_interpolation<T, SV, PK, PP, MK>(make_keypair: MK) -> Result<()>
where
    T: ThresholdDealer<
        ShareValue = SV,
        PublicKey = PK,
        PubPoly = PP,
        Secret = Secret,
        DistKeyShare = DistKeyShare<SV>,
        ReencryptReply = ReencryptReply<SV, PK>,
    >,
    SV: Clone + zeroize::Zeroize,
    PK: PartialEq + std::fmt::Debug + Clone,
    PP: PubPolyTrait<PublicKey = PK>,
    MK: Fn() -> (SV, PK),
{
    // All shares hold the same point — simulates a degree-0 constant polynomial.
    let (_, point) = make_keypair();
    let shares = vec![
        PubShare {
            i: 1,
            v: point.clone(),
        },
        PubShare {
            i: 2,
            v: point.clone(),
        },
        PubShare {
            i: 3,
            v: point.clone(),
        },
    ];

    let dealer = T::new();
    let recovered = dealer.recover(&shares, 3, 5)?;
    let recovered = recovered.expect("recovery should succeed with 3 shares at t=3");
    assert_eq!(
        recovered, point,
        "interpolation of a constant polynomial must return the constant"
    );

    Ok(())
}

// ============================================================================
// Key derivation (derive_key_from_point)
// ============================================================================

pub fn test_key_derivation<T, SV, PK, PP, MK>(make_keypair: MK) -> Result<()>
where
    T: ThresholdDealer<
        ShareValue = SV,
        PublicKey = PK,
        PubPoly = PP,
        Secret = Secret,
        DistKeyShare = DistKeyShare<SV>,
        ReencryptReply = ReencryptReply<SV, PK>,
    >,
    SV: Clone + zeroize::Zeroize,
    PK: PartialEq + std::fmt::Debug + Clone,
    PP: PubPolyTrait<PublicKey = PK>,
    MK: Fn() -> (SV, PK),
{
    let (_, point) = make_keypair();

    let key1 = T::derive_key_from_point(&point)?;
    let key2 = T::derive_key_from_point(&point)?;

    assert_eq!(key1, key2, "key derivation must be deterministic");
    assert_eq!(key1.len(), 32);
    Ok(())
}

pub fn test_key_derivation_different_points<T, SV, PK, PP, MK>(make_keypair: MK) -> Result<()>
where
    T: ThresholdDealer<
        ShareValue = SV,
        PublicKey = PK,
        PubPoly = PP,
        Secret = Secret,
        DistKeyShare = DistKeyShare<SV>,
        ReencryptReply = ReencryptReply<SV, PK>,
    >,
    SV: Clone + zeroize::Zeroize,
    PK: PartialEq + std::fmt::Debug + Clone,
    PP: PubPolyTrait<PublicKey = PK>,
    MK: Fn() -> (SV, PK),
{
    let (_, point1) = make_keypair();
    let (_, point2) = make_keypair();

    let key1 = T::derive_key_from_point(&point1)?;
    let key2 = T::derive_key_from_point(&point2)?;

    assert_ne!(key1, key2, "different points must produce different keys");
    Ok(())
}

// ============================================================================
// Encryption proofs
// ============================================================================

pub fn test_encryption_proof_valid<T, SV, PK, PP, MK>(make_keypair: MK) -> Result<()>
where
    T: ThresholdDealer<
        ShareValue = SV,
        PublicKey = PK,
        PubPoly = PP,
        Secret = Secret,
        DistKeyShare = DistKeyShare<SV>,
        ReencryptReply = ReencryptReply<SV, PK>,
    >,
    SV: Clone + zeroize::Zeroize,
    PK: PartialEq + std::fmt::Debug + Clone,
    PP: PubPolyTrait<PublicKey = PK>,
    MK: Fn() -> (SV, PK),
{
    let (_, dkg_pk) = make_keypair();
    let (_, secret, proof) = T::encrypt_secret(&dkg_pk, b"test secret data", None, &test_ctx())?;
    T::verify_encryption(&proof, &test_ctx(), &secret)?;
    Ok(())
}

pub fn test_encryption_proof_wrong_dkg_pk<T, SV, PK, PP, MK>(make_keypair: MK) -> Result<()>
where
    T: ThresholdDealer<
        ShareValue = SV,
        PublicKey = PK,
        PubPoly = PP,
        Secret = Secret,
        DistKeyShare = DistKeyShare<SV>,
        ReencryptReply = ReencryptReply<SV, PK>,
    >,
    SV: Clone + zeroize::Zeroize,
    PK: PartialEq + std::fmt::Debug + Clone,
    PP: PubPolyTrait<PublicKey = PK>,
    MK: Fn() -> (SV, PK),
{
    let (_, dkg_pk) = make_keypair();

    let (_, secret, proof) = T::encrypt_secret(&dkg_pk, b"test secret data", None, &test_ctx())?;

    // The ring key is bound only through `context.ring_pk`; a mismatch there
    // must fail verification.
    let mut wrong = test_ctx();
    wrong.ring_pk = b"a-different-ring-pk".to_vec();
    let result = T::verify_encryption(&proof, &wrong, &secret);
    assert!(
        result.is_err(),
        "encryption proof should fail with wrong ring_pk in the context"
    );
    Ok(())
}

pub fn test_encryption_proof_tampered_challenge<T, SV, PK, PP, MK>(make_keypair: MK) -> Result<()>
where
    T: ThresholdDealer<
        ShareValue = SV,
        PublicKey = PK,
        PubPoly = PP,
        Secret = Secret,
        DistKeyShare = DistKeyShare<SV>,
        ReencryptReply = ReencryptReply<SV, PK>,
    >,
    SV: Clone + zeroize::Zeroize,
    PK: PartialEq + std::fmt::Debug + Clone,
    PP: PubPolyTrait<PublicKey = PK>,
    MK: Fn() -> (SV, PK),
{
    let (_, dkg_pk) = make_keypair();
    let (_, secret, mut proof) =
        T::encrypt_secret(&dkg_pk, b"test secret data", None, &test_ctx())?;

    proof.challenge[0] ^= 0xFF;

    let result = T::verify_encryption(&proof, &test_ctx(), &secret);
    assert!(result.is_err(), "proof should fail with tampered challenge");
    Ok(())
}

pub fn test_encryption_proof_tampered_response<T, SV, PK, PP, MK>(make_keypair: MK) -> Result<()>
where
    T: ThresholdDealer<
        ShareValue = SV,
        PublicKey = PK,
        PubPoly = PP,
        Secret = Secret,
        DistKeyShare = DistKeyShare<SV>,
        ReencryptReply = ReencryptReply<SV, PK>,
    >,
    SV: Clone + zeroize::Zeroize,
    PK: PartialEq + std::fmt::Debug + Clone,
    PP: PubPolyTrait<PublicKey = PK>,
    MK: Fn() -> (SV, PK),
{
    let (_, dkg_pk) = make_keypair();
    let (_, secret, mut proof) =
        T::encrypt_secret(&dkg_pk, b"test secret data", None, &test_ctx())?;

    proof.response[0] ^= 0xFF;

    let result = T::verify_encryption(&proof, &test_ctx(), &secret);
    assert!(result.is_err(), "proof should fail with tampered response");
    Ok(())
}

/// The proof binds `context_digest`, so verifying against any mutated context
/// field must fail.
pub fn test_encryption_proof_tampered_context<T, SV, PK, PP, MK>(make_keypair: MK) -> Result<()>
where
    T: ThresholdDealer<
        ShareValue = SV,
        PublicKey = PK,
        PubPoly = PP,
        Secret = Secret,
        DistKeyShare = DistKeyShare<SV>,
        ReencryptReply = ReencryptReply<SV, PK>,
    >,
    SV: Clone + zeroize::Zeroize,
    PK: PartialEq + std::fmt::Debug + Clone,
    PP: PubPolyTrait<PublicKey = PK>,
    MK: Fn() -> (SV, PK),
{
    let (_, dkg_pk) = make_keypair();
    let (_, secret, proof) = T::encrypt_secret(&dkg_pk, b"test secret data", None, &test_ctx())?;

    let mut ctx = test_ctx();
    ctx.policy_id = "tampered".to_string();
    assert!(
        T::verify_encryption(&proof, &ctx, &secret).is_err(),
        "tampered policy_id must fail"
    );

    let mut ctx = test_ctx();
    ctx.salt = Some("injected".to_string());
    assert!(
        T::verify_encryption(&proof, &ctx, &secret).is_err(),
        "tampered salt must fail"
    );

    let mut ctx = test_ctx();
    ctx.ring_pk = b"other-ring".to_vec();
    assert!(
        T::verify_encryption(&proof, &ctx, &secret).is_err(),
        "tampered ring_pk must fail"
    );
    Ok(())
}

/// The proof binds `ciphertext_digest`, so verifying against a mutated ciphertext
/// or nonce must fail.
pub fn test_encryption_proof_tampered_ciphertext<T, SV, PK, PP, MK>(make_keypair: MK) -> Result<()>
where
    T: ThresholdDealer<
        ShareValue = SV,
        PublicKey = PK,
        PubPoly = PP,
        Secret = Secret,
        DistKeyShare = DistKeyShare<SV>,
        ReencryptReply = ReencryptReply<SV, PK>,
    >,
    SV: Clone + zeroize::Zeroize,
    PK: PartialEq + std::fmt::Debug + Clone,
    PP: PubPolyTrait<PublicKey = PK>,
    MK: Fn() -> (SV, PK),
{
    let (_, dkg_pk) = make_keypair();
    let (_, secret, proof) = T::encrypt_secret(&dkg_pk, b"test secret data", None, &test_ctx())?;

    let mut tampered = secret.clone();
    tampered.encrypted_data[0] ^= 0xFF;
    assert!(
        T::verify_encryption(&proof, &test_ctx(), &tampered).is_err(),
        "tampered ciphertext must fail"
    );

    let mut tampered = secret.clone();
    tampered.nonce[0] ^= 0xFF;
    assert!(
        T::verify_encryption(&proof, &test_ctx(), &tampered).is_err(),
        "tampered nonce must fail"
    );
    Ok(())
}

// ============================================================================
// Capability derivation
// ============================================================================

pub fn test_encrypt_decrypt_with_derivation<T, SV, PK, PP, MK>(make_keypair: MK) -> Result<()>
where
    T: ThresholdDealer<
        ShareValue = SV,
        PublicKey = PK,
        PubPoly = PP,
        Secret = Secret,
        DistKeyShare = DistKeyShare<SV>,
        ReencryptReply = ReencryptReply<SV, PK>,
    >,
    SV: Clone + zeroize::Zeroize,
    PK: PartialEq + std::fmt::Debug + Clone,
    PP: PubPolyTrait<PublicKey = PK>,
    MK: Fn() -> (SV, PK),
{
    let secret = b"test secret with capability derivation";
    let derivation = b"alice-capability-v1";
    let (dkg_sk, dkg_pk) = make_keypair();
    let (rdr_sk, rdr_pk) = make_keypair();

    let (_, encrypted_secret, _) =
        T::encrypt_secret(&dkg_pk, secret, Some(derivation), &test_ctx())?;
    let derived_pk = T::derive_public_key(&dkg_pk, derivation)?;
    let xnc_cmt =
        single_node_xnc_cmt::<T, SV, PK, PP>(dkg_sk, &encrypted_secret, &rdr_pk, Some(derivation))?;
    let decrypted = T::decrypt_secret(
        &derived_pk,
        &xnc_cmt,
        &rdr_sk,
        &encrypted_secret,
        &test_ctx(),
    )?;
    assert_eq!(decrypted, secret);
    Ok(())
}

pub fn test_reencrypt_with_derivation<T, SV, PK, PP, MK, MP>(
    make_keypair: MK,
    make_pub_poly: MP,
) -> Result<()>
where
    T: ThresholdDealer<
        ShareValue = SV,
        PublicKey = PK,
        PubPoly = PP,
        Secret = Secret,
        DistKeyShare = DistKeyShare<SV>,
        ReencryptReply = ReencryptReply<SV, PK>,
    >,
    SV: Clone + zeroize::Zeroize,
    PK: PartialEq + std::fmt::Debug + Clone,
    PP: PubPolyTrait<PublicKey = PK>,
    MK: Fn() -> (SV, PK),
    MP: Fn(Vec<PK>) -> PP,
{
    let derivation = b"test-capability";
    let (dkg_sk, dkg_pk) = make_keypair();
    let (_, rdr_pk) = make_keypair();

    let commitment = make_pub_poly(vec![dkg_pk.clone()]);
    let share = DistKeyShare {
        pri_share: PriShare { i: 1, v: dkg_sk },
    };

    let (enc_cmt, encrypted_secret, _) = T::encrypt_secret(
        &dkg_pk,
        b"test data with derivation",
        Some(derivation),
        &test_ctx(),
    )?;

    let dealer = T::new();
    let reply = dealer.reencrypt(&share, &encrypted_secret, &rdr_pk, Some(derivation))?;
    dealer.verify(&rdr_pk, &commitment, &enc_cmt, &reply, Some(derivation))?;
    Ok(())
}

pub fn test_reencrypt_wrong_derivation_fails_at_decrypt<T, SV, PK, PP, MK>(
    make_keypair: MK,
) -> Result<()>
where
    T: ThresholdDealer<
        ShareValue = SV,
        PublicKey = PK,
        PubPoly = PP,
        Secret = Secret,
        DistKeyShare = DistKeyShare<SV>,
        ReencryptReply = ReencryptReply<SV, PK>,
    >,
    SV: Clone + zeroize::Zeroize,
    PK: PartialEq + std::fmt::Debug + Clone,
    PP: PubPolyTrait<PublicKey = PK>,
    MK: Fn() -> (SV, PK),
{
    let correct_derivation = b"correct-capability";
    let wrong_derivation = b"wrong-capability";
    let (dkg_sk, dkg_pk) = make_keypair();
    let (rdr_sk, rdr_pk) = make_keypair();

    let (_, encrypted_secret, _) =
        T::encrypt_secret(&dkg_pk, b"test data", Some(correct_derivation), &test_ctx())?;
    let derived_pk = T::derive_public_key(&dkg_pk, correct_derivation)?;

    let xnc_cmt = single_node_xnc_cmt::<T, SV, PK, PP>(
        dkg_sk,
        &encrypted_secret,
        &rdr_pk,
        Some(wrong_derivation),
    )?;

    let result = T::decrypt_secret(
        &derived_pk,
        &xnc_cmt,
        &rdr_sk,
        &encrypted_secret,
        &test_ctx(),
    );
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("authentication failed"),
        "expected AES-GCM authentication failure"
    );
    Ok(())
}

pub fn test_reencrypt_missing_derivation_fails_at_decrypt<T, SV, PK, PP, MK>(
    make_keypair: MK,
) -> Result<()>
where
    T: ThresholdDealer<
        ShareValue = SV,
        PublicKey = PK,
        PubPoly = PP,
        Secret = Secret,
        DistKeyShare = DistKeyShare<SV>,
        ReencryptReply = ReencryptReply<SV, PK>,
    >,
    SV: Clone + zeroize::Zeroize,
    PK: PartialEq + std::fmt::Debug + Clone,
    PP: PubPolyTrait<PublicKey = PK>,
    MK: Fn() -> (SV, PK),
{
    let derivation = b"some-capability";
    let (dkg_sk, dkg_pk) = make_keypair();
    let (rdr_sk, rdr_pk) = make_keypair();

    let (_, encrypted_secret, _) =
        T::encrypt_secret(&dkg_pk, b"test data", Some(derivation), &test_ctx())?;
    let derived_pk = T::derive_public_key(&dkg_pk, derivation)?;

    // Reencrypt WITHOUT derivation
    let xnc_cmt = single_node_xnc_cmt::<T, SV, PK, PP>(dkg_sk, &encrypted_secret, &rdr_pk, None)?;

    let result = T::decrypt_secret(
        &derived_pk,
        &xnc_cmt,
        &rdr_sk,
        &encrypted_secret,
        &test_ctx(),
    );
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("authentication failed"),
        "expected AES-GCM authentication failure"
    );
    Ok(())
}

pub fn test_reencrypt_extra_derivation_fails_at_decrypt<T, SV, PK, PP, MK>(
    make_keypair: MK,
) -> Result<()>
where
    T: ThresholdDealer<
        ShareValue = SV,
        PublicKey = PK,
        PubPoly = PP,
        Secret = Secret,
        DistKeyShare = DistKeyShare<SV>,
        ReencryptReply = ReencryptReply<SV, PK>,
    >,
    SV: Clone + zeroize::Zeroize,
    PK: PartialEq + std::fmt::Debug + Clone,
    PP: PubPolyTrait<PublicKey = PK>,
    MK: Fn() -> (SV, PK),
{
    let derivation = b"some-capability";
    let (dkg_sk, dkg_pk) = make_keypair();
    let (rdr_sk, rdr_pk) = make_keypair();

    // Encrypt WITHOUT derivation
    let (_, encrypted_secret, _) = T::encrypt_secret(&dkg_pk, b"test data", None, &test_ctx())?;

    // Reencrypt WITH (extra) derivation
    let xnc_cmt =
        single_node_xnc_cmt::<T, SV, PK, PP>(dkg_sk, &encrypted_secret, &rdr_pk, Some(derivation))?;

    let result = T::decrypt_secret(&dkg_pk, &xnc_cmt, &rdr_sk, &encrypted_secret, &test_ctx());
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("authentication failed"),
        "expected AES-GCM authentication failure"
    );
    Ok(())
}

pub fn test_different_derivations_produce_different_keys<T, SV, PK, PP, MK>(
    make_keypair: MK,
) -> Result<()>
where
    T: ThresholdDealer<
        ShareValue = SV,
        PublicKey = PK,
        PubPoly = PP,
        Secret = Secret,
        DistKeyShare = DistKeyShare<SV>,
        ReencryptReply = ReencryptReply<SV, PK>,
    >,
    SV: Clone + zeroize::Zeroize,
    PK: PartialEq + std::fmt::Debug + Clone,
    PP: PubPolyTrait<PublicKey = PK>,
    MK: Fn() -> (SV, PK),
{
    let (_, dkg_pk) = make_keypair();
    let derived_pk_1 = T::derive_public_key(&dkg_pk, b"alice")?;
    let derived_pk_2 = T::derive_public_key(&dkg_pk, b"bob")?;

    assert_ne!(
        derived_pk_1, derived_pk_2,
        "different derivations must produce different derived keys"
    );

    let derived_pk_1b = T::derive_public_key(&dkg_pk, b"alice")?;
    assert_eq!(
        derived_pk_1, derived_pk_1b,
        "same derivation must be deterministic"
    );
    Ok(())
}

// ============================================================================
// Context (policy binding)
// ============================================================================

pub fn test_encryption_proof_with_context_valid<T, SV, PK, PP, MK>(make_keypair: MK) -> Result<()>
where
    T: ThresholdDealer<
        ShareValue = SV,
        PublicKey = PK,
        PubPoly = PP,
        Secret = Secret,
        DistKeyShare = DistKeyShare<SV>,
        ReencryptReply = ReencryptReply<SV, PK>,
    >,
    SV: Clone + zeroize::Zeroize,
    PK: PartialEq + std::fmt::Debug + Clone,
    PP: PubPolyTrait<PublicKey = PK>,
    MK: Fn() -> (SV, PK),
{
    let (_, dkg_pk) = make_keypair();
    let ctx = CiphertextContext {
        ring_pk: b"ring".to_vec(),
        policy_id: "123".to_string(),
        resource: "file.txt".to_string(),
        permission: "read".to_string(),
        tier: None,
        timestamp: None,
        salt: None,
    };

    let (_, secret, proof) = T::encrypt_secret(&dkg_pk, b"test secret data", None, &ctx)?;
    T::verify_encryption(&proof, &ctx, &secret)?;
    Ok(())
}

pub fn test_encryption_proof_wrong_context_fails<T, SV, PK, PP, MK>(make_keypair: MK) -> Result<()>
where
    T: ThresholdDealer<
        ShareValue = SV,
        PublicKey = PK,
        PubPoly = PP,
        Secret = Secret,
        DistKeyShare = DistKeyShare<SV>,
        ReencryptReply = ReencryptReply<SV, PK>,
    >,
    SV: Clone + zeroize::Zeroize,
    PK: PartialEq + std::fmt::Debug + Clone,
    PP: PubPolyTrait<PublicKey = PK>,
    MK: Fn() -> (SV, PK),
{
    let (_, dkg_pk) = make_keypair();

    let (_, secret, proof) = T::encrypt_secret(&dkg_pk, b"test secret data", None, &test_ctx())?;

    let result = T::verify_encryption(&proof, &other_ctx(), &secret);
    assert!(
        result.is_err(),
        "proof should fail against a different context"
    );
    Ok(())
}

pub fn test_encryption_proof_context_with_derivation<T, SV, PK, PP, MK>(
    make_keypair: MK,
) -> Result<()>
where
    T: ThresholdDealer<
        ShareValue = SV,
        PublicKey = PK,
        PubPoly = PP,
        Secret = Secret,
        DistKeyShare = DistKeyShare<SV>,
        ReencryptReply = ReencryptReply<SV, PK>,
    >,
    SV: Clone + zeroize::Zeroize,
    PK: PartialEq + std::fmt::Debug + Clone,
    PP: PubPolyTrait<PublicKey = PK>,
    MK: Fn() -> (SV, PK),
{
    let derivation = b"alice-capability-v1";
    let (_, dkg_pk) = make_keypair();
    let ctx = test_ctx();

    let (_, secret, proof) = T::encrypt_secret(&dkg_pk, b"test secret", Some(derivation), &ctx)?;

    T::verify_encryption(&proof, &ctx, &secret)?;

    let result = T::verify_encryption(&proof, &other_ctx(), &secret);
    assert!(
        result.is_err(),
        "proof should fail against a different context even when derivation is correct"
    );
    Ok(())
}

// ============================================================================
// AAD binding — mix-and-match ciphertext components must fail
// ============================================================================

pub fn test_swap_ciphertext_and_nonce_fails_decrypt<T, SV, PK, PP, MK>(
    make_keypair: MK,
) -> Result<()>
where
    T: ThresholdDealer<
        ShareValue = SV,
        PublicKey = PK,
        PubPoly = PP,
        Secret = Secret,
        DistKeyShare = DistKeyShare<SV>,
        ReencryptReply = ReencryptReply<SV, PK>,
    >,
    SV: Clone + zeroize::Zeroize,
    PK: PartialEq + std::fmt::Debug + Clone,
    PP: PubPolyTrait<PublicKey = PK>,
    MK: Fn() -> (SV, PK),
{
    let (dkg_sk, dkg_pk) = make_keypair();
    let (rdr_sk, rdr_pk) = make_keypair();

    let (_, encrypted_a, _) = T::encrypt_secret(&dkg_pk, b"secret A", None, &test_ctx())?;
    let (_, encrypted_b, _) = T::encrypt_secret(&dkg_pk, b"secret B", None, &test_ctx())?;

    let franken_secret = Secret {
        enc_cmt: encrypted_a.enc_cmt.clone(),
        encrypted_data: encrypted_b.encrypted_data.clone(),
        nonce: encrypted_b.nonce.clone(),
    };

    let xnc_cmt = single_node_xnc_cmt::<T, SV, PK, PP>(dkg_sk, &encrypted_a, &rdr_pk, None)?;

    let result = T::decrypt_secret(&dkg_pk, &xnc_cmt, &rdr_sk, &franken_secret, &test_ctx());
    assert!(
        result.is_err(),
        "decryption should fail when ciphertext and nonce are swapped"
    );
    Ok(())
}

pub fn test_swap_enc_cmt_fails_decrypt<T, SV, PK, PP, MK>(make_keypair: MK) -> Result<()>
where
    T: ThresholdDealer<
        ShareValue = SV,
        PublicKey = PK,
        PubPoly = PP,
        Secret = Secret,
        DistKeyShare = DistKeyShare<SV>,
        ReencryptReply = ReencryptReply<SV, PK>,
    >,
    SV: Clone + zeroize::Zeroize,
    PK: PartialEq + std::fmt::Debug + Clone,
    PP: PubPolyTrait<PublicKey = PK>,
    MK: Fn() -> (SV, PK),
{
    let (dkg_sk, dkg_pk) = make_keypair();
    let (rdr_sk, rdr_pk) = make_keypair();

    let (_, encrypted_a, _) = T::encrypt_secret(&dkg_pk, b"secret A", None, &test_ctx())?;
    let (_, encrypted_b, _) = T::encrypt_secret(&dkg_pk, b"secret B", None, &test_ctx())?;

    // enc_cmt from B, ciphertext+nonce from A — AAD mismatch
    let franken_secret = Secret {
        enc_cmt: encrypted_b.enc_cmt.clone(),
        encrypted_data: encrypted_a.encrypted_data.clone(),
        nonce: encrypted_a.nonce.clone(),
    };

    // xnc_cmt derived from encrypted_b (matching the swapped enc_cmt)
    let xnc_cmt = single_node_xnc_cmt::<T, SV, PK, PP>(dkg_sk, &encrypted_b, &rdr_pk, None)?;

    let result = T::decrypt_secret(&dkg_pk, &xnc_cmt, &rdr_sk, &franken_secret, &test_ctx());
    assert!(
        result.is_err(),
        "decryption should fail when enc_cmt is swapped"
    );
    Ok(())
}

pub fn test_swap_nonce_only_fails_decrypt<T, SV, PK, PP, MK>(make_keypair: MK) -> Result<()>
where
    T: ThresholdDealer<
        ShareValue = SV,
        PublicKey = PK,
        PubPoly = PP,
        Secret = Secret,
        DistKeyShare = DistKeyShare<SV>,
        ReencryptReply = ReencryptReply<SV, PK>,
    >,
    SV: Clone + zeroize::Zeroize,
    PK: PartialEq + std::fmt::Debug + Clone,
    PP: PubPolyTrait<PublicKey = PK>,
    MK: Fn() -> (SV, PK),
{
    let (dkg_sk, dkg_pk) = make_keypair();
    let (rdr_sk, rdr_pk) = make_keypair();

    let (_, encrypted_a, _) = T::encrypt_secret(&dkg_pk, b"secret A", None, &test_ctx())?;
    let (_, encrypted_b, _) = T::encrypt_secret(&dkg_pk, b"secret B", None, &test_ctx())?;

    let franken_secret = Secret {
        enc_cmt: encrypted_a.enc_cmt.clone(),
        encrypted_data: encrypted_a.encrypted_data.clone(),
        nonce: encrypted_b.nonce.clone(),
    };

    let xnc_cmt = single_node_xnc_cmt::<T, SV, PK, PP>(dkg_sk, &encrypted_a, &rdr_pk, None)?;

    let result = T::decrypt_secret(&dkg_pk, &xnc_cmt, &rdr_sk, &franken_secret, &test_ctx());
    assert!(
        result.is_err(),
        "decryption should fail when only the nonce is swapped"
    );
    Ok(())
}

pub fn test_swap_enc_cmt_and_proof_fails_decrypt<T, SV, PK, PP, MK>(make_keypair: MK) -> Result<()>
where
    T: ThresholdDealer<
        ShareValue = SV,
        PublicKey = PK,
        PubPoly = PP,
        Secret = Secret,
        DistKeyShare = DistKeyShare<SV>,
        ReencryptReply = ReencryptReply<SV, PK>,
    >,
    SV: Clone + zeroize::Zeroize,
    PK: PartialEq + std::fmt::Debug + Clone,
    PP: PubPolyTrait<PublicKey = PK>,
    MK: Fn() -> (SV, PK),
{
    let (dkg_sk, dkg_pk) = make_keypair();
    let (rdr_sk, rdr_pk) = make_keypair();

    let (_, encrypted_a, _) = T::encrypt_secret(&dkg_pk, b"secret A", None, &test_ctx())?;
    let (_, encrypted_b, proof_b) = T::encrypt_secret(&dkg_pk, b"secret B", None, &test_ctx())?;

    // Confirm proof_b is valid on its own
    T::verify_encryption(&proof_b, &test_ctx(), &encrypted_b)?;

    // Swap enc_cmt+proof from B, ciphertext from A
    let franken_secret = Secret {
        enc_cmt: encrypted_b.enc_cmt.clone(),
        encrypted_data: encrypted_a.encrypted_data.clone(),
        nonce: encrypted_a.nonce.clone(),
    };

    let xnc_cmt = single_node_xnc_cmt::<T, SV, PK, PP>(dkg_sk, &encrypted_b, &rdr_pk, None)?;

    let result = T::decrypt_secret(&dkg_pk, &xnc_cmt, &rdr_sk, &franken_secret, &test_ctx());
    assert!(
        result.is_err(),
        "decryption should fail when enc_cmt+proof are swapped but ciphertext is from another encryption"
    );
    Ok(())
}

// ============================================================================
// Context field tampering — every field is bound
// ============================================================================

pub fn test_context_individual_field_tampering_fails<T, SV, PK, PP, MK>(
    make_keypair: MK,
) -> Result<()>
where
    T: ThresholdDealer<
        ShareValue = SV,
        PublicKey = PK,
        PubPoly = PP,
        Secret = Secret,
        DistKeyShare = DistKeyShare<SV>,
        ReencryptReply = ReencryptReply<SV, PK>,
    >,
    SV: Clone + zeroize::Zeroize,
    PK: PartialEq + std::fmt::Debug + Clone,
    PP: PubPolyTrait<PublicKey = PK>,
    MK: Fn() -> (SV, PK),
{
    let (_, dkg_pk) = make_keypair();
    let correct = CiphertextContext {
        ring_pk: b"ring-1".to_vec(),
        policy_id: "policy-1".to_string(),
        resource: "resource-1".to_string(),
        permission: "read".to_string(),
        tier: Some("tier-gold".to_string()),
        timestamp: Some(1772127215u64),
        salt: Some("salt-xyz".to_string()),
    };
    let (_, secret, proof) = T::encrypt_secret(&dkg_pk, b"test secret", None, &correct)?;

    let mut tampered: Vec<CiphertextContext> = Vec::new();
    let mut c = correct.clone();
    c.ring_pk = b"TAMPERED".to_vec();
    tampered.push(c);
    let mut c = correct.clone();
    c.policy_id = "TAMPERED".to_string();
    tampered.push(c);
    let mut c = correct.clone();
    c.resource = "TAMPERED".to_string();
    tampered.push(c);
    let mut c = correct.clone();
    c.permission = "TAMPERED".to_string();
    tampered.push(c);
    let mut c = correct.clone();
    c.tier = Some("TAMPERED".to_string());
    tampered.push(c);
    let mut c = correct.clone();
    c.tier = None;
    tampered.push(c);
    let mut c = correct.clone();
    c.timestamp = Some(0);
    tampered.push(c);
    let mut c = correct.clone();
    c.timestamp = None;
    tampered.push(c);
    let mut c = correct.clone();
    c.salt = Some("TAMPERED".to_string());
    tampered.push(c);
    let mut c = correct.clone();
    c.salt = None;
    tampered.push(c);

    for variant in &tampered {
        let result = T::verify_encryption(&proof, variant, &secret);
        assert!(
            result.is_err(),
            "proof should fail with a tampered context field"
        );
    }
    Ok(())
}

// ============================================================================
// Full DKG integration
// ============================================================================

pub fn test_dkg_encrypt_decrypt_integration<T, SV, PK, PP, MK, RD>(
    make_keypair: MK,
    run_dkg: RD,
) -> Result<()>
where
    T: ThresholdDealer<
        ShareValue = SV,
        PublicKey = PK,
        PubPoly = PP,
        Secret = Secret,
        DistKeyShare = DistKeyShare<SV>,
        ReencryptReply = ReencryptReply<SV, PK>,
    >,
    SV: Clone + zeroize::Zeroize,
    PK: PartialEq + std::fmt::Debug + Clone,
    PP: PubPolyTrait<PublicKey = PK>,
    MK: Fn() -> (SV, PK),
    RD: Fn(usize, usize) -> Result<(PK, Vec<PriShare<SV>>, PP)>,
{
    let secret = b"This is a secret message that needs to be encrypted and decrypted using threshold re-encryption!";
    let n = 5;
    let t = 3;

    let (aggregate_pk, secret_shares, pub_poly) = run_dkg(n, t)?;
    assert_eq!(secret_shares.len(), n);

    let (enc_cmt, encrypted_secret, _) =
        T::encrypt_secret(&aggregate_pk, secret, None, &test_ctx())?;
    assert!(!encrypted_secret.encrypted_data.is_empty());
    assert_eq!(encrypted_secret.nonce.len(), 12);

    let (rdr_sk, rdr_pk) = make_keypair();

    let dealer = T::new();
    let mut reencrypt_replies = Vec::new();

    for share in secret_shares.iter().take(t) {
        let dist_key_share = DistKeyShare {
            pri_share: share.clone(),
        };
        let reply = dealer.reencrypt(&dist_key_share, &encrypted_secret, &rdr_pk, None)?;
        dealer.verify(&rdr_pk, &pub_poly, &enc_cmt, &reply, None)?;
        reencrypt_replies.push(reply);
    }

    let pub_shares: Vec<PubShare<PK>> = reencrypt_replies.iter().map(|r| r.share.clone()).collect();
    let xnc_cmt = dealer
        .recover(&pub_shares, t, n)?
        .expect("recovery with t shares must succeed");

    let decrypted = T::decrypt_secret(
        &aggregate_pk,
        &xnc_cmt,
        &rdr_sk,
        &encrypted_secret,
        &test_ctx(),
    )?;
    assert_eq!(decrypted, secret);
    Ok(())
}

pub fn test_dkg_encrypt_decrypt_with_derivation_integration<T, SV, PK, PP, MK, RD>(
    make_keypair: MK,
    run_dkg: RD,
) -> Result<()>
where
    T: ThresholdDealer<
        ShareValue = SV,
        PublicKey = PK,
        PubPoly = PP,
        Secret = Secret,
        DistKeyShare = DistKeyShare<SV>,
        ReencryptReply = ReencryptReply<SV, PK>,
    >,
    SV: Clone + zeroize::Zeroize,
    PK: PartialEq + std::fmt::Debug + Clone,
    PP: PubPolyTrait<PublicKey = PK>,
    MK: Fn() -> (SV, PK),
    RD: Fn(usize, usize) -> Result<(PK, Vec<PriShare<SV>>, PP)>,
{
    let secret = b"Secret with capability-based derivation at re-encrypt time!";
    let derivation = b"alice-file-access-v1";
    let n = 5;
    let t = 3;

    let (aggregate_pk, secret_shares, pub_poly) = run_dkg(n, t)?;

    let (enc_cmt, encrypted_secret, _) =
        T::encrypt_secret(&aggregate_pk, secret, Some(derivation), &test_ctx())?;

    let derived_pk = T::derive_public_key(&aggregate_pk, derivation)?;

    let (rdr_sk, rdr_pk) = make_keypair();

    let dealer = T::new();
    let mut reencrypt_replies = Vec::new();

    for share in secret_shares.iter().take(t) {
        let dist_key_share = DistKeyShare {
            pri_share: share.clone(),
        };
        let reply = dealer.reencrypt(
            &dist_key_share,
            &encrypted_secret,
            &rdr_pk,
            Some(derivation),
        )?;
        dealer.verify(&rdr_pk, &pub_poly, &enc_cmt, &reply, Some(derivation))?;
        reencrypt_replies.push(reply);
    }

    let pub_shares: Vec<PubShare<PK>> = reencrypt_replies.iter().map(|r| r.share.clone()).collect();
    let xnc_cmt = dealer
        .recover(&pub_shares, t, n)?
        .expect("recovery with t shares must succeed");

    let decrypted = T::decrypt_secret(
        &derived_pk,
        &xnc_cmt,
        &rdr_sk,
        &encrypted_secret,
        &test_ctx(),
    )?;
    assert_eq!(decrypted, secret);
    Ok(())
}
