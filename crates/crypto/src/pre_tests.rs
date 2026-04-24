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

use crate::error::Result;
use crate::r#trait::{
    DistKeyShare, PriShare, PubPoly as PubPolyTrait, PubShare, ReencryptReply, Secret,
    ThresholdDealer,
};

/// Run all generic PRE tests for a given [`ThresholdDealer`] implementation.
pub fn run_all_tests<T, SV, PK, PP, MK, MP, RD>(
    make_keypair: MK,
    make_pub_poly: MP,
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
    MK: Fn() -> (SV, PK) + Clone,
    MP: Fn(Vec<PK>) -> PP + Clone,
    RD: Fn(usize, usize) -> Result<(PK, Vec<PriShare<SV>>, PP)> + Clone,
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
    test_encryption_proof_tampered_shared_point::<T, SV, PK, PP, _>(make_keypair.clone())?;
    test_encrypt_decrypt_with_derivation::<T, SV, PK, PP, _>(make_keypair.clone())?;
    test_reencrypt_with_derivation::<T, SV, PK, PP, _, _>(
        make_keypair.clone(),
        make_pub_poly.clone(),
    )?;
    test_reencrypt_wrong_derivation_fails_at_decrypt::<T, SV, PK, PP, _>(make_keypair.clone())?;
    test_reencrypt_missing_derivation_fails_at_decrypt::<T, SV, PK, PP, _>(make_keypair.clone())?;
    test_reencrypt_extra_derivation_fails_at_decrypt::<T, SV, PK, PP, _>(make_keypair.clone())?;
    test_different_derivations_produce_different_keys::<T, SV, PK, PP, _>(make_keypair.clone())?;
    test_encryption_proof_with_metadata_valid::<T, SV, PK, PP, _>(make_keypair.clone())?;
    test_encryption_proof_wrong_metadata_fails::<T, SV, PK, PP, _>(make_keypair.clone())?;
    test_encryption_proof_missing_metadata_fails::<T, SV, PK, PP, _>(make_keypair.clone())?;
    test_encryption_proof_extra_metadata_fails::<T, SV, PK, PP, _>(make_keypair.clone())?;
    test_encryption_proof_metadata_with_derivation::<T, SV, PK, PP, _>(make_keypair.clone())?;
    test_swap_ciphertext_and_nonce_fails_decrypt::<T, SV, PK, PP, _>(make_keypair.clone())?;
    test_swap_enc_cmt_fails_decrypt::<T, SV, PK, PP, _>(make_keypair.clone())?;
    test_swap_nonce_only_fails_decrypt::<T, SV, PK, PP, _>(make_keypair.clone())?;
    test_swap_enc_cmt_and_proof_fails_decrypt::<T, SV, PK, PP, _>(make_keypair.clone())?;
    test_verify_encryption_wrong_derivation_fails_loudly::<T, SV, PK, PP, _>(make_keypair.clone())?;
    test_metadata_individual_field_tampering_fails::<T, SV, PK, PP, _>(make_keypair.clone())?;
    test_dkg_encrypt_decrypt_integration::<T, SV, PK, PP, _, _>(
        make_keypair.clone(),
        run_dkg.clone(),
    )?;
    test_dkg_encrypt_decrypt_with_derivation_integration::<T, SV, PK, PP, _, _>(
        make_keypair,
        run_dkg,
    )?;
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

    let (_, encrypted_secret, _) = T::encrypt_secret(&dkg_pk, secret, None, None)?;
    assert!(!encrypted_secret.encrypted_data.is_empty());
    assert_eq!(encrypted_secret.nonce.len(), 12);

    let xnc_cmt = single_node_xnc_cmt::<T, SV, PK, PP>(dkg_sk, &encrypted_secret, &rdr_pk, None)?;
    let decrypted = T::decrypt_secret(&dkg_pk, &xnc_cmt, &rdr_sk, &encrypted_secret)?;
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

    let (_, encrypted_secret, _) = T::encrypt_secret(&dkg_pk, secret, None, None)?;
    assert!(!encrypted_secret.encrypted_data.is_empty());

    let xnc_cmt = single_node_xnc_cmt::<T, SV, PK, PP>(dkg_sk, &encrypted_secret, &rdr_pk, None)?;
    let decrypted = T::decrypt_secret(&dkg_pk, &xnc_cmt, &rdr_sk, &encrypted_secret)?;
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

    let (_, encrypted_secret, _) = T::encrypt_secret(&dkg_pk, secret, None, None)?;
    let xnc_cmt = single_node_xnc_cmt::<T, SV, PK, PP>(dkg_sk, &encrypted_secret, &rdr_pk, None)?;
    let decrypted = T::decrypt_secret(&dkg_pk, &xnc_cmt, &rdr_sk, &encrypted_secret)?;
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

    let (_, encrypted_secret, _) = T::encrypt_secret(&dkg_pk, secret, None, None)?;
    let xnc_cmt = single_node_xnc_cmt::<T, SV, PK, PP>(dkg_sk, &encrypted_secret, &rdr_pk, None)?;

    let result = T::decrypt_secret(&dkg_pk, &xnc_cmt, &wrong_rdr_sk, &encrypted_secret);
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

    let (enc_cmt, encrypted_secret, _) = T::encrypt_secret(&dkg_pk, b"test data", None, None)?;

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

    let (enc_cmt, encrypted_secret, _) = T::encrypt_secret(&dkg_pk, b"test data", None, None)?;

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
    let (enc_cmt, _, proof) = T::encrypt_secret(&dkg_pk, b"test secret data", None, None)?;
    T::verify_encryption(&dkg_pk, &enc_cmt, &proof, None)?;
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
    let (_, wrong_dkg_pk) = make_keypair();

    let (enc_cmt, _, proof) = T::encrypt_secret(&dkg_pk, b"test secret data", None, None)?;

    let result = T::verify_encryption(&wrong_dkg_pk, &enc_cmt, &proof, None);
    assert!(
        result.is_err(),
        "encryption proof should fail with wrong DKG public key"
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
    let (enc_cmt, _, mut proof) = T::encrypt_secret(&dkg_pk, b"test secret data", None, None)?;

    proof.challenge[0] ^= 0xFF;

    let result = T::verify_encryption(&dkg_pk, &enc_cmt, &proof, None);
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
    let (enc_cmt, _, mut proof) = T::encrypt_secret(&dkg_pk, b"test secret data", None, None)?;

    proof.response[0] ^= 0xFF;

    let result = T::verify_encryption(&dkg_pk, &enc_cmt, &proof, None);
    assert!(result.is_err(), "proof should fail with tampered response");
    Ok(())
}

pub fn test_encryption_proof_tampered_shared_point<T, SV, PK, PP, MK>(
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
    let (enc_cmt, _, mut proof) = T::encrypt_secret(&dkg_pk, b"test secret data", None, None)?;

    proof.shared_point[0] ^= 0xFF;

    let result = T::verify_encryption(&dkg_pk, &enc_cmt, &proof, None);
    assert!(
        result.is_err(),
        "proof should fail with tampered shared point"
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

    let (_, encrypted_secret, _) = T::encrypt_secret(&dkg_pk, secret, Some(derivation), None)?;
    let derived_pk = T::derive_public_key(&dkg_pk, derivation)?;
    let xnc_cmt =
        single_node_xnc_cmt::<T, SV, PK, PP>(dkg_sk, &encrypted_secret, &rdr_pk, Some(derivation))?;
    let decrypted = T::decrypt_secret(&derived_pk, &xnc_cmt, &rdr_sk, &encrypted_secret)?;
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
        None,
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
        T::encrypt_secret(&dkg_pk, b"test data", Some(correct_derivation), None)?;
    let derived_pk = T::derive_public_key(&dkg_pk, correct_derivation)?;

    let xnc_cmt = single_node_xnc_cmt::<T, SV, PK, PP>(
        dkg_sk,
        &encrypted_secret,
        &rdr_pk,
        Some(wrong_derivation),
    )?;

    let result = T::decrypt_secret(&derived_pk, &xnc_cmt, &rdr_sk, &encrypted_secret);
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
        T::encrypt_secret(&dkg_pk, b"test data", Some(derivation), None)?;
    let derived_pk = T::derive_public_key(&dkg_pk, derivation)?;

    // Reencrypt WITHOUT derivation
    let xnc_cmt = single_node_xnc_cmt::<T, SV, PK, PP>(dkg_sk, &encrypted_secret, &rdr_pk, None)?;

    let result = T::decrypt_secret(&derived_pk, &xnc_cmt, &rdr_sk, &encrypted_secret);
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
    let (_, encrypted_secret, _) = T::encrypt_secret(&dkg_pk, b"test data", None, None)?;

    // Reencrypt WITH (extra) derivation
    let xnc_cmt =
        single_node_xnc_cmt::<T, SV, PK, PP>(dkg_sk, &encrypted_secret, &rdr_pk, Some(derivation))?;

    let result = T::decrypt_secret(&dkg_pk, &xnc_cmt, &rdr_sk, &encrypted_secret);
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
// Metadata (policy binding)
// ============================================================================

pub fn test_encryption_proof_with_metadata_valid<T, SV, PK, PP, MK>(make_keypair: MK) -> Result<()>
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
    let metadata = T::encode_metadata("123", "file.txt", "read", None, None, None);
    let (_, dkg_pk) = make_keypair();

    let (enc_cmt, _, proof) =
        T::encrypt_secret(&dkg_pk, b"test secret data", None, Some(&metadata))?;
    T::verify_encryption(&dkg_pk, &enc_cmt, &proof, Some(&metadata))?;
    Ok(())
}

pub fn test_encryption_proof_wrong_metadata_fails<T, SV, PK, PP, MK>(make_keypair: MK) -> Result<()>
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
    let correct_metadata = T::encode_metadata("123", "file.txt", "read", None, None, None);
    let wrong_metadata = T::encode_metadata("456", "other.txt", "write", None, None, None);
    let (_, dkg_pk) = make_keypair();

    let (enc_cmt, _, proof) =
        T::encrypt_secret(&dkg_pk, b"test secret data", None, Some(&correct_metadata))?;

    let result = T::verify_encryption(&dkg_pk, &enc_cmt, &proof, Some(&wrong_metadata));
    assert!(result.is_err(), "proof should fail with wrong metadata");
    Ok(())
}

pub fn test_encryption_proof_missing_metadata_fails<T, SV, PK, PP, MK>(
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
    let metadata = T::encode_metadata("123", "file.txt", "read", None, None, None);
    let (_, dkg_pk) = make_keypair();

    let (enc_cmt, _, proof) =
        T::encrypt_secret(&dkg_pk, b"test secret data", None, Some(&metadata))?;

    let result = T::verify_encryption(&dkg_pk, &enc_cmt, &proof, None);
    assert!(
        result.is_err(),
        "proof should fail when metadata is missing"
    );
    Ok(())
}

pub fn test_encryption_proof_extra_metadata_fails<T, SV, PK, PP, MK>(make_keypair: MK) -> Result<()>
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
    let metadata = T::encode_metadata("123", "file.txt", "read", None, None, None);
    let (_, dkg_pk) = make_keypair();

    // Encrypt WITHOUT metadata
    let (enc_cmt, _, proof) = T::encrypt_secret(&dkg_pk, b"test secret data", None, None)?;

    let result = T::verify_encryption(&dkg_pk, &enc_cmt, &proof, Some(&metadata));
    assert!(
        result.is_err(),
        "proof should fail when extra metadata is supplied"
    );
    Ok(())
}

pub fn test_encryption_proof_metadata_with_derivation<T, SV, PK, PP, MK>(
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
    let metadata = T::encode_metadata("789", "sensitive.doc", "decrypt", None, None, None);
    let derivation = b"alice-capability-v1";
    let (_, dkg_pk) = make_keypair();

    let (enc_cmt, _, proof) =
        T::encrypt_secret(&dkg_pk, b"test secret", Some(derivation), Some(&metadata))?;

    let derived_pk = T::derive_public_key(&dkg_pk, derivation)?;

    T::verify_encryption(&derived_pk, &enc_cmt, &proof, Some(&metadata))?;

    let wrong_metadata = T::encode_metadata("000", "other", "none", None, None, None);
    let result = T::verify_encryption(&derived_pk, &enc_cmt, &proof, Some(&wrong_metadata));
    assert!(
        result.is_err(),
        "proof should fail with wrong metadata even when derivation is correct"
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

    let (_, encrypted_a, _) = T::encrypt_secret(&dkg_pk, b"secret A", None, None)?;
    let (_, encrypted_b, _) = T::encrypt_secret(&dkg_pk, b"secret B", None, None)?;

    let franken_secret = Secret {
        enc_cmt: encrypted_a.enc_cmt.clone(),
        encrypted_data: encrypted_b.encrypted_data.clone(),
        nonce: encrypted_b.nonce.clone(),
    };

    let xnc_cmt = single_node_xnc_cmt::<T, SV, PK, PP>(dkg_sk, &encrypted_a, &rdr_pk, None)?;

    let result = T::decrypt_secret(&dkg_pk, &xnc_cmt, &rdr_sk, &franken_secret);
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

    let (_, encrypted_a, _) = T::encrypt_secret(&dkg_pk, b"secret A", None, None)?;
    let (_, encrypted_b, _) = T::encrypt_secret(&dkg_pk, b"secret B", None, None)?;

    // enc_cmt from B, ciphertext+nonce from A — AAD mismatch
    let franken_secret = Secret {
        enc_cmt: encrypted_b.enc_cmt.clone(),
        encrypted_data: encrypted_a.encrypted_data.clone(),
        nonce: encrypted_a.nonce.clone(),
    };

    // xnc_cmt derived from encrypted_b (matching the swapped enc_cmt)
    let xnc_cmt = single_node_xnc_cmt::<T, SV, PK, PP>(dkg_sk, &encrypted_b, &rdr_pk, None)?;

    let result = T::decrypt_secret(&dkg_pk, &xnc_cmt, &rdr_sk, &franken_secret);
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

    let (_, encrypted_a, _) = T::encrypt_secret(&dkg_pk, b"secret A", None, None)?;
    let (_, encrypted_b, _) = T::encrypt_secret(&dkg_pk, b"secret B", None, None)?;

    let franken_secret = Secret {
        enc_cmt: encrypted_a.enc_cmt.clone(),
        encrypted_data: encrypted_a.encrypted_data.clone(),
        nonce: encrypted_b.nonce.clone(),
    };

    let xnc_cmt = single_node_xnc_cmt::<T, SV, PK, PP>(dkg_sk, &encrypted_a, &rdr_pk, None)?;

    let result = T::decrypt_secret(&dkg_pk, &xnc_cmt, &rdr_sk, &franken_secret);
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

    let (_, encrypted_a, _) = T::encrypt_secret(&dkg_pk, b"secret A", None, None)?;
    let (enc_cmt_b, encrypted_b, proof_b) = T::encrypt_secret(&dkg_pk, b"secret B", None, None)?;

    // Confirm proof_b is valid on its own
    T::verify_encryption(&dkg_pk, &enc_cmt_b, &proof_b, None)?;

    // Swap enc_cmt+proof from B, ciphertext from A
    let franken_secret = Secret {
        enc_cmt: encrypted_b.enc_cmt.clone(),
        encrypted_data: encrypted_a.encrypted_data.clone(),
        nonce: encrypted_a.nonce.clone(),
    };

    let xnc_cmt = single_node_xnc_cmt::<T, SV, PK, PP>(dkg_sk, &encrypted_b, &rdr_pk, None)?;

    let result = T::decrypt_secret(&dkg_pk, &xnc_cmt, &rdr_sk, &franken_secret);
    assert!(
        result.is_err(),
        "decryption should fail when enc_cmt+proof are swapped but ciphertext is from another encryption"
    );
    Ok(())
}

// ============================================================================
// Derivation mismatch — verification must fail
// ============================================================================

pub fn test_verify_encryption_wrong_derivation_fails_loudly<T, SV, PK, PP, MK>(
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
    let correct_derivation = b"alice-capability-v1";
    let wrong_derivation = b"eve-capability-v1";
    let metadata = T::encode_metadata("123", "doc", "read", None, None, None);
    let (_, dkg_pk) = make_keypair();

    let (enc_cmt, _, proof) = T::encrypt_secret(
        &dkg_pk,
        b"test secret",
        Some(correct_derivation),
        Some(&metadata),
    )?;
    // Wrong derivation → must fail verification
    let wrong_derived_pk = T::derive_public_key(&dkg_pk, wrong_derivation)?;
    let result = T::verify_encryption(&wrong_derived_pk, &enc_cmt, &proof, Some(&metadata));
    assert!(
        result.is_err(),
        "verify_encryption should fail with wrong derivation"
    );

    // No derivation when one was used → also fail
    let result = T::verify_encryption(&dkg_pk, &enc_cmt, &proof, Some(&metadata));
    assert!(
        result.is_err(),
        "verify_encryption should fail when derivation is omitted"
    );

    // Correct derivation → succeed
    let correct_derived_pk = T::derive_public_key(&dkg_pk, correct_derivation)?;
    T::verify_encryption(&correct_derived_pk, &enc_cmt, &proof, Some(&metadata))?;
    Ok(())
}

pub fn test_metadata_individual_field_tampering_fails<T, SV, PK, PP, MK>(
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
    let policy = "policy-1";
    let resource = "resource-1";
    let permission = "read";
    let tier = Some("tier-gold");
    let timestamp = Some(1772127215u64);
    let salt = Some("salt-xyz");

    let correct = T::encode_metadata(policy, resource, permission, tier, timestamp, salt);
    let (enc_cmt, _, proof) = T::encrypt_secret(&dkg_pk, b"test secret", None, Some(&correct))?;

    let tampered: &[Vec<u8>] = &[
        T::encode_metadata("TAMPERED", resource, permission, tier, timestamp, salt),
        T::encode_metadata(policy, "TAMPERED", permission, tier, timestamp, salt),
        T::encode_metadata(policy, resource, "TAMPERED", tier, timestamp, salt),
        T::encode_metadata(
            policy,
            resource,
            permission,
            Some("TAMPERED"),
            timestamp,
            salt,
        ),
        T::encode_metadata(policy, resource, permission, tier, Some(0u64), salt),
        T::encode_metadata(
            policy,
            resource,
            permission,
            tier,
            timestamp,
            Some("TAMPERED"),
        ),
        T::encode_metadata(policy, resource, permission, None, timestamp, salt),
        T::encode_metadata(policy, resource, permission, tier, None, salt),
        T::encode_metadata(policy, resource, permission, tier, timestamp, None),
    ];

    for variant in tampered {
        let result = T::verify_encryption(&dkg_pk, &enc_cmt, &proof, Some(variant));
        assert!(result.is_err(), "proof should fail with tampered metadata");
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

    let (enc_cmt, encrypted_secret, _) = T::encrypt_secret(&aggregate_pk, secret, None, None)?;
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

    let decrypted = T::decrypt_secret(&aggregate_pk, &xnc_cmt, &rdr_sk, &encrypted_secret)?;
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
        T::encrypt_secret(&aggregate_pk, secret, Some(derivation), None)?;

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

    let decrypted = T::decrypt_secret(&derived_pk, &xnc_cmt, &rdr_sk, &encrypted_secret)?;
    assert_eq!(decrypted, secret);
    Ok(())
}
