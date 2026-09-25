//! Generic PET test suite
//!
//! Contains generic tests that can be applied to any [`Pet`] implementation.
//! Call [`run_all_tests`] from your implementation's test module.

use crate::error::Result;
use crate::r#trait::{CryptoDeserialize, CryptoSerialize, Pet, PetTag};

/// Runs the full generic owner-fingerprint suite against `P`.
pub fn run_all_tests<P: Pet>() -> Result<()> {
    test_fingerprint_is_deterministic::<P>()?;
    test_distinct_owners_produce_distinct_fingerprints::<P>()?;
    test_fingerprint_round_trips_through_serialization::<P>()?;
    test_empty_owner_id_does_not_panic::<P>()?;
    Ok(())
}

pub fn test_fingerprint_is_deterministic<P: Pet>() -> Result<()> {
    let a = P::owner_fingerprint(b"alice")?.to_bytes()?;
    let b = P::owner_fingerprint(b"alice")?.to_bytes()?;
    assert_eq!(
        a, b,
        "owner_fingerprint must be deterministic for the same owner_id"
    );
    Ok(())
}

pub fn test_distinct_owners_produce_distinct_fingerprints<P: Pet>() -> Result<()> {
    let alice = P::owner_fingerprint(b"alice")?.to_bytes()?;
    let charlie = P::owner_fingerprint(b"charlie")?.to_bytes()?;
    assert_ne!(alice, charlie, "distinct owner ids must not collide");
    Ok(())
}

pub fn test_fingerprint_round_trips_through_serialization<P: Pet>() -> Result<()> {
    let point = P::owner_fingerprint(b"alice")?;
    let bytes = point.to_bytes()?;
    let decoded = P::PublicKey::from_bytes(&bytes)?;
    assert_eq!(bytes, decoded.to_bytes()?);
    Ok(())
}

pub fn test_empty_owner_id_does_not_panic<P: Pet>() -> Result<()> {
    P::owner_fingerprint(b"")?.to_bytes()?;
    Ok(())
}

// ============================================================================
// Tag-knowledge-proof suite
// ============================================================================
//
// `make_ephemeral_keypair` returns a random `(r_tag, R = r_tag*G)` pair — the
// same shape a tag producer holds after step 1 of the PET construction order.
// It is a test-only closure, not part of the `Pet` trait itself.

fn fixed_digest(tag: u8) -> [u8; 32] {
    [tag; 32]
}

fn sample_tag<PK: CryptoSerialize>(ephemeral_pk: &PK) -> Result<PetTag> {
    Ok(PetTag {
        ephemeral_point: ephemeral_pk.to_bytes()?,
        masked_fingerprint: vec![1, 2, 3],
    })
}

/// Runs the full generic tag-knowledge-proof suite against `P`.
pub fn run_all_tag_knowledge_tests<P, F>(make_ephemeral_keypair: F) -> Result<()>
where
    P: Pet,
    F: Fn() -> (P::ShareValue, P::PublicKey),
{
    test_tag_knowledge_proof_round_trip::<P, F>(&make_ephemeral_keypair)?;
    test_tag_knowledge_proof_rejects_wrong_digest::<P, F>(&make_ephemeral_keypair)?;
    test_tag_knowledge_proof_rejects_swapped_tag::<P, F>(&make_ephemeral_keypair)?;
    Ok(())
}

pub fn test_tag_knowledge_proof_round_trip<P, F>(make_ephemeral_keypair: &F) -> Result<()>
where
    P: Pet,
    F: Fn() -> (P::ShareValue, P::PublicKey),
{
    let (r_tag, ephemeral_pk) = make_ephemeral_keypair();
    let tag = sample_tag::<P::PublicKey>(&ephemeral_pk)?;
    let digest = fixed_digest(7);

    let proof = P::prove_tag_knowledge(&r_tag, &tag, &digest)?;
    P::verify_tag_knowledge(&tag, &proof, &digest)?;
    Ok(())
}

pub fn test_tag_knowledge_proof_rejects_wrong_digest<P, F>(make_ephemeral_keypair: &F) -> Result<()>
where
    P: Pet,
    F: Fn() -> (P::ShareValue, P::PublicKey),
{
    let (r_tag, ephemeral_pk) = make_ephemeral_keypair();
    let tag = sample_tag::<P::PublicKey>(&ephemeral_pk)?;

    let proof = P::prove_tag_knowledge(&r_tag, &tag, &fixed_digest(7))?;
    assert!(
        P::verify_tag_knowledge(&tag, &proof, &fixed_digest(9)).is_err(),
        "a proof bound to one transcript digest must not verify against another"
    );
    Ok(())
}

pub fn test_tag_knowledge_proof_rejects_swapped_tag<P, F>(make_ephemeral_keypair: &F) -> Result<()>
where
    P: Pet,
    F: Fn() -> (P::ShareValue, P::PublicKey),
{
    let (r_tag_a, ephemeral_pk_a) = make_ephemeral_keypair();
    let (_r_tag_b, ephemeral_pk_b) = make_ephemeral_keypair();

    let tag_a = sample_tag::<P::PublicKey>(&ephemeral_pk_a)?;
    let tag_b = sample_tag::<P::PublicKey>(&ephemeral_pk_b)?;
    let digest = fixed_digest(7);

    let proof = P::prove_tag_knowledge(&r_tag_a, &tag_a, &digest)?;
    assert!(
        P::verify_tag_knowledge(&tag_b, &proof, &digest).is_err(),
        "a proof of knowledge for R_a's discrete log must not verify against a different R_b"
    );
    Ok(())
}
