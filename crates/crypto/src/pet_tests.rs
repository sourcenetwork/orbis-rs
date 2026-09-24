//! Generic PET test suite
//!
//! Contains generic tests that can be applied to any [`Pet`] implementation.
//! Call [`run_all_tests`] from your implementation's test module.

use crate::error::Result;
use crate::r#trait::{CryptoDeserialize, CryptoSerialize, Pet};

/// Runs the full generic PET suite against `P`.
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
