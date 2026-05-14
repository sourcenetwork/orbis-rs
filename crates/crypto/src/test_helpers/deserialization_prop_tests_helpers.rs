use crate::r#trait::{CryptoDeserialize, CryptoSerialize};
use proptest::prelude::*;
use proptest::test_runner::TestCaseError;

pub(crate) const PROPTEST_CASES: u32 = 128;

pub(crate) fn byte_vec() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..=512)
}

pub(crate) fn small_byte_vec() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..=128)
}

pub(crate) fn must<T>(result: crate::error::Result<T>, context: &str) -> Result<T, TestCaseError> {
    result.map_err(|err| TestCaseError::fail(format!("{context}: {err}")))
}

pub(crate) fn assert_canonical_from_bytes<T>(bytes: &[u8]) -> Result<(), TestCaseError>
where
    T: CryptoDeserialize + CryptoSerialize,
{
    if let Ok(value) = T::from_bytes(bytes) {
        let encoded = must(value.to_bytes(), "serializing deserialized value failed")?;
        prop_assert_eq!(&encoded, bytes);

        let reparsed = must(T::from_bytes(&encoded), "re-parsing canonical bytes failed")?;
        let reencoded = must(reparsed.to_bytes(), "re-serializing canonical value failed")?;
        prop_assert_eq!(reencoded, encoded);
    }

    Ok(())
}

pub(crate) fn assert_value_roundtrips<T>(value: &T) -> Result<(), TestCaseError>
where
    T: CryptoDeserialize + CryptoSerialize,
{
    let encoded = must(value.to_bytes(), "serializing generated value failed")?;
    let decoded = must(
        T::from_bytes(&encoded),
        "deserializing generated value failed",
    )?;
    let reencoded = must(decoded.to_bytes(), "re-serializing generated value failed")?;
    prop_assert_eq!(&reencoded, &encoded);

    let mut with_trailing = encoded;
    with_trailing.push(0);
    prop_assert!(
        T::from_bytes(&with_trailing).is_err(),
        "deserializer accepted a canonical value with trailing bytes"
    );

    Ok(())
}

proptest! {
    #![proptest_config(proptest::test_runner::Config::with_cases(PROPTEST_CASES))]

    #[test]
    fn unit_deserializer_is_canonical(bytes in byte_vec()) {
        assert_canonical_from_bytes::<()>(&bytes)?;
    }

    #[test]
    fn encryption_proof_json_never_panics(input in any::<String>()) {
        let _ = crate::r#trait::EncryptionProof::try_from(input);
    }
}
