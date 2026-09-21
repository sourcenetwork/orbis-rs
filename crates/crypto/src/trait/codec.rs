use crate::error::Result;

/// Trait for types that can be serialized to bytes.
///
/// This provides a generic interface for crypto type serialization,
/// allowing implementations to use any serialization format (e.g., ark-serialize).
pub trait CryptoSerialize: Sized {
    /// Serialize this value to bytes (compressed format preferred).
    fn to_bytes(&self) -> Result<Vec<u8>>;

    /// Lower bound on the serialized size in bytes.
    ///
    /// For fixed-size types this is the exact encoded size. For variable-size
    /// types (e.g. polynomials, whose length depends on the value) it is only
    /// the minimum possible encoding — typically just the length prefix. Use it
    /// for pre-allocation and cheap too-short checks, never as an exact-length
    /// validator.
    fn min_serialized_size() -> usize;
}

/// Trait for types that can be deserialized from bytes.
///
/// This provides a generic interface for crypto type deserialization,
/// allowing implementations to use any serialization format (e.g., ark-serialize).
pub trait CryptoDeserialize: Sized {
    /// Deserialize a value from bytes.
    fn from_bytes(bytes: &[u8]) -> Result<Self>;
}
