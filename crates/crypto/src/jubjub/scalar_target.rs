//! Canonical scalar targets for externally admitted external PET documents.
//! The application supplies the canonical scalar.
use super::common::{Element, Fr};
use crate::{
    error::{CryptoError, Result},
    CryptoDeserialize,
};

/// Decode a canonical nonzero Jubjub scalar and multiply the standard generator.
/// Rejecting, rather than reducing, ensures each target point has one encoding.
pub fn fingerprint(binding: &[u8; 32]) -> Result<Element> {
    let scalar = Fr::from_bytes(binding)?;
    if scalar == Fr::from(0u64) {
        return Err(CryptoError::ParseError(
            "identity external fingerprint".into(),
        ));
    }
    Ok(Element::generator() * scalar)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_scalar_targets_and_identity_boundary() {
        let mut one = [0; 32];
        one[0] = 1;
        assert_eq!(fingerprint(&one).unwrap(), Element::generator());
        let mut two = one;
        two[0] = 2;
        assert_eq!(
            fingerprint(&two).unwrap(),
            Element::generator() + Element::generator()
        );
        // Jubjub subgroup order, independently specified in little-endian limbs.
        let order = [
            15030498081868557495u64,
            11990869827041890434,
            461402362329971456,
            1044189607433056169,
        ];
        let mut bytes = [0; 32];
        for (chunk, limb) in bytes.chunks_exact_mut(8).zip(order) {
            chunk.copy_from_slice(&limb.to_le_bytes());
        }
        assert!(fingerprint(&bytes).is_err());
        bytes[0] -= 1;
        assert_eq!(fingerprint(&bytes).unwrap(), -Element::generator());
        assert!(fingerprint(&[0; 32]).is_err());
        assert!(fingerprint(&[0xff; 32]).is_err());
    }
}
