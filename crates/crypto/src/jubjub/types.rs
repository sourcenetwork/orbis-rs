//! Protocol scalars and prime-order points backed by `zkcrypto/jubjub`.
//!
//! The point wrapper admits only the prime-order subgroup. In particular, decoding
//! never clears a supplied point's cofactor: changing a received point would alter
//! the statement being verified by the protocol.

use crate::error::{CryptoError, Result};
use crate::r#trait::{CryptoDeserialize, CryptoSerialize};
use ff::Field;
use group_jubjub::{Group, GroupEncoding};
use rand_core::{CryptoRng, RngCore};
use std::io::Write;
use std::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};
use subtle::{Choice, ConstantTimeEq};

/// A Jubjub scalar, encoded as a canonical 32-byte little-endian integer.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct Fr(::jubjub::Fr);

impl std::fmt::Debug for Fr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Fr([REDACTED])")
    }
}

impl zeroize::Zeroize for Fr {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Fr {
    pub fn zero() -> Self {
        Self(::jubjub::Fr::ZERO)
    }

    pub fn one() -> Self {
        Self(::jubjub::Fr::ONE)
    }

    pub fn is_zero(&self) -> bool {
        bool::from(self.0.is_zero())
    }

    pub fn rand(rng: &mut (impl RngCore + CryptoRng)) -> Self {
        // Keep the protocol's rand_core 0.6 RNG interface while Jubjub uses
        // rand_core 0.10 internally. Rejection sampling is exactly uniform.
        let mut bytes = zeroize::Zeroizing::new([0u8; 32]);
        loop {
            rng.fill_bytes(&mut *bytes);
            bytes[31] &= 0x0f;
            if let Some(scalar) = Option::<::jubjub::Fr>::from(::jubjub::Fr::from_bytes(&bytes)) {
                return Self(scalar);
            }
        }
    }

    pub fn inverse(&self) -> Option<Self> {
        Option::<::jubjub::Fr>::from(self.0.invert()).map(Self)
    }

    /// Reduce a little-endian integer modulo the scalar field order.
    ///
    /// Hash outputs up to 64 bytes use the native wide reduction directly;
    /// longer inputs are supported without truncating their high bytes.
    pub fn from_le_bytes_mod_order(bytes: &[u8]) -> Self {
        if bytes.len() <= 64 {
            let mut wide = zeroize::Zeroizing::new([0u8; 64]);
            wide[..bytes.len()].copy_from_slice(bytes);
            Self(::jubjub::Fr::from_bytes_wide(&wide))
        } else {
            let radix = Self::from(256);
            bytes.iter().rev().fold(Self::zero(), |acc, byte| {
                acc * radix + Self::from(u64::from(*byte))
            })
        }
    }

    /// Borrow the underlying zkcrypto scalar.
    pub fn as_inner(&self) -> &::jubjub::Fr {
        &self.0
    }

    pub fn write_bytes(&self, mut writer: impl Write) -> Result<()> {
        let bytes = zeroize::Zeroizing::new(self.0.to_bytes());
        writer
            .write_all(&*bytes)
            .map_err(|e| CryptoError::ParseError(format!("Jubjub scalar encoding failed: {e}")))
    }
}

impl From<u64> for Fr {
    fn from(value: u64) -> Self {
        Self(::jubjub::Fr::from(value))
    }
}

impl From<::jubjub::Fr> for Fr {
    fn from(value: ::jubjub::Fr) -> Self {
        Self(value)
    }
}

impl From<Fr> for ::jubjub::Fr {
    fn from(value: Fr) -> Self {
        value.0
    }
}

impl ConstantTimeEq for Fr {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl CryptoSerialize for Fr {
    fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::with_capacity(32);
        self.write_bytes(&mut bytes)?;
        Ok(bytes)
    }

    fn min_serialized_size() -> usize {
        32
    }
}

impl CryptoDeserialize for Fr {
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let encoded: &[u8; 32] = bytes.try_into().map_err(|_| {
            CryptoError::ParseError("Jubjub scalar encoding must contain exactly 32 bytes".into())
        })?;
        Option::<::jubjub::Fr>::from(::jubjub::Fr::from_bytes(encoded))
            .map(Self)
            .ok_or_else(|| CryptoError::ParseError("Non-canonical Jubjub scalar encoding".into()))
    }
}

/// A point in Jubjub's prime-order subgroup, using its canonical 32-byte encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Element(::jubjub::SubgroupPoint);

impl std::fmt::Display for Element {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Stable public-key identifier used by the node's session maps.
        for byte in self.0.to_bytes() {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl Default for Element {
    fn default() -> Self {
        Self(::jubjub::SubgroupPoint::identity())
    }
}

impl Element {
    /// Return zkcrypto's generator of Jubjub's prime-order subgroup.
    pub fn generator() -> Self {
        Self(::jubjub::SubgroupPoint::generator())
    }

    /// Borrow the underlying subgroup point.
    pub fn as_inner(&self) -> &::jubjub::SubgroupPoint {
        &self.0
    }

    pub fn write_bytes(&self, mut writer: impl Write) -> Result<()> {
        writer
            .write_all(&self.0.to_bytes())
            .map_err(|e| CryptoError::ParseError(format!("Jubjub point encoding failed: {e}")))
    }
}

impl From<Element> for ::jubjub::SubgroupPoint {
    fn from(value: Element) -> Self {
        value.0
    }
}

impl ConstantTimeEq for Element {
    fn ct_eq(&self, other: &Self) -> Choice {
        ::jubjub::ExtendedPoint::from(self.0).ct_eq(&::jubjub::ExtendedPoint::from(other.0))
    }
}

impl CryptoSerialize for Element {
    fn to_bytes(&self) -> Result<Vec<u8>> {
        Ok(self.0.to_bytes().to_vec())
    }

    fn min_serialized_size() -> usize {
        32
    }
}

impl CryptoDeserialize for Element {
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let encoded: &[u8; 32] = bytes.try_into().map_err(|_| {
            CryptoError::ParseError("Jubjub point encoding must contain exactly 32 bytes".into())
        })?;
        // The checked SubgroupPoint decoder validates the curve encoding AND
        // torsion-freeness. ExtendedPoint::from_bytes alone is insufficient.
        Option::<::jubjub::SubgroupPoint>::from(::jubjub::SubgroupPoint::from_bytes(encoded))
            .map(Self)
            .ok_or_else(|| {
                CryptoError::ParseError("Invalid prime-order Jubjub point encoding".into())
            })
    }
}

macro_rules! impl_binary_op {
    ($lhs:ident, $rhs:ident, $trait:ident, $method:ident, $assign:ident, $assign_method:ident, $op:tt) => {
        impl $trait<$rhs> for $lhs {
            type Output = $lhs;
            fn $method(self, rhs: $rhs) -> Self::Output {
                $lhs(self.0 $op rhs.0)
            }
        }
        impl $trait<&$rhs> for $lhs {
            type Output = $lhs;
            fn $method(self, rhs: &$rhs) -> Self::Output {
                self $op *rhs
            }
        }
        impl $trait<$rhs> for &$lhs {
            type Output = $lhs;
            fn $method(self, rhs: $rhs) -> Self::Output {
                *self $op rhs
            }
        }
        impl $trait<&$rhs> for &$lhs {
            type Output = $lhs;
            fn $method(self, rhs: &$rhs) -> Self::Output {
                *self $op *rhs
            }
        }
        impl $assign<$rhs> for $lhs {
            fn $assign_method(&mut self, rhs: $rhs) {
                *self = *self $op rhs;
            }
        }
        impl $assign<&$rhs> for $lhs {
            fn $assign_method(&mut self, rhs: &$rhs) {
                *self = *self $op *rhs;
            }
        }
    };
}

impl_binary_op!(Fr, Fr, Add, add, AddAssign, add_assign, +);
impl_binary_op!(Fr, Fr, Sub, sub, SubAssign, sub_assign, -);
impl_binary_op!(Fr, Fr, Mul, mul, MulAssign, mul_assign, *);
impl_binary_op!(Element, Element, Add, add, AddAssign, add_assign, +);
impl_binary_op!(Element, Element, Sub, sub, SubAssign, sub_assign, -);
impl_binary_op!(Element, Fr, Mul, mul, MulAssign, mul_assign, *);

macro_rules! impl_neg {
    ($type:ident) => {
        impl Neg for $type {
            type Output = Self;
            fn neg(self) -> Self::Output {
                Self(-self.0)
            }
        }
        impl Neg for &$type {
            type Output = $type;
            fn neg(self) -> Self::Output {
                -*self
            }
        }
    };
}

impl_neg!(Fr);
impl_neg!(Element);

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroize;

    const SCALAR_MODULUS: [u8; 32] = [
        183, 44, 247, 214, 94, 14, 151, 208, 130, 16, 200, 204, 147, 32, 104, 166, 0, 59, 52, 1, 1,
        59, 103, 6, 169, 175, 51, 101, 234, 180, 125, 14,
    ];

    #[test]
    fn scalar_canonical_vectors_and_reduction() {
        assert_eq!(Fr::zero().to_bytes().unwrap(), [0; 32]);
        let mut one = [0u8; 32];
        one[0] = 1;
        assert_eq!(Fr::one().to_bytes().unwrap(), one);
        assert_eq!(Fr::from_bytes(&one).unwrap(), Fr::one());
        assert!(Fr::from_bytes(&SCALAR_MODULUS).is_err());
        assert!(Fr::from_bytes(&[255; 32]).is_err());

        let mut minus_one = SCALAR_MODULUS;
        minus_one[0] -= 1;
        assert_eq!(Fr::from_bytes(&minus_one).unwrap(), -Fr::one());
        assert!(Fr::from_le_bytes_mod_order(&SCALAR_MODULUS).is_zero());
        assert!(Fr::from_le_bytes_mod_order(&[]).is_zero());
        assert_eq!(Fr::from_le_bytes_mod_order(&one), Fr::one());

        let mut wide = [0u8; 64];
        wide[..32].copy_from_slice(&SCALAR_MODULUS);
        wide[0] += 1;
        assert_eq!(Fr::from_le_bytes_mod_order(&wide), Fr::one());
        let mut longer = [0u8; 65];
        longer[..64].copy_from_slice(&wide);
        assert_eq!(Fr::from_le_bytes_mod_order(&longer), Fr::one());
    }

    #[test]
    fn scalar_zeroization_and_arithmetic() {
        let mut secret = Fr::from(123);
        assert_eq!(secret * secret.inverse().unwrap(), Fr::one());
        assert!(Fr::zero().inverse().is_none());
        assert_eq!((secret + Fr::one()) - secret, Fr::one());
        secret.zeroize();
        assert!(secret.is_zero());
        assert_eq!(secret.to_bytes().unwrap(), [0; 32]);
    }

    #[test]
    fn scalar_sampler_retries_out_of_range_values() {
        struct ScriptedRng(usize);
        impl RngCore for ScriptedRng {
            fn next_u32(&mut self) -> u32 {
                unreachable!("sampler draws byte arrays")
            }
            fn next_u64(&mut self) -> u64 {
                unreachable!("sampler draws byte arrays")
            }
            fn fill_bytes(&mut self, dest: &mut [u8]) {
                assert_eq!(dest.len(), 32);
                match self.0 {
                    0 => dest.fill(255), // Still above the modulus after masking.
                    1 => {
                        dest.fill(0);
                        dest[0] = 7;
                        dest[31] = 0xf0; // Unused high bits must be masked.
                    }
                    _ => panic!("unexpected extra draw"),
                }
                self.0 += 1;
            }
            fn try_fill_bytes(
                &mut self,
                dest: &mut [u8],
            ) -> std::result::Result<(), rand_core::Error> {
                self.fill_bytes(dest);
                Ok(())
            }
        }
        // Marker applies only to this deterministic test fixture.
        impl CryptoRng for ScriptedRng {}

        let mut rng = ScriptedRng(0);
        assert_eq!(Fr::rand(&mut rng), Fr::from(7));
        assert_eq!(rng.0, 2);
    }

    #[test]
    fn point_canonical_identity_and_arithmetic() {
        let mut identity = [0u8; 32];
        identity[0] = 1;
        assert_eq!(Element::default().to_bytes().unwrap(), identity);
        assert_eq!(Element::from_bytes(&identity).unwrap(), Element::default());
        // ZIP 216 rejects the otherwise redundant sign bit for u = 0.
        identity[31] |= 128;
        assert!(Element::from_bytes(&identity).is_err());
        assert!(Element::from_bytes(&[255; 32]).is_err());

        let g = Element::generator();
        // zkcrypto's subgroup generator is 8 times its full-curve generator
        // (whose v-coordinate is 11). This encoding was computed independently
        // using the twisted Edwards affine doubling equations.
        let generator_bytes = [
            203, 85, 12, 213, 56, 234, 12, 193, 19, 132, 128, 64, 142, 110, 170, 185, 179, 108, 97,
            63, 13, 211, 247, 120, 79, 219, 110, 234, 131, 123, 19, 215,
        ];
        assert_eq!(g.to_bytes().unwrap(), generator_bytes);
        assert_eq!(Element::from_bytes(&generator_bytes).unwrap(), g);
        assert_eq!(Element::from_bytes(&g.to_bytes().unwrap()).unwrap(), g);
        assert_eq!(g * Fr::from(2), g + g);
        assert_eq!(g * Fr::zero(), Element::default());
        assert_eq!(g + -g, Element::default());
    }

    #[test]
    fn point_decoder_rejects_torsion_and_mixed_order() {
        // The canonical order-two point (u, v) = (0, -1) is a valid
        // Jubjub curve point, but does not belong to the prime-order subgroup.
        let torsion_bytes = (-::jubjub::Fq::ONE).to_bytes();
        let torsion = Option::<::jubjub::ExtendedPoint>::from(::jubjub::ExtendedPoint::from_bytes(
            &torsion_bytes,
        ))
        .unwrap();
        assert!(!bool::from(torsion.is_identity()));
        assert_eq!(torsion + torsion, ::jubjub::ExtendedPoint::identity());
        assert!(Element::from_bytes(&torsion_bytes).is_err());

        let mixed = ::jubjub::ExtendedPoint::from(::jubjub::SubgroupPoint::generator()) + torsion;
        assert!(!bool::from(mixed.is_small_order()));
        assert!(!bool::from(mixed.is_torsion_free()));
        assert!(Element::from_bytes(&mixed.to_bytes()).is_err());
    }

    #[test]
    fn encodings_reject_wrong_lengths() {
        for size in [0, 1, 31, 33, 64] {
            let bytes = vec![0; size];
            assert!(Fr::from_bytes(&bytes).is_err());
            assert!(Element::from_bytes(&bytes).is_err());
        }
        let mut scalar = Fr::one().to_bytes().unwrap();
        scalar.push(0);
        assert!(Fr::from_bytes(&scalar).is_err());
        let mut point = Element::generator().to_bytes().unwrap();
        point.push(0);
        assert!(Element::from_bytes(&point).is_err());
    }
}
