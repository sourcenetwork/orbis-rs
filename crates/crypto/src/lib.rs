//! Crypto abstraction layer for orbis
//!
//! This module defines the core cryptography abstractions that can be implemented
//! by various curves.
pub mod error;
pub mod helpers;
pub mod r#trait;

#[cfg(feature = "bls12-381")]
pub mod bls12_381;
#[cfg(feature = "decaf377")]
pub mod decaf377;

// Enforce mutual exclusivity - only one curve can be selected
#[cfg(all(feature = "bls12-381", feature = "decaf377"))]
compile_error!("Features 'bls12-381' and 'decaf377' are mutually exclusive. Use --no-default-features to disable the default curve.");

// Export the selected implementation
#[cfg(feature = "bls12-381")]
pub use ark_bls12_381::{Fr as ScalarField, G1Affine as GroupAffine};
#[cfg(feature = "bls12-381")]
pub use bls12_381::common::G2Point as SigShareInner;
#[cfg(feature = "bls12-381")]
pub use bls12_381::common::{
    G2Point as SignaturePoint, PolynomialCommitment as PolynomialCommitmentImpl,
    PubPoly as PubPolyImpl, FR_COMPRESSED_SIZE as SCALAR_SIZE,
    G1_COMPRESSED_SIZE as GROUP_POINT_SIZE,
};
#[cfg(feature = "bls12-381")]
pub use bls12_381::dkg::DKGNode as DkgImpl;
#[cfg(feature = "bls12-381")]
pub use bls12_381::pre::ThresholdDealerNode as PreImpl;
#[cfg(feature = "bls12-381")]
pub use bls12_381::sign::ThresholdBlsSigner as SignImpl;

#[cfg(feature = "decaf377")]
pub use ::decaf377::Fr as SigShareInner;
#[cfg(feature = "decaf377")]
pub use ::decaf377::{Element as GroupAffine, Fr as ScalarField};
#[cfg(feature = "decaf377")]
pub use decaf377::common::{
    PolynomialCommitment as PolynomialCommitmentImpl, PubPoly as PubPolyImpl,
    ELEMENT_COMPRESSED_SIZE as GROUP_POINT_SIZE, FR_COMPRESSED_SIZE as SCALAR_SIZE,
};
#[cfg(feature = "decaf377")]
pub use decaf377::dkg::DKGNode as DkgImpl;
#[cfg(feature = "decaf377")]
pub use decaf377::pre::ThresholdDealerNode as PreImpl;
#[cfg(feature = "decaf377")]
pub use decaf377::sign::SchnorrSignature as SignaturePoint;
#[cfg(feature = "decaf377")]
pub use decaf377::sign::ThresholdDecafSigner as SignImpl;

#[cfg(feature = "bls12-381")]
pub const THRESHOLD_SIGNATURE_SCHEME: &str = "bls12_381_g1_pk_g2_sig_nul";

#[cfg(feature = "decaf377")]
pub const THRESHOLD_SIGNATURE_SCHEME: &str = "decaf377_frost";

pub use r#trait::{CryptoDeserialize, CryptoSerialize, SessionId};

#[cfg(any(test, feature = "test-helpers"))]
#[path = "test_helpers/test_helper.rs"]
pub mod test_helper;

#[cfg(test)]
mod dkg_tests;

#[cfg(test)]
mod pre_tests;

#[cfg(test)]
mod sign_tests;

#[cfg(test)]
mod lifecycle_tests;

#[cfg(test)]
#[path = "test_helpers/deserialization_prop_tests_helpers.rs"]
pub(crate) mod deserialization_prop_tests_helpers;
