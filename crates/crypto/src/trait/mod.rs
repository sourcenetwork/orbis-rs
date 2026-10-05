//! Crypto trait definitions
//!
//! This module defines the core cryptography abstractions that can be implemented
//! by various Curves.
//!
//! - [`codec`] — `CryptoSerialize`/`CryptoDeserialize`, the generic byte-codec traits.
//! - [`types`] — the plain data types built from them (shares, secrets, proofs).
//! - [`serialize`] — the codec impls for those types.
//! - [`dkg`] — the DKG abstractions (`Dkg`, `PubPoly`, `PolynomialCommitment`, ...).
//! - [`pre`] — the PRE abstraction (`ThresholdDealer`).
//! - [`sign`] — the threshold-signing abstraction (`ThresholdSigner`).
//! - [`pet`] — the PET ownership-tag abstraction (`Pet`).

mod codec;
mod dkg;
mod pet;
mod pre;
mod serialize;
mod sign;
mod types;

pub use codec::*;
pub use dkg::*;
pub use pet::*;
pub use pre::*;
pub use sign::*;
pub use types::*;
