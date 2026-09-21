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

mod codec;
mod dkg;
mod pre;
mod serialize;
mod sign;
mod types;

pub use codec::*;
pub use dkg::*;
pub use pre::*;
pub use sign::*;
pub use types::*;
