//! Threshold Signing stub for decaf377
//!
//! This is a placeholder implementation. All methods panic with `todo!()`.
//! decaf377 is a prime-order group (no pairing), so the signing scheme
//! will differ from the BLS pairing-based approach used with BLS12-381.

use super::common::PubPoly;
use crate::error::Result;
use crate::r#trait::{DistKeyShare, PubShare, ThresholdSigner};
use decaf377::{Element, Fr};

/// Threshold signer for decaf377 (stub)
pub struct ThresholdDecafSigner;

impl ThresholdSigner for ThresholdDecafSigner {
    type ShareValue = Fr;
    type Signature = Element;
    type PublicKey = Element;
    type PubPoly = PubPoly;
    type DistKeyShare = DistKeyShare<Fr>;
    type SigShare = PubShare<Element>;

    fn new() -> Self {
        todo!("decaf377 threshold signer not yet implemented")
    }

    fn name(&self) -> &str {
        todo!("decaf377 threshold signer not yet implemented")
    }

    fn hash_message(&self, _msg: &[u8]) -> Result<Self::Signature> {
        todo!("decaf377 threshold signer not yet implemented")
    }

    fn sign(&self, _dist_key_share: &Self::DistKeyShare, _msg: &[u8]) -> Result<Self::SigShare> {
        todo!("decaf377 threshold signer not yet implemented")
    }

    fn verify_share(
        &self,
        _msg: &[u8],
        _pub_poly: &Self::PubPoly,
        _sig_share: &Self::SigShare,
    ) -> Result<()> {
        todo!("decaf377 threshold signer not yet implemented")
    }

    fn recover(
        &self,
        _shares: &[Self::SigShare],
        _t: usize,
        _n: usize,
    ) -> Result<Option<Self::Signature>> {
        todo!("decaf377 threshold signer not yet implemented")
    }

    fn verify(&self, _pk: &Self::PublicKey, _msg: &[u8], _sig: &Self::Signature) -> Result<()> {
        todo!("decaf377 threshold signer not yet implemented")
    }
}
