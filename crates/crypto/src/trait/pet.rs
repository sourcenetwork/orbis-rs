use super::codec::{CryptoDeserialize, CryptoSerialize};
use crate::error::Result;

/// PET (ownership-tag) primitives, defined once per curve backend alongside the
/// existing PRE ([`super::pre::ThresholdDealer`]) and signing
/// ([`super::sign::ThresholdSigner`]) abstractions.
///
/// A PET tag masks a fingerprint of the claimed owner's identity under an
/// independently generated PET public key: `T = F(owner_id) + r_tag * pet_pk`.
/// [`Pet::owner_fingerprint`] computes `F`, the deterministic mapping from an
/// owner identifier to a group element.
///
/// `F` is defined and owned here, on the Orbis side, not supplied by the tag
/// producer (Bankd): every PET participant reconstructs the expected
/// fingerprint for an authenticated audit target from this same function
/// rather than trusting a caller-supplied value.
pub trait Pet {
    /// Group element type (matches the curve's `ThresholdDealer::PublicKey`).
    type PublicKey: CryptoSerialize + CryptoDeserialize + Clone;

    fn new() -> Self;
    fn name() -> String;

    /// `F(owner_id) = hash_to_scalar(FINGERPRINT_DOMAIN || owner_id) * G`.
    ///
    /// Deterministic and public. Every verifier recomputes this directly from
    /// the authenticated audit target id; it is never taken as a caller-supplied
    /// value.
    fn owner_fingerprint(owner_id: &[u8]) -> Result<Self::PublicKey>;
}
