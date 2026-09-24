use crate::{error::Result, r#trait::Pet};
use decaf377::{Element, Fr};
use sha2::{Digest, Sha512};

const NAME: &str = "pet/decaf377";
/// Domain separator for the PET owner-fingerprint hash-to-scalar. Distinct from
/// `DERIVATION_DOMAIN` (capability derivation) in `decaf377::pre` so the two
/// hash-to-scalar uses can never collide on the same input bytes.
const FINGERPRINT_DOMAIN: &[u8] = b"orbis-pet-fingerprint-v1";

#[derive(Clone, Debug)]
pub struct PetNode {}

impl Pet for PetNode {
    type PublicKey = Element;

    fn new() -> Self {
        PetNode {}
    }

    fn name() -> String {
        NAME.to_string()
    }

    fn owner_fingerprint(owner_id: &[u8]) -> Result<Self::PublicKey> {
        let mut hasher = Sha512::new();
        hasher.update(FINGERPRINT_DOMAIN);
        hasher.update(owner_id);
        let scalar = Fr::from_le_bytes_mod_order(&hasher.finalize());
        Ok(Element::GENERATOR * scalar)
    }
}
