use super::common::{PolynomialCommitment, PubPoly};
use crate::{
    error::{CryptoError, Result},
    r#trait::{
        DistKeyShare, PolynomialCommitment as PolynomialCommitmentTrait, PriShare, PubShare,
        ReencryptReply, Secret, ThresholdDealer,
    },
};
use ark_bls12_381::{Fr, G1Affine, G1Projective};
use ark_ec::{AffineRepr, Group};
use ark_ff::{Field, One, PrimeField, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{vec::Vec, UniformRand};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug)]
pub struct ThresholdDealerNode {}

impl ThresholdDealer for ThresholdDealerNode {
    type ShareValue = Fr;
    type PublicKey = G1Affine;
    type PubPoly = PubPoly;
    type DistKeyShare = DistKeyShare<Self::ShareValue>;
    type Secret = Secret;
    type ReencryptReply = ReencryptReply<Self::ShareValue, Self::PublicKey>;

    fn reencrypt(
        &self,
        dist_key_share: &Self::DistKeyShare,
        scrt: &Self::Secret,
        rdr_pk: &Self::PublicKey,
    ) -> Result<Self::ReencryptReply> {
        // Input validation
        if scrt.enc_cmt.is_empty() {
            return Err(CryptoError::ElGamalError(
                "Empty commitment in secret".to_string(),
            ));
        }

        let idx = dist_key_share.pri_share.i;
        let ski = dist_key_share.pri_share.v;

        // Validate index is positive
        if idx == 0 {
            return Err(CryptoError::ElGamalError(format!(
                "Invalid share index: {} (must not be 0)",
                idx
            )));
        }

        // Unmarshal the commitment
        let enc_cmt = Self::decompress_point(&scrt.enc_cmt)?;

        let (xnc_ski, chlgi, proofi) = Self::reencrypt(&ski, rdr_pk, &enc_cmt)?;

        Ok(ReencryptReply {
            share: PubShare { i: idx, v: xnc_ski },
            challenge: chlgi,
            proof: proofi,
        })
    }
}

impl ThresholdDealerNode {
    /// Decompress a point from bytes
    fn decompress_point(bytes: &[u8]) -> Result<G1Affine> {
        G1Affine::deserialize_compressed(bytes)
            .map_err(|e| CryptoError::ElGamalError(format!("failed to decompress point: {:?}", e)))
    }

    fn reencrypt(
        dkg_ski: &Fr,
        rdr_pk: &G1Affine,
        enc_cmt: &G1Affine,
    ) -> Result<(G1Affine, Fr, Fr)> {
        // Re-encrypted secret share (Ui)
        let xr_g = G1Projective::from(*rdr_pk) + G1Projective::from(*enc_cmt); // xrG = xG + rG
        let xnc_ski = (xr_g * dkg_ski).into(); // Ui = ski * (xG + rG)

        // Produce random oracle challenge (ei)
        // ei = Hash(Ui + UiHat + HiHat)
        let mut rng = OsRng;
        let ri = Fr::rand(&mut rng); // ri = Random scalar
        let ui_hat = (xr_g * ri).into(); // UiHat = ri * (xG + rG)
        let hi_hat = (G1Projective::generator() * ri).into(); // HiHat = ri * G

        let challenge_hash = Self::hash_points(&[xnc_ski, ui_hat, hi_hat])?;
        let chlgi = Fr::from_le_bytes_mod_order(&challenge_hash);

        // Produce NIZK proof of re-encryption (fi)
        // fi = ri + ei * ski
        let proofi = ri + (chlgi * dkg_ski);

        Ok((xnc_ski, chlgi, proofi))
    }

    /// Hash multiple points together
    fn hash_points(points: &[G1Affine]) -> Result<[u8; 32]> {
        let mut hasher = Sha256::new();

        for point in points {
            let mut bytes = Vec::new();
            point.serialize_compressed(&mut bytes)?;
            hasher.update(&bytes);
        }

        let result = hasher.finalize();
        let mut output = [0u8; 32];
        output.copy_from_slice(&result);

        Ok(output)
    }
}
