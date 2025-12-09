use crate::r#trait::{PolynomialCommitment as PolynomialCommitmentTrait, PubPoly as PubPolyTrait};
use ark_bls12_381::{Fr, G1Affine, G1Projective};
use ark_ec::{AffineRepr, Group};
use ark_serialize::CanonicalSerialize;
use subtle::ConstantTimeEq;

/// Public polynomial for commitments
#[derive(Clone, Debug)]
pub struct PubPoly {
    pub commits: Vec<G1Affine>,
}

impl PubPolyTrait for PubPoly {
    type PublicKey = G1Affine;

    /// Evaluate the public polynomial at index i
    fn eval(&self, i: u32) -> Self::PublicKey {
        if self.commits.is_empty() {
            return G1Affine::zero();
        }

        let x = Fr::from(i as u64);
        let mut result = G1Projective::from(self.commits[0]);
        let mut x_power = x;

        for commit in &self.commits[1..] {
            result += G1Projective::from(*commit) * x_power;
            x_power *= x;
        }

        result.into()
    }
}

/// A polynomial commitment
#[derive(Clone, Debug)]
pub struct PolynomialCommitment {
    pub coefficients: Vec<G1Affine>, // Commitments to polynomial coefficients
}

impl PolynomialCommitmentTrait for PolynomialCommitment {
    type PublicKey = G1Affine;
    type ShareValue = Fr;

    fn eval(&self, x: u32) -> G1Affine {
        if self.coefficients.is_empty() {
            return G1Affine::zero();
        }

        let x_scalar = Fr::from(x as u64);
        let mut result = G1Projective::from(self.coefficients[0]);
        let mut x_power = x_scalar;

        for coeff in &self.coefficients[1..] {
            result += G1Projective::from(*coeff) * x_power;
            x_power *= x_scalar;
        }

        result.into()
    }

    fn verify_share(&self, share_id: u32, share_value: &Fr) -> bool {
        let expected = self.eval(share_id);
        let actual: G1Affine = (G1Projective::generator() * share_value).into();

        // Use constant-time comparison to prevent timing side-channels
        let mut expected_bytes = Vec::new();
        let mut actual_bytes = Vec::new();

        // Serialize both points for comparison
        if expected.serialize_compressed(&mut expected_bytes).is_err() {
            return false;
        }
        if actual.serialize_compressed(&mut actual_bytes).is_err() {
            return false;
        }

        // Pad to same length for constant-time comparison
        let max_len = expected_bytes.len().max(actual_bytes.len());
        let mut expected_padded = vec![0u8; max_len];
        let mut actual_padded = vec![0u8; max_len];
        expected_padded[..expected_bytes.len()].copy_from_slice(&expected_bytes);
        actual_padded[..actual_bytes.len()].copy_from_slice(&actual_bytes);

        // Constant-time comparison
        expected_padded.ct_eq(&actual_padded).into()
    }
}
