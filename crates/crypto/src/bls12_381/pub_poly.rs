use crate::r#trait::PubPoly as PubPolyTrait;
use ark_bls12_381::{Fr, G1Affine, G1Projective};
use ark_ec::AffineRepr;

/// Public polynomial for commitments
#[derive(Clone, Debug)]
pub struct PubPoly {
    pub commits: Vec<G1Affine>,
}

impl PubPolyTrait for PubPoly {
    type PublicKey = G1Affine;

    /// Evaluate the public polynomial at index i
    fn eval(&self, i: i32) -> Self::PublicKey {
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
