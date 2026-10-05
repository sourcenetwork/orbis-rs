use crate::error::{CryptoError, Result};
use crate::r#trait::{
    CryptoDeserialize, CryptoSerialize, PolynomialCommitment as PolynomialCommitmentTrait,
    PubPoly as PubPolyTrait,
};
use subtle::ConstantTimeEq;

pub use super::types::{Element, Fr};

/// Size of a canonically compressed Jubjub subgroup point in bytes.
pub const ELEMENT_COMPRESSED_SIZE: usize = 32;

/// Size of a canonical little-endian Jubjub scalar in bytes.
pub const FR_COMPRESSED_SIZE: usize = 32;

// ============================================================================
// Public polynomial and polynomial commitment types
// ============================================================================

/// Public polynomial for commitments (Jubjub).
#[derive(Clone, Debug)]
pub struct PubPoly {
    pub commits: Vec<Element>,
}

impl PubPolyTrait for PubPoly {
    type PublicKey = Element;

    /// Evaluate the public polynomial at index i.
    fn eval(&self, i: u32) -> Self::PublicKey {
        if self.commits.is_empty() {
            return Element::default();
        }
        crate::helpers::eval_poly_at(self.commits.iter().copied(), Fr::from(i as u64))
    }
}

/// A polynomial commitment (Jubjub).
#[derive(Clone, Debug)]
pub struct PolynomialCommitment {
    pub coefficients: Vec<Element>,
}

impl PolynomialCommitmentTrait for PolynomialCommitment {
    type PublicKey = Element;
    type ShareValue = Fr;

    fn eval(&self, x: u32) -> Element {
        if self.coefficients.is_empty() {
            return Element::default();
        }
        crate::helpers::eval_poly_at(self.coefficients.iter().copied(), Fr::from(x as u64))
    }

    fn verify_share(&self, share_id: u32, share_value: &Fr) -> bool {
        let expected = self.eval(share_id);
        let actual = Element::generator() * share_value;

        // Compare the group elements directly in constant time.
        expected.ct_eq(&actual).into()
    }

    fn constant_term_is_identity(&self) -> bool {
        self.coefficients
            .first()
            .is_some_and(|c| *c == Element::default())
    }
}

// ============================================================================
// CryptoSerialize/CryptoDeserialize implementations for polynomial types
// ============================================================================

impl CryptoSerialize for PubPoly {
    fn to_bytes(&self) -> Result<Vec<u8>> {
        // Format: num_commits (4 bytes) + commits (each ELEMENT_COMPRESSED_SIZE bytes)
        let mut bytes = Vec::with_capacity(4 + self.commits.len() * ELEMENT_COMPRESSED_SIZE);
        bytes.extend_from_slice(&(self.commits.len() as u32).to_le_bytes());
        for commit in &self.commits {
            commit.write_bytes(&mut bytes)?;
        }
        Ok(bytes)
    }

    fn min_serialized_size() -> usize {
        // Variable size, return minimum (just the length field)
        4
    }
}

impl CryptoDeserialize for PubPoly {
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 4 {
            return Err(CryptoError::DKGError("PubPoly bytes too short".to_string()));
        }

        let num_commits = u32::from_le_bytes(
            bytes[0..4]
                .try_into()
                .map_err(|_| CryptoError::DKGError("Invalid num_commits bytes".to_string()))?,
        ) as usize;
        let expected_len = num_commits
            .checked_mul(ELEMENT_COMPRESSED_SIZE)
            .and_then(|size| size.checked_add(4))
            .ok_or_else(|| CryptoError::DKGError("PubPoly length overflow".into()))?;

        if bytes.len() < expected_len {
            return Err(CryptoError::DKGError(format!(
                "PubPoly bytes too short: expected {}, got {}",
                expected_len,
                bytes.len()
            )));
        }
        if bytes.len() != expected_len {
            return Err(CryptoError::DKGError(format!(
                "PubPoly bytes length mismatch: expected {}, got {}",
                expected_len,
                bytes.len()
            )));
        }

        let mut commits = Vec::with_capacity(num_commits);
        for i in 0..num_commits {
            let start = 4 + i * ELEMENT_COMPRESSED_SIZE;
            let end = start + ELEMENT_COMPRESSED_SIZE;
            let commit = Element::from_bytes(&bytes[start..end])?;
            commits.push(commit);
        }

        Ok(Self { commits })
    }
}

impl CryptoSerialize for PolynomialCommitment {
    fn to_bytes(&self) -> Result<Vec<u8>> {
        // Format: num_coefficients (4 bytes) + coefficients (each ELEMENT_COMPRESSED_SIZE bytes)
        let mut bytes = Vec::with_capacity(4 + self.coefficients.len() * ELEMENT_COMPRESSED_SIZE);
        bytes.extend_from_slice(&(self.coefficients.len() as u32).to_le_bytes());
        for coeff in &self.coefficients {
            coeff.write_bytes(&mut bytes)?;
        }
        Ok(bytes)
    }

    fn min_serialized_size() -> usize {
        // Variable size, return minimum (just the length field)
        4
    }
}

impl CryptoDeserialize for PolynomialCommitment {
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 4 {
            return Err(CryptoError::DKGError(
                "PolynomialCommitment bytes too short".to_string(),
            ));
        }

        let num_coefficients = u32::from_le_bytes(
            bytes[0..4]
                .try_into()
                .map_err(|_| CryptoError::DKGError("Invalid num_coefficients bytes".to_string()))?,
        ) as usize;
        let expected_len = num_coefficients
            .checked_mul(ELEMENT_COMPRESSED_SIZE)
            .and_then(|size| size.checked_add(4))
            .ok_or_else(|| CryptoError::DKGError("PolynomialCommitment length overflow".into()))?;

        if bytes.len() < expected_len {
            return Err(CryptoError::DKGError(format!(
                "PolynomialCommitment bytes too short: expected {}, got {}",
                expected_len,
                bytes.len()
            )));
        }
        if bytes.len() != expected_len {
            return Err(CryptoError::DKGError(format!(
                "PolynomialCommitment bytes length mismatch: expected {}, got {}",
                expected_len,
                bytes.len()
            )));
        }

        let mut coefficients = Vec::with_capacity(num_coefficients);
        for i in 0..num_coefficients {
            let start = 4 + i * ELEMENT_COMPRESSED_SIZE;
            let end = start + ELEMENT_COMPRESSED_SIZE;
            let coeff = Element::from_bytes(&bytes[start..end])?;
            coefficients.push(coeff);
        }

        Ok(Self { coefficients })
    }
}
