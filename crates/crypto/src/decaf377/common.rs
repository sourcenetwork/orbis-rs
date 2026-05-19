use crate::error::{CryptoError, Result};
use crate::helpers::reject_non_canonical;
use crate::r#trait::{
    CryptoDeserialize, CryptoSerialize, PolynomialCommitment as PolynomialCommitmentTrait,
    PubPoly as PubPolyTrait,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use decaf377::{Element, Fr};
use subtle::ConstantTimeEq;

// ============================================================================
// Constants for serialized sizes
// ============================================================================

/// Size of a compressed Element in bytes (decaf377)
pub const ELEMENT_COMPRESSED_SIZE: usize = 32;

/// Size of a compressed Fr scalar in bytes (decaf377)
pub const FR_COMPRESSED_SIZE: usize = 32;

// ============================================================================
// CryptoSerialize/CryptoDeserialize implementations for decaf377 types
// ============================================================================

impl CryptoSerialize for Fr {
    fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::with_capacity(FR_COMPRESSED_SIZE);
        self.serialize_compressed(&mut bytes)?;
        Ok(bytes)
    }

    fn serialized_size() -> usize {
        FR_COMPRESSED_SIZE
    }
}

impl CryptoDeserialize for Fr {
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != FR_COMPRESSED_SIZE {
            return Err(CryptoError::SerializationError(
                ark_serialize::SerializationError::InvalidData,
            ));
        }
        let scalar = Fr::deserialize_compressed(bytes)?;
        reject_non_canonical(&scalar, bytes)?;
        Ok(scalar)
    }
}

impl CryptoSerialize for Element {
    fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::with_capacity(ELEMENT_COMPRESSED_SIZE);
        self.serialize_compressed(&mut bytes)?;
        Ok(bytes)
    }

    fn serialized_size() -> usize {
        ELEMENT_COMPRESSED_SIZE
    }
}

impl CryptoDeserialize for Element {
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != ELEMENT_COMPRESSED_SIZE {
            return Err(CryptoError::SerializationError(
                ark_serialize::SerializationError::InvalidData,
            ));
        }
        let element = Element::deserialize_compressed(bytes)?;
        reject_non_canonical(&element, bytes)?;
        Ok(element)
    }
}

// ============================================================================
// Public polynomial and polynomial commitment types
// ============================================================================

/// Public polynomial for commitments (decaf377)
#[derive(Clone, Debug)]
pub struct PubPoly {
    pub commits: Vec<Element>,
}

impl PubPolyTrait for PubPoly {
    type PublicKey = Element;

    /// Evaluate the public polynomial at index i using Horner's method
    fn eval(&self, i: u32) -> Self::PublicKey {
        if self.commits.is_empty() {
            return Element::default();
        }

        let x = Fr::from(i as u64);
        let mut result = self.commits[0];
        let mut x_power = x;

        for commit in &self.commits[1..] {
            result += *commit * x_power;
            x_power *= x;
        }

        result
    }
}

/// A polynomial commitment (decaf377)
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

        let x_scalar = Fr::from(x as u64);
        let mut result = self.coefficients[0];
        let mut x_power = x_scalar;

        for coeff in &self.coefficients[1..] {
            result += *coeff * x_power;
            x_power *= x_scalar;
        }

        result
    }

    fn verify_share(&self, share_id: u32, share_value: &Fr) -> bool {
        let expected = self.eval(share_id);
        let actual = Element::GENERATOR * share_value;

        // Use constant-time comparison to prevent timing side-channels
        let mut expected_bytes = Vec::new();
        let mut actual_bytes = Vec::new();

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

// ============================================================================
// CryptoSerialize/CryptoDeserialize implementations for polynomial types
// ============================================================================

impl CryptoSerialize for PubPoly {
    fn to_bytes(&self) -> Result<Vec<u8>> {
        // Format: num_commits (4 bytes) + commits (each ELEMENT_COMPRESSED_SIZE bytes)
        let mut bytes = Vec::with_capacity(4 + self.commits.len() * ELEMENT_COMPRESSED_SIZE);
        bytes.extend_from_slice(&(self.commits.len() as u32).to_le_bytes());
        for commit in &self.commits {
            commit.serialize_compressed(&mut bytes)?;
        }
        Ok(bytes)
    }

    fn serialized_size() -> usize {
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
        let expected_len = 4 + num_commits * ELEMENT_COMPRESSED_SIZE;

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
            coeff.serialize_compressed(&mut bytes)?;
        }
        Ok(bytes)
    }

    fn serialized_size() -> usize {
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
        let expected_len = 4 + num_coefficients * ELEMENT_COMPRESSED_SIZE;

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
