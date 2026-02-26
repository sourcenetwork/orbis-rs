use ark_ff::Zero;
use decaf377::{Element, Fr};
use rand_core::{OsRng, RngCore};
use std::collections::{HashMap, HashSet};

use super::common::{PolynomialCommitment, PubPoly};
use crate::{
    error::{CryptoError, Result},
    r#trait::{DistributedShare, Dkg, PolynomialCommitment as PolynomialCommitmentTrait, PriShare},
};

/// Maximum number of nonces to store per node to prevent memory exhaustion
const MAX_NONCES_PER_NODE: usize = 1000;

/// Complete DKG state for a single node (decaf377)
#[derive(Clone, Debug)]
pub struct DKGNode {
    pub id: u32,
    pub threshold: usize,
    pub total_nodes: usize,

    // Own polynomial coefficients (kept secret)
    polynomial_coeffs: Vec<Fr>,

    // Own polynomial commitment (publicly broadcast)
    pub commitment: PolynomialCommitment,

    // Shares received from other nodes
    received_shares: HashMap<u32, Fr>, // from_id -> share_value

    // Commitments received from other nodes
    received_commitments: HashMap<u32, PolynomialCommitment>,

    // Session ID for this DKG run (prevents replay attacks)
    pub session_id: u64,

    // Track received nonces to prevent replay (HashSet for O(1) lookup)
    received_nonces: HashMap<u32, HashSet<[u8; 16]>>, // from_id -> set of nonces

    // Track complaints about malicious nodes
    complaints: HashMap<u32, Vec<u32>>, // complainer_id -> list of accused_ids
}

impl Dkg for DKGNode {
    type ShareValue = Fr;
    type PublicKey = Element;
    type PubPoly = PubPoly;
    type PolynomialCommitment = PolynomialCommitment;

    fn new(id: u32, threshold: usize, total_nodes: usize, session_id: u64) -> Result<Box<Self>> {
        if id == 0 || id > total_nodes as u32 {
            return Err(CryptoError::DKGError(format!(
                "Invalid node id: {} (must be between 1 and {})",
                id, total_nodes
            )));
        }

        if threshold > total_nodes {
            return Err(CryptoError::DKGError(
                "Threshold cannot exceed total nodes".to_string(),
            ));
        }

        if threshold == 0 {
            return Err(CryptoError::DKGError(
                "Threshold must be at least 1".to_string(),
            ));
        }

        Ok(Box::new(DKGNode {
            id,
            threshold,
            total_nodes,
            polynomial_coeffs: Vec::new(),
            commitment: PolynomialCommitment {
                coefficients: Vec::new(),
            },
            received_shares: HashMap::new(),
            received_commitments: HashMap::new(),
            session_id,
            received_nonces: HashMap::new(),
            complaints: HashMap::new(),
        }))
    }

    fn generate_polynomial(&mut self) -> Result<()> {
        let mut rng = OsRng;

        // Generate random polynomial coefficients
        // Polynomial is of degree (threshold - 1), so we need threshold coefficients
        self.polynomial_coeffs = (0..self.threshold).map(|_| Fr::rand(&mut rng)).collect();

        // Create commitments: C_i = a_i * G
        self.commitment.coefficients = self
            .polynomial_coeffs
            .iter()
            .map(|coeff| Element::GENERATOR * coeff)
            .collect();

        Ok(())
    }

    fn generate_shares(&self) -> Result<Vec<DistributedShare<Self::ShareValue>>> {
        if self.polynomial_coeffs.is_empty() {
            return Err(CryptoError::DKGError(
                "Must call generate_polynomial first".to_string(),
            ));
        }

        let mut rng = OsRng;
        let mut shares = Vec::new();

        for to_id in 1..=self.total_nodes as u32 {
            let share_value = self.eval_polynomial(to_id);

            // Generate nonce for replay protection
            let mut nonce = [0u8; 16];
            rng.fill_bytes(&mut nonce);

            shares.push(DistributedShare {
                from_id: self.id,
                to_id,
                value: share_value,
                nonce,
                session_id: self.session_id,
            });
        }

        Ok(shares)
    }

    fn receive_share(&mut self, share: DistributedShare<Self::ShareValue>) -> Result<()> {
        // Validate from_id is in the expected participant set (1..=total_nodes, not self)
        if share.from_id == 0 || share.from_id > self.total_nodes as u32 {
            return Err(CryptoError::DKGError(format!(
                "Invalid from_id: {} (must be between 1 and {})",
                share.from_id, self.total_nodes
            )));
        }
        if share.from_id == self.id {
            return Err(CryptoError::DKGError(
                "Invalid from_id: cannot receive share from self".to_string(),
            ));
        }

        // Verify the share is intended for us
        if share.to_id != self.id {
            return Err(CryptoError::DKGError(
                "Share not intended for this node".to_string(),
            ));
        }

        // Replay protection: Check session ID
        if share.session_id != self.session_id {
            return Err(CryptoError::DKGError(
                "Share from different session - possible replay attack".to_string(),
            ));
        }

        // One accepted share per sender per session
        if self.received_shares.contains_key(&share.from_id) {
            return Err(CryptoError::DKGError(format!(
                "Duplicate share from node {}",
                share.from_id
            )));
        }

        // Replay protection: Check if nonce was already used
        let nonces = self
            .received_nonces
            .entry(share.from_id)
            .or_insert_with(HashSet::new);

        // Limit nonces per node to prevent memory exhaustion
        if nonces.len() >= MAX_NONCES_PER_NODE {
            return Err(CryptoError::DKGError(
                "Nonce limit exceeded - possible DoS attack".to_string(),
            ));
        }

        if nonces.contains(&share.nonce) {
            return Err(CryptoError::DKGError(
                "Duplicate nonce detected - possible replay attack".to_string(),
            ));
        }

        // Get the commitment from the sender
        let commitment = self
            .received_commitments
            .get(&share.from_id)
            .ok_or_else(|| {
                CryptoError::DKGError(format!(
                    "No commitment received from node {}",
                    share.from_id
                ))
            })?;

        // Verify the share against the commitment (constant-time)
        if !commitment.verify_share(share.to_id, &share.value) {
            // Record complaint about malicious node
            self.complaints
                .entry(self.id)
                .or_insert_with(Vec::new)
                .push(share.from_id);

            return Err(CryptoError::DKGError(
                "Share verification failed".to_string(),
            ));
        }

        // Store the nonce to prevent replay
        nonces.insert(share.nonce);

        // Store the verified share
        self.received_shares.insert(share.from_id, share.value);

        Ok(())
    }

    fn receive_commitment(&mut self, from_id: u32, commitment: PolynomialCommitment) -> Result<()> {
        if from_id == 0 || from_id > self.total_nodes as u32 {
            return Err(CryptoError::DKGError(format!(
                "Invalid node id: {}",
                from_id
            )));
        }

        if from_id == self.id {
            return Err(CryptoError::DKGError(
                "Cannot receive commitment from self".to_string(),
            ));
        }

        if commitment.coefficients.len() != self.threshold {
            return Err(CryptoError::DKGError(format!(
                "Invalid commitment length: expected {}, got {}",
                self.threshold,
                commitment.coefficients.len()
            )));
        }

        self.received_commitments.insert(from_id, commitment);
        Ok(())
    }

    fn compute_secret_share(&self) -> Result<PriShare<Self::ShareValue>> {
        // Verify local polynomial was generated
        if self.polynomial_coeffs.is_empty() {
            return Err(CryptoError::DKGError(
                "Local polynomial not generated: call generate_polynomial before compute_secret_share".to_string(),
            ));
        }

        // Verify we have received shares from all OTHER nodes
        if self.received_shares.len() != self.total_nodes - 1 {
            return Err(CryptoError::DKGError(format!(
                "Missing shares: received {}, expected {}",
                self.received_shares.len(),
                self.total_nodes - 1
            )));
        }

        // Sum all received shares plus our own share
        let mut secret_share = self.eval_polynomial(self.id); // Own share

        for (_, share_value) in &self.received_shares {
            secret_share += share_value;
        }

        Ok(PriShare {
            i: self.id,
            v: secret_share,
        })
    }

    fn compute_aggregate_public_key(&self) -> Result<Self::PublicKey> {
        // Verify local commitment was generated
        if self.commitment.coefficients.is_empty() {
            return Err(CryptoError::DKGError(
                "Local commitment not generated: call generate_polynomial before compute_aggregate_public_key".to_string(),
            ));
        }

        // Verify we have received commitments from all OTHER nodes
        if self.received_commitments.len() != self.total_nodes - 1 {
            return Err(CryptoError::DKGError(format!(
                "Missing commitments: received {}, expected {}",
                self.received_commitments.len(),
                self.total_nodes - 1
            )));
        }

        // Sum all constant terms (first coefficient of each polynomial)
        // Start with our own commitment
        let mut aggregate_pk = self.commitment.coefficients[0];

        for (_, commitment) in &self.received_commitments {
            aggregate_pk += commitment.coefficients[0];
        }

        // Validate aggregate key is not zero
        if aggregate_pk == Element::default() {
            return Err(CryptoError::DKGError(
                "Aggregate public key is zero - this should not happen".to_string(),
            ));
        }

        Ok(aggregate_pk)
    }

    fn get_complaints(&self) -> &HashMap<u32, Vec<u32>> {
        &self.complaints
    }

    fn compute_public_polynomial(&self) -> Result<Self::PubPoly> {
        // Verify local commitment was generated
        if self.commitment.coefficients.is_empty() {
            return Err(CryptoError::DKGError(
                "Local commitment not generated: call generate_polynomial before compute_public_polynomial".to_string(),
            ));
        }

        // Verify we have received commitments from all OTHER nodes
        if self.received_commitments.len() != self.total_nodes - 1 {
            return Err(CryptoError::DKGError(format!(
                "Missing commitments: received {}, expected {}",
                self.received_commitments.len(),
                self.total_nodes - 1
            )));
        }

        // Initialize with own commitment
        let mut aggregated_coeffs = self.commitment.coefficients.clone();

        // Add all other commitments
        for (_, commitment) in &self.received_commitments {
            for (i, coeff) in commitment.coefficients.iter().enumerate() {
                aggregated_coeffs[i] += coeff;
            }
        }

        Ok(PubPoly {
            commits: aggregated_coeffs,
        })
    }

    fn node_id(&self) -> u32 {
        self.id
    }

    fn threshold(&self) -> usize {
        self.threshold
    }

    fn total_nodes(&self) -> usize {
        self.total_nodes
    }

    fn commitment(&self) -> &Self::PolynomialCommitment {
        &self.commitment
    }
}

impl DKGNode {
    pub fn eval_polynomial(&self, x: u32) -> Fr {
        if self.polynomial_coeffs.is_empty() {
            return Fr::zero();
        }

        let x_scalar = Fr::from(x as u64);
        let mut result = self.polynomial_coeffs[0];
        let mut x_power = x_scalar;

        for coeff in &self.polynomial_coeffs[1..] {
            result += *coeff * x_power;
            x_power *= x_scalar;
        }

        result
    }
}

#[cfg(any(test, feature = "test-helpers"))]
impl crate::test_helper::TestDkgNode for DKGNode {
    fn id(&self) -> u32 {
        self.id
    }
}
