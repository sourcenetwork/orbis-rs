use ark_bls12_381::{Fr, G1Affine, G1Projective};
use ark_ec::{AffineRepr, Group};
use ark_ff::{Field, One, Zero};
use ark_std::UniformRand;
use rand_core::{OsRng, RngCore};
use std::collections::{HashMap, HashSet};

use super::common::{PolynomialCommitment, PubPoly};
use crate::{
    error::{CryptoError, Result},
    r#trait::{
        DistributedShare, Dkg, DkgMode, DkgRole, PolynomialCommitment as PolynomialCommitmentTrait,
        PriShare,
    },
};

/// Maximum number of nonces to store per node to prevent memory exhaustion
const MAX_NONCES_PER_NODE: usize = 1000;

/// Complete DKG state for a single node
#[derive(Clone, Debug)]
pub struct DKGNode {
    pub id: u32,
    pub threshold: usize,
    pub total_nodes: usize,

    /// Role of this node in the protocol.
    pub role: DkgRole,

    /// Effective total nodes for share generation.
    /// For Reshare dealers this is `new_total_nodes`; otherwise equals `total_nodes`.
    effective_total_nodes: usize,

    /// Effective threshold for polynomial degree.
    /// For Reshare dealers this is `new_threshold`; otherwise equals `threshold`.
    effective_threshold: usize,

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
    type PublicKey = G1Affine;
    type PubPoly = PubPoly;
    type PolynomialCommitment = PolynomialCommitment;

    fn new(
        id: u32,
        threshold: usize,
        total_nodes: usize,
        session_id: u64,
        role: DkgRole,
    ) -> Result<Box<Self>> {
        if id == 0 {
            return Err(CryptoError::DKGError("Invalid node id: 0".to_string()));
        }

        // For Receiver nodes, `total_nodes` is the *old* committee size (used for from_id
        // validation of incoming shares), so the Receiver's own id may exceed it.
        if role != DkgRole::Receiver && id > total_nodes as u32 {
            return Err(CryptoError::DKGError(format!(
                "Invalid node id: {} (must be between 1 and {})",
                id, total_nodes
            )));
        }

        // For Receiver nodes, threshold refers to the new committee and may exceed total_nodes
        // (which is the old committee size), so skip this check.
        if role != DkgRole::Receiver && threshold > total_nodes {
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
            role,
            effective_total_nodes: total_nodes,
            effective_threshold: threshold,
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

    fn generate_polynomial(&mut self, mode: DkgMode<Self::ShareValue>) -> Result<()> {
        if self.role == DkgRole::Receiver {
            return Err(CryptoError::DKGError(
                "Receiver role cannot generate a polynomial".to_string(),
            ));
        }

        let mut rng = OsRng;

        let constant_term = match mode {
            DkgMode::Fresh => Fr::rand(&mut rng),
            DkgMode::Refresh => Fr::zero(),
            DkgMode::Reshare {
                old_share,
                participating_ids,
                new_threshold,
                new_total_nodes,
            } => {
                if !participating_ids.contains(&self.id) {
                    return Err(CryptoError::DKGError(
                        "Node not in participating_ids for resharing".to_string(),
                    ));
                }
                if participating_ids.len() < self.threshold {
                    return Err(CryptoError::DKGError(format!(
                        "Reshare requires at least {} participants (threshold), got {}",
                        self.threshold,
                        participating_ids.len()
                    )));
                }
                if new_threshold == 0 || new_threshold > new_total_nodes {
                    return Err(CryptoError::DKGError(format!(
                        "Invalid new threshold {} for new committee of size {}",
                        new_threshold, new_total_nodes
                    )));
                }
                self.effective_threshold = new_threshold;
                self.effective_total_nodes = new_total_nodes;
                lagrange_at_zero(self.id, &participating_ids)? * old_share
            }
        };

        // Polynomial degree is (effective_threshold - 1), so we need effective_threshold coeffs.
        // Index 0 is the constant term (fixed above); the rest are random.
        let mut coeffs = Vec::with_capacity(self.effective_threshold);
        coeffs.push(constant_term);
        for _ in 1..self.effective_threshold {
            coeffs.push(Fr::rand(&mut rng));
        }

        self.polynomial_coeffs = coeffs;

        // Commit: C_i = a_i * G
        self.commitment.coefficients = self
            .polynomial_coeffs
            .iter()
            .map(|coeff| (G1Projective::generator() * coeff).into())
            .collect();

        Ok(())
    }

    fn generate_shares(&self) -> Result<Vec<DistributedShare<Self::ShareValue>>> {
        if self.role == DkgRole::Receiver {
            return Err(CryptoError::DKGError(
                "Receiver role cannot generate shares".to_string(),
            ));
        }

        if self.polynomial_coeffs.is_empty() {
            return Err(CryptoError::DKGError(
                "Must call generate_polynomial first".to_string(),
            ));
        }

        let mut rng = OsRng;
        let mut shares = Vec::new();

        for to_id in 1..=self.effective_total_nodes as u32 {
            let share_value = self.eval_polynomial(to_id);

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
        if self.role == DkgRole::Dealer {
            return Err(CryptoError::DKGError(
                "Dealer role does not receive shares".to_string(),
            ));
        }

        // Validate from_id is in the expected sender set (old committee: 1..=total_nodes)
        if share.from_id == 0 || share.from_id > self.total_nodes as u32 {
            return Err(CryptoError::DKGError(format!(
                "Invalid from_id: {} (must be between 1 and {})",
                share.from_id, self.total_nodes
            )));
        }

        // DealerReceiver and Standard nodes don't receive shares from themselves
        if matches!(self.role, DkgRole::Standard | DkgRole::DealerReceiver)
            && share.from_id == self.id
        {
            return Err(CryptoError::DKGError(
                "Invalid from_id: cannot receive share from self".to_string(),
            ));
        }

        // One accepted share per sender per session
        if self.received_shares.contains_key(&share.from_id) {
            return Err(CryptoError::DKGError(format!(
                "Duplicate share from node {}",
                share.from_id
            )));
        }

        // Verify the share is intended for us
        if share.to_id != self.id {
            return Err(CryptoError::DKGError(
                "Share not intended for this node".to_string(),
            ));
        }

        // Replay protection: check session ID
        if share.session_id != self.session_id {
            return Err(CryptoError::DKGError(
                "Share from different session - possible replay attack".to_string(),
            ));
        }

        // Replay protection: check nonce
        let nonces = self
            .received_nonces
            .entry(share.from_id)
            .or_insert_with(HashSet::new);

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
            self.complaints
                .entry(self.id)
                .or_insert_with(Vec::new)
                .push(share.from_id);

            return Err(CryptoError::DKGError(
                "Share verification failed".to_string(),
            ));
        }

        nonces.insert(share.nonce);
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

        // Standard and DealerReceiver don't receive their own commitment
        if matches!(self.role, DkgRole::Standard | DkgRole::DealerReceiver) && from_id == self.id {
            return Err(CryptoError::DKGError(
                "Cannot receive commitment from self".to_string(),
            ));
        }

        if commitment.coefficients.is_empty() {
            return Err(CryptoError::DKGError(
                "Commitment has no coefficients".to_string(),
            ));
        }

        if self.received_commitments.contains_key(&from_id) {
            return Err(CryptoError::DKGError(format!(
                "Duplicate commitment from node {}",
                from_id
            )));
        }

        self.received_commitments.insert(from_id, commitment);
        Ok(())
    }

    fn compute_secret_share(&self) -> Result<PriShare<Self::ShareValue>> {
        if self.role == DkgRole::Dealer {
            return Err(CryptoError::DKGError(
                "Dealer role does not compute a secret share".to_string(),
            ));
        }

        // Receivers get all shares from the old committee (total_nodes shares).
        // Standard and DealerReceiver get shares from everyone else (total_nodes - 1).
        let expected = match self.role {
            DkgRole::Receiver => self.total_nodes,
            _ => self.total_nodes - 1,
        };

        if self.received_shares.len() != expected {
            return Err(CryptoError::DKGError(format!(
                "Missing shares: received {}, expected {}",
                self.received_shares.len(),
                expected
            )));
        }

        // Receivers have no own polynomial; Standard and DealerReceiver add their own eval.
        let mut secret_share = if self.role == DkgRole::Receiver {
            Fr::zero()
        } else {
            if self.polynomial_coeffs.is_empty() {
                return Err(CryptoError::DKGError(
                    "Local polynomial not generated: call generate_polynomial before compute_secret_share".to_string(),
                ));
            }
            self.eval_polynomial(self.id)
        };

        for (_, share_value) in &self.received_shares {
            secret_share += share_value;
        }

        Ok(PriShare {
            i: self.id,
            v: secret_share,
        })
    }

    fn compute_aggregate_public_key(&self) -> Result<Self::PublicKey> {
        let expected = match self.role {
            DkgRole::Receiver => self.total_nodes,
            _ => self.total_nodes - 1,
        };

        if self.received_commitments.len() != expected {
            return Err(CryptoError::DKGError(format!(
                "Missing commitments: received {}, expected {}",
                self.received_commitments.len(),
                expected
            )));
        }

        // Receivers have no own commitment; start from identity.
        let mut aggregate_pk = if self.role == DkgRole::Receiver {
            G1Projective::zero()
        } else {
            if self.commitment.coefficients.is_empty() {
                return Err(CryptoError::DKGError(
                    "Local commitment not generated: call generate_polynomial first".to_string(),
                ));
            }
            G1Projective::from(self.commitment.coefficients[0])
        };

        for (_, commitment) in &self.received_commitments {
            aggregate_pk += G1Projective::from(commitment.coefficients[0]);
        }

        Ok(aggregate_pk.into())
    }

    fn get_complaints(&self) -> &HashMap<u32, Vec<u32>> {
        &self.complaints
    }

    fn compute_public_polynomial(&self) -> Result<Self::PubPoly> {
        let expected = match self.role {
            DkgRole::Receiver => self.total_nodes,
            _ => self.total_nodes - 1,
        };

        if self.received_commitments.len() != expected {
            return Err(CryptoError::DKGError(format!(
                "Missing commitments: received {}, expected {}",
                self.received_commitments.len(),
                expected
            )));
        }

        let aggregated_coeffs = if self.role == DkgRole::Receiver {
            // No own polynomial — aggregate only received commitments.
            // Infer polynomial length from first received commitment.
            let first = self
                .received_commitments
                .values()
                .next()
                .ok_or_else(|| CryptoError::DKGError("No commitments received".to_string()))?;
            let num_coeffs = first.coefficients.len();

            // All commitments must have the same length (same polynomial degree).
            for (id, commitment) in &self.received_commitments {
                if commitment.coefficients.len() != num_coeffs {
                    return Err(CryptoError::DKGError(format!(
                        "Commitment from node {} has inconsistent length: expected {}, got {}",
                        id,
                        num_coeffs,
                        commitment.coefficients.len()
                    )));
                }
            }

            // Accumulate in projective coordinates; convert to affine once at the end.
            let mut agg: Vec<G1Projective> = vec![G1Projective::zero(); num_coeffs];
            for (_, commitment) in &self.received_commitments {
                for (i, coeff) in commitment.coefficients.iter().enumerate() {
                    agg[i] += G1Projective::from(*coeff);
                }
            }
            agg.into_iter().map(Into::into).collect()
        } else {
            if self.commitment.coefficients.is_empty() {
                return Err(CryptoError::DKGError(
                    "Local commitment not generated: call generate_polynomial first".to_string(),
                ));
            }
            let num_coeffs = self.commitment.coefficients.len();

            // All received commitments must match our own polynomial degree.
            for (id, commitment) in &self.received_commitments {
                if commitment.coefficients.len() != num_coeffs {
                    return Err(CryptoError::DKGError(format!(
                        "Commitment from node {} has inconsistent length: expected {}, got {}",
                        id,
                        num_coeffs,
                        commitment.coefficients.len()
                    )));
                }
            }

            // Accumulate in projective coordinates; convert to affine once at the end.
            let mut agg: Vec<G1Projective> = self
                .commitment
                .coefficients
                .iter()
                .map(|c| G1Projective::from(*c))
                .collect();
            for (_, commitment) in &self.received_commitments {
                for (i, coeff) in commitment.coefficients.iter().enumerate() {
                    agg[i] += G1Projective::from(*coeff);
                }
            }
            agg.into_iter().map(Into::into).collect()
        };

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

/// Compute the Lagrange basis coefficient at x=0 for participant `id` within `participating_ids`.
///
/// λᵢ(0) = ∏_{j ∈ T, j ≠ i} (0 - j) / (i - j)
///
/// The IDs are sorted before computation to ensure a canonical ordering.
fn lagrange_at_zero(id: u32, participating_ids: &[u32]) -> Result<Fr> {
    let mut ids = participating_ids.to_vec();
    ids.sort_unstable();
    ids.dedup();
    if ids.len() != participating_ids.len() {
        return Err(CryptoError::DKGError(
            "participating_ids contains duplicates".to_string(),
        ));
    }

    let mut num = Fr::one();
    let mut den = Fr::one();
    let i_fr = Fr::from(id as u64);

    for &j_raw in &ids {
        if j_raw == id {
            continue;
        }
        let j_fr = Fr::from(j_raw as u64);
        num *= -j_fr; // (0 - j)
        den *= i_fr - j_fr; // (i - j)
    }

    let inv = den.inverse().ok_or_else(|| {
        CryptoError::DKGError(
            "Lagrange denominator is zero — check participating_ids for duplicates".to_string(),
        )
    })?;

    Ok(num * inv)
}

#[cfg(any(test, feature = "test-helpers"))]
impl crate::test_helper::TestDkgNode for DKGNode {
    fn id(&self) -> u32 {
        self.id
    }
}
