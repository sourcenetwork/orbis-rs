use ark_ff::{One, Zero};
use decaf377::{Element, Fr};
use rand_core::{OsRng, RngCore};
use std::collections::{HashMap, HashSet};

use super::common::{PolynomialCommitment, PubPoly};
use crate::{
    error::{CryptoError, Result},
    r#trait::{
        CryptoDeserialize, CryptoSerialize, DistributedShare, Dkg, DkgMode, DkgRole,
        PolynomialCommitment as PolynomialCommitmentTrait, PriShare,
    },
};

/// Maximum number of nonces to store per node to prevent memory exhaustion
const MAX_NONCES_PER_NODE: usize = 1000;

/// Complete DKG state for a single node (decaf377)
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

    /// New-committee index for DealerReceiver nodes in a reshare.
    /// Used to validate `share.to_id` in `receive_share` (incoming shares are addressed
    /// by new-committee index, not old-committee `self.id`).  `None` → fall back to `self.id`.
    effective_receive_id: Option<u32>,

    // Own polynomial coefficients (kept secret)
    polynomial_coeffs: Vec<Fr>,

    // Own polynomial commitment (publicly broadcast)
    pub commitment: PolynomialCommitment,

    // Shares received from other nodes
    received_shares: HashMap<u32, Fr>, // from_id -> share_value

    // Commitments received from other nodes
    received_commitments: HashMap<u32, PolynomialCommitment>,

    // Old-dealer subset selected for reshare aggregation.
    selected_reshare_participants: Option<Vec<u32>>,

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
            effective_receive_id: None,
            polynomial_coeffs: Vec::new(),
            commitment: PolynomialCommitment {
                coefficients: Vec::new(),
            },
            received_shares: HashMap::new(),
            received_commitments: HashMap::new(),
            selected_reshare_participants: None,
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
                new_node_id,
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
                self.selected_reshare_participants = Some(participating_ids.clone());
                // For DealerReceiver nodes the new-committee index differs from the
                // old-committee self.id; record it so receive_share can validate correctly.
                self.effective_receive_id = new_node_id;
                old_share
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
            .map(|coeff| Element::GENERATOR * coeff)
            .collect();

        Ok(())
    }

    fn select_reshare_participants(&mut self, participant_ids: Vec<u32>) -> Result<()> {
        if !matches!(
            self.role,
            DkgRole::Dealer | DkgRole::Receiver | DkgRole::DealerReceiver
        ) {
            return Err(CryptoError::DKGError(
                "select_reshare_participants is only valid for reshare roles".to_string(),
            ));
        }

        let ids = canonicalize_participant_ids(&participant_ids, self.total_nodes)?;
        if ids.len() < self.threshold {
            return Err(CryptoError::DKGError(format!(
                "Reshare participant set has {} dealers, below threshold {}",
                ids.len(),
                self.threshold
            )));
        }
        self.selected_reshare_participants = Some(ids);
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

        // Verify the share is intended for us.
        // DealerReceiver nodes in a reshare use their new-committee index for incoming
        // shares; effective_receive_id holds that index (set during generate_polynomial).
        let expected_receive_id = self.effective_receive_id.unwrap_or(self.id);
        if share.to_id != expected_receive_id {
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
        let nonces = self.received_nonces.entry(share.from_id).or_default();

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
            .ok_or(CryptoError::CommitmentMissing(share.from_id))?;

        // Verify the share against the commitment (constant-time)
        if !commitment.verify_share(share.to_id, &share.value) {
            self.complaints
                .entry(self.id)
                .or_default()
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

        if self.is_reshare_receiver() {
            let participants = self.reshare_participants()?;
            let receive_id = self.effective_receive_id.unwrap_or(self.id);
            let mut secret_share = Fr::zero();

            for participant_id in &participants {
                let lambda = lagrange_at_zero(*participant_id, &participants)?;
                let share_value = if self.role == DkgRole::DealerReceiver
                    && *participant_id == self.id
                {
                    if self.polynomial_coeffs.is_empty() {
                        return Err(CryptoError::DKGError(
                            "Local polynomial not generated: call generate_polynomial before compute_secret_share".to_string(),
                        ));
                    }
                    self.eval_polynomial(receive_id)
                } else {
                    *self.received_shares.get(participant_id).ok_or_else(|| {
                        CryptoError::DKGError(format!(
                            "Missing reshare share from selected dealer {}",
                            participant_id
                        ))
                    })?
                };
                secret_share += lambda * share_value;
            }

            return Ok(PriShare {
                i: receive_id,
                v: secret_share,
            });
        }

        let expected = self.total_nodes - 1;
        if self.received_shares.len() != expected {
            return Err(CryptoError::DKGError(format!(
                "Missing shares: received {}, expected {}",
                self.received_shares.len(),
                expected
            )));
        }

        if self.polynomial_coeffs.is_empty() {
            return Err(CryptoError::DKGError(
                "Local polynomial not generated: call generate_polynomial before compute_secret_share".to_string(),
            ));
        }

        let mut secret_share = self.eval_polynomial(self.id);
        for share_value in self.received_shares.values() {
            secret_share += share_value;
        }

        Ok(PriShare {
            i: self.id,
            v: secret_share,
        })
    }

    fn compute_aggregate_public_key(&self) -> Result<Self::PublicKey> {
        if self.is_reshare_receiver() {
            let participants = self.reshare_participants()?;
            let mut aggregate_pk = Element::default();

            for participant_id in &participants {
                let lambda = lagrange_at_zero(*participant_id, &participants)?;
                let commitment = self.reshare_commitment_for(*participant_id)?;
                aggregate_pk += commitment.coefficients[0] * lambda;
            }

            return Ok(aggregate_pk);
        }

        let expected = self.total_nodes - 1;
        if self.received_commitments.len() != expected {
            return Err(CryptoError::DKGError(format!(
                "Missing commitments: received {}, expected {}",
                self.received_commitments.len(),
                expected
            )));
        }

        if self.commitment.coefficients.is_empty() {
            return Err(CryptoError::DKGError(
                "Local commitment not generated: call generate_polynomial first".to_string(),
            ));
        }
        let mut aggregate_pk = self.commitment.coefficients[0];

        for commitment in self.received_commitments.values() {
            aggregate_pk += commitment.coefficients[0];
        }

        Ok(aggregate_pk)
    }

    fn get_complaints(&self) -> &HashMap<u32, Vec<u32>> {
        &self.complaints
    }

    fn compute_public_polynomial(&self) -> Result<Self::PubPoly> {
        let aggregated_coeffs = if self.is_reshare_receiver() {
            let participants = self.reshare_participants()?;
            let first = self.reshare_commitment_for(participants[0])?;
            let num_coeffs = first.coefficients.len();
            let mut agg: Vec<Element> = vec![Element::default(); num_coeffs];

            for participant_id in &participants {
                let lambda = lagrange_at_zero(*participant_id, &participants)?;
                let commitment = self.reshare_commitment_for(*participant_id)?;
                if commitment.coefficients.len() != num_coeffs {
                    return Err(CryptoError::DKGError(format!(
                        "Commitment from node {} has inconsistent length: expected {}, got {}",
                        participant_id,
                        num_coeffs,
                        commitment.coefficients.len()
                    )));
                }
                for (i, coeff) in commitment.coefficients.iter().enumerate() {
                    agg[i] += *coeff * lambda;
                }
            }
            agg
        } else {
            let expected = self.total_nodes - 1;
            if self.received_commitments.len() != expected {
                return Err(CryptoError::DKGError(format!(
                    "Missing commitments: received {}, expected {}",
                    self.received_commitments.len(),
                    expected
                )));
            }

            if self.commitment.coefficients.is_empty() {
                return Err(CryptoError::DKGError(
                    "Local commitment not generated: call generate_polynomial first".to_string(),
                ));
            }
            let num_coeffs = self.commitment.coefficients.len();

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

            let mut agg = self.commitment.coefficients.clone();
            for commitment in self.received_commitments.values() {
                for (i, coeff) in commitment.coefficients.iter().enumerate() {
                    agg[i] += coeff;
                }
            }
            agg
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

    fn role(&self) -> DkgRole {
        self.role
    }

    fn combine_pub_poly_bytes(a: &[u8], b: &[u8]) -> Result<Vec<u8>>
    where
        Self: Sized,
    {
        let poly_a = PubPoly::from_bytes(a)?;
        let poly_b = PubPoly::from_bytes(b)?;
        if poly_a.commits.len() != poly_b.commits.len() {
            return Err(CryptoError::DKGError(format!(
                "combine_pub_poly_bytes: length mismatch ({} vs {})",
                poly_a.commits.len(),
                poly_b.commits.len()
            )));
        }
        let combined = PubPoly {
            commits: poly_a
                .commits
                .iter()
                .zip(poly_b.commits.iter())
                .map(|(p, q)| *p + *q)
                .collect(),
        };
        combined.to_bytes()
    }
}

impl Drop for DKGNode {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        for coeff in &mut self.polynomial_coeffs {
            coeff.zeroize();
        }
        for val in self.received_shares.values_mut() {
            val.zeroize();
        }
    }
}

impl DKGNode {
    fn is_reshare_receiver(&self) -> bool {
        matches!(self.role, DkgRole::Receiver | DkgRole::DealerReceiver)
    }

    fn reshare_participants(&self) -> Result<Vec<u32>> {
        if let Some(ids) = &self.selected_reshare_participants {
            return canonicalize_participant_ids(ids, self.total_nodes);
        }

        Err(CryptoError::DKGError(
            "Reshare participant set not yet selected — call select_reshare_participants first"
                .to_string(),
        ))
    }

    fn reshare_commitment_for(&self, participant_id: u32) -> Result<&PolynomialCommitment> {
        if self.role == DkgRole::DealerReceiver && participant_id == self.id {
            if self.commitment.coefficients.is_empty() {
                return Err(CryptoError::DKGError(
                    "Local commitment not generated: call generate_polynomial first".to_string(),
                ));
            }
            Ok(&self.commitment)
        } else {
            self.received_commitments
                .get(&participant_id)
                .ok_or_else(|| {
                    CryptoError::DKGError(format!(
                        "Missing commitment from selected dealer {}",
                        participant_id
                    ))
                })
        }
    }

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

fn canonicalize_participant_ids(participant_ids: &[u32], total_nodes: usize) -> Result<Vec<u32>> {
    if participant_ids.is_empty() {
        return Err(CryptoError::DKGError(
            "Reshare participant set cannot be empty".to_string(),
        ));
    }

    let mut ids = participant_ids.to_vec();
    ids.sort_unstable();
    ids.dedup();
    if ids.len() != participant_ids.len() {
        return Err(CryptoError::DKGError(
            "Reshare participant set contains duplicates".to_string(),
        ));
    }
    for id in &ids {
        if *id == 0 || *id > total_nodes as u32 {
            return Err(CryptoError::DKGError(format!(
                "Invalid reshare participant id {} (must be between 1 and {})",
                id, total_nodes
            )));
        }
    }

    Ok(ids)
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
