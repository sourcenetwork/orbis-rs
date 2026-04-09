//! Test helper for DKG implementations
//!
//! This module provides a generic DKG coordinator that can work with any
//! DKG implementation for testing purposes.

use crate::error::{CryptoError, Result};
use crate::r#trait::{DistributedShare, Dkg, DkgMode, DkgRole, PriShare};
use ark_serialize::CanonicalSerialize;
use std::fmt::Debug;
use subtle::ConstantTimeEq;

/// Trait for DKG nodes that can be used in the test coordinator
///
/// This extends the `Dkg` trait with methods to access node-specific
/// information needed for coordination in tests.
pub trait TestDkgNode: Dkg {
    /// Get the node's ID
    fn id(&self) -> u32;
}

/// Coordinator for running a complete DKG ceremony
///
/// This is a helper struct for testing/simulation. In a real distributed
/// system, there would be no central coordinator.
///
/// The coordinator is generic over any DKG implementation that implements
/// `TestDkgNode`.
pub struct DKGCoordinator<Node: TestDkgNode> {
    nodes: Vec<Node>,
}

impl<Node: TestDkgNode> DKGCoordinator<Node>
where
    Node::PublicKey: CanonicalSerialize + PartialEq + Debug,
    Node::PubPoly: Clone,
    Node::PolynomialCommitment: Clone,
    Node::ShareValue: Clone + zeroize::Zeroize,
{
    /// Create a new DKG coordinator with the specified nodes.
    ///
    /// All nodes are created with `DkgRole::Standard` (Fresh / Refresh modes).
    ///
    /// # Arguments
    /// * `node_factory` - A function that creates a DKG node given (id, threshold, total_nodes, session_id, role)
    /// * `node_count` - Total number of nodes
    /// * `threshold` - Minimum number of nodes needed to reconstruct
    pub fn new<F>(node_factory: F, node_count: usize, threshold: usize) -> Result<Self>
    where
        F: Fn(u32, usize, usize, u64, DkgRole) -> Result<Box<Node>>,
    {
        if node_count == 0 {
            return Err(CryptoError::DKGError(
                "node_count must be greater than 0".to_string(),
            ));
        }
        if threshold == 0 {
            return Err(CryptoError::DKGError(
                "threshold must be greater than 0".to_string(),
            ));
        }
        if threshold > node_count {
            return Err(CryptoError::DKGError(format!(
                "threshold ({}) cannot exceed node_count ({})",
                threshold, node_count
            )));
        }

        use rand_core::{OsRng, RngCore};
        let mut rng = OsRng;
        let mut session_id_bytes = [0u8; 8];
        rng.fill_bytes(&mut session_id_bytes);
        let session_id = u64::from_le_bytes(session_id_bytes);

        let mut nodes = Vec::new();
        for i in 1..=node_count {
            let node = *node_factory(
                i as u32,
                threshold,
                node_count,
                session_id,
                DkgRole::Standard,
            )?;
            nodes.push(node);
        }

        Ok(DKGCoordinator { nodes })
    }

    /// Run the complete DKG protocol using Fresh mode.
    pub fn run_dkg(
        &mut self,
    ) -> Result<(
        Node::PublicKey,
        Vec<PriShare<Node::ShareValue>>,
        Node::PubPoly,
    )> {
        self.run_dkg_with_mode(|_| DkgMode::Fresh)
    }

    /// Run the complete DKG protocol with a caller-supplied mode per node.
    ///
    /// `mode_factory` receives the node ID and returns the `DkgMode` to use.
    /// This enables Refresh (`|_| DkgMode::Refresh`) and reshare ceremonies.
    pub fn run_dkg_with_mode<MF>(
        &mut self,
        mode_factory: MF,
    ) -> Result<(
        Node::PublicKey,
        Vec<PriShare<Node::ShareValue>>,
        Node::PubPoly,
    )>
    where
        MF: Fn(u32) -> DkgMode<Node::ShareValue>,
    {
        // Phase 1: Each node generates their polynomial and commitment
        for node in &mut self.nodes {
            let mode = mode_factory(node.id());
            node.generate_polynomial(mode)?;
        }

        // Broadcast commitments
        let commitments: Vec<(u32, Node::PolynomialCommitment)> = self
            .nodes
            .iter()
            .map(|node| (node.id(), node.commitment().clone()))
            .collect();

        for node in &mut self.nodes {
            for (from_id, commitment) in &commitments {
                if *from_id != node.id() {
                    node.receive_commitment(*from_id, commitment.clone())?;
                }
            }
        }

        // Phase 2: Each node generates shares for all other nodes
        let mut all_shares: Vec<Vec<DistributedShare<Node::ShareValue>>> = Vec::new();
        for node in &self.nodes {
            all_shares.push(node.generate_shares()?);
        }

        // Phase 3: Distribute shares — skip self-shares (own contribution added locally)
        for shares in &all_shares {
            for share in shares {
                if share.from_id != share.to_id {
                    let recipient_id = share.to_id;
                    let recipient_node = self
                        .nodes
                        .iter_mut()
                        .find(|n| n.id() == recipient_id)
                        .ok_or_else(|| {
                            CryptoError::DKGError(format!(
                                "Recipient node {} not found",
                                recipient_id
                            ))
                        })?;
                    recipient_node.receive_share(share.clone())?;
                }
            }
        }

        // Phase 4: Each node computes their final secret share
        let mut secret_shares = Vec::new();
        for node in &self.nodes {
            secret_shares.push(node.compute_secret_share()?);
        }

        // Compute aggregate public key — all nodes must agree
        let aggregate_pk = self.nodes[0].compute_aggregate_public_key()?;

        for node in &self.nodes {
            let pk = node.compute_aggregate_public_key()?;

            let mut pk_bytes = Vec::new();
            let mut aggregate_pk_bytes = Vec::new();
            pk.serialize_compressed(&mut pk_bytes)
                .map_err(|e| CryptoError::DKGError(format!("Serialization error: {}", e)))?;
            aggregate_pk
                .serialize_compressed(&mut aggregate_pk_bytes)
                .map_err(|e| CryptoError::DKGError(format!("Serialization error: {}", e)))?;

            let max_len = pk_bytes.len().max(aggregate_pk_bytes.len());
            let mut pk_padded = vec![0u8; max_len];
            let mut aggregate_pk_padded = vec![0u8; max_len];
            pk_padded[..pk_bytes.len()].copy_from_slice(&pk_bytes);
            aggregate_pk_padded[..aggregate_pk_bytes.len()].copy_from_slice(&aggregate_pk_bytes);

            if pk_padded.ct_ne(&aggregate_pk_padded).into() {
                return Err(CryptoError::DKGError(
                    "Nodes computed different aggregate public keys".to_string(),
                ));
            }
        }

        let pub_poly = self.nodes[0].compute_public_polynomial()?;

        Ok((aggregate_pk, secret_shares, pub_poly))
    }
}

/// Generic test suite for DKG implementations
///
/// These tests can be used with any DKG implementation that implements `TestDkgNode`.
/// Simply call these functions from your implementation's test module.
#[cfg(test)]
pub mod generic_tests {
    use super::*;
    use crate::r#trait::{PolynomialCommitment, PubPoly};

    /// Run a basic DKG test with the given parameters
    pub fn test_dkg_basic<Node, F, Z>(
        node_factory: F,
        node_count: usize,
        threshold: usize,
        check_zero: Option<Z>,
    ) -> Result<()>
    where
        Node: TestDkgNode,
        Node::PublicKey: CanonicalSerialize + PartialEq + Debug,
        Node::PubPoly: Clone,
        Node::PolynomialCommitment: Clone,
        Node::ShareValue: Clone + zeroize::Zeroize,
        F: Fn(u32, usize, usize, u64, DkgRole) -> Result<Box<Node>>,
        Z: Fn(&Node::PublicKey) -> bool,
    {
        let mut coordinator = DKGCoordinator::new(node_factory, node_count, threshold)?;
        let result = coordinator.run_dkg();
        assert!(result.is_ok(), "DKG protocol should complete successfully");

        let (aggregate_pk, shares, _pub_poly) = result.unwrap();

        assert_eq!(
            shares.len(),
            node_count,
            "Should have shares for all {} nodes",
            node_count
        );

        if let Some(is_zero) = check_zero {
            assert!(
                !is_zero(&aggregate_pk),
                "Aggregate public key should not be zero"
            );
        }

        Ok(())
    }

    /// Test that shares match the public polynomial evaluation
    pub fn test_shares_match_pub_poly<Node, F, G>(
        node_factory: F,
        node_count: usize,
        threshold: usize,
        share_to_pubkey: G,
    ) -> Result<()>
    where
        Node: TestDkgNode,
        Node::PublicKey: CanonicalSerialize + PartialEq + Debug,
        Node::PubPoly: Clone + PubPoly<PublicKey = Node::PublicKey>,
        Node::PolynomialCommitment: Clone,
        Node::ShareValue: Clone + zeroize::Zeroize,
        F: Fn(u32, usize, usize, u64, DkgRole) -> Result<Box<Node>>,
        G: Fn(&Node::ShareValue) -> Node::PublicKey,
    {
        let mut coordinator = DKGCoordinator::new(node_factory, node_count, threshold)?;
        let (_aggregate_pk, shares, pub_poly) = coordinator.run_dkg()?;

        for share in &shares {
            let expected = share_to_pubkey(&share.v);
            let actual = pub_poly.eval(share.i);
            assert_eq!(
                expected, actual,
                "Share {} should match public polynomial evaluation at index {}",
                share.i, share.i
            );
        }

        Ok(())
    }

    /// Test DKG with 2-of-3 threshold
    pub fn test_dkg_2_of_3<Node, F, Z>(node_factory: F, check_zero: Option<Z>) -> Result<()>
    where
        Node: TestDkgNode,
        Node::PublicKey: CanonicalSerialize + PartialEq + Debug,
        Node::PubPoly: Clone,
        Node::PolynomialCommitment: Clone,
        Node::ShareValue: Clone + zeroize::Zeroize,
        F: Fn(u32, usize, usize, u64, DkgRole) -> Result<Box<Node>>,
        Z: Fn(&Node::PublicKey) -> bool,
    {
        test_dkg_basic(node_factory, 3, 2, check_zero)
    }

    /// Test DKG with 3-of-5 threshold
    pub fn test_dkg_3_of_5<Node, F, Z>(node_factory: F, check_zero: Option<Z>) -> Result<()>
    where
        Node: TestDkgNode,
        Node::PublicKey: CanonicalSerialize + PartialEq + Debug,
        Node::PubPoly: Clone,
        Node::PolynomialCommitment: Clone,
        Node::ShareValue: Clone + zeroize::Zeroize,
        F: Fn(u32, usize, usize, u64, DkgRole) -> Result<Box<Node>>,
        Z: Fn(&Node::PublicKey) -> bool,
    {
        test_dkg_basic(node_factory, 5, 3, check_zero)
    }

    /// Test polynomial commitment verification
    pub fn test_polynomial_commitment_verification<Node, F, CreateWrong>(
        node_factory: F,
        create_wrong_share: CreateWrong,
    ) -> Result<()>
    where
        Node: TestDkgNode,
        Node::PublicKey: CanonicalSerialize + PartialEq + Debug,
        Node::PubPoly: Clone,
        Node::PolynomialCommitment: Clone,
        Node::ShareValue: Clone + zeroize::Zeroize,
        F: Fn(u32, usize, usize, u64, DkgRole) -> Result<Box<Node>>,
        CreateWrong: Fn() -> Node::ShareValue,
    {
        let mut node = *node_factory(1, 2, 3, 0, DkgRole::Standard)?;
        node.generate_polynomial(DkgMode::Fresh)?;

        let commitment = node.commitment().clone();
        let shares = node.generate_shares()?;
        let test_share = shares
            .first()
            .ok_or_else(|| CryptoError::DKGError("No shares generated".to_string()))?;

        assert!(
            commitment.verify_share(test_share.to_id, &test_share.value),
            "Valid share should verify correctly"
        );

        let wrong_value = create_wrong_share();
        assert!(
            !commitment.verify_share(test_share.to_id, &wrong_value),
            "Wrong share should fail verification"
        );

        Ok(())
    }

    /// Test invalid threshold parameters
    pub fn test_invalid_threshold<Node, F>(node_factory: F) -> Result<()>
    where
        Node: TestDkgNode,
        Node::PublicKey: CanonicalSerialize + PartialEq + Debug,
        Node::PubPoly: Clone,
        Node::PolynomialCommitment: Clone,
        Node::ShareValue: Clone + zeroize::Zeroize,
        F: Fn(u32, usize, usize, u64, DkgRole) -> Result<Box<Node>> + Clone,
    {
        let result = DKGCoordinator::new(node_factory.clone(), 3, 4);
        assert!(
            result.is_err(),
            "Should reject threshold (4) greater than node_count (3)"
        );

        let result = DKGCoordinator::new(node_factory.clone(), 3, 0);
        assert!(result.is_err(), "Should reject threshold of 0");

        let result = DKGCoordinator::new(node_factory, 0, 1);
        assert!(result.is_err(), "Should reject node_count of 0");

        Ok(())
    }

    /// Test that share verification fails with wrong/tampered shares
    pub fn test_share_verification_fails_with_wrong_commitment<Node, F, CreateShare>(
        node_factory: F,
        create_invalid_share: CreateShare,
    ) -> Result<()>
    where
        Node: TestDkgNode,
        Node::PublicKey: CanonicalSerialize + PartialEq + Debug,
        Node::PubPoly: Clone,
        Node::PolynomialCommitment: Clone,
        Node::ShareValue: Clone + zeroize::Zeroize,
        F: Fn(u32, usize, usize, u64, DkgRole) -> Result<Box<Node>> + Clone,
        CreateShare: Fn(u32, u32, u64) -> crate::r#trait::DistributedShare<Node::ShareValue>,
    {
        use rand_core::{OsRng, RngCore};
        let mut rng = OsRng;
        let mut session_id_bytes = [0u8; 8];
        rng.fill_bytes(&mut session_id_bytes);
        let session_id = u64::from_le_bytes(session_id_bytes);

        let mut node1 = *node_factory(1, 2, 3, session_id, DkgRole::Standard)?;
        let mut node2 = *node_factory(2, 2, 3, session_id, DkgRole::Standard)?;

        node1.generate_polynomial(DkgMode::Fresh)?;
        node2.generate_polynomial(DkgMode::Fresh)?;

        node2.receive_commitment(1, node1.commitment().clone())?;

        let shares = node1.generate_shares()?;
        let share_for_node2 = shares
            .iter()
            .find(|s| s.to_id == 2)
            .ok_or_else(|| CryptoError::DKGError("Share for node 2 not found".to_string()))?;

        assert!(
            node2.receive_share(share_for_node2.clone()).is_ok(),
            "Valid share should be accepted"
        );

        let mut node2_fresh = *node_factory(2, 2, 3, session_id, DkgRole::Standard)?;
        node2_fresh.receive_commitment(1, node1.commitment().clone())?;

        let tampered_share = create_invalid_share(1, 2, session_id);
        assert!(
            node2_fresh.receive_share(tampered_share).is_err(),
            "Tampered share should be rejected"
        );

        Ok(())
    }

    // =========================================================================
    // Refresh and Reshare generic tests
    // =========================================================================

    /// Test that a Refresh round preserves the secret (aggregate delta PK = identity).
    ///
    /// After a Refresh DKG, `compute_aggregate_public_key()` returns the sum of all
    /// zero-constant-term polynomial commitments, which is the group identity.
    /// The node layer is responsible for confirming this before applying the delta.
    pub fn test_dkg_refresh<Node, F, Z>(node_factory: F, check_zero: Z) -> Result<()>
    where
        Node: TestDkgNode,
        Node::PublicKey: CanonicalSerialize + PartialEq + Debug,
        Node::PubPoly: Clone,
        Node::PolynomialCommitment: Clone,
        Node::ShareValue: Clone + zeroize::Zeroize,
        F: Fn(u32, usize, usize, u64, DkgRole) -> Result<Box<Node>> + Clone,
        Z: Fn(&Node::PublicKey) -> bool,
    {
        // Fresh DKG first — verify we get a non-zero PK
        let mut fresh_coordinator = DKGCoordinator::new(node_factory.clone(), 3, 2)?;
        let (_old_pk, _old_shares, _) = fresh_coordinator.run_dkg()?;

        // Refresh round — all nodes use Refresh mode
        let mut refresh_coordinator = DKGCoordinator::new(node_factory, 3, 2)?;
        let (delta_pk, delta_shares, _) =
            refresh_coordinator.run_dkg_with_mode(|_| DkgMode::Refresh)?;

        // The aggregate delta PK must be the group identity (zero constant term sum)
        assert!(
            check_zero(&delta_pk),
            "Refresh aggregate delta public key must be the group identity"
        );

        // All nodes should have a delta share
        assert_eq!(delta_shares.len(), 3);

        Ok(())
    }

    /// Test that a same-committee Reshare preserves the aggregate public key.
    ///
    /// All nodes act as `DealerReceiver` (they are in both old and new committee).
    /// After resharing, `compute_aggregate_public_key()` must equal the original PK.
    pub fn test_dkg_reshare_same_committee<Node, F>(node_factory: F) -> Result<()>
    where
        Node: TestDkgNode,
        Node::PublicKey: CanonicalSerialize + PartialEq + Debug,
        Node::PubPoly: Clone + PubPoly<PublicKey = Node::PublicKey>,
        Node::PolynomialCommitment: Clone,
        Node::ShareValue: Clone + zeroize::Zeroize,
        F: Fn(u32, usize, usize, u64, DkgRole) -> Result<Box<Node>> + Clone,
    {
        let n: usize = 3;
        let t: usize = 2;

        // ── Step 1: fresh DKG ──────────────────────────────────────────────
        let mut fresh_coord = DKGCoordinator::new(node_factory.clone(), n, t)?;
        let (old_pk, old_shares, _) = fresh_coord.run_dkg()?;

        let mut old_pk_bytes = Vec::new();
        old_pk
            .serialize_compressed(&mut old_pk_bytes)
            .map_err(|e| CryptoError::DKGError(format!("Serialization error: {}", e)))?;

        // ── Step 2: reshare ceremony (same committee, all DealerReceiver) ───
        use rand_core::{OsRng, RngCore};
        let mut rng = OsRng;
        let mut session_id_bytes = [0u8; 8];
        rng.fill_bytes(&mut session_id_bytes);
        let session_id = u64::from_le_bytes(session_id_bytes);

        let participating_ids: Vec<u32> = (1..=n as u32).collect();

        // Build old_share map: node_id -> share_value
        let mut share_map: std::collections::HashMap<u32, Node::ShareValue> =
            std::collections::HashMap::new();
        for s in &old_shares {
            share_map.insert(s.i, s.v.clone());
        }

        // Create DealerReceiver nodes — total_nodes = n_old, effective will be updated by mode
        let mut reshare_nodes: Vec<Box<Node>> = (1..=n as u32)
            .map(|i| node_factory(i, t, n, session_id, DkgRole::DealerReceiver).map(|n| n))
            .collect::<Result<Vec<_>>>()?;

        // Phase 1: generate resharing polynomials
        for node in &mut reshare_nodes {
            let id = node.node_id();
            let old_share = share_map[&id].clone();
            node.generate_polynomial(DkgMode::Reshare {
                old_share,
                participating_ids: participating_ids.clone(),
                new_threshold: t,
                new_total_nodes: n,
                new_node_id: None,
            })?;
        }

        // Broadcast commitments
        let commitments: Vec<(u32, Node::PolynomialCommitment)> = reshare_nodes
            .iter()
            .map(|node| (node.node_id(), node.commitment().clone()))
            .collect();

        for node in &mut reshare_nodes {
            for (from_id, commitment) in &commitments {
                if *from_id != node.node_id() {
                    node.receive_commitment(*from_id, commitment.clone())?;
                }
            }
        }

        // Phase 2: generate and distribute shares (skip self-shares)
        let mut all_shares: Vec<Vec<DistributedShare<Node::ShareValue>>> = Vec::new();
        for node in &reshare_nodes {
            all_shares.push(node.generate_shares()?);
        }

        for shares in &all_shares {
            for share in shares {
                if share.from_id != share.to_id {
                    let recipient = reshare_nodes
                        .iter_mut()
                        .find(|n| n.node_id() == share.to_id)
                        .ok_or_else(|| {
                            CryptoError::DKGError(format!(
                                "Recipient node {} not found",
                                share.to_id
                            ))
                        })?;
                    recipient.receive_share(share.clone())?;
                }
            }
        }

        // Phase 3: every new-committee node must agree on the same aggregate PK
        // and it must equal the original PK from the fresh DKG.
        for node in &reshare_nodes {
            let pk = node.compute_aggregate_public_key()?;

            let mut pk_bytes = Vec::new();
            pk.serialize_compressed(&mut pk_bytes)
                .map_err(|e| CryptoError::DKGError(format!("Serialization error: {}", e)))?;

            assert_eq!(
                old_pk_bytes,
                pk_bytes,
                "Node {}: aggregate public key must equal the pre-reshare key",
                node.node_id()
            );
        }

        // All nodes can compute their new share
        for node in &reshare_nodes {
            node.compute_secret_share()?;
        }

        Ok(())
    }

    /// Test resharing to a different (larger) committee.
    ///
    /// Old committee: 3 nodes (threshold 2), `Dealer` role.
    /// New committee: 4 nodes (threshold 3), `Receiver` role, with IDs 1–4.
    /// No overlap — old committee IDs are also 1–3 but they are different logical nodes
    /// with separate sessions.  The aggregate public key must be preserved.
    pub fn test_dkg_reshare_different_committee<Node, F>(node_factory: F) -> Result<()>
    where
        Node: TestDkgNode,
        Node::PublicKey: CanonicalSerialize + PartialEq + Debug,
        Node::PubPoly: Clone,
        Node::PolynomialCommitment: Clone,
        Node::ShareValue: Clone + zeroize::Zeroize,
        F: Fn(u32, usize, usize, u64, DkgRole) -> Result<Box<Node>> + Clone,
    {
        let n_old: usize = 3;
        let t_old: usize = 2;
        let n_new: usize = 4;
        let t_new: usize = 3;

        // ── Step 1: fresh DKG on old committee ────────────────────────────
        let mut fresh_coord = DKGCoordinator::new(node_factory.clone(), n_old, t_old)?;
        let (old_pk, old_shares, _) = fresh_coord.run_dkg()?;

        let mut old_pk_bytes = Vec::new();
        old_pk
            .serialize_compressed(&mut old_pk_bytes)
            .map_err(|e| CryptoError::DKGError(format!("Serialization error: {}", e)))?;

        // ── Step 2: reshare to new committee ──────────────────────────────
        use rand_core::{OsRng, RngCore};
        let mut rng = OsRng;
        let mut session_id_bytes = [0u8; 8];
        rng.fill_bytes(&mut session_id_bytes);
        let session_id = u64::from_le_bytes(session_id_bytes);

        let participating_ids: Vec<u32> = (1..=n_old as u32).collect();

        let mut share_map: std::collections::HashMap<u32, Node::ShareValue> =
            std::collections::HashMap::new();
        for s in &old_shares {
            share_map.insert(s.i, s.v.clone());
        }

        // Old dealers — total_nodes = n_old; effective_* updated by Reshare mode
        let mut dealer_nodes: Vec<Box<Node>> = (1..=n_old as u32)
            .map(|i| node_factory(i, t_old, n_old, session_id, DkgRole::Dealer))
            .collect::<Result<Vec<_>>>()?;

        // New receivers — total_nodes = n_old (for from_id validation of incoming shares)
        let mut receiver_nodes: Vec<Box<Node>> = (1..=n_new as u32)
            .map(|i| node_factory(i, t_new, n_old, session_id, DkgRole::Receiver))
            .collect::<Result<Vec<_>>>()?;

        // Dealers generate resharing polynomials
        for node in &mut dealer_nodes {
            let id = node.node_id();
            let old_share = share_map[&id].clone();
            node.generate_polynomial(DkgMode::Reshare {
                old_share,
                participating_ids: participating_ids.clone(),
                new_threshold: t_new,
                new_total_nodes: n_new,
                new_node_id: None,
            })?;
        }

        // Dealers broadcast commitments to receivers
        let dealer_commitments: Vec<(u32, Node::PolynomialCommitment)> = dealer_nodes
            .iter()
            .map(|n| (n.node_id(), n.commitment().clone()))
            .collect();

        for receiver in &mut receiver_nodes {
            for (from_id, commitment) in &dealer_commitments {
                receiver.receive_commitment(*from_id, commitment.clone())?;
            }
        }

        // Dealers generate shares for new committee (to_id 1..=n_new)
        let mut dealer_shares: Vec<Vec<DistributedShare<Node::ShareValue>>> = Vec::new();
        for node in &dealer_nodes {
            dealer_shares.push(node.generate_shares()?);
        }

        // Distribute shares to receivers (no self-share skip needed — different committees)
        for shares in &dealer_shares {
            for share in shares {
                let receiver = receiver_nodes
                    .iter_mut()
                    .find(|n| n.node_id() == share.to_id)
                    .ok_or_else(|| {
                        CryptoError::DKGError(format!("Receiver node {} not found", share.to_id))
                    })?;
                receiver.receive_share(share.clone())?;
            }
        }

        // Every receiver must agree on the same aggregate PK and it must equal old_pk.
        for node in &receiver_nodes {
            let pk = node.compute_aggregate_public_key()?;

            let mut pk_bytes = Vec::new();
            pk.serialize_compressed(&mut pk_bytes)
                .map_err(|e| CryptoError::DKGError(format!("Serialization error: {}", e)))?;

            assert_eq!(
                old_pk_bytes,
                pk_bytes,
                "Receiver {}: aggregate public key must equal the pre-reshare key",
                node.node_id()
            );
        }

        // All receivers can compute their new shares
        for node in &receiver_nodes {
            node.compute_secret_share()?;
        }

        Ok(())
    }
}
