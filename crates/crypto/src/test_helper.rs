//! Test helper for DKG implementations
//!
//! This module provides a generic DKG coordinator that can work with any
//! DKG implementation for testing purposes.

use crate::error::{CryptoError, Result};
use crate::r#trait::{DistributedShare, Dkg, PriShare};
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

    /// Get the node's commitment (must be called after `generate_polynomial`)
    fn commitment(&self) -> Self::PolynomialCommitment;

    /// Set the session ID for this node
    fn set_session_id(&mut self, session_id: u64);
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
    Node::ShareValue: Clone,
{
    /// Create a new DKG coordinator with the specified nodes
    ///
    /// # Arguments
    /// * `node_factory` - A function that creates a DKG node given (id, threshold, total_nodes)
    /// * `node_count` - Total number of nodes
    /// * `threshold` - Minimum number of nodes needed to reconstruct
    ///
    /// Note: This coordinator is for testing/simulation only.
    /// In a real distributed system, there would be no central coordinator.
    pub fn new<F>(node_factory: F, node_count: usize, threshold: usize) -> Result<Self>
    where
        F: Fn(u32, usize, usize) -> Result<Box<Node>>,
    {
        // Validate parameters
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

        let mut nodes = Vec::new();

        // Generate a shared session ID for all nodes (in real system, this would be agreed upon)
        use rand_core::{OsRng, RngCore};
        let mut rng = OsRng;
        let mut session_id_bytes = [0u8; 8];
        rng.fill_bytes(&mut session_id_bytes);
        let session_id = u64::from_le_bytes(session_id_bytes);

        for i in 1..=node_count {
            let mut node = *node_factory(i as u32, threshold, node_count)?;
            // Set the same session ID for all nodes (simulation only)
            // In real system, nodes would agree on session ID through consensus
            node.set_session_id(session_id);
            nodes.push(node);
        }

        Ok(DKGCoordinator { nodes })
    }

    /// Run the complete DKG protocol
    ///
    /// Returns the aggregate public key and the secret shares for each node
    pub fn run_dkg(
        &mut self,
    ) -> Result<(
        Node::PublicKey,
        Vec<PriShare<Node::ShareValue>>,
        Node::PubPoly,
    )> {
        // Phase 1: Each node generates their polynomial and commitment
        for node in &mut self.nodes {
            node.generate_polynomial()?;
        }

        // Broadcast commitments (including to self)
        let commitments: Vec<(u32, Node::PolynomialCommitment)> = self
            .nodes
            .iter()
            .map(|node| (node.id(), node.commitment()))
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

        // Phase 3: Distribute shares (in real system, these would be sent securely)
        // Only send shares to OTHER nodes (not to self)
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

        // Compute aggregate public key (all nodes should get the same result)
        let aggregate_pk = self.nodes[0].compute_aggregate_public_key()?;

        // Verify all nodes computed the same aggregate public key using constant-time comparison
        for node in &self.nodes {
            let pk = node.compute_aggregate_public_key()?;

            // Constant-time comparison
            let mut pk_bytes = Vec::new();
            let mut aggregate_pk_bytes = Vec::new();
            pk.serialize_compressed(&mut pk_bytes)
                .map_err(|e| CryptoError::DKGError(format!("Serialization error: {}", e)))?;
            aggregate_pk
                .serialize_compressed(&mut aggregate_pk_bytes)
                .map_err(|e| CryptoError::DKGError(format!("Serialization error: {}", e)))?;

            // Pad to same length
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

        // Validate aggregate public key is not zero
        // Note: We can't use == for generic PublicKey, so we'll skip this check
        // Individual implementations can add this validation if needed

        // Compute public polynomial
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
    ///
    /// # Arguments
    /// * `node_factory` - Function that creates a DKG node given (id, threshold, total_nodes)
    /// * `node_count` - Total number of nodes
    /// * `threshold` - Minimum number of nodes needed to reconstruct
    /// * `check_zero` - Optional function to check if a public key is zero (implementation-specific)
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
        Node::ShareValue: Clone,
        F: Fn(u32, usize, usize) -> Result<Box<Node>>,
        Z: Fn(&Node::PublicKey) -> bool,
    {
        let mut coordinator = DKGCoordinator::new(node_factory, node_count, threshold)?;

        let result = coordinator.run_dkg();
        assert!(result.is_ok(), "DKG protocol should complete successfully");

        let (aggregate_pk, shares, _pub_poly) = result.unwrap();

        // Verify we got shares for all nodes
        assert_eq!(
            shares.len(),
            node_count,
            "Should have shares for all {} nodes",
            node_count
        );

        // Verify aggregate public key is not zero (if zero check provided)
        if let Some(is_zero) = check_zero {
            assert!(
                !is_zero(&aggregate_pk),
                "Aggregate public key should not be zero"
            );
        }

        Ok(())
    }

    /// Test that shares match the public polynomial evaluation
    ///
    /// This verifies that each node's secret share corresponds to the correct
    /// point on the public polynomial.
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
        Node::ShareValue: Clone,
        F: Fn(u32, usize, usize) -> Result<Box<Node>>,
        G: Fn(&Node::ShareValue) -> Node::PublicKey,
    {
        let mut coordinator = DKGCoordinator::new(node_factory, node_count, threshold)?;

        let (_aggregate_pk, shares, pub_poly) = coordinator.run_dkg()?;

        // Verify shares match the public polynomial
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
    ///
    /// This is a common test case: 3 nodes with threshold 2.
    pub fn test_dkg_2_of_3<Node, F, Z>(
        node_factory: F,
        check_zero: Option<Z>,
    ) -> Result<()>
    where
        Node: TestDkgNode,
        Node::PublicKey: CanonicalSerialize + PartialEq + Debug,
        Node::PubPoly: Clone,
        Node::PolynomialCommitment: Clone,
        Node::ShareValue: Clone,
        F: Fn(u32, usize, usize) -> Result<Box<Node>>,
        Z: Fn(&Node::PublicKey) -> bool,
    {
        test_dkg_basic(node_factory, 3, 2, check_zero)
    }

    /// Test DKG with 3-of-5 threshold
    ///
    /// Tests a larger scenario with 5 nodes and threshold 3.
    pub fn test_dkg_3_of_5<Node, F, Z>(
        node_factory: F,
        check_zero: Option<Z>,
    ) -> Result<()>
    where
        Node: TestDkgNode,
        Node::PublicKey: CanonicalSerialize + PartialEq + Debug,
        Node::PubPoly: Clone,
        Node::PolynomialCommitment: Clone,
        Node::ShareValue: Clone,
        F: Fn(u32, usize, usize) -> Result<Box<Node>>,
        Z: Fn(&Node::PublicKey) -> bool,
    {
        test_dkg_basic(node_factory, 5, 3, check_zero)
    }

    /// Test polynomial commitment verification
    ///
    /// Verifies that polynomial commitments can correctly verify shares.
    /// This tests the PolynomialCommitment trait implementation.
    ///
    /// # Arguments
    /// * `node_factory` - Function that creates a DKG node
    /// * `create_wrong_share` - Function that creates an invalid share value for testing
    pub fn test_polynomial_commitment_verification<Node, F, CreateWrong>(
        node_factory: F,
        create_wrong_share: CreateWrong,
    ) -> Result<()>
    where
        Node: TestDkgNode,
        Node::PublicKey: CanonicalSerialize + PartialEq + Debug,
        Node::PubPoly: Clone,
        Node::PolynomialCommitment: Clone,
        Node::ShareValue: Clone,
        F: Fn(u32, usize, usize) -> Result<Box<Node>>,
        CreateWrong: Fn() -> Node::ShareValue,
    {
        // Create a node and generate a polynomial
        let mut node = *node_factory(1, 2, 3)?;
        node.generate_polynomial()?;

        let commitment = node.commitment();

        // Get a valid share by generating shares and taking one
        let shares = node.generate_shares()?;
        let test_share = shares
            .first()
            .ok_or_else(|| CryptoError::DKGError("No shares generated".to_string()))?;

        // Verify the valid share
        assert!(
            commitment.verify_share(test_share.to_id, &test_share.value),
            "Valid share should verify correctly"
        );

        // Verify that a wrong share fails
        let wrong_value = create_wrong_share();
        assert!(
            !commitment.verify_share(test_share.to_id, &wrong_value),
            "Wrong share should fail verification"
        );

        Ok(())
    }

    /// Test invalid threshold parameters
    ///
    /// Verifies that the coordinator rejects invalid threshold configurations.
    pub fn test_invalid_threshold<Node, F>(
        node_factory: F,
    ) -> Result<()>
    where
        Node: TestDkgNode,
        Node::PublicKey: CanonicalSerialize + PartialEq + Debug,
        Node::PubPoly: Clone,
        Node::PolynomialCommitment: Clone,
        Node::ShareValue: Clone,
        F: Fn(u32, usize, usize) -> Result<Box<Node>> + Clone,
    {
        // Test threshold > node_count
        let result = DKGCoordinator::new(node_factory.clone(), 3, 4);
        assert!(
            result.is_err(),
            "Should reject threshold (4) greater than node_count (3)"
        );

        // Test threshold == 0
        let result = DKGCoordinator::new(node_factory.clone(), 3, 0);
        assert!(
            result.is_err(),
            "Should reject threshold of 0"
        );

        // Test node_count == 0
        let result = DKGCoordinator::new(node_factory, 0, 1);
        assert!(
            result.is_err(),
            "Should reject node_count of 0"
        );

        Ok(())
    }

    /// Test that share verification fails with wrong/tampered shares
    ///
    /// Verifies that shares that don't match their commitments are rejected.
    pub fn test_share_verification_fails_with_wrong_commitment<Node, F, CreateShare>(
        node_factory: F,
        create_invalid_share: CreateShare,
    ) -> Result<()>
    where
        Node: TestDkgNode,
        Node::PublicKey: CanonicalSerialize + PartialEq + Debug,
        Node::PubPoly: Clone,
        Node::PolynomialCommitment: Clone,
        Node::ShareValue: Clone,
        F: Fn(u32, usize, usize) -> Result<Box<Node>> + Clone,
        CreateShare: Fn(u32, u32, u64) -> crate::r#trait::DistributedShare<Node::ShareValue>,
    {
        // Create two nodes with same session ID
        use rand_core::{OsRng, RngCore};
        let mut rng = OsRng;
        let mut session_id_bytes = [0u8; 8];
        rng.fill_bytes(&mut session_id_bytes);
        let session_id = u64::from_le_bytes(session_id_bytes);

        let mut node1 = *node_factory(1, 2, 3)?;
        let mut node2 = *node_factory(2, 2, 3)?;

        // Set same session ID for both nodes (for testing)
        node1.set_session_id(session_id);
        node2.set_session_id(session_id);

        // Generate polynomials
        node1.generate_polynomial()?;
        node2.generate_polynomial()?;

        // Node 2 receives node 1's commitment
        node2.receive_commitment(1, node1.commitment())?;

        // Node 1 generates shares
        let shares = node1.generate_shares()?;
        let share_for_node2 = shares
            .iter()
            .find(|s| s.to_id == 2)
            .ok_or_else(|| CryptoError::DKGError("Share for node 2 not found".to_string()))?;

        // This should succeed
        assert!(
            node2.receive_share(share_for_node2.clone()).is_ok(),
            "Valid share should be accepted"
        );

        // Create a fresh node2 to test the tampered share
        let mut node2_fresh = *node_factory(2, 2, 3)?;
        node2_fresh.set_session_id(session_id);
        node2_fresh.receive_commitment(1, node1.commitment())?;

        // Create a tampered share
        let tampered_share = create_invalid_share(1, 2, session_id);

        // This should fail
        assert!(
            node2_fresh.receive_share(tampered_share).is_err(),
            "Tampered share should be rejected"
        );

        Ok(())
    }
}
