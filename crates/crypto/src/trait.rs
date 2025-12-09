//! Crypto trait definitions
//!
//! This module defines the core cryptography abstractions that can be implemented
//! by various Curves.
use crate::error::Result;
use std::collections::HashMap;
use std::fmt::Debug;

/// A share distributed by one participant to another
#[derive(Clone, Debug)]
pub struct DistributedShare<ShareValue> {
    pub from_id: i32,
    pub to_id: i32,
    pub value: ShareValue,
    pub nonce: [u8; 16], // Nonce to prevent replay attacks
    pub session_id: u64, // Session ID to prevent replay attacks
}

/// Private share containing an index and a scalar value
#[derive(Clone, Debug)]
pub struct PriShare<ShareValue> {
    pub i: i32,
    pub v: ShareValue,
}

pub trait PubPoly: Clone + Debug + Send + Sync {
    type PublicKey;
    /// Evaluate the public polynomial at index i
    fn eval(&self, i: i32) -> Self::PublicKey;
}

pub trait PolynomialCommitment: Clone + Debug + Send + Sync {
    type PublicKey;
    type ShareValue;
    /// Evaluate the polynomial commitment at index i
    fn eval(&self, i: i32) -> Self::PublicKey;
    /// Verify a share against this commitment using constant-time comparison
    fn verify_share(&self, share_id: i32, share_value: &Self::ShareValue) -> bool;
}

pub trait DKG: Send + Sync {
    type ShareValue;
    type PublicKey;
    type PubPoly: PubPoly<PublicKey = Self::PublicKey>;

    /// Initialize a new DKG node
    ///
    /// # Arguments
    /// * `id` - Unique identifier for this node (1-indexed)
    /// * `threshold` - Minimum number of nodes needed to reconstruct (t)
    /// * `total_nodes` - Total number of participating nodes (n)
    fn new(id: u32, threshold: usize, total_nodes: usize) -> Result<Box<Self>>
    where
        Self: Sized;
    /// Phase 1: Generate and broadcast polynomial commitment
    ///
    /// Each node generates a random polynomial of degree (threshold - 1)
    /// and creates commitments to its coefficients.
    fn generate_polynomial(&mut self) -> Result<()>;
    /// Phase 2: Generate shares for all other nodes
    ///
    /// Returns a vector of shares to be sent to each node
    fn generate_shares(&self) -> Result<DistributedShare<Self::ShareValue>>;

    /// Phase 3: Receive and verify a share from another node
    fn receive_share(&mut self, share: DistributedShare<Self::ShareValue>) -> Result<()>;

    /// Receive a commitment from another node
    fn receive_commitment(&mut self, from_id: i32, commitment: Self::PublicKey) -> Result<()>;

    /// Phase 4: Compute the final secret share
    ///
    /// Once all shares are received and verified, compute the final share
    /// by summing all received shares (including own share)
    fn compute_secret_share(&self) -> Result<PriShare<Self::ShareValue>>;

    /// Compute the aggregate public key
    ///
    /// The aggregate public key is the sum of all nodes' constant terms
    /// in their polynomial commitments
    fn compute_aggregate_public_key(&self) -> Result<Self::PublicKey>;
    /// Get complaints about malicious nodes
    fn get_complaints(&self) -> &HashMap<i32, Vec<i32>>;
    /// Compute the public polynomial (sum of all commitments)
    ///
    /// This is used for verification in the re-encryption protocol
    fn compute_public_polynomial(&self) -> Result<Self::PubPoly>;
}
