use super::codec::{CryptoDeserialize, CryptoSerialize};
use super::types::{DistributedShare, PriShare};
use crate::error::Result;
use std::collections::HashMap;
use std::fmt::Debug;

pub trait PubPoly: Clone + Debug + Send + Sync + CryptoSerialize + CryptoDeserialize {
    type PublicKey: CryptoSerialize + CryptoDeserialize;
    /// Evaluate the public polynomial at index i
    fn eval(&self, i: u32) -> Self::PublicKey;
}

pub trait PolynomialCommitment:
    Clone + Debug + Send + Sync + CryptoSerialize + CryptoDeserialize
{
    type PublicKey: CryptoSerialize + CryptoDeserialize;
    type ShareValue: CryptoSerialize + CryptoDeserialize;
    /// Evaluate the polynomial commitment at index i
    fn eval(&self, i: u32) -> Self::PublicKey;
    /// Verify a share against this commitment using constant-time comparison
    fn verify_share(&self, share_id: u32, share_value: &Self::ShareValue) -> bool;
    /// Returns true iff the commitment has a constant term and it is the group identity.
    ///
    /// Used to validate PSS **refresh** commitments: a refresh delta polynomial must
    /// satisfy `P(0) = O` so the aggregate secret is unchanged. A non-identity constant
    /// term would silently shift the ring key. Returns `false` for an empty commitment
    /// (empty is already rejected upstream).
    fn constant_term_is_identity(&self) -> bool;
}
/// Role of a participant in the DKG protocol.
///
/// Only meaningful for resharing; use `Standard` for Fresh and Refresh modes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DkgRole {
    /// Symmetric participant in Fresh or Refresh — every node is equivalent.
    Standard,
    /// Old committee member only: generates a resharing polynomial and sends shares,
    /// but does not receive shares or compute a new secret share.
    Dealer,
    /// New committee member only: receives shares from old dealers but does not
    /// generate a polynomial.
    Receiver,
    /// Member of both old and new committees: generates a resharing polynomial
    /// AND receives shares from other old dealers to compute a new share.
    DealerReceiver,
}

/// Operational mode passed to `generate_polynomial`.
#[derive(Clone)]
pub enum DkgMode<F> {
    /// Generate a new random distributed secret (standard DKG).
    Fresh,
    /// Rotate shares while keeping the same secret.
    ///
    /// Each node contributes a polynomial with a zero constant term so the
    /// aggregate delta is zero at `x = 0`. The output of `compute_secret_share`
    /// is an additive delta — the node layer adds it to the existing share.
    Refresh,
    /// Redistribute the same secret to a (potentially different) committee.
    ///
    /// Each old dealer builds a polynomial whose constant term is its unweighted
    /// old share `sᵢ`. Receivers call `select_reshare_participants` with the
    /// session-wide old-dealer subset before Phase 4; aggregation applies the
    /// Lagrange weights for that selected subset.
    Reshare {
        /// This node's current secret share value.
        old_share: F,
        /// IDs of the old committee members participating in this reshare.
        /// Must be at least a threshold-sized subset.
        participating_ids: Vec<u32>,
        /// Threshold for the new committee.
        new_threshold: usize,
        /// Total nodes in the new committee.
        new_total_nodes: usize,
        /// This node's index in the new committee (1-based), if it is also a
        /// new-committee member (`DealerReceiver`).  `None` for pure `Dealer` nodes.
        /// Used so the crypto layer can validate incoming share `to_id` against the
        /// new-committee index rather than the old-committee `self.id`.
        new_node_id: Option<u32>,
    },
}

/// Trait for DKG
pub trait Dkg: Send + Sync {
    type ShareValue: CryptoSerialize + CryptoDeserialize + Clone + Send + Sync + zeroize::Zeroize;
    type PublicKey: CryptoSerialize + CryptoDeserialize + Clone;
    type PubPoly: PubPoly<PublicKey = Self::PublicKey>;
    type PolynomialCommitment: PolynomialCommitment<
        PublicKey = Self::PublicKey,
        ShareValue = Self::ShareValue,
    >;

    fn name() -> String;

    /// Initialize a new DKG node
    ///
    /// # Arguments
    /// * `id` - Unique identifier for this node (1-indexed)
    /// * `threshold` - Minimum number of nodes needed to reconstruct (t)
    /// * `total_nodes` - Total number of participating nodes (n)
    /// * `session_id` - Session ID agreed upon by all nodes before starting DKG
    /// * `role` - Participant role; use `DkgRole::Standard` for Fresh and Refresh
    fn new(
        id: u32,
        threshold: usize,
        total_nodes: usize,
        session_id: u128,
        role: DkgRole,
    ) -> Result<Box<Self>>
    where
        Self: Sized;
    /// Phase 1: Generate and broadcast polynomial commitment
    ///
    /// The constant term of the generated polynomial depends on `mode`:
    /// - `Fresh`: uniformly random
    /// - `Refresh`: zero (share rotation without changing the secret)
    /// - `Reshare`: `old_share` (unweighted; receivers weight the selected subset)
    ///
    /// Returns an error if called on a `Receiver`-role node.
    fn generate_polynomial(&mut self, mode: DkgMode<Self::ShareValue>) -> Result<()>;

    /// Select the old-dealer subset to use for reshare Phase 4 aggregation.
    ///
    /// This must be called by reshare receivers before computing the final share,
    /// aggregate public key, or public polynomial when fewer than all old dealers
    /// participate. Implementations should canonicalize and validate the IDs.
    fn select_reshare_participants(&mut self, participant_ids: Vec<u32>) -> Result<()>;
    /// Phase 2: Generate shares for all other nodes
    ///
    /// Returns a vector of shares to be sent to each node
    fn generate_shares(&self) -> Result<Vec<DistributedShare<Self::ShareValue>>>;

    /// Phase 3: Receive and verify a share from another node
    fn receive_share(&mut self, share: DistributedShare<Self::ShareValue>) -> Result<()>;

    /// Receive a commitment from another node
    fn receive_commitment(
        &mut self,
        from_id: u32,
        commitment: Self::PolynomialCommitment,
    ) -> Result<()>;

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

    /// Return whether a public key is the group identity.
    ///
    /// Fresh and reshare ceremonies must reject this value because it is not a
    /// usable PRE/signing key. Refresh delta polynomials are the exception: they
    /// intentionally have an identity constant term.
    fn public_key_is_identity(public_key: &Self::PublicKey) -> bool
    where
        Self: Sized;

    /// Get complaints about malicious nodes
    fn get_complaints(&self) -> &HashMap<u32, Vec<u32>>;
    /// Compute the public polynomial (sum of all commitments)
    ///
    /// This is used for verification in the re-encryption protocol
    fn compute_public_polynomial(&self) -> Result<Self::PubPoly>;

    /// Get the node ID
    fn node_id(&self) -> u32;

    /// Get the threshold value
    fn threshold(&self) -> usize;

    /// Get the total number of nodes
    fn total_nodes(&self) -> usize;

    /// Get a reference to the polynomial commitment
    fn commitment(&self) -> &Self::PolynomialCommitment;

    /// Get the role of this node in the current DKG session.
    fn role(&self) -> DkgRole;

    /// Add two serialized public polynomials coefficient-wise and return the result.
    ///
    /// Used in PSS refresh Phase 4 to compute the updated public polynomial:
    ///   new_pub_poly = old_pub_poly + refresh_delta_poly
    ///
    /// Both slices must be produced by `PubPoly::to_bytes` and have equal length.
    fn combine_pub_poly_bytes(a: &[u8], b: &[u8]) -> Result<Vec<u8>>
    where
        Self: Sized;
}
