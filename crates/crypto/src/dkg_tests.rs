//! Generic DKG test suite
//!
//! This module contains generic tests that can be applied to any DKG implementation.
//! To use these tests with a new implementation:
//!
//! 1. Implement `TestDkgNode` for your DKG node type
//! 2. Create a test module that calls these test functions with your factory function
//!
//! Example:
//! ```rust,no_run
//! #[cfg(test)]
//! mod tests {
//!     use super::*;
//!     use crate::dkg_tests::run_all_tests;
//!
//!     #[test]
//!     fn test_my_implementation() {
//!         run_all_tests(
//!             |id, threshold, total_nodes, session_id, role| MyDKGNode::new(id, threshold, total_nodes, session_id, role),
//!             |pk| pk.is_zero(),
//!             |share| share_to_pubkey(share),
//!         );
//!     }
//! }
//! ```
use crate::error::Result;
use crate::r#trait::{DkgRole, PubPoly};
use crate::test_helper::generic_tests;

/// Run all generic DKG tests for a given implementation
///
/// # Arguments
/// * `node_factory` - Function that creates a DKG node given (id, threshold, total_nodes, session_id, role)
/// * `check_zero` - Function to check if a public key is zero / the group identity
/// * `share_to_pubkey` - Function to convert a share value to a public key
/// * `create_wrong_share` - Function that creates an invalid share value for testing
/// * `create_invalid_share` - Function that creates an invalid DistributedShare for testing
pub fn run_all_tests<Node, F, Z, G, W, I>(
    node_factory: F,
    check_zero: Z,
    share_to_pubkey: G,
    create_wrong_share: W,
    create_invalid_share: I,
) -> Result<()>
where
    Node: crate::test_helper::TestDkgNode,
    Node::PublicKey: ark_serialize::CanonicalSerialize + PartialEq + std::fmt::Debug,
    Node::PubPoly: Clone + PubPoly<PublicKey = Node::PublicKey>,
    Node::PolynomialCommitment: Clone,
    Node::ShareValue: Clone + zeroize::Zeroize,
    F: Fn(u32, usize, usize, u64, DkgRole) -> Result<Box<Node>> + Clone,
    Z: Fn(&Node::PublicKey) -> bool + Clone,
    G: Fn(&Node::ShareValue) -> Node::PublicKey + Clone,
    W: Fn() -> Node::ShareValue + Clone,
    I: Fn(u32, u32, u64) -> crate::r#trait::DistributedShare<Node::ShareValue> + Clone,
{
    generic_tests::test_dkg_2_of_3(node_factory.clone(), Some(check_zero.clone()))?;
    generic_tests::test_dkg_3_of_5(node_factory.clone(), Some(check_zero.clone()))?;
    generic_tests::test_shares_match_pub_poly(node_factory.clone(), 3, 2, share_to_pubkey.clone())?;
    generic_tests::test_polynomial_commitment_verification(
        node_factory.clone(),
        create_wrong_share.clone(),
    )?;
    generic_tests::test_invalid_threshold(node_factory.clone())?;
    generic_tests::test_share_verification_fails_with_wrong_commitment(
        node_factory.clone(),
        create_invalid_share,
    )?;
    generic_tests::test_dkg_refresh(node_factory.clone(), check_zero.clone())?;
    generic_tests::test_dkg_reshare_same_committee(node_factory.clone())?;
    generic_tests::test_dkg_reshare_different_committee(node_factory)?;

    Ok(())
}
