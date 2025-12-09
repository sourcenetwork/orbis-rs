//! Generic DKG test suite
//!
//! This module contains generic tests that can be applied to any DKG implementation.
//! To use these tests with a new implementation:
//!
//! 1. Implement `TestDkgNode` for your DKG node type
//! 2. Create a test module that calls these test functions with your factory function
//!
//! Example:
//! ```rust
//! #[cfg(test)]
//! mod tests {
//!     use super::*;
//!     use crate::dkg_tests::run_all_tests;
//!
//!     #[test]
//!     fn test_my_implementation() {
//!         run_all_tests(
//!             |id, threshold, total_nodes| MyDKGNode::new(id, threshold, total_nodes),
//!             |pk| pk.is_zero(), // zero check function
//!             |share| share_to_pubkey(share), // share to pubkey conversion
//!         );
//!     }
//! }
//! ```
use crate::error::Result;
use crate::r#trait::PubPoly;
use crate::test_helper::{generic_tests, DKGCoordinator};

/// Run all generic DKG tests for a given implementation
///
/// This is a convenience function that runs all the standard DKG tests.
/// You can also call individual test functions if you prefer.
pub fn run_all_tests<Node, F, Z, G>(
    node_factory: F,
    check_zero: Z,
    share_to_pubkey: G,
) -> Result<()>
where
    Node: crate::test_helper::TestDkgNode,
    Node::PublicKey: ark_serialize::CanonicalSerialize
        + PartialEq
        + std::fmt::Debug,
    Node::PubPoly: Clone + PubPoly<PublicKey = Node::PublicKey>,
    Node::PolynomialCommitment: Clone,
    Node::ShareValue: Clone,
    F: Fn(u32, usize, usize) -> Result<Box<Node>> + Clone,
    Z: Fn(&Node::PublicKey) -> bool + Clone,
    G: Fn(&Node::ShareValue) -> Node::PublicKey + Clone,
{
    // Run all the generic tests
    generic_tests::test_dkg_2_of_3(node_factory.clone(), Some(check_zero.clone()))?;
    generic_tests::test_dkg_3_of_5(node_factory.clone(), Some(check_zero.clone()))?;
    generic_tests::test_shares_match_pub_poly(
        node_factory,
        3,
        2,
        share_to_pubkey,
    )?;

    Ok(())
}

