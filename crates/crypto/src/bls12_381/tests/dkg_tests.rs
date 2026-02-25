use crate::bls12_381::dkg::DKGNode;
use crate::dkg_tests::run_all_tests;
use crate::r#trait::{DistributedShare, Dkg};
use ark_bls12_381::{Fr, G1Affine, G1Projective};
use ark_ec::{AffineRepr, Group};
use ark_std::UniformRand;
use rand_core::{OsRng, RngCore};

#[test]
fn test_all_dkg_tests() {
    // Run all generic DKG tests using the convenience function
    run_all_tests(
        |id, threshold, total_nodes, session_id| {
            DKGNode::new(id, threshold, total_nodes, session_id)
        },
        |pk: &G1Affine| *pk == G1Affine::zero(),
        |share_value: &Fr| (G1Projective::generator() * share_value).into(),
        || {
            // Create a wrong share value (random)
            let mut rng = OsRng;
            Fr::rand(&mut rng)
        },
        |from_id, to_id, session_id| {
            // Create an invalid share with random value
            let mut rng = OsRng;
            let mut nonce = [0u8; 16];
            rng.fill_bytes(&mut nonce);
            DistributedShare {
                from_id,
                to_id,
                value: Fr::rand(&mut rng),
                nonce,
                session_id,
            }
        },
    )
    .unwrap();
}
