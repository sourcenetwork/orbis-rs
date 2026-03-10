use crate::decaf377::dkg::DKGNode;
use crate::dkg_tests::run_all_tests;
use crate::r#trait::{DistributedShare, Dkg};
use decaf377::{Element, Fr};
use rand_core::{OsRng, RngCore};

#[test]
fn test_all_dkg_tests() {
    run_all_tests(
        |id, threshold, total_nodes, session_id, role| {
            DKGNode::new(id, threshold, total_nodes, session_id, role)
        },
        |pk: &Element| *pk == Element::default(),
        |share_value: &Fr| Element::GENERATOR * share_value,
        || {
            let mut rng = OsRng;
            Fr::rand(&mut rng)
        },
        |from_id, to_id, session_id| {
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
