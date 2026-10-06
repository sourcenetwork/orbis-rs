use crypto::jubjub::dkg::DKGNode;
use crypto::r#trait::{Dkg, DkgRole};

use crate::DkgBenchSetup;

pub struct JubjubDkgBench;

impl DkgBenchSetup for JubjubDkgBench {
    type Node = DKGNode;

    fn create_node(
        id: u32,
        threshold: usize,
        total_nodes: usize,
        session_id: u128,
    ) -> Box<DKGNode> {
        <DKGNode as Dkg>::new(id, threshold, total_nodes, session_id, DkgRole::Standard).unwrap()
    }
}
