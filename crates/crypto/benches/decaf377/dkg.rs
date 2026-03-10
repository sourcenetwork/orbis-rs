use crypto::decaf377::dkg::DKGNode;
use crypto::r#trait::{Dkg, DkgRole};

use crate::DkgBenchSetup;

pub struct Decaf377DkgBench;

impl DkgBenchSetup for Decaf377DkgBench {
    type Node = DKGNode;

    fn create_node(id: u32, threshold: usize, total_nodes: usize, session_id: u64) -> Box<DKGNode> {
        <DKGNode as Dkg>::new(id, threshold, total_nodes, session_id, DkgRole::Standard).unwrap()
    }
}
