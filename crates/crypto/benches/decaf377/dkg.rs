use crypto::decaf377::dkg::DKGNode;
use crypto::r#trait::Dkg;

use crate::DkgBenchSetup;

pub struct Decaf377DkgBench;

impl DkgBenchSetup for Decaf377DkgBench {
    type Node = DKGNode;

    fn create_node(id: u32, threshold: usize, total_nodes: usize) -> Box<DKGNode> {
        <DKGNode as Dkg>::new(id, threshold, total_nodes).unwrap()
    }
}
