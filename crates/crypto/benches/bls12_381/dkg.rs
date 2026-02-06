use crypto::bls12_381::dkg::DKGNode;
use crypto::r#trait::Dkg;

use crate::DkgBenchSetup;

pub struct Bls12381DkgBench;

impl DkgBenchSetup for Bls12381DkgBench {
    type Node = DKGNode;

    fn create_node(id: u32, threshold: usize, total_nodes: usize) -> Box<DKGNode> {
        <DKGNode as Dkg>::new(id, threshold, total_nodes).unwrap()
    }
}
