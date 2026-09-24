use crate::bls12_381::pet::PetNode;
use ark_bls12_381::{Fr, G1Affine, G1Projective};
use ark_ec::Group;
use ark_std::UniformRand;
use rand_core::OsRng;

#[test]
fn test_all_pet() {
    crate::pet_tests::run_all_tests::<PetNode>().unwrap();
}

#[test]
fn test_all_tag_knowledge() {
    crate::pet_tests::run_all_tag_knowledge_tests::<PetNode, _>(|| {
        let r_tag = Fr::rand(&mut OsRng);
        let ephemeral_point: G1Affine = (G1Projective::generator() * r_tag).into();
        (r_tag, ephemeral_point)
    })
    .unwrap();
}
