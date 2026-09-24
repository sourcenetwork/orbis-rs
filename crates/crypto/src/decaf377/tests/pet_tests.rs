use crate::decaf377::pet::PetNode;
use decaf377::{Element, Fr};
use rand_core::OsRng;

#[test]
fn test_all_pet() {
    crate::pet_tests::run_all_tests::<PetNode>().unwrap();
}

#[test]
fn test_all_tag_knowledge() {
    crate::pet_tests::run_all_tag_knowledge_tests::<PetNode, _>(|| {
        let r_tag = Fr::rand(&mut OsRng);
        let ephemeral_point = Element::GENERATOR * r_tag;
        (r_tag, ephemeral_point)
    })
    .unwrap();
}
