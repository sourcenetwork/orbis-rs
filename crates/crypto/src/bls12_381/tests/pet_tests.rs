use crate::bls12_381::pet::PetNode;

#[test]
fn test_all_pet() {
    crate::pet_tests::run_all_tests::<PetNode>().unwrap();
}
