use crate::memory::MemoryStorage;
use crate::tests::test_set_get_contrains_delete;

#[test]
fn test_non_encrypted_db_functions() {
    test_set_get_contrains_delete::<MemoryStorage>(MemoryStorage::default());
}
