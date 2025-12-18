use crate::memory::MemoryStorage;
use crate::r#trait::LocalStorage;
use crate::tests::{test_encrypted_functions, test_set_get_contains_delete};

#[test]
fn test_db_functions() {
    test_set_get_contains_delete::<MemoryStorage>(MemoryStorage::new(None));
    test_encrypted_functions::<MemoryStorage>(MemoryStorage::new(None));
    test_encrypted_functions::<MemoryStorage>(MemoryStorage::new(Some(
        "test_password".to_string(),
    )));
}
