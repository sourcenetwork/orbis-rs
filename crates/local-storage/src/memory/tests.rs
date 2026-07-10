use crate::memory::MemoryStorage;
use crate::r#trait::LocalStorage;
use crate::tests::{test_encrypted_functions, test_set_get_contains_delete};

#[test]
fn test_db_functions_memory() {
    test_set_get_contains_delete::<MemoryStorage>(
        MemoryStorage::new("test_password".to_string(), "".to_string()).unwrap(),
    );
    test_encrypted_functions::<MemoryStorage>(
        MemoryStorage::new("test_password".to_string(), "".to_string()).unwrap(),
    );
}

#[test]
fn test_local_storage_name() {
    assert_eq!(MemoryStorage::name(), "local-storage/memory");
}
