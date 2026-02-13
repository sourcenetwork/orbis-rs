use crate::memory::MemoryStorage;
use crate::r#trait::LocalStorage;
use crate::tests::{test_encrypted_functions, test_set_get_contains_delete};

#[test]
fn test_db_functions_memory() {
    test_set_get_contains_delete::<MemoryStorage>(
        MemoryStorage::new(None, "".to_string()).unwrap(),
    );
    test_encrypted_functions::<MemoryStorage>(MemoryStorage::new(None, "".to_string()).unwrap());
    test_encrypted_functions::<MemoryStorage>(
        MemoryStorage::new(Some("test_password".to_string()), "".to_string()).unwrap(),
    );
}

#[test]
fn test_local_storage_name() {
    let storage = MemoryStorage::new().unwrap();
    assert_eq!(storage.name(), "local-storage/memory");
}
