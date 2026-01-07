use crate::redb::RedbStorage;
use crate::r#trait::LocalStorage;
use crate::tests::{test_encrypted_functions, test_set_get_contains_delete};

#[test]
fn test_db_functions_Redb() {
    test_set_get_contains_delete::<RedbStorage>(RedbStorage::new(None).unwrap());
    test_encrypted_functions::<RedbStorage>(RedbStorage::new(None).unwrap());
    test_encrypted_functions::<RedbStorage>(
        RedbStorage::new(Some("test_password".to_string())).unwrap(),
    );
}
