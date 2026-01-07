use crate::r#trait::LocalStorage;
use crate::redb::RedbStorage;
use crate::tests::{test_encrypted_functions, test_set_get_contains_delete};

#[test]
fn test_db_functions_redb() {
    let project_root = project_root::get_project_root().unwrap();
    let path = format!("{}/orbis_test_db", project_root.display());
    test_set_get_contains_delete::<RedbStorage>(RedbStorage::new(None, path.clone()).unwrap());
    test_encrypted_functions::<RedbStorage>(RedbStorage::new(None, path.clone()).unwrap());
    test_encrypted_functions::<RedbStorage>(
        RedbStorage::new(Some("test_password".to_string()), path.clone()).unwrap(),
    );
}
