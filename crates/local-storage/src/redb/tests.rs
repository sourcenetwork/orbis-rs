use crate::r#trait::LocalStorage;
use crate::redb::RedbStorage;
use crate::tests::{
    test_encrypted_data_persists, test_encrypted_functions, test_fails_with_wrong_password,
    test_new_creates_database, test_reopens_with_correct_password, test_set_get_contains_delete,
    test_without_password,
};
use std::fs;

#[test]
fn test_local_storage_name() {
    let path = test_db_path("test_local_storage_name");
    let storage = RedbStorage::new(None, path.clone()).unwrap();
    assert_eq!(storage.name(), "local-storage/redb");
}

fn test_db_path(name: &str) -> String {
    let project_root = project_root::get_project_root().unwrap();
    format!("{}/test_dbs/{}.redb", project_root.display(), name)
}

fn cleanup_db(path: &str) {
    let _ = fs::remove_file(path);
}

#[test]
fn test_db_functions_redb() {
    let path = test_db_path("test_db_functions");
    cleanup_db(&path);

    test_set_get_contains_delete::<RedbStorage>(RedbStorage::new(None, path.clone()).unwrap());
    test_encrypted_functions::<RedbStorage>(RedbStorage::new(None, path.clone()).unwrap());

    let path_with_pw = test_db_path("test_db_functions_pw");
    cleanup_db(&path_with_pw);
    test_encrypted_functions::<RedbStorage>(
        RedbStorage::new(Some("test_password".to_string()), path_with_pw.clone()).unwrap(),
    );

    cleanup_db(&path);
    cleanup_db(&path_with_pw);
}

#[test]
fn test_redb_new_database() {
    let path = test_db_path("test_new_creates");
    cleanup_db(&path);
    test_new_creates_database::<RedbStorage, _>(&path, RedbStorage::new);
    cleanup_db(&path);
    test_reopens_with_correct_password::<RedbStorage, _>(&path, RedbStorage::new);
    cleanup_db(&path);
    test_fails_with_wrong_password::<RedbStorage, _>(&path, RedbStorage::new);
    cleanup_db(&path);
    test_without_password::<RedbStorage, _>(&path, RedbStorage::new);
    cleanup_db(&path);
    test_encrypted_data_persists::<RedbStorage, _>(&path, RedbStorage::new);
    cleanup_db(&path);
}
