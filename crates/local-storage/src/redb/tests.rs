use crate::error::LocalStorageError;
use crate::r#trait::{LocalStorage, LocalStorageKeys};
use crate::redb::RedbStorage;
use crate::tests::{test_encrypted_functions, test_set_get_contains_delete};
use std::fs;

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
fn test_new_creates_database() {
    let path = test_db_path("test_new_creates");
    cleanup_db(&path);

    // Creating a new database should succeed
    let storage = RedbStorage::new(Some("my_password".to_string()), path.clone());
    assert!(storage.is_ok());

    // Verify the file was created
    assert!(fs::metadata(&path).is_ok());

    cleanup_db(&path);
}

#[test]
fn test_new_reopens_with_correct_password() {
    let path = test_db_path("test_reopen_correct");
    cleanup_db(&path);

    // Create a new database with a password
    {
        let storage = RedbStorage::new(Some("correct_password".to_string()), path.clone()).unwrap();
        storage
            .set(
                LocalStorageKeys::RingKey("test".to_string()),
                b"test_value".to_vec(),
            )
            .unwrap();
    }

    // Reopen with the same password - should succeed
    {
        let storage = RedbStorage::new(Some("correct_password".to_string()), path.clone()).unwrap();
        let value = storage
            .get(LocalStorageKeys::RingKey("test".to_string()))
            .unwrap();
        assert_eq!(value, Some(b"test_value".to_vec()));
    }

    cleanup_db(&path);
}

#[test]
fn test_new_fails_with_wrong_password() {
    let path = test_db_path("test_reopen_wrong");
    cleanup_db(&path);

    // Create a new database with a password
    {
        let _storage =
            RedbStorage::new(Some("correct_password".to_string()), path.clone()).unwrap();
    }

    // Try to reopen with wrong password - should fail
    let result = RedbStorage::new(Some("wrong_password".to_string()), path.clone());
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        LocalStorageError::InvalidPassword
    ));

    cleanup_db(&path);
}

#[test]
fn test_new_without_password() {
    let path = test_db_path("test_no_password");
    cleanup_db(&path);

    // Create without password
    let storage = RedbStorage::new(None, path.clone());
    assert!(storage.is_ok());

    let storage = storage.unwrap();
    // Basic operations should still work
    storage
        .set(
            LocalStorageKeys::RingKey("key".to_string()),
            b"value".to_vec(),
        )
        .unwrap();
    let value = storage
        .get(LocalStorageKeys::RingKey("key".to_string()))
        .unwrap();
    assert_eq!(value, Some(b"value".to_vec()));

    cleanup_db(&path);
}

#[test]
fn test_encrypted_data_persists_across_reopens() {
    let path = test_db_path("test_encrypted_persist");
    cleanup_db(&path);

    let password = "persistence_test".to_string();
    let key = LocalStorageKeys::RingKey("secret".to_string());
    let secret_data = b"super_secret_data".to_vec();

    // Create and store encrypted data
    {
        let storage = RedbStorage::new(Some(password.clone()), path.clone()).unwrap();
        storage
            .set_encrypted(key.clone(), secret_data.clone())
            .unwrap();
    }

    // Reopen and verify we can decrypt
    {
        let storage = RedbStorage::new(Some(password.clone()), path.clone()).unwrap();
        let decrypted = storage.get_encrypted(key.clone()).unwrap();
        assert_eq!(decrypted, Some(secret_data));
    }

    cleanup_db(&path);
}
