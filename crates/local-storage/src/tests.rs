use crate::error::LocalStorageError;
use crate::r#trait::{LocalStorage, LocalStorageKeys};
use std::path::Path;

// Checks set, get, contains, delete
pub fn test_set_get_contains_delete<DB: LocalStorage>(db: DB) {
    let store_value = b"test_store";
    let key = "test_key".to_string();
    let set_result = db.set(LocalStorageKeys::RingKey(key.clone()), store_value.to_vec());
    assert!(set_result.is_ok());

    let get_result = db.get(LocalStorageKeys::RingKey(key.clone()));
    assert!(get_result.is_ok());
    assert_eq!(get_result.unwrap().unwrap(), store_value);

    let contains_result = db.contains(LocalStorageKeys::RingKey(key.clone()));
    assert!(contains_result.is_ok());
    assert_eq!(contains_result.unwrap(), true);

    let delete_result = db.delete(LocalStorageKeys::RingKey(key.clone()));
    assert!(delete_result.is_ok());

    let contains_result_2 = db.contains(LocalStorageKeys::RingKey(key));
    assert!(contains_result_2.is_ok());
    assert_eq!(contains_result_2.unwrap(), false);
}

pub fn test_encrypted_functions<DB: LocalStorage>(db: DB) {
    let store_value = b"test_store";
    let key = "test_key".to_string();

    let set_encrypted =
        db.set_encrypted(LocalStorageKeys::RingKey(key.clone()), store_value.to_vec());
    assert!(set_encrypted.is_ok());

    // get should return an encrypted data not the same as original value
    let get_result = db.get(LocalStorageKeys::RingKey(key.clone()));
    assert!(get_result.is_ok());
    assert_ne!(get_result.unwrap().unwrap(), store_value);

    let get_encrypted_result = db.get_encrypted(LocalStorageKeys::RingKey(key.clone()));
    assert!(get_encrypted_result.is_ok());
    assert_eq!(get_encrypted_result.unwrap().unwrap(), store_value);
}

// ============================================================================
// Persistence tests - for storage backends that persist to disk
// ============================================================================

/// Test that creating a new database succeeds and creates the file
pub fn test_new_creates_database<DB, F>(path: &str, constructor: F)
where
    DB: LocalStorage,
    F: Fn(Option<String>, String) -> crate::error::Result<DB>,
{
    // Creating a new database should succeed
    let storage = constructor(Some("my_password".to_string()), path.to_string());
    assert!(
        storage.is_ok(),
        "Failed to create database: {:?}",
        storage.err()
    );

    // Verify the file was created
    assert!(
        Path::new(path).exists(),
        "Database file was not created at {}",
        path
    );
}

/// Test that reopening a database with the correct password succeeds and data persists
pub fn test_reopens_with_correct_password<DB, F>(path: &str, constructor: F)
where
    DB: LocalStorage,
    F: Fn(Option<String>, String) -> crate::error::Result<DB>,
{
    let password = "correct_password".to_string();

    // Create a new database with a password and store data
    {
        let storage = constructor(Some(password.clone()), path.to_string())
            .expect("Failed to create database");
        storage
            .set(
                LocalStorageKeys::RingKey("test".to_string()),
                b"test_value".to_vec(),
            )
            .expect("Failed to set value");
    }

    // Reopen with the same password - should succeed and data should persist
    {
        let storage = constructor(Some(password), path.to_string())
            .expect("Failed to reopen database with correct password");
        let value = storage
            .get(LocalStorageKeys::RingKey("test".to_string()))
            .expect("Failed to get value");
        assert_eq!(
            value,
            Some(b"test_value".to_vec()),
            "Data did not persist across reopens"
        );
    }
}

/// Test that reopening a database with the wrong password fails
pub fn test_fails_with_wrong_password<DB, F>(path: &str, constructor: F)
where
    DB: LocalStorage + std::fmt::Debug,
    F: Fn(Option<String>, String) -> crate::error::Result<DB>,
{
    // Create a new database with a password
    {
        let _storage = constructor(Some("correct_password".to_string()), path.to_string())
            .expect("Failed to create database");
    }

    // Try to reopen with wrong password - should fail
    let result = constructor(Some("wrong_password".to_string()), path.to_string());
    assert!(result.is_err(), "Should have failed with wrong password");
    assert!(
        matches!(result.unwrap_err(), LocalStorageError::InvalidPassword),
        "Expected InvalidPassword error"
    );
}

/// Test that creating a database without password works
pub fn test_without_password<DB, F>(path: &str, constructor: F)
where
    DB: LocalStorage,
    F: Fn(Option<String>, String) -> crate::error::Result<DB>,
{
    // Create without password
    let storage =
        constructor(None, path.to_string()).expect("Failed to create database without password");

    // Basic operations should still work
    storage
        .set(
            LocalStorageKeys::RingKey("key".to_string()),
            b"value".to_vec(),
        )
        .expect("Failed to set value");
    let value = storage
        .get(LocalStorageKeys::RingKey("key".to_string()))
        .expect("Failed to get value");
    assert_eq!(value, Some(b"value".to_vec()));
}

/// Test that encrypted data persists across reopens
pub fn test_encrypted_data_persists<DB, F>(path: &str, constructor: F)
where
    DB: LocalStorage,
    F: Fn(Option<String>, String) -> crate::error::Result<DB>,
{
    let password = "persistence_test".to_string();
    let key = LocalStorageKeys::RingKey("secret".to_string());
    let secret_data = b"super_secret_data".to_vec();

    // Create and store encrypted data
    {
        let storage = constructor(Some(password.clone()), path.to_string())
            .expect("Failed to create database");
        storage
            .set_encrypted(key.clone(), secret_data.clone())
            .expect("Failed to set encrypted value");
    }

    // Reopen and verify we can decrypt
    {
        let storage =
            constructor(Some(password), path.to_string()).expect("Failed to reopen database");
        let decrypted = storage
            .get_encrypted(key)
            .expect("Failed to get encrypted value");
        assert_eq!(
            decrypted,
            Some(secret_data),
            "Encrypted data did not persist or decrypt correctly"
        );
    }
}
