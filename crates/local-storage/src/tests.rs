use crate::r#trait::{LocalStorage, LocalStorageKeys};

// Checks set and get work
pub fn test_set_get_contrains_delete<DB: LocalStorage>(db: DB) {
    let store_value = b"test_store";
    let key = "test_key".to_string();
    let set_result = db.set(LocalStorageKeys::RingPkMapping(key.clone()), store_value.to_vec());
    assert!(set_result.is_ok());

    let get_result = db.get(LocalStorageKeys::RingPkMapping(key.clone()));
    assert!(get_result.is_ok());
    assert_eq!(get_result.unwrap().unwrap(), store_value);

    let contains_result = db.contains(LocalStorageKeys::RingPkMapping(key.clone()));
    assert!(contains_result.is_ok());
    assert_eq!(contains_result.unwrap(), true);

    let delete_result = db.delete(LocalStorageKeys::RingPkMapping(key.clone()));
    assert!(delete_result.is_ok());

    let contains_result_2 = db.contains(LocalStorageKeys::RingPkMapping(key));
    assert!(contains_result_2.is_ok());
    assert_eq!(contains_result_2.unwrap(), false);
}
