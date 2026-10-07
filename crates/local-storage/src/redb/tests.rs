use super::{
    raw_delete, raw_get, raw_set, serialize_key, RedbStorage, INTERNAL_KDF_PARAMS_KEY,
    INTERNAL_KEY_COMMITMENT_KEY,
};
use crate::common::StoredKdfParams;
use crate::error::LocalStorageError;
use crate::r#trait::{LocalStorage, LocalStorageKeys};
use crate::tests::{
    test_encrypted_data_persists, test_encrypted_functions, test_fails_with_wrong_password,
    test_new_creates_database, test_reopens_with_correct_password, test_set_get_contains_delete,
};
use std::fs;
use zeroize::Zeroizing;

#[test]
fn test_local_storage_name() {
    assert_eq!(RedbStorage::name(), "local-storage/redb");
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

    test_set_get_contains_delete::<RedbStorage>(
        RedbStorage::new("test_password".to_string(), path.clone()).unwrap(),
    );
    test_encrypted_functions::<RedbStorage>(
        RedbStorage::new("test_password".to_string(), path.clone()).unwrap(),
    );

    let path_with_pw = test_db_path("test_db_functions_pw");
    cleanup_db(&path_with_pw);
    test_encrypted_functions::<RedbStorage>(
        RedbStorage::new("test_password".to_string(), path_with_pw.clone()).unwrap(),
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
    test_encrypted_data_persists::<RedbStorage, _>(&path, RedbStorage::new);
    cleanup_db(&path);
}

fn ring(name: &str) -> LocalStorageKeys {
    LocalStorageKeys::RingKey(name.to_string())
}

/// A value moved from another slot fails authentication for the slot it lands in.
#[test]
fn rejects_cross_slot_substitution() {
    let path = test_db_path("sec04_cross_slot");
    cleanup_db(&path);

    let db = RedbStorage::new("pw".to_string(), path.clone()).unwrap();
    db.set_encrypted(ring("A"), Zeroizing::new(b"share-A".to_vec()))
        .unwrap();
    db.set_encrypted(ring("B"), Zeroizing::new(b"share-B".to_vec()))
        .unwrap();

    let blob_a = raw_get(&db.store, &serialize_key(&ring("A")).unwrap())
        .unwrap()
        .unwrap();
    raw_set(&db.store, &serialize_key(&ring("B")).unwrap(), &blob_a).unwrap();

    assert!(matches!(
        db.get_encrypted(ring("B")),
        Err(LocalStorageError::IntegrityCheckFailed)
    ));

    cleanup_db(&path);
}

/// Two databases created with the same password still isolate: each generates a
/// random salt, so their derived keys differ and a blob copied from one does not
/// authenticate in the other. (This is the per-database salt doing the work, not
/// the slot AAD.)
#[test]
fn cross_database_blobs_do_not_authenticate() {
    let path1 = test_db_path("sec04_xdb_1");
    let path2 = test_db_path("sec04_xdb_2");
    cleanup_db(&path1);
    cleanup_db(&path2);

    let db1 = RedbStorage::new("shared-pw".to_string(), path1.clone()).unwrap();
    let db2 = RedbStorage::new("shared-pw".to_string(), path2.clone()).unwrap();

    db1.set_encrypted(ring("A"), Zeroizing::new(b"node-1 share".to_vec()))
        .unwrap();
    db2.set_encrypted(ring("A"), Zeroizing::new(b"node-2 share".to_vec()))
        .unwrap();

    let db2_blob = raw_get(&db2.store, &serialize_key(&ring("A")).unwrap())
        .unwrap()
        .unwrap();
    raw_set(&db1.store, &serialize_key(&ring("A")).unwrap(), &db2_blob).unwrap();

    assert!(matches!(
        db1.get_encrypted(ring("A")),
        Err(LocalStorageError::IntegrityCheckFailed)
    ));

    cleanup_db(&path1);
    cleanup_db(&path2);
}

/// The KDF parameters a database was created with are persisted, so reopening
/// re-derives the same key even if the default / env override would now differ.
#[test]
fn kdf_params_are_persisted_and_reused_on_reopen() {
    let path = test_db_path("sec04_kdf_persist");
    cleanup_db(&path);

    let expected = StoredKdfParams::for_new_db();
    let db = RedbStorage::new("pw".to_string(), path.clone()).unwrap();
    assert_eq!(db.stored_kdf_params().unwrap(), expected);
    drop(db);

    let reopened = RedbStorage::new("pw".to_string(), path.clone()).unwrap();
    assert_eq!(reopened.stored_kdf_params().unwrap(), expected);
    drop(reopened);

    cleanup_db(&path);
}

/// Tampering the stored key commitment makes the database refuse to open.
#[test]
fn rejects_tampered_key_commitment() {
    let path = test_db_path("sec04_commitment");
    cleanup_db(&path);

    {
        let _db = RedbStorage::new("pw".to_string(), path.clone()).unwrap();
    }

    let db_for_raw = ::redb::Database::create(&path).unwrap();
    raw_set(&db_for_raw, INTERNAL_KEY_COMMITMENT_KEY, &[7u8; 32]).unwrap();
    drop(db_for_raw);

    assert!(matches!(
        RedbStorage::new("pw".to_string(), path.clone()),
        Err(LocalStorageError::KeyCommitmentMismatch)
    ));

    cleanup_db(&path);
}

/// Repeated writes to one slot keep working and read back the latest value.
/// (Note: this deliberately does *not* check that an old ciphertext restored
/// over a newer one is rejected — SEC-04 scoped rollback detection out. A
/// value's AAD binds it to its slot, not to when it was written, so a slot can
/// still be rolled back to an earlier value of its own.)
#[test]
fn repeated_writes_still_read_latest() {
    let path = test_db_path("sec04_repeat");
    cleanup_db(&path);

    let db = RedbStorage::new("pw".to_string(), path.clone()).unwrap();
    for i in 0..5u8 {
        db.set_encrypted(ring("A"), Zeroizing::new(vec![i; 4]))
            .unwrap();
    }
    assert_eq!(
        db.get_encrypted(ring("A")).unwrap().unwrap().as_slice(),
        &[4u8; 4]
    );

    cleanup_db(&path);
}

#[test]
fn persisted_storage_tags_remain_stable() {
    // Slots 0..=7 are the published layout at a18d22cc and f1c15b0.
    let fixtures: &[(LocalStorageKeys, &[u8])] = &[
        (
            LocalStorageKeys::RingKey("r".into()),
            b"\x00\0\0\0\x01\0\0\0\0\0\0\0r",
        ),
        (
            LocalStorageKeys::PetRingKey("r".into()),
            b"\x01\0\0\0\x01\0\0\0\0\0\0\0r",
        ),
        (LocalStorageKeys::RingIndex, b"\x02\0\0\0"),
        (LocalStorageKeys::NodeSecretKey, b"\x03\0\0\0"),
        (LocalStorageKeys::NodeSigningKey, b"\x04\0\0\0"),
        (
            LocalStorageKeys::RingPolyHistory("r".into()),
            b"\x05\0\0\0\x01\0\0\0\0\0\0\0r",
        ),
        (
            LocalStorageKeys::PendingReshareBundle("r".into()),
            b"\x06\0\0\0\x01\0\0\0\0\0\0\0r",
        ),
        (
            LocalStorageKeys::PendingResharePetBundle("r".into()),
            b"\x07\0\0\0\x01\0\0\0\0\0\0\0r",
        ),
        (
            LocalStorageKeys::NativeWorkerKey("r".into()),
            b"\x08\0\0\0\x01\0\0\0\0\0\0\0r",
        ),
    ];
    for (key, bytes) in fixtures {
        assert_eq!(serialize_key(key).unwrap(), *bytes, "{key:?}");
        assert_eq!(
            bincode::deserialize::<LocalStorageKeys>(bytes).unwrap(),
            *key
        );
    }
}

#[test]
fn published_identity_slots_reopen_without_aliasing() {
    let path = test_db_path("published_identity_slots");
    cleanup_db(&path);
    let network_secret = b"1111111111111111111111111111111111111111111111111111111111111111";
    let signing_secret = b"2222222222222222222222222222222222222222222222222222222222222222";
    let index = br#"[{"ring_pk_str":"main-ring","post_id":"ring-id"}]"#;
    let db = RedbStorage::new("pw".into(), path.clone()).unwrap();
    // Write the baseline's raw slots without serializing the current enum.
    raw_set(&db.store, &[2, 0, 0, 0], index).unwrap();
    for (slot, secret) in [(3, network_secret), (4, signing_secret)] {
        let key = [slot, 0, 0, 0];
        let encrypted = super::encrypt_value(&db.cipher, &super::slot_aad(&key), secret).unwrap();
        raw_set(&db.store, &key, &encrypted).unwrap();
    }
    drop(db);
    let db = RedbStorage::new("pw".into(), path.clone()).unwrap();
    assert_eq!(db.get(LocalStorageKeys::RingIndex).unwrap().unwrap(), index);
    for (key, secret) in [
        (LocalStorageKeys::NodeSecretKey, network_secret),
        (LocalStorageKeys::NodeSigningKey, signing_secret),
    ] {
        assert_eq!(db.get_encrypted(key).unwrap().unwrap().as_slice(), secret);
    }
    drop(db);
    cleanup_db(&path);
}

#[test]
fn native_worker_identity_survives_restart_and_deletion() {
    let path = test_db_path("native_worker_identity");
    cleanup_db(&path);
    let key = LocalStorageKeys::NativeWorkerKey("vera-worker-test".into());
    let history = LocalStorageKeys::RingPolyHistory("ring-public-key".into());
    let pending = LocalStorageKeys::PendingReshareBundle("ring-public-key".into());
    let db = RedbStorage::new("pw".into(), path.clone()).unwrap();
    db.set_encrypted(key.clone(), Zeroizing::new(vec![31; 32]))
        .unwrap();
    db.set(history.clone(), b"public polynomial".to_vec())
        .unwrap();
    db.set_encrypted(pending.clone(), Zeroizing::new(b"pending share".to_vec()))
        .unwrap();
    drop(db);
    let db = RedbStorage::new("pw".into(), path.clone()).unwrap();
    assert_eq!(
        db.get_encrypted(key.clone()).unwrap().unwrap().as_slice(),
        &[31; 32]
    );
    assert_eq!(db.get(history).unwrap().unwrap(), b"public polynomial");
    assert_eq!(
        db.get_encrypted(pending).unwrap().unwrap().as_slice(),
        b"pending share"
    );
    db.delete(key.clone()).unwrap();
    drop(db);
    let db = RedbStorage::new("pw".into(), path.clone()).unwrap();
    assert!(db.get_encrypted(key).unwrap().is_none());
    drop(db);
    cleanup_db(&path);
}

/// The readback must use the stored header, never current defaults or a cache.
#[test]
fn stored_kdf_params_rejects_missing_or_malformed_header() {
    let path = test_db_path("kdf_readback_invalid");
    cleanup_db(&path);
    let db = RedbStorage::new("pw".to_string(), path.clone()).unwrap();
    raw_set(&db.store, INTERNAL_KDF_PARAMS_KEY, &[0; 15]).unwrap();
    assert!(matches!(
        db.stored_kdf_params(),
        Err(LocalStorageError::CorruptData)
    ));
    raw_delete(&db.store, INTERNAL_KDF_PARAMS_KEY).unwrap();
    assert!(matches!(
        db.stored_kdf_params(),
        Err(LocalStorageError::CorruptData)
    ));
    drop(db);
    cleanup_db(&path);
}
