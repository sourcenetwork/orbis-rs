use super::{
    raw_get, raw_set, serialize_key, RedbStorage, INTERNAL_KDF_PARAMS_KEY,
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

    {
        RedbStorage::new("pw".to_string(), path.clone()).unwrap();
    }

    let raw = raw_get(
        &::redb::Database::create(&path).unwrap(),
        INTERNAL_KDF_PARAMS_KEY,
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        StoredKdfParams::from_bytes(&raw).unwrap(),
        StoredKdfParams::for_new_db(),
        "creation parameters must be written to disk"
    );

    // Reopen re-derives from the persisted parameters — succeeds.
    RedbStorage::new("pw".to_string(), path.clone()).unwrap();

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

const LEGACY_WORKER_NAME: &str = "vera-worker-0123456789abcdef0123456789abcdef";

fn legacy_worker_slot() -> Vec<u8> {
    let mut key = 4_u32.to_le_bytes().to_vec();
    key.extend_from_slice(&(LEGACY_WORKER_NAME.len() as u64).to_le_bytes());
    key.extend_from_slice(LEGACY_WORKER_NAME.as_bytes());
    key
}

fn seed_legacy_worker(db: &RedbStorage) {
    let key = legacy_worker_slot();
    let ciphertext = super::encrypt_value(&db.cipher, &super::slot_aad(&key), &[31; 32]).unwrap();
    raw_set(&db.store, &key, &ciphertext).unwrap();
}

#[test]
fn persisted_storage_tags_remain_stable() {
    let keys = [
        LocalStorageKeys::RingKey("ring".into()),
        LocalStorageKeys::RingIndex,
        LocalStorageKeys::NodeSecretKey,
        LocalStorageKeys::NodeSigningKey,
        LocalStorageKeys::RingPolyHistory("ring".into()),
        LocalStorageKeys::PendingReshareBundle("ring".into()),
        LocalStorageKeys::NativeWorkerKey(LEGACY_WORKER_NAME.into()),
    ];
    for (tag, key) in keys.iter().enumerate() {
        assert_eq!(
            &serialize_key(key).unwrap()[..4],
            &(tag as u32).to_le_bytes()
        );
    }
}

#[test]
fn native_worker_migration_preserves_key_and_does_not_resurrect_deleted_identity() {
    let path = test_db_path("native_worker_migration");
    cleanup_db(&path);
    let db = RedbStorage::new("pw".into(), path.clone()).unwrap();
    seed_legacy_worker(&db);
    let history = LocalStorageKeys::RingPolyHistory("ring-public-key".into());
    db.set(history.clone(), b"public polynomial".to_vec())
        .unwrap();
    let pending = LocalStorageKeys::PendingReshareBundle("ring-public-key".into());
    db.set_encrypted(pending.clone(), Zeroizing::new(b"pending share".to_vec()))
        .unwrap();
    drop(db);
    let key = LocalStorageKeys::NativeWorkerKey(LEGACY_WORKER_NAME.into());
    for _ in 0..2 {
        let db = RedbStorage::new("pw".into(), path.clone()).unwrap();
        assert_eq!(
            db.get_encrypted(key.clone()).unwrap().unwrap().as_slice(),
            &[31; 32]
        );
        assert!(raw_get(&db.store, &legacy_worker_slot()).unwrap().is_none());
        assert_eq!(
            db.get(history.clone()).unwrap().unwrap(),
            b"public polynomial"
        );
        assert_eq!(
            db.get_encrypted(pending.clone())
                .unwrap()
                .unwrap()
                .as_slice(),
            b"pending share"
        );
    }
    let db = RedbStorage::new("pw".into(), path.clone()).unwrap();
    db.delete(key.clone()).unwrap();
    drop(db);
    let db = RedbStorage::new("pw".into(), path.clone()).unwrap();
    assert!(db.get_encrypted(key).unwrap().is_none());
    drop(db);
    cleanup_db(&path);
}

#[test]
fn native_worker_migration_rejects_corrupt_ciphertext_without_deleting_it() {
    let path = test_db_path("native_worker_corrupt");
    cleanup_db(&path);
    let db = RedbStorage::new("pw".into(), path.clone()).unwrap();
    raw_set(&db.store, &legacy_worker_slot(), b"corrupt").unwrap();
    drop(db);
    assert!(matches!(
        RedbStorage::new("pw".into(), path.clone()),
        Err(LocalStorageError::IntegrityCheckFailed)
    ));
    let db = redb::Database::create(&path).unwrap();
    assert_eq!(
        raw_get(&db, &legacy_worker_slot()).unwrap().unwrap(),
        b"corrupt"
    );
    let key = serialize_key(&LocalStorageKeys::NativeWorkerKey(
        LEGACY_WORKER_NAME.into(),
    ))
    .unwrap();
    assert!(raw_get(&db, &key).unwrap().is_none());
    drop(db);
    cleanup_db(&path);
}

#[test]
fn native_worker_migration_rejects_conflicting_identities() {
    let path = test_db_path("native_worker_conflict");
    cleanup_db(&path);
    let db = RedbStorage::new("pw".into(), path.clone()).unwrap();
    seed_legacy_worker(&db);
    let key = LocalStorageKeys::NativeWorkerKey(LEGACY_WORKER_NAME.into());
    db.set_encrypted(key.clone(), Zeroizing::new(vec![32; 32]))
        .unwrap();
    let before = raw_get(&db.store, &serialize_key(&key).unwrap()).unwrap();
    drop(db);
    assert!(matches!(
        RedbStorage::new("pw".into(), path.clone()),
        Err(LocalStorageError::CorruptData)
    ));
    let db = redb::Database::create(&path).unwrap();
    assert!(raw_get(&db, &legacy_worker_slot()).unwrap().is_some());
    assert_eq!(raw_get(&db, &serialize_key(&key).unwrap()).unwrap(), before);
    drop(db);
    cleanup_db(&path);
}
