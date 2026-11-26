use super::service::UnsafeTestingServiceImpl;
use crate::helpers::test_helpers::{cleanup_db, test_db_path};
use local_storage::{r#trait::LocalStorage, LocalStorageImpl};
use proto::unsafe_testing::{
    unsafe_testing_service_server::UnsafeTestingService, DeleteLocalStorageRequest,
    GetLocalStorageRequest, LocalStorageAccessMode, LocalStorageKey, LocalStorageKeyType,
    SetLocalStorageRequest,
};
use tonic::{Code, Request};

fn key(key_type: LocalStorageKeyType, ring_key: &str) -> LocalStorageKey {
    LocalStorageKey {
        key_type: key_type as i32,
        ring_key: ring_key.to_string(),
    }
}

fn service(name: &str) -> (UnsafeTestingServiceImpl, String) {
    let path = test_db_path(name);
    let storage = LocalStorageImpl::new("unsafe-testing-password".to_string(), path.clone())
        .expect("create local storage");
    (UnsafeTestingServiceImpl::new(storage), path)
}

#[tokio::test]
async fn plain_get_set_and_missing_get() {
    let (service, path) = service("unsafe_testing_plain_get_set");
    let storage_key = key(LocalStorageKeyType::RingIndex, "");

    let missing = service
        .get_local_storage(Request::new(GetLocalStorageRequest {
            key: Some(storage_key.clone()),
            access_mode: LocalStorageAccessMode::Plain as i32,
        }))
        .await
        .expect("get missing value")
        .into_inner();
    assert!(!missing.found);
    assert!(missing.value.is_empty());

    service
        .set_local_storage(Request::new(SetLocalStorageRequest {
            key: Some(storage_key.clone()),
            access_mode: LocalStorageAccessMode::Plain as i32,
            value: b"ring-index-json".to_vec(),
        }))
        .await
        .expect("set plain value");

    let stored = service
        .get_local_storage(Request::new(GetLocalStorageRequest {
            key: Some(storage_key),
            access_mode: LocalStorageAccessMode::Plain as i32,
        }))
        .await
        .expect("get plain value")
        .into_inner();
    assert!(stored.found);
    assert_eq!(stored.value, b"ring-index-json");

    cleanup_db(&path);
}

#[tokio::test]
async fn encrypted_get_set_round_trip() {
    let (service, path) = service("unsafe_testing_encrypted_get_set");
    let storage_key = key(LocalStorageKeyType::RingKey, "ring-key");

    service
        .set_local_storage(Request::new(SetLocalStorageRequest {
            key: Some(storage_key.clone()),
            access_mode: LocalStorageAccessMode::Encrypted as i32,
            value: b"secret-share".to_vec(),
        }))
        .await
        .expect("set encrypted value");

    let stored = service
        .get_local_storage(Request::new(GetLocalStorageRequest {
            key: Some(storage_key),
            access_mode: LocalStorageAccessMode::Encrypted as i32,
        }))
        .await
        .expect("get encrypted value")
        .into_inner();
    assert!(stored.found);
    assert_eq!(stored.value, b"secret-share");

    cleanup_db(&path);
}

#[tokio::test]
async fn delete_is_idempotent_and_reports_existence() {
    let (service, path) = service("unsafe_testing_delete");
    let storage_key = key(LocalStorageKeyType::NodeSecretKey, "");

    service
        .set_local_storage(Request::new(SetLocalStorageRequest {
            key: Some(storage_key.clone()),
            access_mode: LocalStorageAccessMode::Plain as i32,
            value: b"node-secret".to_vec(),
        }))
        .await
        .expect("set value");

    let first = service
        .delete_local_storage(Request::new(DeleteLocalStorageRequest {
            key: Some(storage_key.clone()),
        }))
        .await
        .expect("delete existing value")
        .into_inner();
    assert!(first.existed);

    let second = service
        .delete_local_storage(Request::new(DeleteLocalStorageRequest {
            key: Some(storage_key),
        }))
        .await
        .expect("delete missing value")
        .into_inner();
    assert!(!second.existed);

    cleanup_db(&path);
}

#[tokio::test]
async fn rejects_invalid_keys_and_access_modes() {
    let (service, path) = service("unsafe_testing_validation");

    let missing_key = service
        .get_local_storage(Request::new(GetLocalStorageRequest {
            key: None,
            access_mode: LocalStorageAccessMode::Plain as i32,
        }))
        .await
        .expect_err("missing key should fail");
    assert_eq!(missing_key.code(), Code::InvalidArgument);

    let unspecified_key = service
        .get_local_storage(Request::new(GetLocalStorageRequest {
            key: Some(key(LocalStorageKeyType::Unspecified, "")),
            access_mode: LocalStorageAccessMode::Plain as i32,
        }))
        .await
        .expect_err("unspecified key should fail");
    assert_eq!(unspecified_key.code(), Code::InvalidArgument);

    let empty_ring_key = service
        .get_local_storage(Request::new(GetLocalStorageRequest {
            key: Some(key(LocalStorageKeyType::RingKey, "")),
            access_mode: LocalStorageAccessMode::Plain as i32,
        }))
        .await
        .expect_err("empty ring key should fail");
    assert_eq!(empty_ring_key.code(), Code::InvalidArgument);

    let unexpected_ring_key = service
        .get_local_storage(Request::new(GetLocalStorageRequest {
            key: Some(key(LocalStorageKeyType::RingIndex, "unexpected")),
            access_mode: LocalStorageAccessMode::Plain as i32,
        }))
        .await
        .expect_err("ring key on RingIndex should fail");
    assert_eq!(unexpected_ring_key.code(), Code::InvalidArgument);

    let unspecified_mode = service
        .get_local_storage(Request::new(GetLocalStorageRequest {
            key: Some(key(LocalStorageKeyType::NodeSigningKey, "")),
            access_mode: LocalStorageAccessMode::Unspecified as i32,
        }))
        .await
        .expect_err("unspecified access mode should fail");
    assert_eq!(unspecified_mode.code(), Code::InvalidArgument);

    cleanup_db(&path);
}
