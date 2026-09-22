use super::*;
use crate::constants::{MAX_DKG_COMMITTEE_SIZE, PSS_GRACE_PERIOD_SECS};
use crate::dkg::v0::error::DkgError;
use crate::helpers::test_helpers::{cleanup_db, test_db_path, write_ring_to_bulletin};
use crate::ring_state::{RingIndexEntry, RingShareBundle};
use bulletin::dummy::DummyBulletin;
use bulletin::r#trait::{Bulletin, BulletinPost, NodeInfo, RingPayload};
use crypto::r#trait::{DkgRole, PriShare};
use crypto::{CryptoSerialize, GroupAffine as G1Affine, ScalarField as Fr};
use local_storage::{
    r#trait::{LocalStorage, LocalStorageKeys},
    LocalStorageImpl,
};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

fn make_storage(db_name: &str) -> (LocalStorageImpl, String) {
    let db_path = test_db_path(db_name);
    let storage = LocalStorageImpl::new("test-password".to_string(), db_path.clone())
        .expect("create storage");
    (storage, db_path)
}

fn write_last_refresh(storage: &LocalStorageImpl, ring_pk: &str, secs: u64) {
    let bundle = RingShareBundle {
        share_bytes: vec![].into(),
        public_polynomial: String::new(),
        last_pss: secs,
    };
    bundle.save_by_ring_key(storage, ring_pk).unwrap();
}

async fn seed_node_info(
    bulletin: &DummyBulletin,
    node_key: &str,
    peer_id: &str,
    policy_ids: Vec<String>,
    ring_ids: Vec<String>,
) {
    let node_info = NodeInfo {
        peer_id: peer_id.to_string(),
        controller_key: "controller".to_string(),
        whitelisted_policy_ids: policy_ids,
        whitelisted_ring_ids: ring_ids,
    };
    bulletin
        .set_node_info(node_key.to_string(), node_info)
        .expect("post NodeInfo");
}

fn make_valid_ring_payload(node_key: &str) -> RingPayload {
    RingPayload {
        upgrade_info: Default::default(),
        ring_pk: String::new(),
        peer_node_keys: vec![node_key.to_string()],
        new_peer_node_keys: None,
        new_threshold: None,
        threshold: 1,
        pss_interval: 86400,
        block_number_nonce: 0,
        policy_id: Some("policy".to_string()),
        trusted_auth_relay_dids: None,
        reporting: Default::default(),
    }
}

fn make_valid_reshare_ring_payload(old_node_key: &str, new_node_key: &str) -> RingPayload {
    RingPayload {
        upgrade_info: Default::default(),
        ring_pk: "ring-pk".to_string(),
        peer_node_keys: vec![old_node_key.to_string()],
        new_peer_node_keys: Some(vec![new_node_key.to_string()]),
        new_threshold: Some(1),
        threshold: 1,
        pss_interval: 86400,
        block_number_nonce: 0,
        policy_id: Some("policy".to_string()),
        trusted_auth_relay_dids: None,
        reporting: Default::default(),
    }
}

#[test]
fn fresh_commitment_hash_binds_session_sender_and_bytes() {
    let commitment = b"commitment-bytes";
    let base = fresh_commitment_hash(7, 2, commitment);

    assert_eq!(base, fresh_commitment_hash(7, 2, commitment));
    assert_ne!(base, fresh_commitment_hash(8, 2, commitment));
    assert_ne!(base, fresh_commitment_hash(7, 3, commitment));
    assert_ne!(base, fresh_commitment_hash(7, 2, b"other"));
}

#[test]
fn public_key_matches_storage_key_compares_canonical_key_string() {
    let pk = G1Affine::default();
    assert!(public_key_matches_storage_key(&pk, &pk.to_string()));
    assert!(!public_key_matches_storage_key(&pk, "different-key"));
}

#[tokio::test]
async fn test_validate_fresh_dkg_node_authorization_allows_policy_id() {
    let dummy_bulletin = Arc::new(DummyBulletin::new().await.expect("DummyBulletin::new"));
    let bulletin: Arc<dyn Bulletin + Send + Sync> = dummy_bulletin.clone();
    let node_key = "node-key";
    let local_peer_id = "peer-local";
    let ring_payload = make_valid_ring_payload(node_key);
    seed_node_info(
        &dummy_bulletin,
        node_key,
        local_peer_id,
        vec!["policy".to_string()],
        vec![],
    )
    .await;

    let result = validate_dkg_node_authorization_for_committee(
        &bulletin,
        node_key,
        local_peer_id,
        "ring-1",
        &ring_payload,
        &ring_payload.peer_node_keys,
        "Fresh DKG",
    )
    .await;
    assert!(result.is_ok(), "expected policy allow, got: {:?}", result);
}

#[tokio::test]
async fn test_validate_fresh_dkg_node_authorization_allows_ring_id_with_blank_placeholder() {
    let dummy_bulletin = Arc::new(DummyBulletin::new().await.expect("DummyBulletin::new"));
    let bulletin: Arc<dyn Bulletin + Send + Sync> = dummy_bulletin.clone();
    let node_key = "node-key";
    let local_peer_id = "peer-local";
    let ring_id = "ring-1";
    let ring_payload = RingPayload {
        upgrade_info: Default::default(),
        ring_pk: String::new(),
        peer_node_keys: vec![node_key.to_string()],
        new_peer_node_keys: None,
        new_threshold: None,
        threshold: 1,
        pss_interval: 60,
        block_number_nonce: 0,
        policy_id: Some("policy".to_string()),
        trusted_auth_relay_dids: None,
        reporting: Default::default(),
    };
    seed_node_info(
        &dummy_bulletin,
        node_key,
        local_peer_id,
        vec![],
        vec![ring_id.to_string()],
    )
    .await;

    let result = validate_dkg_node_authorization_for_committee(
        &bulletin,
        node_key,
        local_peer_id,
        ring_id,
        &ring_payload,
        &ring_payload.peer_node_keys,
        "Fresh DKG",
    )
    .await;
    assert!(result.is_ok(), "expected ring allow, got: {:?}", result);
}

#[tokio::test]
async fn test_validate_fresh_dkg_node_authorization_rejects_deny() {
    let dummy_bulletin = Arc::new(DummyBulletin::new().await.expect("DummyBulletin::new"));
    let bulletin: Arc<dyn Bulletin + Send + Sync> = dummy_bulletin.clone();
    let node_key = "node-key";
    let local_peer_id = "peer-local";
    let ring_payload = make_valid_ring_payload(node_key);
    seed_node_info(
        &dummy_bulletin,
        node_key,
        local_peer_id,
        vec!["other-policy".to_string()],
        vec!["other-ring".to_string()],
    )
    .await;

    // ring_id = "ring-1" is not in ["other-ring"], policy "policy" is not in ["other-policy"]
    let result = validate_dkg_node_authorization_for_committee(
        &bulletin,
        node_key,
        local_peer_id,
        "ring-1",
        &ring_payload,
        &ring_payload.peer_node_keys,
        "Fresh DKG",
    )
    .await;
    assert!(matches!(result, Err(DkgError::Unauthorized(_))));
}

#[tokio::test]
async fn test_validate_fresh_dkg_node_authorization_rejects_missing_node_info() {
    let dummy_bulletin = Arc::new(DummyBulletin::new().await.expect("DummyBulletin::new"));
    let bulletin: Arc<dyn Bulletin + Send + Sync> = dummy_bulletin.clone();
    let ring_payload = make_valid_ring_payload("missing-node");

    let result = validate_dkg_node_authorization_for_committee(
        &bulletin,
        "missing-node",
        "peer-local",
        "ring-1",
        &ring_payload,
        &ring_payload.peer_node_keys,
        "Fresh DKG",
    )
    .await;
    assert!(matches!(result, Err(DkgError::Unauthorized(_))));
}

#[tokio::test]
async fn test_validate_fresh_dkg_node_authorization_rejects_malformed_node_info() {
    let dummy_bulletin = Arc::new(DummyBulletin::new().await.expect("DummyBulletin::new"));
    let bulletin: Arc<dyn Bulletin + Send + Sync> = dummy_bulletin.clone();
    let node_key = "node-key";
    dummy_bulletin.set_post(
        node_key.to_string(),
        BulletinPost {
            id: node_key.to_string(),
            payload: b"not-json".to_vec(),
        },
    );
    let ring_payload = make_valid_ring_payload(node_key);

    let result = validate_dkg_node_authorization_for_committee(
        &bulletin,
        node_key,
        "peer-local",
        "ring-1",
        &ring_payload,
        &ring_payload.peer_node_keys,
        "Fresh DKG",
    )
    .await;
    assert!(matches!(result, Err(DkgError::Unauthorized(_))));
}

#[tokio::test]
async fn test_validate_fresh_dkg_node_authorization_rejects_peer_id_mismatch() {
    let dummy_bulletin = Arc::new(DummyBulletin::new().await.expect("DummyBulletin::new"));
    let bulletin: Arc<dyn Bulletin + Send + Sync> = dummy_bulletin.clone();
    let node_key = "node-key";
    seed_node_info(
        &dummy_bulletin,
        node_key,
        "different-peer",
        vec!["policy".to_string()],
        vec![],
    )
    .await;
    let ring_payload = make_valid_ring_payload(node_key);

    let result = validate_dkg_node_authorization_for_committee(
        &bulletin,
        node_key,
        "peer-local",
        "ring-1",
        &ring_payload,
        &ring_payload.peer_node_keys,
        "Fresh DKG",
    )
    .await;
    assert!(matches!(result, Err(DkgError::Unauthorized(_))));
}

#[tokio::test]
async fn test_validate_reshare_dkg_node_authorization_allows_policy_id() {
    let dummy_bulletin = Arc::new(DummyBulletin::new().await.expect("DummyBulletin::new"));
    let bulletin: Arc<dyn Bulletin + Send + Sync> = dummy_bulletin.clone();
    let node_key = "new-node-key";
    let local_peer_id = "peer-local";
    let ring_payload = make_valid_reshare_ring_payload("old-node-key", node_key);
    seed_node_info(
        &dummy_bulletin,
        node_key,
        local_peer_id,
        vec!["policy".to_string()],
        vec![],
    )
    .await;

    let result = validate_dkg_node_authorization_for_committee(
        &bulletin,
        node_key,
        local_peer_id,
        "reshare-ring-id",
        &ring_payload,
        effective_new_peer_node_keys(&ring_payload),
        "Reshare",
    )
    .await;
    assert!(result.is_ok(), "expected policy allow, got: {:?}", result);
}

#[tokio::test]
async fn test_validate_reshare_dkg_node_authorization_allows_ring_id() {
    let dummy_bulletin = Arc::new(DummyBulletin::new().await.expect("DummyBulletin::new"));
    let bulletin: Arc<dyn Bulletin + Send + Sync> = dummy_bulletin.clone();
    let node_key = "new-node-key";
    let local_peer_id = "peer-local";
    let ring_id = "reshare-ring-id";
    let mut ring_payload = make_valid_reshare_ring_payload("old-node-key", node_key);
    ring_payload.policy_id = None;
    seed_node_info(
        &dummy_bulletin,
        node_key,
        local_peer_id,
        vec![],
        vec![ring_id.to_string()],
    )
    .await;

    let result = validate_dkg_node_authorization_for_committee(
        &bulletin,
        node_key,
        local_peer_id,
        ring_id,
        &ring_payload,
        effective_new_peer_node_keys(&ring_payload),
        "Reshare",
    )
    .await;
    assert!(result.is_ok(), "expected ring allow, got: {:?}", result);
}

#[tokio::test]
async fn test_validate_reshare_dkg_node_authorization_rejects_deny() {
    let dummy_bulletin = Arc::new(DummyBulletin::new().await.expect("DummyBulletin::new"));
    let bulletin: Arc<dyn Bulletin + Send + Sync> = dummy_bulletin.clone();
    let node_key = "new-node-key";
    let local_peer_id = "peer-local";
    let ring_payload = make_valid_reshare_ring_payload("old-node-key", node_key);
    seed_node_info(
        &dummy_bulletin,
        node_key,
        local_peer_id,
        vec!["other-policy".to_string()],
        vec!["other-ring".to_string()],
    )
    .await;

    let result = validate_dkg_node_authorization_for_committee(
        &bulletin,
        node_key,
        local_peer_id,
        "reshare-ring-id",
        &ring_payload,
        effective_new_peer_node_keys(&ring_payload),
        "Reshare",
    )
    .await;
    assert!(matches!(result, Err(DkgError::Unauthorized(_))));
}

#[tokio::test]
async fn test_validate_reshare_dkg_node_authorization_uses_new_committee_membership() {
    let dummy_bulletin = Arc::new(DummyBulletin::new().await.expect("DummyBulletin::new"));
    let bulletin: Arc<dyn Bulletin + Send + Sync> = dummy_bulletin.clone();
    let old_only_node_key = "old-node-key";
    let local_peer_id = "peer-local";
    let ring_payload = make_valid_reshare_ring_payload(old_only_node_key, "new-node-key");
    seed_node_info(
        &dummy_bulletin,
        old_only_node_key,
        local_peer_id,
        vec!["policy".to_string()],
        vec!["reshare-ring-id".to_string()],
    )
    .await;

    let result = validate_dkg_node_authorization_for_committee(
        &bulletin,
        old_only_node_key,
        local_peer_id,
        "reshare-ring-id",
        &ring_payload,
        effective_new_peer_node_keys(&ring_payload),
        "Reshare",
    )
    .await;
    assert!(matches!(result, Err(DkgError::Unauthorized(_))));
}

#[test]
fn test_validate_fresh_dkg_ring_payload_ok() {
    let payload = make_valid_ring_payload("node-key");
    assert!(validate_fresh_dkg_ring_payload("ring-1", &payload).is_ok());
}

#[test]
fn test_validate_fresh_dkg_ring_payload_rejects_non_blank_ring() {
    let mut payload = make_valid_ring_payload("node-key");
    payload.ring_pk = "some-pk".to_string();
    assert!(matches!(
        validate_fresh_dkg_ring_payload("ring-1", &payload),
        Err(DkgError::Unauthorized(_))
    ));
}

#[test]
fn test_validate_fresh_dkg_ring_payload_rejects_empty_committee() {
    let mut payload = make_valid_ring_payload("node-key");
    payload.peer_node_keys = vec![];
    assert!(matches!(
        validate_fresh_dkg_ring_payload("ring-1", &payload),
        Err(DkgError::InvalidInput(_))
    ));
}

#[test]
fn test_validate_fresh_dkg_ring_payload_rejects_more_than_fifty_members() {
    let mut payload = make_valid_ring_payload("node-key");
    payload.peer_node_keys = (1..=MAX_DKG_COMMITTEE_SIZE + 1)
        .map(|node_id| format!("node-{node_id}"))
        .collect();
    payload.threshold = MAX_DKG_COMMITTEE_SIZE as u32;
    assert!(matches!(
        validate_fresh_dkg_ring_payload("ring-1", &payload),
        Err(DkgError::InvalidInput(_))
    ));
}

#[test]
fn test_validate_fresh_dkg_ring_payload_rejects_zero_threshold() {
    let mut payload = make_valid_ring_payload("node-key");
    payload.threshold = 0;
    assert!(matches!(
        validate_fresh_dkg_ring_payload("ring-1", &payload),
        Err(DkgError::InvalidInput(_))
    ));
}

#[test]
fn test_validate_fresh_dkg_ring_payload_rejects_threshold_exceeds_n() {
    let mut payload = make_valid_ring_payload("node-key");
    payload.threshold = 3; // Only 1 node in committee
    assert!(matches!(
        validate_fresh_dkg_ring_payload("ring-1", &payload),
        Err(DkgError::InvalidInput(_))
    ));
}

#[test]
fn test_validate_fresh_dkg_ring_payload_rejects_missing_policy_id() {
    let mut payload = make_valid_ring_payload("node-key");
    payload.policy_id = None;
    assert!(matches!(
        validate_fresh_dkg_ring_payload("ring-1", &payload),
        Err(DkgError::InvalidInput(_))
    ));
}

#[test]
fn test_derive_reshare_session_id_uses_chain_transition_only() {
    let old_peer_node_keys = vec!["node-c".to_string(), "node-a".to_string()];
    let new_peer_node_keys = vec!["node-b".to_string(), "node-a".to_string()];

    let id_1 = derive_reshare_session_id(
        "ring-pk",
        "ring-id",
        &old_peer_node_keys,
        &new_peer_node_keys,
        2,
    )
    .unwrap();
    let id_2 = derive_reshare_session_id(
        "ring-pk",
        "ring-id",
        &old_peer_node_keys,
        &new_peer_node_keys,
        2,
    )
    .unwrap();
    assert_eq!(
        id_1, id_2,
        "reshare session ID should be stable across nodes that see the same ring update"
    );

    let changed = derive_reshare_session_id(
        "ring-pk",
        "ring-id",
        &old_peer_node_keys,
        &new_peer_node_keys,
        1,
    )
    .unwrap();
    assert_ne!(
        id_1, changed,
        "reshare session ID should still change when the announced transition changes"
    );
}

#[tokio::test]
async fn test_unknown_ring() {
    let (storage, db_path) = make_storage("helpers_unknown_ring");
    let dummy_bulletin = Arc::new(DummyBulletin::new().await.expect("DummyBulletin::new"));
    let bulletin: Arc<dyn Bulletin + Send + Sync> = dummy_bulletin.clone();
    // No RingIndex written — ring is unknown.
    let result = validate_refresh_session_init_for_version(
        "some_pk",
        &storage,
        &bulletin,
        network::V0.version,
    )
    .await;
    assert!(
        matches!(result, Err(DkgError::Unauthorized(_))),
        "Expected Unauthorized for unknown ring, got: {:?}",
        result
    );
    cleanup_db(&db_path);
}

#[tokio::test]
async fn test_corrupt_ring_payload() {
    let (storage, db_path) = make_storage("helpers_corrupt_payload");
    // Post garbage bytes to the bulletin and point RingIndex at them.
    let garbage = b"not valid json".to_vec();
    let post_id = "test-garbage-ring".to_string();
    let dummy_bulletin = Arc::new(DummyBulletin::new().await.expect("DummyBulletin::new"));
    let bulletin: Arc<dyn Bulletin + Send + Sync> = dummy_bulletin.clone();
    dummy_bulletin.set_post(
        post_id.clone(),
        BulletinPost {
            id: post_id.clone(),
            payload: garbage,
        },
    );
    storage
        .set(
            LocalStorageKeys::RingIndex,
            serde_json::to_vec(&vec![RingIndexEntry {
                ring_pk_str: "pk".to_string(),
                bulletin_post_id: post_id,
                indexed_at_secs: 0,
            }])
            .unwrap(),
        )
        .unwrap();
    let result =
        validate_refresh_session_init_for_version("pk", &storage, &bulletin, network::V0.version)
            .await;
    assert!(
        matches!(result, Err(DkgError::ProtocolError(_))),
        "Expected ProtocolError for corrupt payload, got: {:?}",
        result
    );
    cleanup_db(&db_path);
}

#[tokio::test]
async fn test_no_last_refresh_timestamp() {
    // When pss_interval is set, a missing bundle (no DKG yet) must be rejected.
    let (storage, db_path) = make_storage("helpers_no_timestamp");
    let dummy_bulletin = Arc::new(DummyBulletin::new().await.expect("DummyBulletin::new"));
    let bulletin: Arc<dyn Bulletin + Send + Sync> = dummy_bulletin.clone();
    let ring_pk = "ring_pk_def";
    write_ring_to_bulletin(
        &storage,
        &dummy_bulletin,
        ring_pk,
        vec!["aabbccdd".to_string()],
        86400,
    )
    .await;
    // Intentionally do not write a RingShareBundle.
    let result = validate_refresh_session_init_for_version(
        ring_pk,
        &storage,
        &bulletin,
        network::V0.version,
    )
    .await;
    assert!(
        matches!(result, Err(DkgError::Unauthorized(_))),
        "Expected Unauthorized for missing timestamp, got: {:?}",
        result
    );
    if let Err(DkgError::Unauthorized(msg)) = result {
        assert!(
            msg.contains("no refresh timestamp"),
            "Expected 'no refresh timestamp' message, got: {}",
            msg
        );
    }
    cleanup_db(&db_path);
}

#[tokio::test]
async fn test_refresh_too_soon() {
    let (storage, db_path) = make_storage("helpers_too_soon");
    let dummy_bulletin = Arc::new(DummyBulletin::new().await.expect("DummyBulletin::new"));
    let bulletin: Arc<dyn Bulletin + Send + Sync> = dummy_bulletin.clone();
    let ring_pk = "ring_pk_ghi";
    write_ring_to_bulletin(
        &storage,
        &dummy_bulletin,
        ring_pk,
        vec!["aabbccdd".to_string()],
        86400,
    )
    .await;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    write_last_refresh(&storage, ring_pk, now);
    let result = validate_refresh_session_init_for_version(
        ring_pk,
        &storage,
        &bulletin,
        network::V0.version,
    )
    .await;
    assert!(
        matches!(result, Err(DkgError::Unauthorized(_))),
        "Expected Unauthorized for too soon, got: {:?}",
        result
    );
    if let Err(DkgError::Unauthorized(msg)) = result {
        assert!(
            msg.contains("too soon"),
            "Expected 'too soon' message, got: {}",
            msg
        );
    }
    cleanup_db(&db_path);
}

#[tokio::test]
async fn test_refresh_succeeds() {
    let (storage, db_path) = make_storage("helpers_success");
    let dummy_bulletin = Arc::new(DummyBulletin::new().await.expect("DummyBulletin::new"));
    let bulletin: Arc<dyn Bulletin + Send + Sync> = dummy_bulletin.clone();
    let ring_pk = "ring_pk_jkl";
    write_ring_to_bulletin(
        &storage,
        &dummy_bulletin,
        ring_pk,
        vec!["aabbccdd".to_string()],
        86400,
    )
    .await;
    // Timestamp at epoch — elapsed >> interval.
    write_last_refresh(&storage, ring_pk, 0);
    let result = validate_refresh_session_init_for_version(
        ring_pk,
        &storage,
        &bulletin,
        network::V0.version,
    )
    .await;
    assert!(
        result.is_ok(),
        "Expected Ok for valid refresh, got: {:?}",
        result
    );
    cleanup_db(&db_path);
}

#[tokio::test]
async fn test_zero_pss_interval_requires_existing_timestamp() {
    // pss_interval = 0 means "immediately due" but still requires a prior timestamp.
    let (storage, db_path) = make_storage("helpers_zero_interval");
    let dummy_bulletin = Arc::new(DummyBulletin::new().await.expect("DummyBulletin::new"));
    let bulletin: Arc<dyn Bulletin + Send + Sync> = dummy_bulletin.clone();
    let ring_pk = "ring_pk_zero_interval";
    write_ring_to_bulletin(
        &storage,
        &dummy_bulletin,
        ring_pk,
        vec!["aabbccdd".to_string()],
        0,
    )
    .await;

    let missing = validate_refresh_session_init_for_version(
        ring_pk,
        &storage,
        &bulletin,
        network::V0.version,
    )
    .await;
    assert!(
        matches!(missing, Err(DkgError::Unauthorized(_))),
        "Expected missing timestamp to be rejected when pss_interval is 0, got: {:?}",
        missing
    );

    write_last_refresh(&storage, ring_pk, 0);
    let result = validate_refresh_session_init_for_version(
        ring_pk,
        &storage,
        &bulletin,
        network::V0.version,
    )
    .await;
    assert!(
        result.is_ok(),
        "Expected pss_interval=0 to be accepted once the ring has a timestamp, got: {:?}",
        result
    );
    cleanup_db(&db_path);
}

/// A refresh that arrives within the grace window (elapsed just under pss_interval)
/// must be accepted — the grace period exists precisely for this case.
#[tokio::test]
async fn test_refresh_within_grace_period_succeeds() {
    let (storage, db_path) = make_storage("helpers_within_grace");
    let dummy_bulletin = Arc::new(DummyBulletin::new().await.expect("DummyBulletin::new"));
    let bulletin: Arc<dyn Bulletin + Send + Sync> = dummy_bulletin.clone();
    let ring_pk = "ring_pk_grace_ok";
    let pss_interval: u64 = 86400;
    write_ring_to_bulletin(
        &storage,
        &dummy_bulletin,
        ring_pk,
        vec!["aabbccdd".to_string()],
        pss_interval,
    )
    .await;
    // elapsed = pss_interval - (PSS_GRACE_PERIOD_SECS / 2): inside the grace window.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let half_grace = PSS_GRACE_PERIOD_SECS / 2;
    write_last_refresh(&storage, ring_pk, now - pss_interval + half_grace);
    let result = validate_refresh_session_init_for_version(
        ring_pk,
        &storage,
        &bulletin,
        network::V0.version,
    )
    .await;
    assert!(
        result.is_ok(),
        "Expected Ok: elapsed is within grace window, got: {:?}",
        result
    );
    cleanup_db(&db_path);
}

/// A refresh that arrives outside the grace window (more than PSS_GRACE_PERIOD_SECS
/// before the interval expires) must still be rejected.
#[tokio::test]
async fn test_refresh_outside_grace_period_rejected() {
    let (storage, db_path) = make_storage("helpers_outside_grace");
    let dummy_bulletin = Arc::new(DummyBulletin::new().await.expect("DummyBulletin::new"));
    let bulletin: Arc<dyn Bulletin + Send + Sync> = dummy_bulletin.clone();
    let ring_pk = "ring_pk_grace_fail";
    let pss_interval: u64 = 86400;
    write_ring_to_bulletin(
        &storage,
        &dummy_bulletin,
        ring_pk,
        vec!["aabbccdd".to_string()],
        pss_interval,
    )
    .await;
    // elapsed = pss_interval - (PSS_GRACE_PERIOD_SECS + 2): safely outside the grace window.
    // The +2 margin ensures the test remains reliable even if SystemTime advances by 1s
    // between this snapshot and validate_refresh_session_init's own now() call.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    write_last_refresh(
        &storage,
        ring_pk,
        now - pss_interval + PSS_GRACE_PERIOD_SECS + 2,
    );
    let result = validate_refresh_session_init_for_version(
        ring_pk,
        &storage,
        &bulletin,
        network::V0.version,
    )
    .await;
    assert!(
        matches!(result, Err(DkgError::Unauthorized(_))),
        "Expected Unauthorized: elapsed is outside grace window, got: {:?}",
        result
    );
    cleanup_db(&db_path);
}

// ──────────────────────────────────────────────────────────────────────────
// build_reshare_params tests
// ──────────────────────────────────────────────────────────────────────────

/// Serialize a minimal `PriShare<Fr>` so we can write a valid `RingShareBundle`.
fn valid_share_bytes() -> Vec<u8> {
    let pri = PriShare {
        i: 1u32,
        v: Fr::from(42u64),
    };
    CryptoSerialize::to_bytes(&pri).expect("serialize PriShare")
}

fn write_valid_bundle(storage: &LocalStorageImpl, ring_pk: &str) {
    let bundle = RingShareBundle {
        share_bytes: Zeroizing::new(valid_share_bytes()),
        public_polynomial: String::new(),
        last_pss: 0,
    };
    bundle.save_by_ring_key(storage, ring_pk).unwrap();
}

/// Node is not in either committee → `InvalidInput`.
#[test]
fn test_build_reshare_params_not_in_committee() {
    let (storage, db_path) = make_storage("reshare_params_not_in_committee");
    let result = build_reshare_params(
        "ring_pk",
        &["aabbccdd".to_string()],
        &["11223344".to_string()],
        1,
        "post_id",
        "ffffffff", // not in either committee
        &storage,
    );
    assert!(
        matches!(result, Err(DkgError::InvalidInput(_))),
        "Expected InvalidInput for node not in either committee: {:?}",
        result
    );
    cleanup_db(&db_path);
}

/// Pure Receiver (only in new committee) — no share bundle needed.
#[test]
fn test_build_reshare_params_receiver() {
    let (storage, db_path) = make_storage("reshare_params_receiver");
    let result = build_reshare_params(
        "ring_pk",
        &["aabbccdd".to_string()],
        &["11223344".to_string()],
        1,
        "post_id",
        "11223344", // in new committee only
        &storage,
    );
    let (node_id, role, params) = result.expect("Receiver case should succeed");
    assert_eq!(role, DkgRole::Receiver);
    assert_eq!(
        node_id, 1,
        "Receiver gets 1-based index in sorted new committee"
    );
    assert!(params.old_share.is_none(), "Receiver has no old share");
    assert_eq!(params.new_node_id, Some(1));
    cleanup_db(&db_path);
}

/// Pure Dealer (only in old committee) — valid share bundle required.
#[test]
fn test_build_reshare_params_dealer() {
    let (storage, db_path) = make_storage("reshare_params_dealer");
    write_valid_bundle(&storage, "ring_pk");

    let result = build_reshare_params(
        "ring_pk",
        &["aabbccdd".to_string()],
        &["11223344".to_string()],
        1,
        "post_id",
        "aabbccdd", // in old committee only
        &storage,
    );
    let (node_id, role, params) = result.expect("Dealer case should succeed");
    assert_eq!(role, DkgRole::Dealer);
    assert_eq!(node_id, 1);
    assert!(params.old_share.is_some(), "Dealer must have old share");
    assert_eq!(params.new_node_id, None, "Pure Dealer has no new_node_id");
    cleanup_db(&db_path);
}

/// DealerReceiver (in both committees) — valid share bundle required.
#[test]
fn test_build_reshare_params_dealer_receiver() {
    let (storage, db_path) = make_storage("reshare_params_dealer_receiver");
    write_valid_bundle(&storage, "ring_pk");

    let result = build_reshare_params(
        "ring_pk",
        &["aabbccdd".to_string(), "bbbbbbbb".to_string()],
        &["aabbccdd".to_string(), "cccccccc".to_string()],
        1,
        "post_id",
        "aabbccdd", // in both committees
        &storage,
    );
    let (node_id, role, params) = result.expect("DealerReceiver case should succeed");
    assert_eq!(role, DkgRole::DealerReceiver);
    assert_eq!(node_id, 1, "aabbccdd is smallest in old committee");
    assert!(params.old_share.is_some());
    assert_eq!(
        params.new_node_id,
        Some(1),
        "aabbccdd is smallest in new committee"
    );
    cleanup_db(&db_path);
}

/// Dealer path with missing share bundle must return a `Storage` error.
#[test]
fn test_build_reshare_params_dealer_missing_bundle() {
    let (storage, db_path) = make_storage("reshare_params_missing_bundle");
    // No bundle written — load will fail.
    let result = build_reshare_params(
        "ring_pk",
        &["aabbccdd".to_string()],
        &["11223344".to_string()],
        1,
        "post_id",
        "aabbccdd",
        &storage,
    );
    assert!(
        matches!(result, Err(DkgError::Storage(_))),
        "Expected Storage error when share bundle is absent: {:?}",
        result
    );
    cleanup_db(&db_path);
}

/// Unsorted input peer lists must be sorted before computing node indices.
///
/// old = ["cccccccc", "aabbccdd", "bbbbbbbb"] — sorted: ["aabbccdd", "bbbbbbbb", "cccccccc"]
/// Our node is "aabbccdd" → index 1 in sorted old committee.
#[test]
fn test_build_reshare_params_sorts_committees() {
    let (storage, db_path) = make_storage("reshare_params_sorting");
    write_valid_bundle(&storage, "ring_pk");

    let result = build_reshare_params(
        "ring_pk",
        &[
            "cccccccc".to_string(),
            "aabbccdd".to_string(),
            "bbbbbbbb".to_string(),
        ],
        &["11223344".to_string()],
        1,
        "post_id",
        "aabbccdd",
        &storage,
    );
    let (node_id, role, params) = result.expect("sorting test should succeed");
    assert_eq!(role, DkgRole::Dealer);
    assert_eq!(node_id, 1, "aabbccdd must be index 1 after sorting");
    // participating_ids covers the full old committee (3 nodes, 1-based)
    assert_eq!(params.participating_ids, vec![1, 2, 3]);
    cleanup_db(&db_path);
}
