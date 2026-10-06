//! Finite refresh qualification: only the persisted PET timestamp is backdated.
//! The real scheduler dispatch, transport, cryptography and 86400-second interval remain active.
//! This does not qualify 24-hour native-service scheduling or the native permission backend.

use super::{pss_ring, read_ring_index};
use crate::{
    dkg::v0::{
        error::DkgError,
        helpers::derive_fresh_pet_dkg_session_id,
        network::{start_refresh_pet, RefreshStartOutcome},
        service::DkgServiceImpl,
    },
    helpers::test_helpers::{
        cleanup_db, create_authenticated_request, get_test_ring_post, setup_three_node_network,
        test_db_path, TestKeyPair, TEST_FRESH_DKG_RING_ID,
    },
    ring_state::RingShareBundle,
};
use bulletin::r#trait::{Bulletin, BulletinKind, RingPayload};
use crypto::{
    r#trait::{CryptoDeserialize, CryptoSerialize, Dkg, Pet, PubPoly},
    DkgImpl, PetImpl,
};
use local_storage::{common::StoredKdfParams, r#trait::LocalStorage, LocalStorageImpl};
use proto::v0::dkg::{dkg_service_server::DkgService, StartDkgRequest};
use redb::{ReadableDatabase, TableDefinition};
use std::{sync::Arc, time::Duration};

struct Stores([String; 3]);
impl Drop for Stores {
    fn drop(&mut self) {
        for path in &self.0 {
            cleanup_db(path);
        }
    }
}

#[test]
#[serial_test::serial]
#[ignore = "requires isolated production-KDF qualification (262144 KiB, t=3)"]
fn independent_pet_refresh_preserves_keys_and_reopens_rotated_shares() {
    let unique = tempfile::tempdir().unwrap();
    let name = format!(
        "pet-refresh-{}",
        unique.path().file_name().unwrap().to_string_lossy()
    );
    let stores = Stores(std::array::from_fn(|index| {
        test_db_path(&format!("{name}_{}", index + 1))
    }));
    let (ring, main_before, refreshed) = {
        // Dropping the runtime terminates remaining protocol tasks and closes every DB handle.
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(refresh(&name))
    };
    let mut reopened = Vec::new();
    let main_key = main_key(&ring);
    for (index, path) in stores.0.iter().enumerate() {
        let storage = LocalStorageImpl::new("test-password".into(), path.clone()).unwrap();
        assert_production_kdf(&storage);
        let main = RingShareBundle::load_by_ring_key(&storage, &main_key).unwrap();
        assert_same_bundle(&main, &main_before[index]);
        let pet = RingShareBundle::load_by_pet_ring_key(&storage, TEST_FRESH_DKG_RING_ID).unwrap();
        assert_same_bundle(&pet, &refreshed[index]);
        reopened.push(pet);
    }
    assert_usable_pet_shares(&ring, &reopened);
}

async fn refresh(name: &str) -> (RingPayload, Vec<RingShareBundle>, Vec<RingShareBundle>) {
    let mut network = setup_three_node_network(true, name).await;
    for state in [
        &network.alice.app_state,
        &network.bob.app_state,
        &network.charlie.app_state,
    ] {
        assert_production_kdf(&state.local_storage);
    }
    let bulletin = network.dummy_bulletin.as_ref().unwrap().clone();
    let mut ring: RingPayload = bulletin
        .read(TEST_FRESH_DKG_RING_ID.into(), BulletinKind::Ring)
        .await
        .unwrap()
        .try_into()
        .unwrap();
    ring.requires_pet = true;
    assert_eq!(ring.pss_interval, 86400);
    bulletin
        .set_ring(TEST_FRESH_DKG_RING_ID.into(), ring)
        .unwrap();
    let service =
        DkgServiceImpl::<DkgImpl>::with_routes(network.alice.app_state.clone(), &network::V0);
    let token = TestKeyPair::new()
        .create_dkg_jwt(TEST_FRESH_DKG_RING_ID)
        .unwrap();
    service
        .start_dkg(
            create_authenticated_request(
                StartDkgRequest {
                    ring_id: TEST_FRESH_DKG_RING_ID.into(),
                },
                &token,
            )
            .unwrap(),
        )
        .await
        .unwrap();
    drop(service);
    let states = [
        &network.alice.app_state,
        &network.bob.app_state,
        &network.charlie.app_state,
    ];
    let fresh_pet_session = derive_fresh_pet_dkg_session_id(TEST_FRESH_DKG_RING_ID).unwrap();
    let ring = tokio::time::timeout(Duration::from_secs(90), async {
        loop {
            let mut cleanup_complete = true;
            for state in states {
                let session_present = state
                    .dkg_session_state
                    .session_exists(&fresh_pet_session)
                    .await;
                let claim = state
                    .dkg_session_state
                    .active_ring_pss_session(TEST_FRESH_DKG_RING_ID)
                    .await;
                cleanup_complete &= !session_present && claim.is_none();
            }
            if let Ok(ring) = RingPayload::try_from(get_test_ring_post(&bulletin)) {
                if cleanup_complete
                    && ring.pet_pk.is_some()
                    && states.iter().all(|state| {
                        RingShareBundle::load_by_pet_ring_key(
                            &state.local_storage,
                            TEST_FRESH_DKG_RING_ID,
                        )
                        .is_ok()
                    })
                {
                    break ring;
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("paired fresh DKG and every original node’s FreshPet cleanup must complete");
    let main_key = main_key(&ring);
    let main_before: Vec<_> = states
        .iter()
        .map(|state| RingShareBundle::load_by_ring_key(&state.local_storage, &main_key).unwrap())
        .collect();
    let pet_before: Vec<_> = states
        .iter()
        .map(|state| {
            RingShareBundle::load_by_pet_ring_key(&state.local_storage, TEST_FRESH_DKG_RING_ID)
                .unwrap()
        })
        .collect();
    assert_usable_pet_shares(&ring, &pet_before);
    let leader = states
        .iter()
        .copied()
        .min_by(|a, b| a.node_key.cmp(&b.node_key))
        .unwrap();
    assert!(matches!(
        start_refresh_pet(
            Arc::new(leader.clone()),
            &network::V0,
            TEST_FRESH_DKG_RING_ID.into()
        )
        .await
        .unwrap(),
        RefreshStartOutcome::NotDue
    ));

    for (state, old) in states.iter().zip(&pet_before) {
        let mut due = old.clone();
        due.last_pss = 0;
        due.save_by_pet_ring_key(&state.local_storage, TEST_FRESH_DKG_RING_ID)
            .unwrap();
    }
    // Membership remains an authorization boundary even when the elapsed-time check is met.
    let mut outsider = leader.clone();
    outsider.node_key = "not-a-current-member".into();
    assert!(matches!(
        start_refresh_pet(
            Arc::new(outsider),
            &network::V0,
            TEST_FRESH_DKG_RING_ID.into()
        )
        .await,
        Err(DkgError::Unauthorized(_))
    ));
    let entry = read_ring_index(&leader.local_storage)
        .unwrap()
        .into_iter()
        .find(|entry| entry.bulletin_post_id == TEST_FRESH_DKG_RING_ID)
        .unwrap();
    // Dispatch through the normal independent scheduling path, not a reshare or forced RPC.
    tokio::time::timeout(
        Duration::from_secs(60),
        pss_ring(&Arc::new(leader.clone()), &entry),
    )
    .await
    .expect("refresh scheduling must be bounded")
    .unwrap();
    let refreshed = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            let bundles: Vec<_> = states
                .iter()
                .map(|state| {
                    RingShareBundle::load_by_pet_ring_key(
                        &state.local_storage,
                        TEST_FRESH_DKG_RING_ID,
                    )
                    .unwrap()
                })
                .collect();
            if bundles.iter().zip(&pet_before).all(|(new, old)| {
                new.last_pss > 0
                    && new.public_polynomial != old.public_polynomial
                    && new.share_bytes != old.share_bytes
            }) && bundles
                .iter()
                .all(|bundle| bundle.public_polynomial == bundles[0].public_polynomial)
            {
                break bundles;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("independent PET refresh must rotate every share and converge");
    for (state, old) in states.iter().zip(&main_before) {
        assert_same_bundle(
            &RingShareBundle::load_by_ring_key(&state.local_storage, &main_key).unwrap(),
            old,
        );
    }
    let current: RingPayload = bulletin
        .read(TEST_FRESH_DKG_RING_ID.into(), BulletinKind::Ring)
        .await
        .unwrap()
        .try_into()
        .unwrap();
    assert_eq!(
        serde_json::to_value(&current).unwrap(),
        serde_json::to_value(&ring).unwrap()
    );
    assert_usable_pet_shares(&ring, &refreshed);
    // The completed timestamp must prevent immediately starting a second rotation.
    tokio::time::timeout(Duration::from_secs(10), async {
        while leader
            .dkg_session_state
            .active_ring_pss_session(TEST_FRESH_DKG_RING_ID)
            .await
            .is_some()
        {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("completed refresh must release its scheduler claim");
    assert!(matches!(
        start_refresh_pet(
            Arc::new(leader.clone()),
            &network::V0,
            TEST_FRESH_DKG_RING_ID.into()
        )
        .await
        .unwrap(),
        RefreshStartOutcome::NotDue
    ));
    network.shutdown_routers().await.unwrap();
    (ring, main_before, refreshed)
}

fn assert_production_kdf(storage: &LocalStorageImpl) {
    let transaction = storage.store.begin_read().unwrap();
    let table = transaction
        .open_table(TableDefinition::<&[u8], &[u8]>::new("orbis_local"))
        .unwrap();
    let stored = table
        .get(b"__internal__kdf_params".as_slice())
        .unwrap()
        .unwrap();
    assert_eq!(
        StoredKdfParams::from_bytes(stored.value()).unwrap(),
        StoredKdfParams {
            m_cost_kib: 262_144,
            t_cost: 3,
            p_cost: 1,
            version: 0x13,
        },
        "run this isolated qualification with ORBIS_LOCAL_STORAGE_KDF_M_COST_KIB=262144 and ORBIS_LOCAL_STORAGE_KDF_T_COST=3; the shared fixture otherwise lowers costs"
    );
}

fn main_key(ring: &RingPayload) -> String {
    <DkgImpl as Dkg>::PublicKey::from_bytes(&hex::decode(&ring.ring_pk).unwrap())
        .unwrap()
        .to_string()
}

fn assert_same_bundle(actual: &RingShareBundle, expected: &RingShareBundle) {
    // Avoid emitting secret share bytes if a regression is detected.
    assert!(
        actual.share_bytes == expected.share_bytes,
        "persisted private share differs"
    );
    assert_eq!(actual.public_polynomial, expected.public_polynomial);
    assert_eq!(actual.last_pss, expected.last_pss);
}

fn assert_usable_pet_shares(ring: &RingPayload, bundles: &[RingShareBundle]) {
    let pet_key = ring.pet_pk.as_ref().unwrap();
    let (tag, _) = cli_tool::generate_pet_tag(pet_key, "refresh-owner").unwrap();
    let mut shares = Vec::new();
    for bundle in bundles {
        let polynomial =
            <DkgImpl as Dkg>::PubPoly::from_bytes(&hex::decode(&bundle.public_polynomial).unwrap())
                .unwrap();
        assert_eq!(
            polynomial.eval(0).to_bytes().unwrap(),
            hex::decode(pet_key).unwrap()
        );
        let share = bundle.pri_share().unwrap();
        let reply = PetImpl::partial_pet_check(&share.v, share.i, &tag).unwrap();
        PetImpl::verify_partial_pet_check(&polynomial, &tag, &reply).unwrap();
        shares.push(reply.partial.clone());
    }
    for pair in [[0, 1], [0, 2], [1, 2]] {
        let selected = [shares[pair[0]].clone(), shares[pair[1]].clone()];
        let combined = PetImpl::combine_pet_check_shares(&selected, 2, 3).unwrap();
        PetImpl::verify_pet_match(
            &tag,
            &combined,
            &PetImpl::owner_fingerprint(b"refresh-owner").unwrap(),
        )
        .unwrap();
        assert!(PetImpl::verify_pet_match(
            &tag,
            &combined,
            &PetImpl::owner_fingerprint(b"other-owner").unwrap()
        )
        .is_err());
    }
}
