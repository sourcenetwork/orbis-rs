use crypto::r#trait::{CryptoDeserialize, CryptoSerialize, PolynomialCommitment, PriShare};
use local_storage::{
    r#trait::{LocalStorage, LocalStorageKeys},
    LocalStorageImpl,
};
use proto::unsafe_testing::{
    unsafe_testing_service_client::UnsafeTestingServiceClient, GetLocalStorageRequest,
    LocalStorageAccessMode, LocalStorageKey, LocalStorageKeyType, SetLocalStorageRequest,
};
use std::{ops::Range, path::Path};
use zeroize::Zeroizing;

pub(super) struct Bundle {
    pub bytes: Zeroizing<Vec<u8>>,
    share: Range<usize>,
    pub polynomial: String,
    pub last_pss: u64,
}

impl Bundle {
    pub fn load(
        storage: &LocalStorageImpl,
        key: LocalStorageKeys,
        public_key: &str,
        member: u32,
    ) -> Self {
        let bytes = storage
            .get_encrypted(key)
            .unwrap()
            .expect("persisted ring bundle");
        Self::decode(bytes, public_key, member)
    }

    fn decode(bytes: Zeroizing<Vec<u8>>, public_key: &str, member: u32) -> Self {
        // Version 1: share length/data, polynomial length/hex, then the LE timestamp.
        assert!(
            (17..=65_536).contains(&bytes.len()),
            "invalid fixture bundle size"
        );
        assert_eq!(bytes[0], 1, "fixture requires the current bundle codec");
        let mut cursor = 1;
        let share = field(&bytes, &mut cursor);
        let polynomial_range = field(&bytes, &mut cursor);
        assert_eq!(cursor + 8, bytes.len(), "bundle trailing bytes");
        let polynomial = std::str::from_utf8(&bytes[polynomial_range])
            .unwrap()
            .to_owned();
        let encoded = hex::decode(&polynomial).unwrap();
        assert_eq!(
            hex::encode(&encoded),
            polynomial,
            "noncanonical polynomial hex"
        );
        assert_eq!(encoded.len(), 4 + 2 * crypto::GROUP_POINT_SIZE);
        assert_eq!(u32::from_le_bytes(encoded[..4].try_into().unwrap()), 2);
        let commitment = crypto::PolynomialCommitmentImpl::from_bytes(&encoded).unwrap();
        assert_eq!(commitment.to_bytes().unwrap(), encoded);
        assert_eq!(
            commitment.eval(0).to_bytes().unwrap(),
            hex::decode(public_key).unwrap()
        );
        let secret = PriShare::<crypto::ScalarField>::from_bytes(&bytes[share.clone()]).unwrap();
        let canonical = Zeroizing::new(secret.to_bytes().unwrap());
        assert!(
            canonical.as_slice() == &bytes[share.clone()],
            "noncanonical private share"
        );
        assert_eq!(secret.i, member);
        assert!(
            commitment.verify_share(secret.i, &secret.v),
            "share does not match polynomial"
        );
        let last_pss = u64::from_le_bytes(bytes[cursor..].try_into().unwrap());
        Self {
            bytes,
            share,
            polynomial,
            last_pss,
        }
    }

    pub fn backdated(bytes: Vec<u8>, public_key: &str, member: u32) -> Vec<u8> {
        let bundle = Self::decode(Zeroizing::new(bytes), public_key, member);
        bundle.due_bytes().to_vec()
    }

    pub fn polynomial(bytes: &[u8], public_key: &str, member: u32) -> String {
        Self::decode(Zeroizing::new(bytes.to_vec()), public_key, member).polynomial
    }

    pub fn share(&self) -> &[u8] {
        &self.bytes[self.share.clone()]
    }

    pub fn make_due(&self, storage: &LocalStorageImpl, ring_id: &str) {
        self.make_due_at(storage, LocalStorageKeys::PetRingKey(ring_id.into()));
    }

    fn make_due_at(&self, storage: &LocalStorageImpl, key: LocalStorageKeys) {
        let due = self.due_bytes();
        storage.set_encrypted(key.clone(), due.clone()).unwrap();
        let persisted = storage.get_encrypted(key).unwrap().unwrap();
        assert!(persisted == due, "persisted backdated bundle differs");
    }

    fn due_bytes(&self) -> Zeroizing<Vec<u8>> {
        assert!(
            self.last_pss > 0,
            "initial ring bundle has no completion timestamp"
        );
        let mut due = self.bytes.clone();
        let timestamp = due.len() - 8;
        due[timestamp..].copy_from_slice(&0u64.to_le_bytes());
        assert!(
            due[..timestamp] == self.bytes[..timestamp],
            "backdating changed bundle material"
        );
        due
    }
}

fn field(bytes: &[u8], cursor: &mut usize) -> Range<usize> {
    let header = bytes
        .get(*cursor..*cursor + 4)
        .expect("truncated bundle length");
    let len = u32::from_le_bytes(header.try_into().unwrap()) as usize;
    *cursor += 4;
    let end = cursor.checked_add(len).expect("bundle field overflow");
    assert!(len > 0 && end <= bytes.len(), "invalid bundle field length");
    let range = *cursor..end;
    *cursor = end;
    range
}

/// Backdate the main ring bundle on each still-running member. Call this only
/// after the target process has stopped: a 5-second interval is already inside
/// the scheduler's grace window, so the refresh would otherwise start while
/// that member was still up and then miss the test's demerit wait.
pub(super) async fn backdate_live_main_ring(
    nodes: &[(String, String)],
    ring_pk: &str,
    members: &[String],
) {
    let main_storage_key =
        crypto::GroupAffine::from_bytes(&hex::decode(ring_pk).expect("ring public key is hex"))
            .expect("ring public key must decode")
            .to_string();
    let assignments =
        crate::helpers::node_routes::canonical_node_id_assignments_from_node_keys(members)
            .expect("ring member keys are unique");
    let mut backdated = 0usize;
    for (endpoint, node_key) in nodes {
        if !members.iter().any(|key| key == node_key) {
            continue;
        }
        let member = assignments
            .get(node_key)
            .copied()
            .expect("node key must be a ring member");
        let mut control = UnsafeTestingServiceClient::connect(endpoint.clone())
            .await
            .expect("connect refresh test control");
        let storage_key = LocalStorageKey {
            key_type: LocalStorageKeyType::RingKey as i32,
            ring_key: main_storage_key.clone(),
        };
        let stored = control
            .get_local_storage(GetLocalStorageRequest {
                key: Some(storage_key.clone()),
                access_mode: LocalStorageAccessMode::Encrypted as i32,
            })
            .await
            .expect("read live refresh bundle")
            .into_inner();
        assert!(stored.found, "refresh bundle must exist");
        let due = Bundle::backdated(stored.value, ring_pk, member);
        control
            .set_local_storage(SetLocalStorageRequest {
                key: Some(storage_key),
                access_mode: LocalStorageAccessMode::Encrypted as i32,
                value: due,
            })
            .await
            .expect("backdate live refresh bundle");
        backdated += 1;
    }
    assert!(backdated > 0, "refresh backdate requires a running member");
}

/// Backdate the main ring bundle in a stopped node's store so the
/// scheduler treats a refresh as due on the next start. The polynomial and
/// share bytes stay as they were.
pub(super) fn backdate_main_ring(directory: &Path, public_key: &str, member: u32) {
    let storage = open(directory);
    let main_key =
        crypto::GroupAffine::from_bytes(&hex::decode(public_key).expect("ring public key is hex"))
            .expect("ring public key must decode")
            .to_string();
    let key = LocalStorageKeys::RingKey(main_key);
    let stored = storage
        .get_encrypted(key.clone())
        .expect("read stopped ring bundle")
        .expect("stopped node must already hold the ring bundle");
    let due = Bundle::backdated(stored.to_vec(), public_key, member);
    storage
        .set_encrypted(key, Zeroizing::new(due))
        .expect("persist backdated ring bundle");
}

pub(super) fn persisted_kdf_params(directory: &Path) -> local_storage::common::StoredKdfParams {
    open(directory)
        .stored_kdf_params()
        .expect("read persisted KDF header")
}

pub(super) fn open(directory: &Path) -> LocalStorageImpl {
    let backend = LocalStorageImpl::name();
    assert_eq!(backend, "local-storage/redb");
    let path = directory.join("dbs/orbis.redb");
    assert!(path.is_file(), "restart must reopen an existing store");
    LocalStorageImpl::new(
        std::fs::read_to_string(directory.join("password")).unwrap(),
        path.to_str().unwrap().into(),
    )
    .unwrap()
}
