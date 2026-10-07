use crypto::r#trait::{CryptoDeserialize, CryptoSerialize, PolynomialCommitment, PriShare};
use local_storage::{
    r#trait::{LocalStorage, LocalStorageKeys},
    LocalStorageImpl,
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

    pub fn share(&self) -> &[u8] {
        &self.bytes[self.share.clone()]
    }

    pub fn make_due(&self, storage: &LocalStorageImpl, ring_id: &str) {
        assert!(
            self.last_pss > 0,
            "initial PET bundle has no completion timestamp"
        );
        let mut due = self.bytes.clone();
        let timestamp = due.len() - 8;
        due[timestamp..].copy_from_slice(&0u64.to_le_bytes());
        assert!(
            due[..timestamp] == self.bytes[..timestamp],
            "backdating changed bundle material"
        );
        storage
            .set_encrypted(LocalStorageKeys::PetRingKey(ring_id.into()), due.clone())
            .unwrap();
        let persisted = storage
            .get_encrypted(LocalStorageKeys::PetRingKey(ring_id.into()))
            .unwrap()
            .unwrap();
        assert!(persisted == due, "persisted backdated bundle differs");
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
