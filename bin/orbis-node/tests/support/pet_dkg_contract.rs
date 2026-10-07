//! Shared paired-DKG assertions for the Cosmos and native Docker scenarios.

use crypto::r#trait::{Dkg, PubPoly};
use crypto::{CryptoDeserialize, DkgImpl, GroupAffine};

pub(super) struct FinalizedRing {
    pub requires_pet: bool,
    pub confirmations: usize,
    pub public_key: String,
    pub pet_public_key: Option<String>,
}

pub(super) struct Keys {
    pub main: String,
    pub pet: String,
}

pub(super) trait Backend {
    type LocalState;

    async fn finalized_ring(&self) -> FinalizedRing;
    async fn local_state(&self, keys: &Keys) -> Self::LocalState;
}

pub(super) async fn verify<B: Backend>(backend: &B) -> (Keys, B::LocalState) {
    let ring = backend.finalized_ring().await;
    assert!(ring.requires_pet, "finalized ring must retain PET mode");
    assert_eq!(
        ring.confirmations, 0,
        "finalized confirmations must be cleared"
    );
    let keys = Keys {
        main: ring.public_key,
        pet: ring
            .pet_public_key
            .expect("paired DKG must finalize the PET key"),
    };
    assert!(
        !keys.main.is_empty(),
        "paired DKG must finalize the main key"
    );
    assert!(!keys.pet.is_empty(), "paired DKG must finalize the PET key");
    assert_ne!(keys.main, keys.pet, "PET and main keys must be independent");
    for key in [&keys.main, &keys.pet] {
        let bytes = hex::decode(key).expect("finalized key must be hex");
        let point =
            GroupAffine::from_bytes(&bytes).expect("finalized key must be a valid curve point");
        assert_ne!(
            point,
            GroupAffine::default(),
            "finalized key must not be identity"
        );
    }
    let local = backend.local_state(&keys).await;
    (keys, local)
}

pub(super) fn assert_polynomial(encoded: &str, key: &str) {
    let bytes = hex::decode(encoded).expect("local polynomial must be hex");
    let polynomial = <DkgImpl as Dkg>::PubPoly::from_bytes(&bytes)
        .expect("local polynomial must decode on the selected curve");
    let key = GroupAffine::from_bytes(&hex::decode(key).expect("finalized key must be hex"))
        .expect("finalized key must decode on the selected curve");
    assert_eq!(
        polynomial.eval(0),
        key,
        "local polynomial must commit to the finalized key"
    );
}
