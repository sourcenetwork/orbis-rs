//! Shared paired-DKG scenario and assertions for the Cosmos and native Docker
//! backends.

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
    pub pet: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum DkgMode {
    Standard,
    Pet,
}

impl DkgMode {
    pub fn requires_pet(self) -> bool {
        matches!(self, Self::Pet)
    }
}

pub(super) trait Backend {
    type LocalState;

    fn mode(&self) -> DkgMode;
    async fn finalized_ring(&self) -> FinalizedRing;
    async fn local_state(&self, keys: &Keys) -> Self::LocalState;
}

/// Backend-specific construction and DKG triggering for the shared paired-DKG
/// scenario. Provisioning remains behind the adapter because Cosmos seeds its
/// ring in genesis while native Vera creates and authorizes it through its own
/// protocol. Once provisioned, both backends execute the same scenario body.
pub(super) trait ScenarioBackend: Backend + Sized {
    type Config;

    async fn provision(config: Self::Config) -> Self;
    async fn start_dkg(&self) -> String;
}

/// Provision one backend, trigger its paired DKG, then run the common
/// finalization and local-state assertions. The backend fixture is returned so
/// callers can continue into longer PET/PRE scenarios without rebuilding it.
pub(super) async fn run<B: ScenarioBackend>(config: B::Config) -> (B, Keys, B::LocalState) {
    let backend = B::provision(config).await;
    let session_id = backend.start_dkg().await;
    assert!(!session_id.is_empty(), "DKG must return a session id");
    let (keys, local_state) = verify(&backend).await;
    (backend, keys, local_state)
}

pub(super) async fn verify<B: Backend>(backend: &B) -> (Keys, B::LocalState) {
    let ring = backend.finalized_ring().await;
    assert_eq!(
        ring.requires_pet,
        backend.mode().requires_pet(),
        "finalized ring must retain its configured DKG mode"
    );
    assert_eq!(
        ring.confirmations, 0,
        "finalized confirmations must be cleared"
    );
    let keys = Keys {
        main: ring.public_key,
        pet: ring.pet_public_key,
    };
    assert!(!keys.main.is_empty(), "DKG must finalize the main key");
    match backend.mode() {
        DkgMode::Standard => assert!(
            keys.pet.is_none(),
            "standard DKG must not produce a PET key"
        ),
        DkgMode::Pet => {
            let pet = keys
                .pet
                .as_ref()
                .expect("paired DKG must finalize the PET key");
            assert!(!pet.is_empty(), "paired DKG must finalize the PET key");
            assert_ne!(&keys.main, pet, "PET and main keys must be independent");
        }
    }
    for key in std::iter::once(&keys.main).chain(keys.pet.iter()) {
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
