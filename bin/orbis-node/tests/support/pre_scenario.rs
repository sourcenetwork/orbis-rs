//! Shared standard-DKG StoreSecret → authorized PRE conformance scenario.

use super::pet_dkg_contract::{self, DkgMode, Keys, ScenarioBackend};
use tokio::time::{sleep, Duration, Instant};

const READER_SEED: &str = "shared-pre-reader";
const RESOURCE: &str = "document";
const PERMISSION: &str = "read";
const PLAINTEXT: &[u8] = b"shared backend StoreSecret and PRE";

pub(super) struct Outcome {
    pub object_id: String,
}

/// Backend capabilities that remain chain-specific around an otherwise common
/// Orbis gRPC flow.
pub(super) trait Backend: ScenarioBackend {
    fn node_endpoint(&self) -> String;
    fn ring_id(&self) -> &str;
    fn authorization_chain_id(&self) -> String;

    async fn document_policy_id(&self) -> String;
    async fn authorize_reader(&self, policy_id: &str, object_id: &str, reader_did: &str);
}

pub(super) async fn run<B: Backend>(config: B::Config) -> (B, Keys, B::LocalState, Outcome) {
    let (backend, keys, local_state) = pet_dkg_contract::run::<B>(config).await;
    assert_eq!(
        backend.mode(),
        DkgMode::Standard,
        "the shared PRE scenario currently exercises a standard non-PET ring"
    );

    let policy_id = backend.document_policy_id().await;
    let prepared = cli_tool::prepare_secret(
        PLAINTEXT,
        &keys.main,
        None,
        policy_id.clone(),
        RESOURCE.to_string(),
        PERMISSION.to_string(),
        None,
        None,
        None,
        None,
    )
    .expect("prepare shared PRE secret");

    let stored = store_with_retry(&backend, &prepared).await;
    assert!(
        !stored.object_id.is_empty(),
        "StoreSecret must return an object id"
    );
    assert!(
        !stored.signature.is_empty(),
        "StoreSecret with_proof must return a threshold signature"
    );

    let reader_did = cli_tool::reader_did_from_seed(READER_SEED);
    backend
        .authorize_reader(&policy_id, &stored.object_id, &reader_did)
        .await;

    let decrypted = pre_with_retry(&backend, &keys.main, &stored.object_id).await;
    assert_eq!(
        decrypted, PLAINTEXT,
        "PRE must recover the original plaintext"
    );

    // API-level idempotency is common to both backends. Backend-specific
    // transaction/account-sequence assertions remain in their own suites.
    let duplicate = store_with_retry(&backend, &prepared).await;
    assert_eq!(
        duplicate.object_id, stored.object_id,
        "storing identical prepared ciphertext must return the same object id"
    );

    (
        backend,
        keys,
        local_state,
        Outcome {
            object_id: stored.object_id,
        },
    )
}

async fn store_with_retry<B: Backend>(
    backend: &B,
    prepared: &cli_tool::PreparedSecret,
) -> cli_tool::StoreSecretResult {
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        match cli_tool::store_prepared_secret(
            backend.node_endpoint(),
            prepared,
            backend.ring_id().to_string(),
            Some(READER_SEED.to_string()),
            true,
            None,
        )
        .await
        {
            Ok(result) => return result,
            Err(error) => {
                assert!(
                    Instant::now() < deadline,
                    "StoreSecret did not succeed before the shared scenario deadline: {error}"
                );
                sleep(Duration::from_secs(2)).await;
            }
        }
    }
}

async fn pre_with_retry<B: Backend>(backend: &B, ring_pk: &str, object_id: &str) -> Vec<u8> {
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        match cli_tool::do_pre(
            backend.node_endpoint(),
            backend.authorization_chain_id(),
            ring_pk.to_string(),
            object_id.to_string(),
            Some(READER_SEED.to_string()),
            None,
            None,
            None,
            None,
        )
        .await
        {
            Ok(plaintext) => return plaintext,
            Err(error) => {
                assert!(
                    Instant::now() < deadline,
                    "PRE did not succeed before the shared scenario deadline: {error}"
                );
                sleep(Duration::from_secs(2)).await;
            }
        }
    }
}
