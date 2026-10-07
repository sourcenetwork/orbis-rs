//! Shared standard-DKG StoreSecret → authorized PRE conformance scenario.

use super::pet_dkg_contract::{self, DkgMode, Keys, ScenarioBackend};
use bulletin::r#trait::{BulletinPost, DocumentPayload};
use crypto::r#trait::{CryptoDeserialize, EncryptionProof, ThresholdSigner};
use crypto::{GroupAffine, SignImpl};
use tokio::time::{sleep, Duration, Instant};

pub(super) const READER_SEED: &str = "shared-pre-reader";
pub(super) const RESOURCE: &str = "document";
pub(super) const PERMISSION: &str = "read";
pub(super) const RELATION: &str = "reader";
const UNAUTHORIZED_READER_SEED: &str = "shared-pre-unauthorized";
const PLAINTEXT: &[u8] = b"shared backend StoreSecret and PRE";
const DIRECT_PLAINTEXT: &[u8] = b"shared direct bulletin document";
const DERIVATION: &[u8] = b"shared-pre-derivation";
const SALT: &str = "shared-pre-salt";
const TIER: &str = "shared-pre-tier";
const TIMESTAMP: u64 = 100;
const VALID_WINDOW_START: u64 = 50;
const VALID_WINDOW_END: u64 = 150;

#[derive(Debug)]
// This module is compiled into separate Cosmos and native test binaries. The
// native adapter currently constructs only `Unsupported`; Cosmos exercises
// both variants.
#[allow(dead_code)]
pub(super) enum Capability<T> {
    Supported(T),
    Unsupported(&'static str),
}

pub(super) struct Outcome {
    pub object_id: String,
    pub policy_id: String,
}

/// Backend capabilities that remain chain-specific around an otherwise common
/// Orbis gRPC flow. Optional observations are explicit: an adapter may report
/// `Unsupported`, but it may not turn an unimplemented assertion into `true`.
pub(super) trait Backend: ScenarioBackend {
    fn node_endpoint(&self) -> String;
    fn ring_id(&self) -> &str;
    fn authorization_chain_id(&self) -> String;

    async fn document_policy_id(&self) -> String;
    async fn authorize_object(
        &self,
        policy_id: &str,
        object_id: &str,
        resource: &str,
        relation: &str,
        actor_did: &str,
    );
    async fn read_document(&self, object_id: &str) -> Vec<u8>;

    async fn store_write_marker(&self) -> Capability<u64> {
        Capability::Unsupported("backend exposes no stable StoreSecret write marker")
    }

    async fn post_document_direct(&self, _payload: Vec<u8>) -> Capability<String> {
        Capability::Unsupported("backend adapter does not expose direct bulletin writes")
    }
}

pub(super) async fn run<B: Backend>(config: B::Config) -> (B, Keys, B::LocalState, Outcome) {
    let (backend, keys, local_state) = pet_dkg_contract::run::<B>(config).await;
    assert_eq!(
        backend.mode(),
        DkgMode::Standard,
        "the shared PRE scenario currently exercises a standard non-PET ring"
    );

    let policy_id = backend.document_policy_id().await;
    let prepared = prepare(PLAINTEXT, &keys.main, &policy_id, None, None, None, None);

    verify_optional_direct_path(&backend, &keys.main, &policy_id).await;

    let before_first_store = backend.store_write_marker().await;
    let stored = store_with_retry(&backend, &prepared, true).await;
    assert!(
        !stored.object_id.is_empty(),
        "StoreSecret must return an object id"
    );
    assert!(
        !stored.signature.is_empty(),
        "StoreSecret with_proof must return a threshold signature"
    );
    assert_store_write_happened(&backend, before_first_store).await;
    verify_store_signature(&backend, &keys.main, &stored).await;

    // The object ID and backend write marker must both remain stable for an
    // idempotent retry. Unsupported observations are reported, not faked.
    let before_duplicate = backend.store_write_marker().await;
    let duplicate = store_with_retry(&backend, &prepared, true).await;
    assert_eq!(
        duplicate.object_id, stored.object_id,
        "storing identical prepared ciphertext must return the same object id"
    );
    assert_no_store_write(&backend, before_duplicate).await;

    let derived = prepare(
        PLAINTEXT,
        &keys.main,
        &policy_id,
        Some(DERIVATION.to_vec()),
        Some(TIER.to_string()),
        Some(TIMESTAMP),
        Some(SALT.to_string()),
    );
    let derived_stored = store_with_retry(&backend, &derived, false).await;

    let reader_did = cli_tool::reader_did_from_seed(READER_SEED);
    for object_id in [&stored.object_id, &derived_stored.object_id] {
        backend
            .authorize_object(&policy_id, object_id, RESOURCE, RELATION, &reader_did)
            .await;
    }

    let decrypted = pre_with_retry(
        &backend,
        &keys.main,
        &stored.object_id,
        READER_SEED,
        None,
        None,
        None,
        None,
    )
    .await;
    assert_eq!(
        decrypted, PLAINTEXT,
        "PRE must recover the original plaintext"
    );

    let derived_decrypted = pre_with_retry(
        &backend,
        &keys.main,
        &derived_stored.object_id,
        READER_SEED,
        Some(DERIVATION.to_vec()),
        Some(SALT.to_string()),
        Some(VALID_WINDOW_START),
        Some(VALID_WINDOW_END),
    )
    .await;
    assert_eq!(
        derived_decrypted, PLAINTEXT,
        "derived PRE must recover the original plaintext"
    );

    let unauthorized = cli_tool::do_pre(
        backend.node_endpoint(),
        backend.authorization_chain_id(),
        keys.main.clone(),
        derived_stored.object_id.clone(),
        Some(UNAUTHORIZED_READER_SEED.to_string()),
        Some(DERIVATION.to_vec()),
        Some(SALT.to_string()),
        Some(VALID_WINDOW_START),
        Some(VALID_WINDOW_END),
    )
    .await
    .expect_err("PRE without a policy relationship must fail");
    assert_policy_rejection("PRE without permission", &unauthorized);

    let outside_window = cli_tool::do_pre(
        backend.node_endpoint(),
        backend.authorization_chain_id(),
        keys.main.clone(),
        derived_stored.object_id.clone(),
        Some(READER_SEED.to_string()),
        Some(DERIVATION.to_vec()),
        Some(SALT.to_string()),
        Some(VALID_WINDOW_START),
        Some(VALID_WINDOW_START),
    )
    .await
    .expect_err("PRE outside the document timestamp window must fail");
    assert_policy_rejection("PRE outside the valid timestamp window", &outside_window);

    (
        backend,
        keys,
        local_state,
        Outcome {
            object_id: stored.object_id,
            policy_id,
        },
    )
}

fn prepare(
    plaintext: &[u8],
    ring_pk: &str,
    policy_id: &str,
    derivation: Option<Vec<u8>>,
    tier: Option<String>,
    timestamp: Option<u64>,
    salt: Option<String>,
) -> cli_tool::PreparedSecret {
    cli_tool::prepare_secret(
        plaintext,
        ring_pk,
        derivation,
        policy_id.to_string(),
        RESOURCE.to_string(),
        PERMISSION.to_string(),
        tier,
        timestamp,
        salt,
        None,
    )
    .expect("prepare shared PRE secret")
}

async fn verify_optional_direct_path<B: Backend>(backend: &B, ring_pk: &str, policy_id: &str) {
    let prepared = prepare(DIRECT_PLAINTEXT, ring_pk, policy_id, None, None, None, None);
    let payload = DocumentPayload {
        ring_id: backend.ring_id().to_string(),
        document: String::from_utf8(prepared.encrypted_document).expect("encrypted JSON is UTF-8"),
        proof: EncryptionProof {
            challenge: prepared.challenge,
            response: prepared.response,
        }
        .try_into()
        .expect("serialize direct encryption proof"),
        policy_id: policy_id.to_string(),
        resource: RESOURCE.to_string(),
        permission: PERMISSION.to_string(),
        tier: None,
        timestamp: None,
        pet_tag: None,
        pet_tag_proof: None,
    };
    let bytes: Vec<u8> = payload
        .clone()
        .try_into()
        .expect("serialize direct document");
    match backend.post_document_direct(bytes).await {
        Capability::Supported(object_id) => {
            let restored: DocumentPayload =
                serde_json::from_slice(&backend.read_document(&object_id).await)
                    .expect("parse direct document read-back");
            assert_eq!(
                restored, payload,
                "direct bulletin document must round-trip"
            );
        }
        Capability::Unsupported(reason) => {
            eprintln!("shared PRE capability skipped: direct bulletin write ({reason})");
        }
    }
}

async fn verify_store_signature<B: Backend>(
    backend: &B,
    ring_pk: &str,
    stored: &cli_tool::StoreSecretResult,
) {
    let post = BulletinPost {
        id: stored.object_id.clone(),
        payload: backend.read_document(&stored.object_id).await,
    };
    let message: Vec<u8> = post
        .try_into()
        .expect("serialize authoritative bulletin post");
    let public_key = GroupAffine::from_bytes(&hex::decode(ring_pk).expect("ring key is hex"))
        .expect("ring key is a curve point");
    let signature = <SignImpl as ThresholdSigner>::Signature::from_bytes(
        &hex::decode(&stored.signature).expect("StoreSecret signature is hex"),
    )
    .expect("StoreSecret signature must decode");
    SignImpl::new()
        .verify(&public_key, &message, &signature)
        .expect("StoreSecret signature must verify over authoritative bulletin bytes");
}

async fn assert_store_write_happened<B: Backend>(backend: &B, before: Capability<u64>) {
    let Capability::Supported(before) = before else {
        if let Capability::Unsupported(reason) = before {
            eprintln!("shared PRE capability skipped: first-store write marker ({reason})");
        }
        return;
    };
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        match backend.store_write_marker().await {
            Capability::Supported(after) if after > before => return,
            Capability::Supported(_) => {
                assert!(
                    Instant::now() < deadline,
                    "StoreSecret did not advance the backend write marker"
                );
                sleep(Duration::from_millis(200)).await;
            }
            Capability::Unsupported(reason) => {
                panic!("StoreSecret write-marker support changed during the scenario: {reason}")
            }
        }
    }
}

async fn assert_no_store_write<B: Backend>(backend: &B, before: Capability<u64>) {
    let Capability::Supported(before) = before else {
        if let Capability::Unsupported(reason) = before {
            eprintln!("shared PRE capability skipped: duplicate-store write marker ({reason})");
        }
        return;
    };
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        match backend.store_write_marker().await {
            Capability::Supported(after) => assert_eq!(
                after, before,
                "idempotent StoreSecret must not advance the backend write marker"
            ),
            Capability::Unsupported(reason) => {
                panic!("StoreSecret write-marker support changed during the scenario: {reason}")
            }
        }
        if Instant::now() >= deadline {
            return;
        }
        sleep(Duration::from_millis(200)).await;
    }
}

async fn store_with_retry<B: Backend>(
    backend: &B,
    prepared: &cli_tool::PreparedSecret,
    with_proof: bool,
) -> cli_tool::StoreSecretResult {
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        match cli_tool::store_prepared_secret(
            backend.node_endpoint(),
            prepared,
            backend.ring_id().to_string(),
            Some(READER_SEED.to_string()),
            with_proof,
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

#[allow(clippy::too_many_arguments)]
async fn pre_with_retry<B: Backend>(
    backend: &B,
    ring_pk: &str,
    object_id: &str,
    reader_seed: &str,
    derivation: Option<Vec<u8>>,
    salt: Option<String>,
    valid_window_start: Option<u64>,
    valid_window_end: Option<u64>,
) -> Vec<u8> {
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        match cli_tool::do_pre(
            backend.node_endpoint(),
            backend.authorization_chain_id(),
            ring_pk.to_string(),
            object_id.to_string(),
            Some(reader_seed.to_string()),
            derivation.clone(),
            salt.clone(),
            valid_window_start,
            valid_window_end,
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

pub(super) fn assert_policy_rejection(context: &str, error: &anyhow::Error) {
    let status = error
        .downcast_ref::<tonic::Status>()
        .unwrap_or_else(|| panic!("{context}: expected tonic::Status source, got: {error:#}"));
    assert_eq!(
        status.code(),
        tonic::Code::Unauthenticated,
        "{context}: unexpected server status: {status}"
    );
}
