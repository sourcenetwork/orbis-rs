//! Shared standard-DKG StoreSecret → authorized PRE conformance scenario —
//! triggers and verifies DKG itself too, absorbing what the retired
//! `pet_dkg_contract::{Backend, ScenarioBackend}` traits did for this
//! scenario specifically. `pet_dkg_contract.rs`
//! (`bin/orbis-node/tests/support/pet_dkg_contract.rs`) is untouched and
//! still backs the PET scenarios that still use it — this is a parallel,
//! non-generic implementation for the one DKG/PRE slice, not a replacement.

use super::TestEnvironmentImpl;
use bulletin::r#trait::{BulletinPost, DocumentPayload};
use crypto::r#trait::{CryptoDeserialize, Dkg, EncryptionProof, PubPoly, ThresholdSigner};
use crypto::{DkgImpl, GroupAffine, SignImpl};
use proto::info_service::{info_service_client::InfoServiceClient, GetRingStateRequest};
use proto::v0::dkg::{dkg_service_client::DkgServiceClient, StartDkgRequest};
use test_support::admin::{PolicyId, RingId};
use test_support::fixture::{
    AuthorizationTestDriver, BulletinTestDriver, NetworkTestDriver, TestEnvironment,
};
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

pub(super) struct Keys {
    pub main: String,
}

pub(super) struct Outcome {
    pub object_id: String,
}

/// Trigger DKG on `ring`, wait for it to finalize, and return the finalized
/// main public key plus every running node's local polynomial commitment
/// (the baseline refresh/reshare rotate away from).
pub(super) async fn run_dkg(
    environment: &TestEnvironmentImpl,
    ring: &RingId,
) -> (Keys, Vec<String>) {
    let endpoint = environment.nodes()[0].grpc_endpoint.clone();
    let session_id = DkgServiceClient::connect(endpoint)
        .await
        .expect("connect to node for DKG trigger")
        .start_dkg(StartDkgRequest {
            ring_id: ring.0.clone(),
        })
        .await
        .expect("DKG should succeed")
        .into_inner()
        .session_id;
    assert!(!session_id.is_empty(), "DKG must return a session id");

    let view = environment
        .wait_for_finalized(ring, Duration::from_secs(240))
        .await;
    assert_eq!(
        view.confirmations, 0,
        "finalized confirmations must be cleared"
    );
    assert!(
        !view.requires_pet,
        "the shared DKG/PRE scenario uses a standard non-PET ring"
    );
    assert!(
        view.pet_pk.is_none(),
        "standard DKG must not produce a PET key"
    );
    let main = view.ring_pk;
    assert!(!main.is_empty(), "DKG must finalize the main key");
    let bytes = hex::decode(&main).expect("finalized key must be hex");
    let point = GroupAffine::from_bytes(&bytes).expect("finalized key must be a valid curve point");
    assert_ne!(
        point,
        GroupAffine::default(),
        "finalized key must not be identity"
    );

    let local_state =
        wait_for_polynomials(environment.nodes(), &main, None, Duration::from_secs(60)).await;
    for state in &local_state {
        assert_polynomial(state, &main);
    }
    (Keys { main }, local_state)
}

/// Poll every node in `nodes`' `InfoService.GetRingState` until they all
/// agree on the same, non-empty polynomial commitment — and, when `previous`
/// is given, until every one of them has *changed* from it (used after a
/// refresh/reshare to prove the rotation actually happened). Callers pass a
/// subset of `environment.nodes()` for a reshare that drops members. Shared,
/// backend-neutral replacement for the old `wait_for_ring_state_on_all_nodes`
/// (Cosmos)/`wait_polynomials`/`wait_main_polynomials` (native) — same
/// `InfoService` contract on both backends, so one implementation instead of
/// near-duplicates.
pub(super) async fn wait_for_polynomials(
    nodes: &[test_support::NodeInfo],
    ring_pk: &str,
    previous: Option<&[String]>,
    timeout: Duration,
) -> Vec<String> {
    if let Some(previous) = previous {
        assert_eq!(previous.len(), nodes.len());
    }
    tokio::time::timeout(timeout, async {
        loop {
            let mut states = Vec::with_capacity(nodes.len());
            for node in nodes {
                let Ok(mut client) = InfoServiceClient::connect(node.grpc_endpoint.clone()).await
                else {
                    break;
                };
                match client
                    .get_ring_state(GetRingStateRequest {
                        ring_pk_hex: ring_pk.to_string(),
                    })
                    .await
                {
                    Ok(state) => states.push(state.into_inner().public_polynomial),
                    Err(_) => break,
                }
            }
            if states.len() == nodes.len()
                && !states[0].is_empty()
                && states.iter().all(|state| state == &states[0])
                && previous.is_none_or(|old| states.iter().zip(old).all(|(now, old)| now != old))
            {
                return states;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("all members must hold the same polynomial generation")
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

pub(super) async fn run(
    environment: &TestEnvironmentImpl,
    ring: &RingId,
    policy: &PolicyId,
) -> (Keys, Vec<String>, Outcome) {
    let (keys, local_state) = run_dkg(environment, ring).await;

    let prepared = prepare(PLAINTEXT, &keys.main, &policy.0, None, None, None, None);

    verify_optional_direct_path(environment, ring, &keys.main, &policy.0).await;

    let stored = store_with_retry(environment, ring, &prepared, true).await;
    assert!(
        !stored.object_id.is_empty(),
        "StoreSecret must return an object id"
    );
    assert!(
        !stored.signature.is_empty(),
        "StoreSecret with_proof must return a threshold signature"
    );
    verify_store_signature(environment, &keys.main, &stored).await;

    // The object ID must remain stable for an idempotent retry.
    let duplicate = store_with_retry(environment, ring, &prepared, true).await;
    assert_eq!(
        duplicate.object_id, stored.object_id,
        "storing identical prepared ciphertext must return the same object id"
    );

    let derived = prepare(
        PLAINTEXT,
        &keys.main,
        &policy.0,
        Some(DERIVATION.to_vec()),
        Some(TIER.to_string()),
        Some(TIMESTAMP),
        Some(SALT.to_string()),
    );
    let derived_stored = store_with_retry(environment, ring, &derived, false).await;

    let reader_did = cli_tool::reader_did_from_seed(READER_SEED);
    for object_id in [&stored.object_id, &derived_stored.object_id] {
        environment
            .register_object(policy, RESOURCE, object_id)
            .await;
        environment
            .grant(policy, RESOURCE, object_id, RELATION, &reader_did)
            .await;
    }

    let decrypted = pre_with_retry(
        environment,
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
        environment,
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
        environment.nodes()[0].grpc_endpoint.clone(),
        environment.chain_id(),
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
        environment.nodes()[0].grpc_endpoint.clone(),
        environment.chain_id(),
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
        keys,
        local_state,
        Outcome {
            object_id: stored.object_id,
        },
    )
}

/// Re-run the successful, policy-authorized PRE operation against the object
/// created before a share-generation transition. This is intentionally a
/// separate contract from `run`: refresh and reshare tests must prove an
/// existing object remains usable, not merely that a newly-created one works.
pub(super) async fn verify_existing(
    environment: &TestEnvironmentImpl,
    keys: &Keys,
    outcome: &Outcome,
) {
    let decrypted = pre_with_retry(
        environment,
        &keys.main,
        &outcome.object_id,
        READER_SEED,
        None,
        None,
        None,
        None,
    )
    .await;
    assert_eq!(
        decrypted, PLAINTEXT,
        "PRE must keep decrypting an existing document after a share-generation transition"
    );
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

async fn verify_optional_direct_path(
    environment: &TestEnvironmentImpl,
    ring: &RingId,
    ring_pk: &str,
    policy_id: &str,
) {
    if !environment.supports_direct_document_write() {
        eprintln!("shared PRE capability skipped: direct bulletin write (backend has no direct-write path)");
        return;
    }
    let prepared = prepare(DIRECT_PLAINTEXT, ring_pk, policy_id, None, None, None, None);
    let payload = DocumentPayload {
        ring_id: ring.0.clone(),
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
    let document_id = environment.store_document(ring, &bytes, &[]).await;
    let restored: DocumentPayload =
        serde_json::from_slice(&environment.read_document(&document_id).await)
            .expect("parse direct document read-back");
    assert_eq!(
        restored, payload,
        "direct bulletin document must round-trip"
    );
}

async fn verify_store_signature(
    environment: &TestEnvironmentImpl,
    ring_pk: &str,
    stored: &cli_tool::StoreSecretResult,
) {
    let post = BulletinPost {
        id: stored.object_id.clone(),
        payload: environment
            .read_document(&test_support::admin::DocumentId(stored.object_id.clone()))
            .await,
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

async fn store_with_retry(
    environment: &TestEnvironmentImpl,
    ring: &RingId,
    prepared: &cli_tool::PreparedSecret,
    with_proof: bool,
) -> cli_tool::StoreSecretResult {
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        match cli_tool::store_prepared_secret(
            environment.nodes()[0].grpc_endpoint.clone(),
            prepared,
            ring.0.clone(),
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
async fn pre_with_retry(
    environment: &TestEnvironmentImpl,
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
            environment.nodes()[0].grpc_endpoint.clone(),
            environment.chain_id(),
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
