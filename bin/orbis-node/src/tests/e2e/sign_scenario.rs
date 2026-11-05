//! Shared policy-authorized derived-key signing conformance scenario.

use super::{pre_scenario, TestEnvironmentImpl};
use crypto::r#trait::{CryptoDeserialize, CryptoSerialize, ThresholdSigner};
use crypto::{GroupAffine, SignImpl};
#[cfg(all(feature = "native", feature = "bls12-381"))]
use defra_core::signing::RemoteSigner;
#[cfg(all(feature = "native", feature = "bls12-381"))]
use sha2::{Digest, Sha256};
#[cfg(all(feature = "native", feature = "bls12-381"))]
use std::sync::Arc;
use test_support::admin::{PolicyId, RingId};
use test_support::fixture::{AuthorizationTestDriver, BulletinTestDriver, NetworkTestDriver};
use tokio::time::{sleep, Duration, Instant};

const DERIVATION: &str = "shared-sign-derivation";
const SIGNER_SEED: &str = "shared-sign-reader";
const UNAUTHORIZED_SIGNER_SEED: &str = "shared-sign-unauthorized";
const MESSAGE: &[u8] = b"shared backend threshold signing";

pub(super) struct Outcome {
    pub derivation_id: String,
    derived_pk: String,
}

pub(super) async fn run(
    environment: &TestEnvironmentImpl,
    ring: &RingId,
    keys: &pre_scenario::Keys,
    policy: &PolicyId,
) -> Outcome {
    let endpoint = environment.nodes()[0].grpc_endpoint.clone();
    let derivation_id = environment
        .register_key_derivation(
            ring,
            DERIVATION,
            policy,
            pre_scenario::RESOURCE,
            pre_scenario::PERMISSION,
        )
        .await;
    assert!(
        !derivation_id.is_empty(),
        "key derivation must return an object id"
    );
    // Deriving the public key from the ring key is pure curve math,
    // identical on both backends — computed here once instead of inside
    // each backend's own key-derivation call, as the old adapters did.
    let ring_pk = GroupAffine::from_bytes(&hex::decode(&keys.main).expect("ring key is hex"))
        .expect("ring key must decode");
    let metadata =
        SignImpl::encode_metadata(&policy.0, pre_scenario::RESOURCE, pre_scenario::PERMISSION);
    let derived_pk = SignImpl::derive_public_key(&ring_pk, DERIVATION.as_bytes(), Some(&metadata))
        .expect("derive shared Sign public key");
    let derived_pk = hex::encode(derived_pk.to_bytes().expect("serialize derived public key"));

    let unauthorized = cli_tool::do_sign(
        environment.nodes()[0].grpc_endpoint.clone(),
        MESSAGE.to_vec(),
        derivation_id.clone(),
        Some(UNAUTHORIZED_SIGNER_SEED.to_string()),
        None,
        None,
    )
    .await
    .expect_err("signing without a policy relationship must fail");
    pre_scenario::assert_policy_rejection("Sign without permission", &unauthorized);

    let signer_did = cli_tool::reader_did_from_seed(SIGNER_SEED);
    environment
        .register_object(policy, pre_scenario::RESOURCE, &derivation_id)
        .await;
    #[cfg(all(feature = "native", feature = "bls12-381"))]
    let defra = {
        let client = defra_client(&endpoint, &derivation_id, &derived_pk).await;
        let error = defra_sign(&client)
            .await
            .expect_err("Defra signing requires a grant");
        assert!(
            error
                .message
                .contains(&tonic::Code::Unauthenticated.to_string()),
            "{error:?}"
        );
        client
    };
    environment
        .grant(
            policy,
            pre_scenario::RESOURCE,
            &derivation_id,
            pre_scenario::RELATION,
            &signer_did,
        )
        .await;

    verify_signature(&endpoint, keys, &derivation_id, &derived_pk).await;
    #[cfg(all(feature = "native", feature = "bls12-381"))]
    assert!(
        defra_sign(&defra).await.is_ok(),
        "Defra signing should succeed after grant"
    );

    environment
        .revoke(
            policy,
            pre_scenario::RESOURCE,
            &derivation_id,
            pre_scenario::RELATION,
            &signer_did,
        )
        .await;
    let revoked = cli_tool::do_sign(
        environment.nodes()[0].grpc_endpoint.clone(),
        MESSAGE.to_vec(),
        derivation_id.clone(),
        Some(SIGNER_SEED.to_string()),
        None,
        None,
    )
    .await
    .expect_err("signing after revoking the authorized relationship must fail");
    pre_scenario::assert_policy_rejection("Sign after revocation", &revoked);
    #[cfg(all(feature = "native", feature = "bls12-381"))]
    let error = defra_sign(&defra)
        .await
        .expect_err("Defra signing must fail after revocation");
    #[cfg(all(feature = "native", feature = "bls12-381"))]
    assert!(
        error
            .message
            .contains(&tonic::Code::Unauthenticated.to_string()),
        "{error:?}"
    );
    environment
        .grant(
            policy,
            pre_scenario::RESOURCE,
            &derivation_id,
            pre_scenario::RELATION,
            &signer_did,
        )
        .await;
    verify_signature(&endpoint, keys, &derivation_id, &derived_pk).await;
    #[cfg(all(feature = "native", feature = "bls12-381"))]
    assert!(
        defra_sign(&defra).await.is_ok(),
        "Defra signing should recover after regrant"
    );

    Outcome {
        derivation_id,
        derived_pk,
    }
}

#[cfg(all(feature = "native", feature = "bls12-381"))]
async fn defra_client(
    endpoint: &str,
    derivation_id: &str,
    derived_pk: &str,
) -> defra_orbis::OrbisClient {
    let seed: [u8; 32] = Sha256::digest(SIGNER_SEED.as_bytes()).into();
    let identity = Arc::new(
        defra_identity::RawIdentity::from_ed25519(
            defra_crypto::Ed25519PrivateKey::from_bytes(
                &defra_crypto::ed25519_key_from_seed(&seed).unwrap(),
            )
            .unwrap(),
        )
        .unwrap(),
    );
    assert_eq!(
        defra_identity::Identity::did(identity.as_ref())
            .unwrap()
            .to_string(),
        cli_tool::reader_did_from_seed(SIGNER_SEED),
    );
    defra_orbis::OrbisClient::new(
        endpoint.to_owned(),
        derivation_id.to_owned(),
        hex::decode(derived_pk).unwrap(),
        identity,
        defra_edge::on_demand().unwrap().clone(),
    )
    .await
    .expect("connect Defra signer")
}

#[cfg(all(feature = "native", feature = "bls12-381"))]
async fn defra_sign(
    client: &defra_orbis::OrbisClient,
) -> Result<Vec<u8>, defra_core::signing::SignFailure> {
    let mut results = client.sign_batch(vec![Arc::from(MESSAGE)], None).await;
    assert_eq!(results.len(), 1);
    results.pop().unwrap()
}

/// Reuse the derivation object created before a share-generation transition
/// and verify that a new signature still uses the same derived public key.
pub(super) async fn verify_existing(
    environment: &TestEnvironmentImpl,
    keys: &pre_scenario::Keys,
    outcome: &Outcome,
) {
    let endpoint = environment.nodes()[0].grpc_endpoint.clone();
    verify_existing_at(environment, &endpoint, keys, outcome).await;
}

/// Same contract as [`verify_existing`] against an endpoint chosen by the
/// caller. See [`pre_scenario::verify_existing_at`].
pub(super) async fn verify_existing_at(
    _environment: &TestEnvironmentImpl,
    endpoint: &str,
    keys: &pre_scenario::Keys,
    outcome: &Outcome,
) {
    verify_signature(endpoint, keys, &outcome.derivation_id, &outcome.derived_pk).await;
    #[cfg(all(feature = "native", feature = "bls12-381"))]
    {
        let client = defra_client(endpoint, &outcome.derivation_id, &outcome.derived_pk).await;
        assert!(
            defra_sign(&client).await.is_ok(),
            "Defra signing must survive the transition"
        );
    }
}

async fn verify_signature(
    endpoint: &str,
    keys: &pre_scenario::Keys,
    derivation_id: &str,
    derived_pk: &str,
) {
    let signed = sign_with_retry(endpoint, derivation_id).await;
    let signature = <SignImpl as ThresholdSigner>::Signature::from_bytes(
        &hex::decode(&signed.signature).expect("Sign signature is hex"),
    )
    .expect("Sign signature must decode");
    let derived_pk =
        GroupAffine::from_bytes(&hex::decode(derived_pk).expect("derived public key is hex"))
            .expect("derived public key must decode");
    SignImpl::new()
        .verify(&derived_pk, MESSAGE, &signature)
        .expect("signature must verify against the derived public key");

    let ring_pk = GroupAffine::from_bytes(&hex::decode(&keys.main).expect("ring key is hex"))
        .expect("ring key must decode");
    assert!(
        SignImpl::new()
            .verify(&ring_pk, MESSAGE, &signature)
            .is_err(),
        "a derived-key signature must not verify against the bare ring key"
    );
}

async fn sign_with_retry(endpoint: &str, derivation_id: &str) -> cli_tool::SignResult {
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        match cli_tool::do_sign(
            endpoint.to_string(),
            MESSAGE.to_vec(),
            derivation_id.to_string(),
            Some(SIGNER_SEED.to_string()),
            None,
            None,
        )
        .await
        {
            Ok(result) => return result,
            Err(error) => {
                assert!(
                    Instant::now() < deadline,
                    "Sign did not succeed before the shared scenario deadline: {error}"
                );
                sleep(Duration::from_secs(2)).await;
            }
        }
    }
}
