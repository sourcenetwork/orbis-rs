//! Shared policy-authorized derived-key signing conformance scenario.

use super::{pet_dkg_contract::Keys, pre_scenario};
use crypto::r#trait::{CryptoDeserialize, ThresholdSigner};
use crypto::{GroupAffine, SignImpl};
use tokio::time::{sleep, Duration, Instant};

const DERIVATION: &str = "shared-sign-derivation";
const SIGNER_SEED: &str = "shared-sign-reader";
const UNAUTHORIZED_SIGNER_SEED: &str = "shared-sign-unauthorized";
const MESSAGE: &[u8] = b"shared backend threshold signing";

pub(super) struct Outcome {
    pub derivation_id: String,
}

pub(super) trait Backend: pre_scenario::Backend {
    async fn post_key_derivation(
        &self,
        policy_id: &str,
        derivation: &str,
        resource: &str,
        permission: &str,
        ring_pk: &str,
    ) -> (String, String);
}

pub(super) async fn run<B: Backend>(backend: &B, keys: &Keys, policy_id: &str) -> Outcome {
    let (derivation_id, derived_pk) = backend
        .post_key_derivation(
            policy_id,
            DERIVATION,
            pre_scenario::RESOURCE,
            pre_scenario::PERMISSION,
            &keys.main,
        )
        .await;
    assert!(
        !derivation_id.is_empty(),
        "key derivation must return an object id"
    );

    let unauthorized = cli_tool::do_sign(
        backend.node_endpoint(),
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
    backend
        .authorize_object(
            policy_id,
            &derivation_id,
            pre_scenario::RESOURCE,
            pre_scenario::RELATION,
            &signer_did,
        )
        .await;

    let signed = sign_with_retry(backend, &derivation_id).await;
    let signature = <SignImpl as ThresholdSigner>::Signature::from_bytes(
        &hex::decode(&signed.signature).expect("Sign signature is hex"),
    )
    .expect("Sign signature must decode");
    let derived_pk =
        GroupAffine::from_bytes(&hex::decode(&derived_pk).expect("derived public key is hex"))
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

    Outcome { derivation_id }
}

async fn sign_with_retry<B: Backend>(backend: &B, derivation_id: &str) -> cli_tool::SignResult {
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        match cli_tool::do_sign(
            backend.node_endpoint(),
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
