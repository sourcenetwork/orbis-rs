//! Docker e2e scenario: passkey-authorized threshold signing.
//!
//! A WebAuthn assertion replaces the JWT entirely — the identity ACP
//! grants/revokes is the `did:key` the passkey's own P-256 public key
//! decodes to directly; there is no separate enrollment registry. Mirrors
//! `sign_scenario.rs`'s deny-before-grant / sign / revoke / deny-again /
//! re-grant / sign cycle, which is exactly what proves "remove from policy,
//! add a new one" is the whole recovery story for a lost or compromised
//! passkey. Deliberately skips `sign_scenario.rs`'s Defra-specific checks:
//! those exercise a remote-signing integration unrelated to how a request
//! gets authenticated.
//!
//! Runs against its own ring/policy (not the one `standard_dkg_pre.rs`'s
//! shared scenarios provision) so the `ORBIS_WEBAUTHN_RP_ID`/
//! `ORBIS_WEBAUTHN_ORIGIN` node env vars this test sets — the opt-in
//! pass-through in `test_support::network::{vera,cosmos}` — apply only to
//! this test's own containers, never to a scenario that must keep rejecting
//! WebAuthn-authorized Sign requests.

use super::standard_dkg_pre::POLICY_YAML;
use super::{pre_scenario, TestEnvironmentImpl};
use crypto::r#trait::{CryptoDeserialize, ThresholdSigner};
use crypto::{GroupAffine, SignImpl};
use p256::ecdsa::SigningKey;
use std::time::Duration;
use test_support::fixture::{
    AuthorizationTestDriver, BulletinTestDriver, FixtureId, NetworkTestDriver, NodeFixture,
    NodeRef, NodeRole, PolicyFixture, RingFixture, ScenarioFixture, TestEnvironment,
};
use tokio::time::{sleep, Instant};

const RESOURCE: &str = "key";
const RELATION: &str = "signer";
const PERMISSION: &str = "sign";
const DERIVATION: &str = "passkey-sign-derivation";
const RP_ID: &str = "orbis-passkey-sign.test";
const ORIGIN: &str = "https://orbis-passkey-sign.test";
const MESSAGE: &[u8] = b"passkey-authorized threshold signing";

fn signer_key() -> SigningKey {
    let mut scalar = [0u8; 32];
    scalar[31] = 42;
    SigningKey::from_bytes((&scalar).into()).expect("small nonzero scalar is a valid P-256 key")
}

fn unauthorized_key() -> SigningKey {
    let mut scalar = [0u8; 32];
    scalar[31] = 43;
    SigningKey::from_bytes((&scalar).into()).expect("small nonzero scalar is a valid P-256 key")
}

fn did_for(key: &SigningKey) -> String {
    let compressed: [u8; 33] = key
        .verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .expect("compressed P-256 point is 33 bytes");
    authn::did_from_p256_public_key(&compressed)
}

/// Sets the two env vars the Docker provisioning path forwards into every
/// node container before `provision`, and clears them on drop. Safe despite
/// being process-wide global state: every scenario entry point in this tree
/// is `#[serial_test::serial]`, so nothing else runs while these are set.
struct WebAuthnNodeEnv;

impl WebAuthnNodeEnv {
    fn set() -> Self {
        std::env::set_var("ORBIS_WEBAUTHN_RP_ID", RP_ID);
        std::env::set_var("ORBIS_WEBAUTHN_ORIGIN", ORIGIN);
        Self
    }
}

impl Drop for WebAuthnNodeEnv {
    fn drop(&mut self) {
        std::env::remove_var("ORBIS_WEBAUTHN_RP_ID");
        std::env::remove_var("ORBIS_WEBAUTHN_ORIGIN");
    }
}

#[tokio::test]
#[serial_test::serial]
async fn test_passkey_authorized_signing() {
    let _node_env = WebAuthnNodeEnv::set();

    let policy = FixtureId::new("passkey-sign-policy");
    let ring = FixtureId::new("passkey-sign-ring");
    let fixture = ScenarioFixture {
        requires_unsafe_testing: true,
        nodes: (0..3)
            .map(|_| NodeFixture {
                id: FixtureId::new("node"),
                role: NodeRole::Running,
            })
            .collect(),
        policies: vec![PolicyFixture {
            id: policy.clone(),
            definition: POLICY_YAML.to_string(),
        }],
        rings: vec![RingFixture {
            id: ring.clone(),
            members: vec![
                NodeRef::Running(0),
                NodeRef::Running(1),
                NodeRef::Running(2),
            ],
            threshold: 2,
            pss_interval: Duration::from_secs(5),
            requires_pet: false,
            policy: policy.clone(),
            reporting: Default::default(),
            upgrade: None,
        }],
        ..Default::default()
    };

    let environment = TestEnvironmentImpl::provision(fixture).await;
    let ring_id = environment.fixture().rings[&ring].id.clone();
    let policy_id = environment.fixture().policies[&policy].id.clone();
    let endpoint = environment.nodes()[0].grpc_endpoint.clone();

    let (keys, _local_state) = pre_scenario::run_dkg(&environment, &ring_id).await;

    let derivation_id = environment
        .register_key_derivation(&ring_id, DERIVATION, &policy_id, RESOURCE, PERMISSION)
        .await;
    assert!(
        !derivation_id.is_empty(),
        "key derivation must return an object id"
    );

    let ring_pk = GroupAffine::from_bytes(&hex::decode(&keys.main).expect("ring key is hex"))
        .expect("ring key must decode");
    let metadata = SignImpl::encode_metadata(&policy_id.0, RESOURCE, PERMISSION);
    let derived_pk = SignImpl::derive_public_key(&ring_pk, DERIVATION.as_bytes(), Some(&metadata))
        .expect("derive passkey Sign public key");

    let signer = signer_key();
    let signer_did = did_for(&signer);
    let unauthorized = unauthorized_key();

    let denied = cli_tool::do_sign_with_passkey(
        endpoint.clone(),
        MESSAGE.to_vec(),
        derivation_id.clone(),
        &unauthorized,
        RP_ID,
        ORIGIN,
        None,
        None,
    )
    .await
    .expect_err("signing without a policy relationship must fail");
    super::pre_scenario::assert_policy_rejection("passkey Sign without permission", &denied);

    environment
        .register_object(&policy_id, RESOURCE, &derivation_id)
        .await;
    environment
        .grant(&policy_id, RESOURCE, &derivation_id, RELATION, &signer_did)
        .await;

    verify_signature(&endpoint, &derivation_id, &derived_pk, &ring_pk, &signer).await;

    environment
        .revoke(&policy_id, RESOURCE, &derivation_id, RELATION, &signer_did)
        .await;
    let revoked = cli_tool::do_sign_with_passkey(
        endpoint.clone(),
        MESSAGE.to_vec(),
        derivation_id.clone(),
        &signer,
        RP_ID,
        ORIGIN,
        None,
        None,
    )
    .await
    .expect_err("signing after revoking the authorized relationship must fail");
    super::pre_scenario::assert_policy_rejection("passkey Sign after revocation", &revoked);

    // The whole recovery story for a lost or compromised passkey: remove
    // the old DID from the policy, add a new one. No separate
    // enrollment/binding registry involved.
    let replacement = {
        let mut scalar = [0u8; 32];
        scalar[31] = 44;
        SigningKey::from_bytes((&scalar).into()).expect("small nonzero scalar is a valid P-256 key")
    };
    let replacement_did = did_for(&replacement);
    environment
        .grant(
            &policy_id,
            RESOURCE,
            &derivation_id,
            RELATION,
            &replacement_did,
        )
        .await;

    verify_signature(
        &endpoint,
        &derivation_id,
        &derived_pk,
        &ring_pk,
        &replacement,
    )
    .await;
}

async fn verify_signature(
    endpoint: &str,
    derivation_id: &str,
    derived_pk: &GroupAffine,
    ring_pk: &GroupAffine,
    signing_key: &SigningKey,
) {
    let signed = sign_with_retry(endpoint, derivation_id, signing_key).await;
    let signature = <SignImpl as ThresholdSigner>::Signature::from_bytes(
        &hex::decode(&signed.signature).expect("Sign signature is hex"),
    )
    .expect("Sign signature must decode");
    SignImpl::new()
        .verify(derived_pk, MESSAGE, &signature)
        .expect("signature must verify against the derived public key");
    assert!(
        SignImpl::new()
            .verify(ring_pk, MESSAGE, &signature)
            .is_err(),
        "a derived-key signature must not verify against the bare ring key"
    );
}

async fn sign_with_retry(
    endpoint: &str,
    derivation_id: &str,
    signing_key: &SigningKey,
) -> cli_tool::SignResult {
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        match cli_tool::do_sign_with_passkey(
            endpoint.to_string(),
            MESSAGE.to_vec(),
            derivation_id.to_string(),
            signing_key,
            RP_ID,
            ORIGIN,
            None,
            None,
        )
        .await
        {
            Ok(result) => return result,
            Err(error) => {
                assert!(
                    Instant::now() < deadline,
                    "passkey Sign did not succeed before the scenario deadline: {error}"
                );
                sleep(Duration::from_secs(2)).await;
            }
        }
    }
}
