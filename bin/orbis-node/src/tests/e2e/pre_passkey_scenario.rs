//! Docker e2e scenario: passkey-authorized PRE decryption.
//!
//! A WebAuthn assertion replaces the JWT entirely for the *read* side only
//! — storing the encrypted document still goes through the ordinary JWT
//! `StoreSecret` path, since that step's authentication method is
//! irrelevant to what this scenario proves. The identity ACP grants/revokes
//! is the `did:key` the passkey's own P-256 public key decodes to directly;
//! there is no separate enrollment registry. Mirrors
//! `passkey_sign_scenario.rs`'s deny-before-grant / decrypt / revoke /
//! deny-again / re-grant / decrypt cycle, which is exactly what proves
//! "remove from policy, add a new one" is the whole recovery story for a
//! lost or compromised passkey — same proof PRE's own JWT-authorized
//! scenario (`pre_scenario::run`) already gives for the JWT path.
//!
//! Runs against its own ring/policy (not the one `standard_dkg_pre.rs`'s
//! shared scenarios provision) so the `ORBIS_WEBAUTHN_RP_ID`/
//! `ORBIS_WEBAUTHN_ORIGIN` node env vars this test sets — the opt-in
//! pass-through in `test_support::network::{vera,cosmos}` — apply only to
//! this test's own containers, never to a scenario that must keep rejecting
//! WebAuthn-authorized PRE requests.

use super::standard_dkg_pre::POLICY_YAML;
use super::{pre_scenario, TestEnvironmentImpl};
use p256::ecdsa::SigningKey;
use std::time::Duration;
use test_support::fixture::{
    AuthorizationTestDriver, FixtureId, NetworkTestDriver, NodeFixture, NodeRef, NodeRole,
    PolicyFixture, RingFixture, ScenarioFixture, TestEnvironment,
};
use tokio::time::{sleep, Instant};

const RESOURCE: &str = "document";
const RELATION: &str = "reader";
const RP_ID: &str = "orbis-passkey-pre.test";
const ORIGIN: &str = "https://orbis-passkey-pre.test";
const PLAINTEXT: &[u8] = b"passkey-authorized PRE decryption";

fn reader_key() -> SigningKey {
    let mut scalar = [0u8; 32];
    scalar[31] = 52;
    SigningKey::from_bytes((&scalar).into()).expect("small nonzero scalar is a valid P-256 key")
}

fn unauthorized_key() -> SigningKey {
    let mut scalar = [0u8; 32];
    scalar[31] = 53;
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
async fn test_passkey_authorized_pre_decryption() {
    let _node_env = WebAuthnNodeEnv::set();

    // Two separate policy fixtures, not one shared between the ring and the
    // document — same byte-identical YAML, but a ring-creation grant and a
    // document registration need their own on-chain policy ids. Mirrors
    // every other `pre_scenario::run` caller (`standard_dkg_pre.rs`,
    // `member_replacement.rs`, `scheduled_refresh.rs`), none of which reuse
    // the ring's own policy for document registration.
    let ring_policy = FixtureId::new("passkey-pre-ring-policy");
    let document_policy = FixtureId::new("passkey-pre-document-policy");
    let ring = FixtureId::new("passkey-pre-ring");
    let fixture = ScenarioFixture {
        requires_unsafe_testing: true,
        nodes: (0..3)
            .map(|_| NodeFixture {
                id: FixtureId::new("node"),
                role: NodeRole::Running,
            })
            .collect(),
        policies: vec![
            PolicyFixture {
                id: ring_policy.clone(),
                definition: POLICY_YAML.to_string(),
            },
            PolicyFixture {
                id: document_policy.clone(),
                definition: POLICY_YAML.to_string(),
            },
        ],
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
            policy: ring_policy,
            reporting: Default::default(),
            upgrade: None,
        }],
        ..Default::default()
    };

    let environment = TestEnvironmentImpl::provision(fixture).await;
    let ring_id = environment.fixture().rings[&ring].id.clone();
    let policy_id = environment.fixture().policies[&document_policy].id.clone();
    let endpoint = environment.nodes()[0].grpc_endpoint.clone();
    let chain_id = environment.chain_id();

    let (keys, _local_state) = pre_scenario::run_dkg(&environment, &ring_id).await;

    let prepared =
        pre_scenario::prepare(PLAINTEXT, &keys.main, &policy_id.0, None, None, None, None);
    let stored = pre_scenario::store_with_retry(&environment, &ring_id, &prepared, false).await;
    assert!(
        !stored.object_id.is_empty(),
        "StoreSecret must return an object id"
    );
    environment
        .register_object(&policy_id, RESOURCE, &stored.object_id)
        .await;

    let reader = reader_key();
    let reader_did = did_for(&reader);
    let unauthorized = unauthorized_key();

    let denied = cli_tool::do_pre_with_passkey(
        endpoint.clone(),
        chain_id.clone(),
        keys.main.clone(),
        stored.object_id.clone(),
        &unauthorized,
        RP_ID,
        ORIGIN,
        None,
        None,
        None,
        None,
    )
    .await
    .expect_err("decrypting without a policy relationship must fail");
    pre_scenario::assert_policy_rejection("passkey PRE without permission", &denied);

    environment
        .grant(
            &policy_id,
            RESOURCE,
            &stored.object_id,
            RELATION,
            &reader_did,
        )
        .await;

    let decrypted =
        decrypt_with_retry(&endpoint, &chain_id, &keys.main, &stored.object_id, &reader).await;
    assert_eq!(
        decrypted, PLAINTEXT,
        "passkey PRE must recover the original plaintext"
    );

    environment
        .revoke(
            &policy_id,
            RESOURCE,
            &stored.object_id,
            RELATION,
            &reader_did,
        )
        .await;
    let revoked = cli_tool::do_pre_with_passkey(
        endpoint.clone(),
        chain_id.clone(),
        keys.main.clone(),
        stored.object_id.clone(),
        &reader,
        RP_ID,
        ORIGIN,
        None,
        None,
        None,
        None,
    )
    .await
    .expect_err("decrypting after revoking the authorized relationship must fail");
    pre_scenario::assert_policy_rejection("passkey PRE after revocation", &revoked);

    // The whole recovery story for a lost or compromised passkey: remove
    // the old DID from the policy, add a new one. No separate
    // enrollment/binding registry involved.
    let replacement = {
        let mut scalar = [0u8; 32];
        scalar[31] = 54;
        SigningKey::from_bytes((&scalar).into()).expect("small nonzero scalar is a valid P-256 key")
    };
    let replacement_did = did_for(&replacement);
    environment
        .grant(
            &policy_id,
            RESOURCE,
            &stored.object_id,
            RELATION,
            &replacement_did,
        )
        .await;

    let restored = decrypt_with_retry(
        &endpoint,
        &chain_id,
        &keys.main,
        &stored.object_id,
        &replacement,
    )
    .await;
    assert_eq!(
        restored, PLAINTEXT,
        "passkey PRE must succeed again, with a new passkey, after the reader relationship is restored"
    );
}

async fn decrypt_with_retry(
    endpoint: &str,
    chain_id: &str,
    ring_pk: &str,
    object_id: &str,
    signing_key: &SigningKey,
) -> Vec<u8> {
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        match cli_tool::do_pre_with_passkey(
            endpoint.to_string(),
            chain_id.to_string(),
            ring_pk.to_string(),
            object_id.to_string(),
            signing_key,
            RP_ID,
            ORIGIN,
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
                    "passkey PRE did not succeed before the scenario deadline: {error}"
                );
                sleep(Duration::from_secs(2)).await;
            }
        }
    }
}
