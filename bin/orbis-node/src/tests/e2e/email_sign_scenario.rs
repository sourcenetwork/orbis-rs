//! Docker e2e scenario: DKIM-email-authorized threshold signing.
//!
//! A DKIM-signed reply replaces the JWT entirely — the identity ACP
//! grants/revokes is `did:emailhash:sha256(normalized address)`, the
//! address a node independently extracts from the DKIM-verified message,
//! never a client-asserted field (see `orbis-email`'s own README for the
//! format and the dedicated `did:emailhash:` method). Mirrors
//! `passkey_sign_scenario.rs`'s deny-before-grant / sign / revoke /
//! deny-again / re-grant / sign cycle — same recovery story, same
//! isolation from `sign_scenario.rs`'s Defra-specific checks.
//!
//! Unlike the passkey scenario, DKIM verification needs an actual public
//! key to check the signature against. There's no real DNS record for a
//! synthetic test domain, so this scenario runs the node's *production*
//! pinned-key path (`--email-dkim-keys-file`, `orbis_email::PinnedDnsCache`)
//! instead of live DNS: a freshly generated RSA test key's TXT record is
//! written to a file and bind-mounted into every node container (the
//! `ORBIS_EMAIL_DKIM_KEYS_FILE_SOURCE`/`ORBIS_EMAIL_DKIM_KEYS_FILE` opt-in
//! pass-through in `test_support::network::{vera,cosmos}`), so this still
//! exercises the real node binary end to end — only the DKIM key lookup
//! itself is pinned rather than hitting live DNS, which a synthetic test
//! domain could never do anyway.
//!
//! Also covers the user-requested "swap a field element" case: a validly
//! captured, DKIM-signed reply confirming one message cannot be replayed
//! to authorize a *different* message. The reply's DKIM signature covers
//! `challenge_text`'s full rendering of the operation (derivation id,
//! message digest, expiry, nonce — see `orbis_integration_core::CanonicalDisplay`);
//! changing any one of those fields changes the rendered text, so the
//! swapped request's independently reconstructed text no longer appears in
//! the already-DKIM-verified body.

use super::standard_dkg_pre::POLICY_YAML;
use super::{pre_scenario, TestEnvironmentImpl};
use crypto::r#trait::{CryptoDeserialize, ThresholdSigner};
use crypto::{GroupAffine, SignImpl};
use orbis_email::test_support::TestSigningKey;
use orbis_integration_core::{CanonicalDisplay, SignOperation};
use proto::v0::sign::sign_service_client::SignServiceClient;
use proto::v0::sign::{EmailAssertion, StartSignRequest};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::time::Duration;
use test_support::fixture::{
    AuthorizationTestDriver, BulletinTestDriver, FixtureId, NetworkTestDriver, NodeFixture,
    NodeRef, NodeRole, PolicyFixture, RingFixture, ScenarioFixture, TestEnvironment,
};
use tokio::time::{sleep, Instant};

const RESOURCE: &str = "key";
const RELATION: &str = "signer";
const PERMISSION: &str = "sign";
const DERIVATION: &str = "email-sign-derivation";
const DKIM_DOMAIN: &str = "orbis-email-sign.test";
const DKIM_SELECTOR: &str = "orbistest";
const FROM_ADDRESS: &str = "alice@orbis-email-sign.test";
const REPLACEMENT_ADDRESS: &str = "bob@orbis-email-sign.test";
const TO_ADDRESS: &str = "ring@orbis-email-sign.test";
const MESSAGE: &[u8] = b"email-authorized threshold signing";
const CONTAINER_KEYS_PATH: &str = "/etc/orbis/email-dkim-keys.json";

/// `did:emailhash:sha256(normalized address)` — the exact ACP subject
/// `orbis_email::verify_and_build_token`'s own `build_token` derives,
/// replicated here (not imported: that function is a private
/// implementation detail of `orbis-email`) so this scenario can grant and
/// revoke it like any other actor id.
fn email_issuer_id(address: &str) -> String {
    let normalized = address.trim().to_lowercase();
    format!(
        "did:emailhash:{}",
        hex::encode(Sha256::digest(normalized.as_bytes()))
    )
}

/// Writes a pinned-DKIM-keys file in the format
/// `orbis_email::PinnedDnsCache::load_from_file` expects, world-readable so
/// Docker's bind mount can read it regardless of which user the daemon
/// runs as — mirrors `CosmosNetworkBuilder::build`'s own genesis-patch
/// tempfile handling.
fn write_pinned_keys_file(signing_key: &TestSigningKey) -> tempfile::NamedTempFile {
    let txt_record = std::str::from_utf8(signing_key.txt_record())
        .expect("test DKIM TXT record is ASCII")
        .to_string();
    let contents = serde_json::json!({
        "keys": [
            { "domain": DKIM_DOMAIN, "selector": DKIM_SELECTOR, "txt_record": txt_record },
        ]
    });
    let mut file = tempfile::NamedTempFile::new().expect("pinned DKIM keys tempfile");
    file.write_all(contents.to_string().as_bytes())
        .expect("write pinned DKIM keys tempfile");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mut permissions = file
            .as_file()
            .metadata()
            .expect("read pinned DKIM keys tempfile metadata")
            .permissions();
        permissions.set_mode(0o644);
        file.as_file()
            .set_permissions(permissions)
            .expect("make pinned DKIM keys tempfile readable by Docker container");
    }
    file
}

/// Sets the three env vars the Docker provisioning path forwards into
/// every node container before `provision` (see `test_support::network::
/// {vera,cosmos}`'s opt-in pass-through), and clears them on drop. Safe
/// despite being process-wide global state: every scenario entry point in
/// this tree is `#[serial_test::serial]`, so nothing else runs while these
/// are set — same reasoning as `passkey_sign_scenario.rs`'s `WebAuthnNodeEnv`.
struct EmailNodeEnv;

impl EmailNodeEnv {
    fn set(pinned_keys_host_path: &std::path::Path) -> Self {
        std::env::set_var("ORBIS_EMAIL_EVIDENCE_ENABLED", "true");
        std::env::set_var("ORBIS_EMAIL_DKIM_KEYS_FILE", CONTAINER_KEYS_PATH);
        std::env::set_var(
            "ORBIS_EMAIL_DKIM_KEYS_FILE_SOURCE",
            pinned_keys_host_path.as_os_str(),
        );
        Self
    }
}

impl Drop for EmailNodeEnv {
    fn drop(&mut self) {
        std::env::remove_var("ORBIS_EMAIL_EVIDENCE_ENABLED");
        std::env::remove_var("ORBIS_EMAIL_DKIM_KEYS_FILE");
        std::env::remove_var("ORBIS_EMAIL_DKIM_KEYS_FILE_SOURCE");
    }
}

#[tokio::test]
#[serial_test::serial]
async fn test_email_authorized_signing() {
    let signing_key = TestSigningKey::generate(DKIM_DOMAIN, DKIM_SELECTOR);
    let pinned_keys_file = write_pinned_keys_file(&signing_key);
    let _node_env = EmailNodeEnv::set(pinned_keys_file.path());

    let ring_policy = FixtureId::new("email-sign-ring-policy");
    let key_policy = FixtureId::new("email-sign-key-policy");
    let ring = FixtureId::new("email-sign-ring");
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
                id: key_policy.clone(),
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
    let policy_id = environment.fixture().policies[&key_policy].id.clone();
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
        .expect("derive email Sign public key");

    let signer_id = email_issuer_id(FROM_ADDRESS);

    let denied = cli_tool::do_sign_with_email(
        endpoint.clone(),
        MESSAGE.to_vec(),
        derivation_id.clone(),
        FROM_ADDRESS.to_string(),
        &signing_key,
        TO_ADDRESS,
        None,
        None,
    )
    .await
    .expect_err("signing without a policy relationship must fail");
    pre_scenario::assert_policy_rejection("email Sign without permission", &denied);

    environment
        .register_object(&policy_id, RESOURCE, &derivation_id)
        .await;
    environment
        .grant(&policy_id, RESOURCE, &derivation_id, RELATION, &signer_id)
        .await;

    verify_signature(
        &endpoint,
        &derivation_id,
        &derived_pk,
        &ring_pk,
        &signing_key,
        FROM_ADDRESS,
    )
    .await;

    environment
        .revoke(&policy_id, RESOURCE, &derivation_id, RELATION, &signer_id)
        .await;
    let revoked = cli_tool::do_sign_with_email(
        endpoint.clone(),
        MESSAGE.to_vec(),
        derivation_id.clone(),
        FROM_ADDRESS.to_string(),
        &signing_key,
        TO_ADDRESS,
        None,
        None,
    )
    .await
    .expect_err("signing after revoking the authorized relationship must fail");
    pre_scenario::assert_policy_rejection("email Sign after revocation", &revoked);

    // The whole recovery story for a compromised mailbox: remove the old
    // address from the policy, add a new one. No separate
    // enrollment/binding registry involved — same shape as
    // `passkey_sign_scenario.rs`'s key-replacement cycle.
    let replacement_id = email_issuer_id(REPLACEMENT_ADDRESS);
    environment
        .grant(
            &policy_id,
            RESOURCE,
            &derivation_id,
            RELATION,
            &replacement_id,
        )
        .await;

    verify_signature(
        &endpoint,
        &derivation_id,
        &derived_pk,
        &ring_pk,
        &signing_key,
        REPLACEMENT_ADDRESS,
    )
    .await;

    // A validly captured, DKIM-signed reply confirming one message must
    // not authorize a *different* message, even while the replying
    // address still holds an active grant — isolates this to the
    // challenge-text binding itself, not an incidental policy failure.
    reject_message_swapped_evidence(&endpoint, &derivation_id, &signing_key).await;
}

async fn verify_signature(
    endpoint: &str,
    derivation_id: &str,
    derived_pk: &GroupAffine,
    ring_pk: &GroupAffine,
    signing_key: &TestSigningKey,
    from_address: &str,
) {
    let signed = sign_with_retry(endpoint, derivation_id, signing_key, from_address).await;
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
    signing_key: &TestSigningKey,
    from_address: &str,
) -> cli_tool::SignResult {
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        match cli_tool::do_sign_with_email(
            endpoint.to_string(),
            MESSAGE.to_vec(),
            derivation_id.to_string(),
            from_address.to_string(),
            signing_key,
            TO_ADDRESS,
            None,
            None,
        )
        .await
        {
            Ok(result) => return result,
            Err(error) => {
                assert!(
                    Instant::now() < deadline,
                    "email Sign did not succeed before the scenario deadline: {error}"
                );
                sleep(Duration::from_secs(2)).await;
            }
        }
    }
}

/// Captures a legitimate DKIM-signed reply confirming a Sign operation for
/// `message_a`, then submits it against a `StartSignRequest` carrying a
/// *different* message — the "swap a field element" case. Built with the
/// raw proto client (not `orbis-sdk`, which orbis-node doesn't depend on)
/// since this deliberately constructs a request `orbis-sdk`'s own honest
/// API has no way to produce.
async fn reject_message_swapped_evidence(
    endpoint: &str,
    derivation_id: &str,
    signing_key: &TestSigningKey,
) {
    let message_a = b"the message the reader actually approved".to_vec();
    let message_b = b"a different message the reader never saw".to_vec();

    let issued_at = current_unix_time();
    let expiry = issued_at + 300;
    let nonce = [7u8; 16];

    let operation_for_a = SignOperation {
        derivation_id: derivation_id.to_string(),
        message_sha256: Sha256::digest(&message_a).to_vec(),
        expiry,
        nonce,
    };
    let challenge_text = operation_for_a.canonical_display();
    let raw_message = signing_key.sign_message(
        REPLACEMENT_ADDRESS,
        TO_ADDRESS,
        &format!("confirming:\n{challenge_text}"),
    );

    let email_assertion = EmailAssertion {
        claimed_address: REPLACEMENT_ADDRESS.to_string(),
        raw_message,
        issued_at,
        expiry,
        nonce: nonce.to_vec(),
    };

    let channel = tonic::transport::Channel::from_shared(endpoint.to_string())
        .expect("valid endpoint")
        .connect()
        .await
        .expect("connect to node for swapped-evidence request");
    let mut client = SignServiceClient::new(channel);

    let request = StartSignRequest {
        message: message_b,
        derivation_id: derivation_id.to_string(),
        valid_window: None,
        webauthn_assertion: None,
        email_assertion: Some(email_assertion),
    };
    let result = client.start_sign(tonic::Request::new(request)).await;
    assert!(
        result.is_err(),
        "a reply confirming one message must not authorize signing a different one"
    );
}

fn current_unix_time() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock is after the Unix epoch")
        .as_secs()
}
