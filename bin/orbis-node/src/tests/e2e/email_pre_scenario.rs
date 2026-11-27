//! Docker e2e scenario: DKIM-email-authorized PRE decryption.
//!
//! A DKIM-signed reply replaces the JWT entirely for the *read* side only
//! — storing the encrypted document still goes through the ordinary JWT
//! `StoreSecret` path, since that step's authentication method is
//! irrelevant to what this scenario proves. The identity ACP grants/revokes
//! is `did:key:sha256(normalized address)`, the address a node
//! independently extracts from the DKIM-verified message, never a
//! client-asserted field (see `orbis-email`'s own README for the format,
//! and why it reuses the `did:key:` prefix rather than a dedicated one —
//! the chain's ACP module rejects any other prefix for a grant). Mirrors
//! `pre_passkey_scenario.rs`'s deny-before-grant / decrypt / revoke /
//! deny-again / re-grant / decrypt cycle, and `email_sign_scenario.rs`'s
//! use of the pinned-DKIM-keys production path (there's no real DNS
//! record for a synthetic test domain) plus its message-swap-style
//! misdirection check — here, a reply confirming one PRE challenge
//! (bound to a specific `rdr_pk`) must not authorize decryption for a
//! request carrying a *different* reader key.
//!
//! Runs against its own ring/policy (not the one `standard_dkg_pre.rs`'s
//! shared scenarios provision) so the `ORBIS_EMAIL_*` node env vars this
//! test sets — the opt-in pass-through in `test_support::network::
//! {vera,cosmos}` — apply only to this test's own containers, never to a
//! scenario that must keep rejecting email-authorized PRE requests.

use super::standard_dkg_pre::POLICY_YAML;
use super::{pre_scenario, TestEnvironmentImpl};
use orbis_email::test_support::TestSigningKey;
use orbis_integration_core::{CanonicalDisplay, PreOperation};
use proto::v0::pre::pre_service_client::PreServiceClient;
use proto::v0::pre::{EmailAssertion, StartPreRequest};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::time::Duration;
use test_support::fixture::{
    AuthorizationTestDriver, FixtureId, NetworkTestDriver, NodeFixture, NodeRef, NodeRole,
    PolicyFixture, RingFixture, ScenarioFixture, TestEnvironment,
};
use tokio::time::{sleep, Instant};

const RESOURCE: &str = "document";
const RELATION: &str = "reader";
const DKIM_DOMAIN: &str = "orbis-email-pre.test";
const DKIM_SELECTOR: &str = "orbistest";
const FROM_ADDRESS: &str = "alice@orbis-email-pre.test";
const REPLACEMENT_ADDRESS: &str = "bob@orbis-email-pre.test";
const TO_ADDRESS: &str = "ring@orbis-email-pre.test";
const PLAINTEXT: &[u8] = b"email-authorized PRE decryption";
const CONTAINER_KEYS_PATH: &str = "/etc/orbis/email-dkim-keys.json";

/// `did:key:sha256(normalized address)` — see `email_sign_scenario.rs`'s
/// identical helper for why.
fn email_issuer_id(address: &str) -> String {
    let normalized = address.trim().to_lowercase();
    format!(
        "did:key:{}",
        hex::encode(Sha256::digest(normalized.as_bytes()))
    )
}

/// Writes a pinned-DKIM-keys file in the format
/// `orbis_email::PinnedDnsCache::load_from_file` expects — see
/// `email_sign_scenario.rs`'s identical helper for why this is needed at
/// all (no real DNS record exists for a synthetic test domain).
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
/// every node container before `provision` — see `email_sign_scenario.rs`'s
/// identical `EmailNodeEnv` for why.
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
async fn test_email_authorized_pre_decryption() {
    let signing_key = TestSigningKey::generate(DKIM_DOMAIN, DKIM_SELECTOR);
    let pinned_keys_file = write_pinned_keys_file(&signing_key);
    let _node_env = EmailNodeEnv::set(pinned_keys_file.path());

    // Two separate policy fixtures, not one shared between the ring and
    // the document — mirrors every other `pre_scenario::run` caller, none
    // of which reuse the ring's own policy for document registration.
    let ring_policy = FixtureId::new("email-pre-ring-policy");
    let document_policy = FixtureId::new("email-pre-document-policy");
    let ring = FixtureId::new("email-pre-ring");
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

    let signer_id = email_issuer_id(FROM_ADDRESS);

    let denied = cli_tool::do_pre_with_email(
        endpoint.clone(),
        chain_id.clone(),
        keys.main.clone(),
        stored.object_id.clone(),
        FROM_ADDRESS.to_string(),
        &signing_key,
        TO_ADDRESS,
        None,
        None,
        None,
        None,
    )
    .await
    .expect_err("decrypting without a policy relationship must fail");
    pre_scenario::assert_policy_rejection("email PRE without permission", &denied);

    environment
        .grant(
            &policy_id,
            RESOURCE,
            &stored.object_id,
            RELATION,
            &signer_id,
        )
        .await;

    let decrypted = decrypt_with_retry(
        &endpoint,
        &chain_id,
        &keys.main,
        &stored.object_id,
        &signing_key,
        FROM_ADDRESS,
    )
    .await;
    assert_eq!(
        decrypted, PLAINTEXT,
        "email PRE must recover the original plaintext"
    );

    environment
        .revoke(
            &policy_id,
            RESOURCE,
            &stored.object_id,
            RELATION,
            &signer_id,
        )
        .await;
    let revoked = cli_tool::do_pre_with_email(
        endpoint.clone(),
        chain_id.clone(),
        keys.main.clone(),
        stored.object_id.clone(),
        FROM_ADDRESS.to_string(),
        &signing_key,
        TO_ADDRESS,
        None,
        None,
        None,
        None,
    )
    .await
    .expect_err("decrypting after revoking the authorized relationship must fail");
    pre_scenario::assert_policy_rejection("email PRE after revocation", &revoked);

    // The whole recovery story for a compromised mailbox: remove the old
    // address from the policy, add a new one. No separate
    // enrollment/binding registry involved — same shape as
    // `pre_passkey_scenario.rs`'s key-replacement cycle.
    let replacement_id = email_issuer_id(REPLACEMENT_ADDRESS);
    environment
        .grant(
            &policy_id,
            RESOURCE,
            &stored.object_id,
            RELATION,
            &replacement_id,
        )
        .await;

    let restored = decrypt_with_retry(
        &endpoint,
        &chain_id,
        &keys.main,
        &stored.object_id,
        &signing_key,
        REPLACEMENT_ADDRESS,
    )
    .await;
    assert_eq!(
        restored, PLAINTEXT,
        "email PRE must succeed again, with a new address, after the reader relationship is restored"
    );

    // A validly captured, DKIM-signed reply confirming a PRE challenge for
    // one reader key (`rdr_pk`) must not authorize decryption for a
    // request carrying a *different* reader key, even while the replying
    // address still holds an active grant — isolates this to the
    // challenge-text binding itself (which necessarily covers `rdr_pk`),
    // not an incidental policy failure. Mirrors
    // `email_sign_scenario.rs`'s message-swap check.
    reject_reader_key_swapped_evidence(&endpoint, &stored.object_id, &signing_key).await;
}

async fn decrypt_with_retry(
    endpoint: &str,
    chain_id: &str,
    ring_pk: &str,
    object_id: &str,
    signing_key: &TestSigningKey,
    from_address: &str,
) -> Vec<u8> {
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        match cli_tool::do_pre_with_email(
            endpoint.to_string(),
            chain_id.to_string(),
            ring_pk.to_string(),
            object_id.to_string(),
            from_address.to_string(),
            signing_key,
            TO_ADDRESS,
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
                    "email PRE did not succeed before the scenario deadline: {error}"
                );
                sleep(Duration::from_secs(2)).await;
            }
        }
    }
}

/// Captures a legitimate DKIM-signed reply confirming a PRE challenge for
/// `reader_pk_a`, then submits it against a `StartPreRequest` carrying a
/// *different* `rdr_pk` — the PRE analog of `email_sign_scenario.rs`'s
/// message-swap case. Built with the raw proto client (not `orbis-sdk`,
/// which orbis-node doesn't depend on) since this deliberately constructs
/// a request `orbis-sdk`'s own honest API has no way to produce.
async fn reject_reader_key_swapped_evidence(
    endpoint: &str,
    object_id: &str,
    signing_key: &TestSigningKey,
) {
    let reader_pk_a = vec![0xAA; 48];
    let reader_pk_b = vec![0xBB; 48];

    let issued_at = current_unix_time();
    let expiry = issued_at + 300;
    let nonce = [9u8; 16];

    let operation_for_a = PreOperation {
        object_id: object_id.to_string(),
        rdr_pk: reader_pk_a,
        derivation: None,
        salt: None,
        issued_at,
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
    let mut client = PreServiceClient::new(channel);

    let request = StartPreRequest {
        rdr_pk: reader_pk_b,
        object_id: object_id.to_string(),
        derivation: None,
        salt: None,
        valid_window: None,
        document: None,
        // Deliberately omitted: `resolve_request_auth` (and therefore the
        // email challenge-text check this test targets) runs and short-
        // circuits with `?` before `authenticate_pre_request` ever reads
        // this field — see that function's own body — so leaving it unset
        // doesn't change why this request fails.
        rdr_pk_signature: None,
        audit_target_object_id: None,
        webauthn_assertion: None,
        email_assertion: Some(email_assertion),
    };
    let status = client
        .start_pre(tonic::Request::new(request))
        .await
        .expect_err("a reply confirming one reader key must not authorize PRE for a different one");
    assert_eq!(
        status.code(),
        tonic::Code::Unauthenticated,
        "swapped reader-key evidence must be rejected as unauthenticated, got: {status:?}"
    );
    assert!(
        status.message().contains("challenge text was not found"),
        "expected a challenge-text mismatch rejection, got: {status:?}"
    );
}

fn current_unix_time() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock is after the Unix epoch")
        .as_secs()
}
