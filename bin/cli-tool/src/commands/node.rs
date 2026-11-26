//! Commands that talk to a running orbis-node over gRPC: DKG, PRE, Sign, StoreSecret,
//! and node/ring status queries.
//!
//! Thin wrappers over `orbis-sdk`: this module's job is CLI output
//! (`println!`) and adapting cli-tool's own CLI-only conveniences (a
//! string seed hashed into a JWT identity, a raw P-256 key standing in for
//! a passkey) onto the SDK's real API — never a second copy of the
//! request-building/crypto logic itself, which lives in `orbis-sdk`.

use anyhow::{anyhow, Context, Result};
use orbis_sdk::{InMemoryEd25519Signer, OrbisClient};

pub use orbis_sdk::{
    DkgResult, NodeInfoResult, PendingPreRetrieval, SignResult, StoreSecretResult,
};

/// A caller-supplied `--reader-did-pk` seed string, or the long-standing
/// `"test_jwt"` default, hashed into a JWT-signing identity — cli-tool's
/// own low-security convenience; see `orbis_sdk::InMemoryEd25519Signer`'s
/// doc comment for why a real integration should bring its own signer
/// instead.
fn jwt_signer(reader_did_pk: Option<String>) -> InMemoryEd25519Signer {
    InMemoryEd25519Signer::from_seed_str(&reader_did_pk.unwrap_or_else(|| "test_jwt".to_string()))
}

/// Prints a PRE/StoreSecret-style decrypted payload the same way every
/// decrypt path (`do_pre`, `do_pre_with_passkey`, `do_retrieve_pre`) always
/// has: as text when it's valid UTF-8, a byte count otherwise.
fn print_decrypted_secret(decrypted: &[u8]) {
    match std::str::from_utf8(decrypted) {
        Ok(text) => println!("  Decrypted Secret: {text}"),
        Err(_) => println!(
            "  Decrypted Secret: <binary data, {} bytes>",
            decrypted.len()
        ),
    }
}

pub async fn do_dkg(endpoint: String, ring_id: String) -> Result<DkgResult> {
    println!("Starting DKG session:");
    println!("  Endpoint: {endpoint}");
    println!("  Ring ID: {ring_id}");
    println!();

    let client = OrbisClient::connect(endpoint).await?;
    let result = client.start_dkg(ring_id).await?;

    println!("DKG Result:");
    println!("{}", "=".repeat(60));
    println!("  Session ID: {}", result.session_id);
    println!("  Status: {}", result.status);
    println!("  Message: {}", result.message);

    Ok(result)
}

/// Store a secret using the StoreSecret service (convenience function).
///
/// Encrypts `secret` locally against `ring_pk_hex`, then sends it to the
/// node for validation and posting. For retry scenarios, use
/// [`prepare_secret`] + [`store_prepared_secret`] instead, to ensure the
/// same encrypted data is sent (idempotent storage).
#[allow(clippy::too_many_arguments)]
pub async fn do_store_secret(
    endpoint: String,
    secret: &[u8],
    ring_pk_hex: String,
    ring_id: String,
    policy_id: String,
    resource: String,
    permission: String,
    tier: Option<String>,
    timestamp: Option<u64>,
    salt: Option<String>,
    reader_did_pk: Option<String>,
    derivation: Option<Vec<u8>>,
    with_proof: bool,
) -> Result<StoreSecretResult> {
    let signer = jwt_signer(reader_did_pk);
    let client = OrbisClient::connect(endpoint).await?;
    let result = client
        .store_secret_with_jwt(
            secret,
            &ring_pk_hex,
            ring_id,
            policy_id,
            resource,
            permission,
            tier,
            timestamp,
            salt,
            &signer,
            derivation,
            with_proof,
        )
        .await?;
    print_store_secret_result(&result);
    Ok(result)
}

/// Store a prepared (pre-encrypted) secret via the StoreSecret service.
/// Idempotent — calling with the same [`super::crypto::PreparedSecret`]
/// returns the same `object_id` without creating duplicates.
pub async fn store_prepared_secret(
    endpoint: String,
    prepared: &super::crypto::PreparedSecret,
    ring_id: String,
    reader_did_pk: Option<String>,
    with_proof: bool,
    pet_tag: Option<&super::crypto::PreparedPetTag>,
) -> Result<StoreSecretResult> {
    let signer = jwt_signer(reader_did_pk);
    let client = OrbisClient::connect(endpoint).await?;
    let result = client
        .store_prepared_secret_with_jwt(prepared, ring_id, &signer, with_proof, pet_tag)
        .await?;
    print_store_secret_result(&result);
    Ok(result)
}

fn print_store_secret_result(result: &StoreSecretResult) {
    println!("StoreSecret Result:");
    println!("{}", "=".repeat(60));
    println!("  Status: {}", result.status);
    println!("  Message: {}", result.message);
    println!("  Object ID: {}", result.object_id);
    println!("  Ring ID: {}", result.ring_id);
    println!("  signature: {}", result.signature);
}

#[allow(clippy::too_many_arguments)]
pub async fn do_pre(
    endpoint: String,
    chain_id: String,
    ring_pk: String,
    object_id: String,
    reader_did_pk: Option<String>,
    derivation: Option<Vec<u8>>,
    salt: Option<String>,
    valid_window_start: Option<u64>,
    valid_window_end: Option<u64>,
) -> Result<Vec<u8>> {
    do_pre_impl(
        endpoint,
        chain_id,
        ring_pk,
        object_id,
        reader_did_pk,
        derivation,
        salt,
        valid_window_start,
        valid_window_end,
        None,
        None,
    )
    .await
}

/// Same as [`do_pre`], but supplies the document inline in the request
/// instead of reading it from the bulletin, and optionally names the ACP
/// object PET should audit ownership against. Exists so a `requires_pet`
/// ring's PET+PRE gate can be exercised end to end without needing
/// `StoreSecret` at all.
// Only called via the `cli-tool` lib target (orbis-node integration tests); unused from the bin target.
#[allow(dead_code)]
#[allow(clippy::too_many_arguments)]
pub async fn do_pre_with_inline_document(
    endpoint: String,
    chain_id: String,
    ring_pk: String,
    object_id: String,
    reader_did_pk: Option<String>,
    derivation: Option<Vec<u8>>,
    salt: Option<String>,
    valid_window_start: Option<u64>,
    valid_window_end: Option<u64>,
    document: proto::v0::pre::InlineDocument,
    audit_target_object_id: Option<String>,
) -> Result<Vec<u8>> {
    do_pre_impl(
        endpoint,
        chain_id,
        ring_pk,
        object_id,
        reader_did_pk,
        derivation,
        salt,
        valid_window_start,
        valid_window_end,
        Some(document),
        audit_target_object_id,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn do_pre_impl(
    endpoint: String,
    chain_id: String,
    ring_pk: String,
    object_id: String,
    reader_did_pk: Option<String>,
    derivation: Option<Vec<u8>>,
    salt: Option<String>,
    valid_window_start: Option<u64>,
    valid_window_end: Option<u64>,
    document: Option<proto::v0::pre::InlineDocument>,
    audit_target_object_id: Option<String>,
) -> Result<Vec<u8>> {
    let signer = jwt_signer(reader_did_pk);
    let client = OrbisClient::connect(endpoint).await?;
    let decrypted = client
        .submit_pre_with_jwt(
            chain_id,
            ring_pk,
            object_id,
            &signer,
            derivation,
            salt,
            valid_window_start,
            valid_window_end,
            document,
            audit_target_object_id,
        )
        .await?;
    print_decrypted_secret(&decrypted);
    Ok(decrypted)
}

/// Same request as [`do_pre`], but doesn't decrypt — returns a
/// [`PendingPreRetrieval`] the caller can serialize and decrypt later via
/// [`do_retrieve_pre`], independently of this process.
// Only called via the `cli-tool` lib target (orbis-node integration tests) and the
// `retrieve-pre`/`--save-only` CLI path; unused from the bin target's default flow.
#[allow(dead_code)]
#[allow(clippy::too_many_arguments)]
pub async fn do_pre_and_save(
    endpoint: String,
    chain_id: String,
    ring_pk: String,
    object_id: String,
    reader_did_pk: Option<String>,
    derivation: Option<Vec<u8>>,
    salt: Option<String>,
    valid_window_start: Option<u64>,
    valid_window_end: Option<u64>,
) -> Result<PendingPreRetrieval> {
    let signer = jwt_signer(reader_did_pk);
    let client = OrbisClient::connect(endpoint).await?;
    client
        .submit_pre_with_jwt_and_hold(
            chain_id,
            ring_pk,
            object_id,
            &signer,
            derivation,
            salt,
            valid_window_start,
            valid_window_end,
        )
        .await
        .map_err(Into::into)
}

/// Decrypts a [`PendingPreRetrieval`] saved by [`do_pre_and_save`] — the
/// deferred half of the save-now/retrieve-later path, independent of the
/// process that made the original request.
#[allow(dead_code)]
pub async fn do_retrieve_pre(pending_json: String) -> Result<Vec<u8>> {
    let pending: PendingPreRetrieval = serde_json::from_str(&pending_json)
        .map_err(|e| anyhow!("Failed to parse pending PRE retrieval JSON: {}", e))?;
    let decrypted = orbis_sdk::retrieve_pre(pending).await?;
    print_decrypted_secret(&decrypted);
    Ok(decrypted)
}

/// The `did:key` a raw P-256 key decodes to — the identity a passkey
/// stand-in authenticates as.
fn passkey_issuer_did(signing_key: &p256::ecdsa::SigningKey) -> String {
    let compressed_pubkey: [u8; 33] = signing_key
        .verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .expect("compressed P-256 point is 33 bytes");
    authn::did_from_p256_public_key(&compressed_pubkey)
}

/// Call `PreService.StartPre` with a passkey-authorized request — a
/// WebAuthn assertion in place of a JWT. `object_id`'s document's policy
/// must have granted `read` (or whichever permission it names) to the
/// `did:key` the signing key's own public key decodes to; there is no
/// separate enrollment step.
///
/// `signing_key` stands in for a real passkey: there is no browser or
/// hardware authenticator to drive here, so this process signs the
/// challenge directly with a key it already controls, via
/// `orbis_webauthn::build_test_assertion`. Fine for CLI tooling and tests;
/// never represents a real end-user flow. This is the synchronous,
/// no-real-browser shape of `orbis-sdk`'s own `build_pre_challenge` +
/// `submit_pre_with_evidence`.
#[allow(clippy::too_many_arguments)]
pub async fn do_pre_with_passkey(
    endpoint: String,
    chain_id: String,
    ring_pk: String,
    object_id: String,
    signing_key: &p256::ecdsa::SigningKey,
    rp_id: &str,
    origin: &str,
    derivation: Option<Vec<u8>>,
    salt: Option<String>,
    valid_window_start: Option<u64>,
    valid_window_end: Option<u64>,
) -> Result<Vec<u8>> {
    let issuer_did = passkey_issuer_did(signing_key);

    let pending = orbis_sdk::build_pre_challenge(
        chain_id,
        ring_pk,
        object_id,
        &issuer_did,
        derivation,
        salt,
        valid_window_start,
        valid_window_end,
    )?;
    let assertion =
        orbis_webauthn::build_test_assertion(signing_key, rp_id, origin, &pending.challenge());
    let evidence = pending.passkey_evidence(issuer_did, assertion);

    let client = OrbisClient::connect(endpoint).await?;
    let decrypted = client.submit_pre_with_evidence(pending, evidence).await?;
    print_decrypted_secret(&decrypted);
    Ok(decrypted)
}

/// Call `SignService.StartSign` with a JWT-authenticated request.
///
/// `derivation_id` must match the `KeyDerivation` posted to the bulletin via
/// `post_key_derivation`. The JWT is bound to it so the node can verify the
/// caller is authorised to sign under that key derivation.
pub async fn do_sign(
    endpoint: String,
    message: Vec<u8>,
    derivation_id: String,
    reader_did_pk: Option<String>,
    valid_window_start: Option<u64>,
    valid_window_end: Option<u64>,
) -> Result<SignResult> {
    println!("Starting Sign session:");
    println!("  Endpoint: {endpoint}");
    println!("  Derivation ID: {derivation_id}");
    println!("  Message length: {} bytes", message.len());
    println!();

    let signer = jwt_signer(reader_did_pk);
    let client = OrbisClient::connect(endpoint).await?;
    let result = client
        .submit_sign_with_jwt(
            message,
            derivation_id,
            &signer,
            valid_window_start,
            valid_window_end,
        )
        .await?;
    print_sign_result(&result);
    Ok(result)
}

/// Call `SignService.StartSign` with a passkey-authorized request — a
/// WebAuthn assertion in place of a JWT. `derivation_id` must have been
/// granted (via ACP) to the `did:key` the signing key's own public key
/// decodes to (see `authn::did_from_p256_public_key`); there is no
/// separate enrollment step.
///
/// `signing_key` stands in for a real passkey: there is no browser or
/// hardware authenticator to drive here, so this process signs the
/// challenge directly with a key it already controls, via
/// `orbis_webauthn::build_test_assertion`. Fine for CLI tooling and tests;
/// never represents a real end-user flow.
pub async fn do_sign_with_passkey(
    endpoint: String,
    message: Vec<u8>,
    derivation_id: String,
    signing_key: &p256::ecdsa::SigningKey,
    rp_id: &str,
    origin: &str,
    valid_window_start: Option<u64>,
    valid_window_end: Option<u64>,
) -> Result<SignResult> {
    println!("Starting passkey-authorized Sign session:");
    println!("  Endpoint: {endpoint}");
    println!("  Derivation ID: {derivation_id}");
    println!("  Message length: {} bytes", message.len());
    println!();

    let issuer_did = passkey_issuer_did(signing_key);
    let pending = orbis_sdk::build_sign_challenge(
        derivation_id,
        message,
        valid_window_start,
        valid_window_end,
    )?;
    let assertion =
        orbis_webauthn::build_test_assertion(signing_key, rp_id, origin, &pending.challenge());
    let evidence = pending.passkey_evidence(issuer_did, assertion)?;

    let client = OrbisClient::connect(endpoint).await?;
    let result = client.submit_sign_with_evidence(pending, evidence).await?;
    print_sign_result(&result);
    Ok(result)
}

fn print_sign_result(result: &SignResult) {
    println!("Sign Result:");
    println!("{}", "=".repeat(60));
    println!("  Status: {}", result.status);
    println!("  Message: {}", result.message);
    println!("  Signature: {}", result.signature);
}

pub async fn query_node_info(endpoint: String) -> Result<NodeInfoResult> {
    println!("Querying node info from: {endpoint}");
    let client = OrbisClient::connect(endpoint).await?;
    let info = client.query_node_info().await?;

    println!(
        "Node Info:\n{}\n  Public Address: {}\n  Peer ID: {}\n  Node Key: {}\n  P2P Address: {}\n  Status: {}\n  Managed Ring Count: {}\n  Supported Protocol Versions: {:?}",
        "=".repeat(60),
        info.public_address,
        info.peer_id,
        info.node_key,
        info.p2p_address,
        info.status.as_str_name(),
        info.managed_ring_count,
        info.supported_protocol_versions
    );

    Ok(info)
}

/// Query the local RingPolyState from a node (public polynomial + last_pss timestamp).
/// Returns an error if the ring_pk_hex is not found on that node.
pub async fn query_ring_state(endpoint: String, ring_pk_hex: String) -> Result<(String, u64)> {
    let client = OrbisClient::connect(endpoint).await.context("connect")?;
    client
        .query_ring_state(ring_pk_hex)
        .await
        .map_err(Into::into)
}

/// Same as [`query_ring_state`], for a ring's independent PET checking key —
/// keyed by `ring_id` (PET has no public-key storage handle to query by).
/// Returns an error if the ring has no PET bundle on that node.
pub async fn query_pet_ring_state(endpoint: String, ring_id: String) -> Result<(String, u64)> {
    let client = OrbisClient::connect(endpoint).await.context("connect")?;
    client
        .query_pet_ring_state(ring_id)
        .await
        .map_err(Into::into)
}
