//! CLI command implementations
//!
//! This module contains the actual implementation of CLI commands,
//! separated from main.rs so they can be used in integration tests.

use anyhow::{anyhow, Result};
use authn::{create_authenticated_request, JwtSigner};
use bulletin::r#trait::{Bulletin, KeyDerivation, RingPayload};
use bulletin::sourcehub::SourceHubBulletin;
use common::blockchain::{
    acp::{Actor, Object, Relationship, Subject, SubjectKind},
    ChainConfig, ChainConfigBuilder, SourceHubClient, TxSigner, TEST_ACCOUNT_HEX_KEY,
};
use crypto::r#trait::{Secret, ThresholdDealer, ThresholdSigner};
use crypto::{CryptoDeserialize, CryptoSerialize};
use crypto::{
    GroupAffine as G1Affine, PreImpl as ThresholdDealerNode, ScalarField as Fr, SignImpl,
};
use did_key::{generate, Ed25519KeyPair as DidEd25519KeyPair, Fingerprint};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use proto::dkg_service::dkg_service_client::DkgServiceClient;
use proto::info_service::info_service_client::InfoServiceClient;
use proto::pre_service::pre_service_client::PreServiceClient;
use proto::sign_service::sign_service_client::SignServiceClient;
use proto::store_secret_service::store_secret_service_client::StoreSecretServiceClient;
use tonic::Request;

/// Response structure from PRE server
#[derive(Debug, Deserialize)]
struct PreResponse {
    /// Recovered reencrypted commitment (xnc_cmt) as hex string
    xnc_cmt: String,
    /// Original encrypted secret
    secret: Secret,
}

/// Result of a DKG operation
#[derive(Debug)]
pub struct DkgResult {
    pub session_id: String,
    pub status: String,
    pub message: String,
}

pub async fn do_dkg(
    endpoint: String,
    threshold: u32,
    peer_ids: Vec<String>,
    pss_interval: Option<u64>,
) -> Result<DkgResult> {
    do_dkg_with_policy(endpoint, threshold, peer_ids, pss_interval, None).await
}

pub async fn do_dkg_with_policy(
    endpoint: String,
    threshold: u32,
    peer_ids: Vec<String>,
    pss_interval: Option<u64>,
    policy_id: Option<String>,
) -> Result<DkgResult> {
    // Total nodes = peers + the node we're connecting to
    let total_nodes = peer_ids.len() as u32;

    if threshold > total_nodes {
        return Err(anyhow!(
            "Threshold ({}) cannot be greater than total nodes ({})",
            threshold,
            total_nodes
        ));
    }

    println!("Starting DKG session:");
    println!("  Endpoint: {}", endpoint);
    println!("  Threshold: {}/{}", threshold, total_nodes);
    println!("  Peer IDs: {:?}", peer_ids);
    if let Some(policy_id) = &policy_id {
        println!("  Policy ID: {}", policy_id);
    }
    println!();

    println!("Connecting to {}...", endpoint);

    let mut client = DkgServiceClient::connect(endpoint.clone())
        .await
        .map_err(|e| anyhow!("Failed to connect to {}: {}", endpoint, e))?;

    let request = proto::dkg_service::StartDkgRequest {
        threshold,
        peer_ids: peer_ids.clone(),
        pss_interval,
        policy_id: policy_id.clone(),
    };

    // JWT work
    let jwt_signer = JwtSigner::new();
    let token = jwt_signer
        .create_dkg_jwt_with_policy(threshold, &peer_ids, pss_interval, policy_id)
        .expect("Failed to create JWT");
    let tonic_request = create_authenticated_request(request, &token)
        .map_err(|e| anyhow!("Failed to create_dkg_jwt: {}", e))?;

    let response = client
        .start_dkg(tonic_request)
        .await
        .map_err(|e| anyhow!("DKG request failed: {}", e))?;

    let response = response.into_inner();

    println!("DKG Result:");
    println!("{}", "=".repeat(60));
    println!("  Session ID: {}", response.session_id);
    println!("  Status: {}", response.status);
    println!("  Message: {}", response.message);

    Ok(DkgResult {
        session_id: response.session_id,
        status: response.status,
        message: response.message,
    })
}

/// Result of a StoreSecret operation
#[derive(Debug)]
pub struct StoreSecretResult {
    pub status: String,
    pub message: String,
    pub created_at: i64,
    pub object_id: String,
    pub ring_id: String,
    pub signature: String,
}

/// Prepared secret ready for storage - can be reused for retries
/// This contains the encrypted data and proof, which are deterministic
/// for a given plaintext and ring public key encryption.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PreparedSecret {
    /// Encrypted document as serialized bytes
    pub encrypted_document: Vec<u8>,
    /// Encryption commitment bytes (compressed G1 point)
    pub enc_cmt: Vec<u8>,
    /// Shared point for encryption proof
    pub shared_point: Vec<u8>,
    /// Challenge for encryption proof
    pub challenge: Vec<u8>,
    /// Response for encryption proof
    pub response: Vec<u8>,
    /// Policy metadata hash
    pub metadata: Vec<u8>,
}

/// Prepare a secret for storage by encrypting it locally.
/// The returned PreparedSecret can be stored and reused for retries,
/// ensuring idempotent storage (same encrypted data = same object_id).
pub fn prepare_secret(
    secret: &[u8],
    ring_pk_hex: &str,
    derivation: Option<Vec<u8>>,
    policy_id: String,
    resource: String,
    permission: String,
    tier: Option<String>,
    timestamp: Option<u64>,
    salt: Option<String>,
) -> Result<PreparedSecret> {
    // Parse ring public key
    let ring_pk_bytes =
        hex::decode(ring_pk_hex).map_err(|e| anyhow!("Invalid ring_pk hex: {}", e))?;
    let ring_pk_point =
        G1Affine::from_bytes(&ring_pk_bytes).map_err(|e| anyhow!("Invalid ring_pk: {}", e))?;

    let metadata = ThresholdDealerNode::encode_metadata(
        &policy_id,
        &resource,
        &permission,
        tier.as_deref(),
        timestamp,
        salt.as_deref(),
    );

    // Encrypt locally - node never sees plaintext
    let (enc_cmt, encrypted_secret, proof) = ThresholdDealerNode::encrypt_secret(
        &ring_pk_point,
        secret,
        derivation.as_deref(),
        Some(&metadata),
    )
    .map_err(|e| anyhow!("Encryption failed: {}", e))?;

    let encrypted_document = serde_json::to_vec(&encrypted_secret)
        .map_err(|e| anyhow!("Failed to serialize encrypted secret: {}", e))?;
    let enc_cmt = enc_cmt
        .to_bytes()
        .map_err(|e| anyhow!("Failed to serialize enc_cmt: {}", e))?
        .to_vec();

    Ok(PreparedSecret {
        encrypted_document,
        enc_cmt,
        shared_point: proof.shared_point,
        challenge: proof.challenge,
        response: proof.response,
        metadata,
    })
}

/// Store a prepared (pre-encrypted) secret using the StoreSecret service.
/// This is idempotent - calling with the same PreparedSecret will return
/// the same object_id without creating duplicates.
pub async fn store_prepared_secret(
    endpoint: String,
    prepared: &PreparedSecret,
    ring_id: String,
    namespace: String,
    policy_id: String,
    resource: String,
    permission: String,
    reader_did_pk: Option<String>,
    with_proof: bool,
    tier: Option<String>,
    timestamp: Option<u64>,
) -> Result<StoreSecretResult> {
    println!("Storing secret via StoreSecret service:");
    println!("  Endpoint: {}", endpoint);
    println!("  Ring ID: {}", ring_id);
    println!("  Namespace: {}", namespace);
    println!();

    let mut client = StoreSecretServiceClient::connect(endpoint.clone())
        .await
        .map_err(|e| anyhow!("Failed to connect to {}: {}", endpoint, e))?;

    let request = proto::store_secret_service::StoreSecretRequest {
        encrypted_document: prepared.encrypted_document.clone(),
        enc_cmt: prepared.enc_cmt.clone(),
        ring_id: ring_id.clone(),
        namespace: namespace.clone(),
        policy_id: policy_id.clone(),
        resource: resource.clone(),
        permission: permission.clone(),
        shared_point: prepared.shared_point.clone(),
        challenge: prepared.challenge.clone(),
        response: prepared.response.clone(),
        with_proof,
        tier: tier.clone(),
        timestamp,
    };

    // Create JWT for authentication with all request fields
    let reader_did_pk = reader_did_pk.unwrap_or("test_jwt".to_string());
    let seed = did_seed(&reader_did_pk);
    let key_pair = generate::<DidEd25519KeyPair>(Some(&seed));
    let jwt_signer = JwtSigner::from_key_pair(key_pair);
    let token = jwt_signer
        .create_store_secret_jwt(
            &prepared.encrypted_document,
            prepared.enc_cmt.clone(),
            &ring_id,
            &namespace,
            &policy_id,
            &resource,
            &permission,
            prepared.shared_point.clone(),
            prepared.challenge.clone(),
            prepared.response.clone(),
            with_proof,
            tier,
            timestamp,
        )
        .map_err(|e| anyhow!("Failed to create JWT: {}", e))?;

    let tonic_request = create_authenticated_request(request, &token)
        .map_err(|e| anyhow!("Failed to create authenticated request: {}", e))?;

    let response = client
        .store_secret(tonic_request)
        .await
        .map_err(|e| anyhow!("StoreSecret request failed: {}", e))?;

    let response = response.into_inner();

    println!("StoreSecret Result:");
    println!("{}", "=".repeat(60));
    println!("  Status: {}", response.status);
    println!("  Message: {}", response.message);
    println!("  Object ID: {}", response.object_id);
    println!("  Ring ID: {}", response.ring_id);
    println!("  signature: {}", response.signature);
    println!("  enc_cmt: {}", hex::encode(&prepared.enc_cmt));

    Ok(StoreSecretResult {
        status: response.status,
        message: response.message,
        created_at: response.created_at,
        object_id: response.object_id,
        ring_id: response.ring_id,
        signature: response.signature,
    })
}

/// Store a secret using the StoreSecret service (convenience function).
///
/// This function:
/// 1. Encrypts the secret locally using the ring's public key (node never sees plaintext)
/// 2. Connects to the orbis-node endpoint
/// 3. Sends the encrypted secret to the node for validation and posting
/// 4. Returns the object_id needed for PRE requests
///
/// Note: For retry scenarios, use prepare_secret() + store_prepared_secret()
/// to ensure the same encrypted data is sent (idempotent storage).
pub async fn do_store_secret(
    endpoint: String,
    secret: &[u8],       // Plaintext secret - encrypted locally before sending
    ring_pk_hex: String, // Ring public key (hex) - used for encryption
    ring_id: String,
    namespace: String,
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
    let prepared = prepare_secret(
        secret,
        &ring_pk_hex,
        derivation.clone(),
        policy_id.clone(),
        resource.clone(),
        permission.clone(),
        tier.clone(),
        timestamp,
        salt.clone(),
    )?;
    store_prepared_secret(
        endpoint,
        &prepared.clone(),
        ring_id,
        namespace,
        policy_id,
        resource,
        permission,
        reader_did_pk,
        with_proof,
        tier,
        timestamp,
    )
    .await
}

/// Derive a 32-byte Ed25519 seed from an arbitrary string via SHA-256.
///
/// `did_key::generate` only uses the seed deterministically when it is exactly
/// 32 bytes; for any other length it falls back to a random key. Hashing to 32
/// bytes ensures consistent, reproducible DIDs regardless of the input length.
fn did_seed(s: &str) -> [u8; 32] {
    Sha256::digest(s.as_bytes()).into()
}

pub async fn do_pre(
    endpoint: String,
    ring_pk: String,
    reader_pk: String,
    reader_sk: Option<String>,
    object_id: String,
    reader_did_pk: Option<String>,
    namespace: String,
    derivation: Option<Vec<u8>>,
    salt: Option<String>,
    valid_window_start: Option<u64>,
    valid_window_end: Option<u64>,
    xnc_only: bool,
) -> Result<Vec<u8>> {
    println!("Starting PRE session:");
    println!("  Endpoint: {}", endpoint);
    println!("  Reader PK: {}...", &reader_pk[..reader_pk.len().min(20)]);

    // Parse the reader public key
    let reader_pk_bytes =
        hex::decode(&reader_pk).map_err(|e| anyhow!("Failed to decode reader_pk hex: {}", e))?;
    let _reader_pk_point = G1Affine::from_bytes(&reader_pk_bytes)
        .map_err(|e| anyhow!("Failed to deserialize reader_pk: {}", e))?;

    // Parse reader secret key (not needed for --xnc-only)
    let reader_sk_scalar = if let Some(ref sk_hex) = reader_sk {
        let reader_sk_bytes =
            hex::decode(sk_hex).map_err(|e| anyhow!("Failed to decode reader_sk hex: {}", e))?;
        Some(
            Fr::from_bytes(&reader_sk_bytes)
                .map_err(|e| anyhow!("Failed to deserialize reader_sk: {}", e))?,
        )
    } else {
        None
    };

    println!("  Encrypted secret created");
    println!();

    // Step 2: Send to PRE service for re-encryption
    println!("Step 2: Sending to PRE service for re-encryption...");
    let mut client = PreServiceClient::connect(endpoint.clone())
        .await
        .map_err(|e| anyhow!("Failed to connect to {}: {}", endpoint, e))?;

    let valid_window = match (valid_window_start, valid_window_end) {
        (Some(start), Some(end)) => Some(proto::pre_service::TimestampRange { start, end }),
        _ => None,
    };

    let request = proto::pre_service::StartPreRequest {
        rdr_pk: reader_pk_bytes.clone(),
        object_id: object_id.clone(),
        namespace: namespace.clone(),
        derivation: derivation.clone(),
        salt: salt.clone(),
        valid_window,
    };

    // JWT work use determinitic key_pair for now
    let reader_did_pk = reader_did_pk.unwrap_or("test_jwt".to_string());
    let seed = did_seed(&reader_did_pk);
    let key_pair = generate::<DidEd25519KeyPair>(Some(&seed));
    let jwt_signer = JwtSigner::from_key_pair(key_pair);
    let token = jwt_signer
        .create_pre_jwt(
            reader_pk_bytes.clone(),
            &namespace,
            &object_id,
            derivation.clone(),
            salt.clone(),
        )
        .expect("Failed to create JWT");
    let tonic_request = create_authenticated_request(request, &token)
        .map_err(|e| anyhow!("Failed to create_authenticated_request: {}", e))?;

    let response = client
        .start_pre(tonic_request)
        .await
        .map_err(|e| anyhow!("PRE request failed: {}", e))?;

    let response = response.into_inner();

    println!("PRE Result:");
    println!("{}", "=".repeat(60));
    println!("  Status: {}", response.status);
    println!("  Message: {}", response.message);

    // Step 3: If we got a re-encrypted commitment back, decrypt it
    if !response.encrypted_secret.is_empty() {
        // Parse the response from server
        let pre_response: PreResponse = serde_json::from_slice(&response.encrypted_secret)
            .map_err(|e| anyhow!("Failed to parse PRE response: {}", e))?;

        // Parse the re-encrypted commitment (xnc_cmt) from hex
        let xnc_cmt_bytes = hex::decode(&pre_response.xnc_cmt)
            .map_err(|e| anyhow!("Failed to decode xnc_cmt hex: {}", e))?;
        let xnc_cmt = G1Affine::from_bytes(&xnc_cmt_bytes)
            .map_err(|e| anyhow!("Failed to deserialize xnc_cmt: {}", e))?;

        // --xnc-only: print xnc_cmt and return without decrypting
        if xnc_only {
            let xnc_hex = hex::encode(
                xnc_cmt
                    .to_bytes()
                    .map_err(|e| anyhow!("Failed to serialize xnc_cmt: {}", e))?,
            );
            println!("Re-encrypted commitment (xnc_cmt): {}", xnc_hex);
            return Ok(xnc_cmt_bytes);
        }

        println!();
        println!("Step 3: Decrypting with reader secret key...");

        let reader_sk_scalar =
            reader_sk_scalar.ok_or_else(|| anyhow!("--reader-sk is required for decryption"))?;

        // Parse the ring public key
        let ring_pk_bytes =
            hex::decode(&ring_pk).map_err(|e| anyhow!("Failed to decode ring_pk hex: {}", e))?;
        let ring_pk_point = G1Affine::from_bytes(&ring_pk_bytes)
            .map_err(|e| anyhow!("Failed to deserialize ring_pk: {}", e))?;

        // Compute effective_pk from derivation when provided, otherwise use ring_pk
        let effective_pk = if let Some(ref deriv) = derivation {
            ThresholdDealerNode::derive_public_key(&ring_pk_point, deriv)
                .map_err(|e| anyhow!("Failed to derive public key: {}", e))?
        } else {
            ring_pk_point
        };

        // Decrypt using reader's secret key and the secret from the response
        let decrypted = ThresholdDealerNode::decrypt_secret(
            &effective_pk,
            &xnc_cmt,
            &reader_sk_scalar,
            &pre_response.secret,
        )
        .map_err(|e| anyhow!("Decryption failed: {}", e))?;

        if let Ok(decrypted_str) = String::from_utf8(decrypted.clone()) {
            println!("  Decrypted Secret: {}", decrypted_str);
        } else {
            println!(
                "  Decrypted Secret: <binary data, {} bytes>",
                decrypted.len()
            );
        }

        return Ok(decrypted);
    }

    Err(anyhow!("PRE response did not contain encrypted_secret"))
}

pub async fn do_encrypt_secret(
    ring_pk: String,
    secret: String,
    derivation: Option<Vec<u8>>,
    policy_id: String,
    resource: String,
    permission: String,
    tier: Option<String>,
    timestamp: Option<u64>,
    salt: Option<String>,
) -> Result<()> {
    println!("Encrypting secret to ring public key...");
    println!("  Ring PK: {}...", &ring_pk[..ring_pk.len().min(20)]);
    println!();

    // Parse the ring public key from hex
    let ring_pk_bytes =
        hex::decode(&ring_pk).map_err(|e| anyhow!("Failed to decode ring_pk hex: {}", e))?;

    let ring_pk_point = G1Affine::from_bytes(&ring_pk_bytes)
        .map_err(|e| anyhow!("Failed to deserialize ring_pk: {}", e))?;

    let metadata = ThresholdDealerNode::encode_metadata(
        &policy_id,
        &resource,
        &permission,
        tier.as_deref(),
        timestamp,
        salt.as_deref(),
    );

    // Encrypt the secret
    let (_enc_cmt, encrypted_secret, _proof) = ThresholdDealerNode::encrypt_secret(
        &ring_pk_point,
        secret.as_bytes(),
        derivation.as_deref(),
        Some(&metadata),
    )
    .map_err(|e| anyhow!("Encryption failed: {}", e))?;

    // Output the full secret as JSON (this is what PRE expects)
    let secret_json = serde_json::to_string(&encrypted_secret)
        .map_err(|e| anyhow!("Failed to serialize secret: {}", e))?;

    println!("Encrypted Secret (JSON):");
    println!("{}", "=".repeat(60));
    println!("{}", secret_json);

    Ok(())
}

pub fn do_generate_reader_key() -> Result<()> {
    let (sk, pk) = crypto::helpers::generate_keypair()
        .map_err(|e| anyhow!("Failed to generate keypair: {}", e))?;

    // Serialize to bytes then hex (use trait method explicitly to avoid inherent method shadowing)
    let sk_bytes = CryptoSerialize::to_bytes(&sk)
        .map_err(|e| anyhow!("Failed to serialize secret key: {}", e))?;
    let pk_bytes = CryptoSerialize::to_bytes(&pk)
        .map_err(|e| anyhow!("Failed to serialize public key: {}", e))?;

    let sk_hex = hex::encode(&sk_bytes);
    let pk_hex = hex::encode(&pk_bytes);

    println!("Generated Reader Keypair:");
    println!("{}", "=".repeat(60));
    println!("Reader Secret Key (--reader-sk):");
    println!("{}", sk_hex);
    println!();
    println!("Reader Public Key (--reader-pk):");
    println!("{}", pk_hex);

    Ok(())
}

/// Ring governance policy. Uses SourceHub bulletin's ACP model:
/// - resource `namespace`, object = "bulletin/<namespace>", permission `update_post`.
/// - `owner` is reserved and automatically injected by acp_core's DiscretionaryTransformer
///   into every permission expression (`update_post = collaborator` → `owner + collaborator`).
/// - `RegisterObject` sets the signer as `owner`, so no explicit collaborator setup is needed.
const RING_GOVERNANCE_POLICY_YAML: &str = r#"
name: ring-governance-policy
resources:
  - name: namespace
    relations:
      - name: collaborator
        types:
          - actor
    permissions:
      - name: update_post
        expr: collaborator
"#;

const TEST_POLICY_YAML: &str = r#"
name: test-policy
resources:
  - name: document
    relations:
      - name: creator
        types:
          - actor
      - name: reader
        types:
          - actor
    permissions:
      - name: read
        expr: creator + reader
      - name: write
        expr: creator
"#;

pub async fn add_policy_to_chain() -> Result<String> {
    let client = SourceHubClient::with_signer(
        ChainConfig::local(),
        TxSigner::from_hex_key(TEST_ACCOUNT_HEX_KEY, ChainConfig::local()).expect("Tx signer"),
    )
    .await
    .map_err(|e| anyhow!("client builder issue: {}", e))?;

    let ids_before: std::collections::HashSet<String> = client
        .acp_list_policy_ids()
        .await
        .map_err(|e| anyhow!("Failed to list policy IDs: {}", e))?
        .ids
        .into_iter()
        .collect();

    let create_result = client
        .acp_create_policy(TEST_POLICY_YAML, 1)
        .await
        .map_err(|e| anyhow!("Failed to create policy: {}", e))?;
    println!(
        "[ACP] create_policy: code={} hash={} log={}",
        create_result.code, create_result.tx_hash, create_result.log
    );

    let policy_id = client
        .acp_list_policy_ids()
        .await
        .map_err(|e| anyhow!("Failed to list policy IDs: {}", e))?
        .ids
        .into_iter()
        .find(|id| !ids_before.contains(id))
        .ok_or_else(|| anyhow!("Newly created policy ID not found in list"))?;
    println!("[ACP] policy_id from list: {}", policy_id);
    Ok(policy_id)
}

/// Creates a ring governance ACP policy and registers the bulletin ring namespace
/// as an object within it. The signer (TEST_ACCOUNT_HEX_KEY) becomes the object
/// `owner`, which grants `update_post` permission for `UpdateRingPostByAcp`.
///
/// Returns the ring governance `policy_id`.
pub async fn add_ring_governance_policy(bulletin_namespace: &str) -> Result<String> {
    let client = SourceHubClient::with_signer(
        ChainConfig::local(),
        TxSigner::from_hex_key(TEST_ACCOUNT_HEX_KEY, ChainConfig::local()).expect("Tx signer"),
    )
    .await
    .map_err(|e| anyhow!("client builder issue: {}", e))?;

    let ids_before: std::collections::HashSet<String> = client
        .acp_list_policy_ids()
        .await
        .map_err(|e| anyhow!("Failed to list policy IDs: {}", e))?
        .ids
        .into_iter()
        .collect();

    let create_result = client
        .acp_create_policy(RING_GOVERNANCE_POLICY_YAML, 1)
        .await
        .map_err(|e| anyhow!("Failed to create ring governance policy: {}", e))?;
    println!(
        "[ACP] ring governance create_policy: code={} hash={} log={}",
        create_result.code, create_result.tx_hash, create_result.log
    );

    let policy_id = client
        .acp_list_policy_ids()
        .await
        .map_err(|e| anyhow!("Failed to list policy IDs: {}", e))?
        .ids
        .into_iter()
        .find(|id| !ids_before.contains(id))
        .ok_or_else(|| anyhow!("Newly created ring governance policy ID not found in list"))?;
    println!("[ACP] ring governance policy_id: {}", policy_id);

    // The bulletin keeper uses namespaceId = "bulletin/" + namespace.
    // Registering this object makes the signer the `owner`, granting `update_post`.
    let namespace_object_id = format!("bulletin/{}", bulletin_namespace);
    let result = client
        .acp_register_object(
            &policy_id,
            Object {
                resource: "namespace".to_string(),
                id: namespace_object_id.clone(),
            },
        )
        .await
        .map_err(|e| {
            anyhow!(
                "Failed to register namespace object in ring governance policy: {}",
                e
            )
        })?;
    println!(
        "[ACP] ring governance register_object({}): code={} hash={}",
        namespace_object_id, result.code, result.tx_hash
    );
    if result.code != 0 {
        return Err(anyhow!(
            "register_object failed: code={} log={}",
            result.code,
            result.log
        ));
    }

    Ok(policy_id)
}

pub async fn register_object_to_chain(
    policy_id: String,
    object_id: String,
    resource: String,
) -> Result<()> {
    let client = SourceHubClient::with_signer(
        ChainConfig::local(),
        TxSigner::from_hex_key(TEST_ACCOUNT_HEX_KEY, ChainConfig::local()).expect("Tx signer"),
    )
    .await
    .expect("client builder issue");

    let document = Object {
        resource,
        id: object_id,
    };
    let result = client
        .acp_register_object(&policy_id, document)
        .await
        .map_err(|e| anyhow!("Failed to register object: {}", e))?;

    println!(
        "[ACP] register_object: code={} hash={} log={}",
        result.code, result.tx_hash, result.log
    );

    if result.code != 0 {
        return Err(anyhow!(
            "register_object tx failed: code={} log={}",
            result.code,
            result.log
        ));
    }

    Ok(())
}
pub async fn set_relationship_on_chain(
    policy_id: String,
    object_id: String,
    resource: String,
    relation: String,
    reader_did_pk: Option<String>,
) -> Result<()> {
    let client = SourceHubClient::with_signer(
        ChainConfig::local(),
        TxSigner::from_hex_key(TEST_ACCOUNT_HEX_KEY, ChainConfig::local()).expect("Tx signer"),
    )
    .await
    .expect("client builder issue");

    let document = Object {
        resource,
        id: object_id,
    };

    let reader_did_pk = reader_did_pk.unwrap_or("test_jwt".to_string());
    let seed = did_seed(&reader_did_pk);
    let key_pair = generate::<DidEd25519KeyPair>(Some(&seed));
    let did_uri = format!("did:key:{}", key_pair.fingerprint());

    let reader_relationship = Relationship {
        object: Some(document),
        relation,
        subject: Some(Subject {
            kind: Some(SubjectKind::Actor(Actor {
                id: did_uri.clone(),
            })),
        }),
    };

    let result = client
        .acp_set_relationship(&policy_id, reader_relationship)
        .await
        .map_err(|e| anyhow!("Failed to set reader relationship: {}", e))?;

    println!(
        "[ACP] set_relationship({}): code={} hash={} log={}",
        did_uri, result.code, result.tx_hash, result.log
    );

    if result.code != 0 {
        return Err(anyhow!(
            "set_relationship tx failed: code={} log={}",
            result.code,
            result.log
        ));
    }

    Ok(())
}

pub async fn register_bulletin_namespace(namespace: String) -> Result<()> {
    let read_client = SourceHubClient::new(ChainConfig::local())
        .await
        .map_err(|e| anyhow!("Failed to create chain client: {}", e))?;

    if read_client.bulletin_get_namespace(&namespace).await.is_ok() {
        println!("Bulletin namespace already exists: {}", namespace);
        return Ok(());
    }

    let signer = TxSigner::from_hex_key(TEST_ACCOUNT_HEX_KEY, ChainConfig::local())
        .map_err(|e| anyhow!("Failed to create signer: {}", e))?;

    let bulletin = SourceHubBulletin::with_signer(ChainConfigBuilder::default(), signer, None)
        .await
        .map_err(|e| anyhow!("Failed to create bulletin client: {}", e))?;

    if let Err(e) = bulletin.register(namespace.clone()).await {
        let msg = e.to_string();
        if msg.contains("already exists") || msg.contains("namespace already exists") {
            println!("Bulletin namespace already exists: {}", namespace);
            return Ok(());
        }
        return Err(anyhow!("Failed to register namespace: {}", e));
    }

    println!("Registered bulletin namespace: {}", namespace);
    Ok(())
}

pub async fn add_bulletin_collaborator(
    namespace: String,
    collaborator_address: String,
) -> Result<()> {
    let signer = TxSigner::from_hex_key(TEST_ACCOUNT_HEX_KEY, ChainConfig::local())
        .map_err(|e| anyhow!("Failed to create signer: {}", e))?;

    let client = SourceHubClient::with_signer(ChainConfig::local(), signer)
        .await
        .map_err(|e| anyhow!("Failed to create blockchain client: {}", e))?;

    let result = match client
        .bulletin_add_collaborator(&namespace, &collaborator_address)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("already exists") || msg.contains("collaborator already exists") {
                println!(
                    "Collaborator {} already on namespace {}",
                    collaborator_address, namespace
                );
                return Ok(());
            }
            return Err(anyhow!("Failed to add collaborator: {}", e));
        }
    };

    if result.code != 0 {
        let log = result.log;
        if log.contains("already exists") || log.contains("collaborator already exists") {
            println!(
                "Collaborator {} already on namespace {}",
                collaborator_address, namespace
            );
            return Ok(());
        }
        return Err(anyhow!(
            "Failed to add collaborator: code {} {}",
            result.code,
            log
        ));
    }

    println!(
        "Added collaborator {} to namespace {}",
        collaborator_address, namespace
    );
    Ok(())
}

pub async fn create_bulletin_post(namespace: String, payload: Vec<u8>) -> Result<String> {
    let signer = TxSigner::from_hex_key(TEST_ACCOUNT_HEX_KEY, ChainConfig::local())
        .map_err(|e| anyhow!("Failed to create signer: {}", e))?;

    let bulletin = SourceHubBulletin::with_signer(ChainConfigBuilder::default(), signer, None)
        .await
        .map_err(|e| anyhow!("Failed to create bulletin client: {}", e))?;

    let post_id = bulletin
        .get_post_id(&namespace, &payload)
        .map_err(|e| anyhow!("Failed to generate post ID: {}", e))?;

    bulletin
        .post(namespace, payload, None)
        .await
        .map_err(|e| anyhow!("Failed to create post: {}", e))?;

    println!("Created bulletin post with ID: {}", post_id);
    Ok(post_id)
}

pub async fn update_ring_post_by_acp(
    namespace: String,
    id: String,
    new_peer_ids: Vec<String>,
    new_threshold: Option<u32>,
    pss_interval: Option<u64>,
) -> Result<()> {
    let signer = TxSigner::from_hex_key(TEST_ACCOUNT_HEX_KEY, ChainConfig::local())
        .map_err(|e| anyhow!("Failed to create signer: {}", e))?;

    let client = SourceHubClient::with_signer(ChainConfig::local(), signer)
        .await
        .map_err(|e| anyhow!("Failed to create SourceHub client: {}", e))?;

    let result = client
        .bulletin_update_ring_post_by_acp(
            &namespace,
            &id,
            None,
            new_peer_ids,
            new_threshold,
            pss_interval,
        )
        .await
        .map_err(|e| anyhow!("Failed to update ring post: {}", e))?;

    if result.code != 0 {
        return Err(anyhow!(
            "Failed to update ring post: code {} {}",
            result.code,
            result.log
        ));
    }

    println!("Updated ring post with ID: {}", id);
    Ok(())
}

/// Read a bulletin post by namespace and ID
pub async fn read_bulletin_post(namespace: String, id: String) -> Result<Vec<u8>> {
    let bulletin = SourceHubBulletin::new(ChainConfigBuilder::default())
        .await
        .map_err(|e| anyhow!("Failed to create bulletin client: {}", e))?;

    let post = bulletin
        .read(namespace, id)
        .await
        .map_err(|e| anyhow!("Failed to read bulletin post: {}", e))?;

    Ok(post.payload)
}

/// List all bulletin posts in a namespace
pub async fn list_bulletin_posts(namespace: String) -> Result<Vec<Vec<u8>>> {
    let client = SourceHubClient::new(ChainConfig::local())
        .await
        .map_err(|e| anyhow!("Failed to create client: {}", e))?;

    let posts = client
        .bulletin_list_posts(&namespace)
        .await
        .map_err(|e| anyhow!("Failed to list bulletin posts: {}", e))?;

    Ok(posts.into_iter().map(|p| p.payload).collect())
}

/// Fetch the latest ring from the bulletin (e.g. after DKG).
/// Returns (ring_id, ring_pk_hex). Uses namespace "orbis" by default.
pub async fn get_latest_ring(namespace: Option<String>) -> Result<(String, String)> {
    let namespace = namespace.as_deref().unwrap_or("orbis");
    let client = SourceHubClient::new(ChainConfig::local())
        .await
        .map_err(|e| anyhow!("Failed to create client: {}", e))?;

    let posts = client
        .bulletin_list_posts(namespace)
        .await
        .map_err(|e| anyhow!("Failed to list bulletin posts: {}", e))?;

    let post = posts
        .last()
        .ok_or_else(|| anyhow!("No posts in namespace {:?}; run DKG first", namespace))?;

    let ring_payload: RingPayload = serde_json::from_slice(&post.payload)
        .map_err(|e| anyhow!("Failed to parse ring payload: {}", e))?;

    Ok((post.id.clone(), ring_payload.ring_pk))
}

/// Result of querying node info
#[derive(Debug, Clone)]
pub struct NodeInfoResult {
    pub public_address: String,
    pub peer_id: String,
    pub p2p_address: String,
    pub status: proto::info_service::NodeStatus,
    pub managed_ring_count: u32,
}

pub async fn query_node_info(endpoint: String) -> Result<NodeInfoResult> {
    println!("Querying node info from: {}", endpoint);

    let mut client = InfoServiceClient::connect(endpoint.clone())
        .await
        .map_err(|e| anyhow!("Failed to connect to {}: {}", endpoint, e))?;

    let request = Request::new(proto::info_service::GetNodeInfoRequest {});

    let response = client
        .get_node_info(request)
        .await
        .map_err(|e| anyhow!("Failed to query node info: {}", e))?;

    let node_info = response.into_inner();
    let status = proto::info_service::NodeStatus::try_from(node_info.status)
        .unwrap_or(proto::info_service::NodeStatus::Unspecified);

    let output = format!(
        "Node Info:\n{}\n  Public Address: {}\n  Peer ID: {}\n  P2P Address: {}\n  Status: {}\n  Managed Ring Count: {}",
        "=".repeat(60),
        node_info.public_address,
        node_info.peer_id,
        node_info.p2p_address,
        status.as_str_name(),
        node_info.managed_ring_count
    );

    println!("{}", output);

    Ok(NodeInfoResult {
        public_address: node_info.public_address,
        peer_id: node_info.peer_id,
        p2p_address: node_info.p2p_address,
        status,
        managed_ring_count: node_info.managed_ring_count,
    })
}

/// Query the local RingPolyState from a node (public polynomial + last_pss timestamp).
/// Returns an error if the ring_pk_hex is not found on that node.
pub async fn query_ring_state(endpoint: String, ring_pk_hex: String) -> Result<(String, u64)> {
    let mut client = InfoServiceClient::connect(endpoint.clone())
        .await
        .map_err(|e| anyhow!("Failed to connect to {}: {}", endpoint, e))?;

    let response = client
        .get_ring_state(proto::info_service::GetRingStateRequest { ring_pk_hex })
        .await
        .map_err(|e| anyhow!("get_ring_state failed: {}", e))?;

    let inner = response.into_inner();
    Ok((inner.public_polynomial, inner.last_pss))
}

/// Get the current sequence number for an account address.
/// Useful for verifying if a transaction was broadcast (sequence increments after each tx).
pub async fn get_account_sequence(address: &str) -> Result<u64> {
    let client = SourceHubClient::new(ChainConfig::local())
        .await
        .map_err(|e| anyhow!("Failed to create client: {}", e))?;

    let account_info = client
        .get_account(address)
        .await
        .map_err(|e| anyhow!("Failed to get account info: {}", e))?;

    Ok(account_info.sequence)
}

/// Post a `KeyDerivation` to the bulletin under `namespace`.
///
/// Returns `(post_id, derived_pk_hex)` where `post_id` is used as the
/// `derivation_id` in sign requests and `derived_pk_hex` is the public key
/// derived from the ring PK and the derivation bytes.
///
/// The caller must ensure the node's public address has been added as a
/// collaborator on the namespace before posting.
pub async fn post_key_derivation(
    namespace: String,
    ring_id: String,
    derivation: String,
    policy_id: String,
    resource: String,
    permission: String,
) -> Result<(String, String)> {
    // Fetch ring payload from bulletin to get the ring public key
    let ring_bulletin = SourceHubBulletin::new(ChainConfigBuilder::default())
        .await
        .map_err(|e| anyhow!("Failed to create bulletin client: {}", e))?;
    let ring_post = ring_bulletin
        .read("orbis".to_string(), ring_id.clone())
        .await
        .map_err(|e| anyhow!("Failed to read ring post '{}': {}", ring_id, e))?;
    let ring_payload: RingPayload = serde_json::from_slice(&ring_post.payload)
        .map_err(|e| anyhow!("Failed to parse RingPayload: {}", e))?;

    // Compute derived public key using the signer's derivation (not PRE's)
    let ring_pk_bytes = hex::decode(&ring_payload.ring_pk)
        .map_err(|e| anyhow!("Invalid ring_pk hex in bulletin: {}", e))?;
    let ring_pk_point =
        G1Affine::from_bytes(&ring_pk_bytes).map_err(|e| anyhow!("Invalid ring_pk: {}", e))?;
    let metadata = SignImpl::encode_metadata(&policy_id, &resource, &permission);
    let derived_pk =
        SignImpl::derive_public_key(&ring_pk_point, derivation.as_bytes(), Some(&metadata))
            .map_err(|e| anyhow!("Failed to derive public key: {}", e))?;
    let derived_pk_hex = hex::encode(
        derived_pk
            .to_bytes()
            .map_err(|e| anyhow!("Failed to serialize derived_pk: {}", e))?,
    );

    let signer = TxSigner::from_hex_key(TEST_ACCOUNT_HEX_KEY, ChainConfig::local())
        .map_err(|e| anyhow!("Failed to create signer: {}", e))?;

    let bulletin = SourceHubBulletin::with_signer(ChainConfigBuilder::default(), signer, None)
        .await
        .map_err(|e| anyhow!("Failed to create bulletin client: {}", e))?;

    let key_derivation = KeyDerivation {
        ring_id: ring_id.clone(),
        derivation: derivation.clone(),
        policy_id: policy_id.clone(),
        resource: resource.clone(),
        permission: permission.clone(),
    };

    let payload: Vec<u8> = serde_json::to_vec(&key_derivation)
        .map_err(|e| anyhow!("Failed to serialize KeyDerivation: {}", e))?;

    let post_id = bulletin
        .get_post_id(&namespace, &payload)
        .map_err(|e| anyhow!("Failed to generate post ID: {}", e))?;

    bulletin
        .post(namespace.clone(), payload, None)
        .await
        .map_err(|e| anyhow!("Failed to post KeyDerivation: {}", e))?;

    println!(
        "Posted KeyDerivation to namespace '{}': derivation_id={} derived_pk={}",
        namespace, post_id, derived_pk_hex
    );
    Ok((post_id, derived_pk_hex))
}

/// Result of a Sign operation
#[derive(Debug)]
pub struct SignResult {
    pub status: String,
    pub message: String,
    pub created_at: i64,
    pub signature: String,
}

/// Call `SignService.StartSign` with a JWT-authenticated request.
///
/// `namespace` and `derivation_id` must match the `KeyDerivation` posted to
/// the bulletin via `post_key_derivation`. The JWT is bound to both fields so
/// the node can verify the caller is authorised to sign under that key derivation.
pub async fn do_sign(
    endpoint: String,
    message: Vec<u8>,
    namespace: String,
    derivation_id: String,
    reader_did_pk: Option<String>,
    valid_window_start: Option<u64>,
    valid_window_end: Option<u64>,
) -> Result<SignResult> {
    println!("Starting Sign session:");
    println!("  Endpoint: {}", endpoint);
    println!("  Namespace: {}", namespace);
    println!("  Derivation ID: {}", derivation_id);
    println!("  Message length: {} bytes", message.len());
    println!();

    let mut client = SignServiceClient::connect(endpoint.clone())
        .await
        .map_err(|e| anyhow!("Failed to connect to {}: {}", endpoint, e))?;

    let valid_window = match (valid_window_start, valid_window_end) {
        (Some(start), Some(end)) => Some(proto::sign_service::TimestampRange { start, end }),
        _ => None,
    };

    let request = proto::sign_service::StartSignRequest {
        message: message.clone(),
        namespace: namespace.clone(),
        derivation_id: derivation_id.clone(),
        valid_window,
    };

    let reader_did_pk = reader_did_pk.unwrap_or("test_jwt".to_string());
    let seed = did_seed(&reader_did_pk);
    let key_pair = generate::<DidEd25519KeyPair>(Some(&seed));
    let jwt_signer = JwtSigner::from_key_pair(key_pair);
    let token = jwt_signer
        .create_sign_jwt(&namespace, &derivation_id, &message)
        .map_err(|e| anyhow!("Failed to create sign JWT: {}", e))?;

    let tonic_request = create_authenticated_request(request, &token)
        .map_err(|e| anyhow!("Failed to create authenticated request: {}", e))?;

    let response = client
        .start_sign(tonic_request)
        .await
        .map_err(|e| anyhow!("Sign request failed: {}", e))?;

    let response = response.into_inner();

    println!("Sign Result:");
    println!("{}", "=".repeat(60));
    println!("  Status: {}", response.status);
    println!("  Message: {}", response.message);
    println!("  Signature: {}", response.signature);

    Ok(SignResult {
        status: response.status,
        message: response.message,
        created_at: response.created_at,
        signature: response.signature,
    })
}

pub async fn fund(address: String, config: ChainConfig) -> Result<()> {
    println!("Funding address: {}", address);

    // Transfer a reasonable amount (e.g., 1000000 uopen = 1 OPEN)
    // This should be enough for multiple transactions
    let amount = 1_000_000u64;
    let denom = "uopen";

    println!("Transferring {} {} to {}", amount, denom, address);

    // Retry logic for timing issues (REST API might not be ready immediately)
    // and sequence mismatch issues (multiple nodes starting simultaneously)
    // This is dumb but fine for testing
    let max_retries = 15;
    let mut last_error = None;

    // Create the signer once
    let signer = TxSigner::from_hex_key(TEST_ACCOUNT_HEX_KEY, config.clone())
        .map_err(|e| anyhow!("Failed to create signer from test account: {}", e))?;

    let client = SourceHubClient::with_signer(config.clone(), signer)
        .await
        .map_err(|e| anyhow!("Failed to create client: {}", e))?;

    for attempt in 1..=max_retries {
        match client.transfer(&address, amount, denom).await {
            Ok(result) => {
                println!(
                    "Transfer successful! Tx hash: {}, Height: {:?}",
                    result.tx_hash, result.height
                );
                return Ok(());
            }
            Err(e) => {
                let err_str = e.to_string();
                println!(
                    "Transfer attempt {}/{} failed: {}",
                    attempt, max_retries, err_str
                );
                last_error = Some(anyhow!("{}", e));
                if attempt < max_retries {
                    // Use pseudo-random delay (1-4 seconds) to desynchronize competing nodes
                    // Based on current time nanos to add jitter between nodes
                    let nanos = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_nanos() as u64)
                        .unwrap_or(0);
                    let delay_ms = 1000 + (nanos % 3000);
                    println!("Retrying in {}ms...", delay_ms);
                    tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;
                }
            }
        }
    }

    Err(anyhow!(
        "Failed to transfer funds after {} attempts: {}",
        max_retries,
        last_error.map(|e| e.to_string()).unwrap_or_default()
    ))
}
