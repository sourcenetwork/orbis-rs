//! Commands that talk to a running orbis-node over gRPC: DKG, PRE, Sign, StoreSecret,
//! and node/ring status queries.

use anyhow::{anyhow, Context, Result};
use authn::{create_authenticated_request, JwtSigner};
use crypto::context::CiphertextContext;
use crypto::r#trait::{Secret, ThresholdDealer};
use crypto::{CryptoDeserialize, CryptoSerialize};
use crypto::{GroupAffine as G1Affine, PreImpl as ThresholdDealerNode, ScalarField as Fr};
use did_key::{generate, Ed25519KeyPair as DidEd25519KeyPair};
use serde::Deserialize;
use tonic::{Code, Request, Status};

use proto::info_service::info_service_client::InfoServiceClient;
use proto::v0::dkg::dkg_service_client::DkgServiceClient;
use proto::v0::pre::pre_service_client::PreServiceClient;
use proto::v0::sign::sign_service_client::SignServiceClient;
use proto::v0::store_secret::store_secret_service_client::StoreSecretServiceClient;

use super::crypto::did_seed;
use super::crypto::PreparedSecret;

const DKG_START_MAX_ATTEMPTS: usize = 3;
const DKG_START_RETRY_DELAY: std::time::Duration = std::time::Duration::from_secs(2);

/// Response structure from PRE server (JSON in `StartPreResponse.encrypted_secret`).
#[derive(Debug, Deserialize)]
struct PreResponse {
    /// Recovered reencrypted commitment (xnc_cmt) as hex string
    xnc_cmt: String,
    /// Original encrypted secret
    secret: Secret,
    /// Ciphertext-binding context the node verified the proof against; needed to
    /// rebuild the AES-GCM AAD for local decryption.
    context: CiphertextContext,
}

/// Result of a DKG operation
#[derive(Debug)]
pub struct DkgResult {
    pub session_id: String,
    pub status: String,
    pub message: String,
}

pub(crate) fn is_retryable_dkg_start_error(status: &Status) -> bool {
    status.code() == Code::Unavailable
        && status.message().to_ascii_lowercase().contains("timed out")
}

pub async fn do_dkg(endpoint: String, ring_id: String) -> Result<DkgResult> {
    println!("Starting DKG session:");
    println!("  Endpoint: {}", endpoint);
    println!("  Ring ID: {}", ring_id);
    println!();

    println!("Connecting to {}...", endpoint);

    let mut client = DkgServiceClient::connect(endpoint.clone())
        .await
        .map_err(|e| anyhow!("Failed to connect to {}: {}", endpoint, e))?;

    // JWT work
    let jwt_signer = JwtSigner::new();
    let token = jwt_signer
        .create_dkg_jwt(&ring_id)
        .expect("Failed to create JWT");

    let mut response = None;
    for attempt in 1..=DKG_START_MAX_ATTEMPTS {
        let request = proto::v0::dkg::StartDkgRequest {
            ring_id: ring_id.clone(),
        };
        let tonic_request = create_authenticated_request(request, &token)
            .map_err(|e| anyhow!("Failed to create_dkg_jwt: {}", e))?;

        match client.start_dkg(tonic_request).await {
            Ok(ok) => {
                response = Some(ok);
                break;
            }
            Err(status)
                if attempt < DKG_START_MAX_ATTEMPTS && is_retryable_dkg_start_error(&status) =>
            {
                println!(
                    "DKG request timed out connecting to a peer (attempt {attempt}/{DKG_START_MAX_ATTEMPTS}); retrying..."
                );
                tokio::time::sleep(DKG_START_RETRY_DELAY).await;
            }
            Err(status) => return Err(status).context("DKG request failed"),
        }
    }

    let response = response.expect("DKG retry loop should return or store a response");

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

/// Store a prepared (pre-encrypted) secret using the StoreSecret service.
/// This is idempotent - calling with the same PreparedSecret will return
/// the same object_id without creating duplicates.
pub async fn store_prepared_secret(
    endpoint: String,
    prepared: &PreparedSecret,
    ring_id: String,
    reader_did_pk: Option<String>,
    with_proof: bool,
) -> Result<StoreSecretResult> {
    println!("Storing secret via StoreSecret service:");
    println!("  Endpoint: {}", endpoint);
    println!("  Ring ID: {}", ring_id);
    println!();

    // Policy fields are sourced from the context the proof was bound to, so the
    // stored DocumentPayload can never diverge from what the proof commits to.
    let ctx = &prepared.context;

    let mut client = StoreSecretServiceClient::connect(endpoint.clone())
        .await
        .map_err(|e| anyhow!("Failed to connect to {}: {}", endpoint, e))?;

    let request = proto::v0::store_secret::StoreSecretRequest {
        encrypted_document: prepared.encrypted_document.clone(),
        enc_cmt: prepared.enc_cmt.clone(),
        ring_id: ring_id.clone(),
        policy_id: ctx.policy_id.clone(),
        resource: ctx.resource.clone(),
        permission: ctx.permission.clone(),
        challenge: prepared.challenge.clone(),
        response: prepared.response.clone(),
        with_proof,
        tier: ctx.tier.clone(),
        timestamp: ctx.timestamp,
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
            &ctx.policy_id,
            &ctx.resource,
            &ctx.permission,
            prepared.challenge.clone(),
            prepared.response.clone(),
            with_proof,
            ctx.tier.clone(),
            ctx.timestamp,
        )
        .map_err(|e| anyhow!("Failed to create JWT: {}", e))?;

    let tonic_request = create_authenticated_request(request, &token)
        .map_err(|e| anyhow!("Failed to create authenticated request: {}", e))?;

    let response = client
        .store_secret(tonic_request)
        .await
        .context("StoreSecret request failed")?;

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
#[allow(clippy::too_many_arguments)]
pub async fn do_store_secret(
    endpoint: String,
    secret: &[u8],       // Plaintext secret - encrypted locally before sending
    ring_pk_hex: String, // Ring public key (hex) - used for encryption
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
    let prepared = super::crypto::prepare_secret(
        secret,
        &ring_pk_hex,
        derivation,
        policy_id,
        resource,
        permission,
        tier,
        timestamp,
        salt,
    )?;
    store_prepared_secret(endpoint, &prepared, ring_id, reader_did_pk, with_proof).await
}

#[allow(clippy::too_many_arguments)]
pub async fn do_pre(
    endpoint: String,
    ring_pk: String,
    reader_pk: String,
    reader_sk: Option<String>,
    object_id: String,
    reader_did_pk: Option<String>,
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
    let reader_pk_point = G1Affine::from_bytes(&reader_pk_bytes)
        .map_err(|e| anyhow!("Failed to deserialize reader_pk: {}", e))?;

    // Parse reader secret key. Always required — not merely for the final
    // decrypt step, but because the node now requires a proof of knowledge of
    // reader_pk's discrete log before it will re-encrypt to it at all.
    let reader_sk_hex = reader_sk
        .as_deref()
        .ok_or_else(|| anyhow!("--reader-sk is required"))?;
    let reader_sk_bytes =
        hex::decode(reader_sk_hex).map_err(|e| anyhow!("Failed to decode reader_sk hex: {}", e))?;
    let reader_sk_scalar = Fr::from_bytes(&reader_sk_bytes)
        .map_err(|e| anyhow!("Failed to deserialize reader_sk: {}", e))?;

    // Prove knowledge of reader_sk for reader_pk; every responder verifies
    // this before computing anything with reader_pk.
    let rdr_pk_proof = ThresholdDealerNode::prove_reader_key(&reader_sk_scalar, &reader_pk_point)
        .map_err(|e| anyhow!("Failed to prove reader key: {}", e))?;

    println!("  Encrypted secret created");
    println!();

    // Step 2: Send to PRE service for re-encryption
    println!("Step 2: Sending to PRE service for re-encryption...");
    let mut client = PreServiceClient::connect(endpoint.clone())
        .await
        .map_err(|e| anyhow!("Failed to connect to {}: {}", endpoint, e))?;

    let valid_window = match (valid_window_start, valid_window_end) {
        (Some(start), Some(end)) => Some(proto::v0::pre::TimestampRange { start, end }),
        _ => None,
    };

    let request = proto::v0::pre::StartPreRequest {
        rdr_pk: reader_pk_bytes.clone(),
        object_id: object_id.clone(),
        derivation: derivation.clone(),
        salt: salt.clone(),
        valid_window,
        document: None,
        rdr_pk_proof: Some(proto::v0::pre::ReaderKeyProof {
            challenge: rdr_pk_proof.challenge,
            response: rdr_pk_proof.response,
        }),
    };

    // JWT work use determinitic key_pair for now
    let reader_did_pk = reader_did_pk.unwrap_or("test_jwt".to_string());
    let seed = did_seed(&reader_did_pk);
    let key_pair = generate::<DidEd25519KeyPair>(Some(&seed));
    let jwt_signer = JwtSigner::from_key_pair(key_pair);
    let token = jwt_signer
        .create_pre_jwt(
            reader_pk_bytes.clone(),
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
        .context("PRE request failed")?;

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

        // The node echoes back the ciphertext-binding context it verified the
        // proof against; it is needed to rebuild the AES-GCM AAD. A wrong context
        // (or a lying node) makes the authenticated decryption below fail.
        let decrypted = ThresholdDealerNode::decrypt_secret(
            &effective_pk,
            &xnc_cmt,
            &reader_sk_scalar,
            &pre_response.secret,
            &pre_response.context,
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
    println!("  Endpoint: {}", endpoint);
    println!("  Derivation ID: {}", derivation_id);
    println!("  Message length: {} bytes", message.len());
    println!();

    let mut client = SignServiceClient::connect(endpoint.clone())
        .await
        .map_err(|e| anyhow!("Failed to connect to {}: {}", endpoint, e))?;

    let valid_window = match (valid_window_start, valid_window_end) {
        (Some(start), Some(end)) => Some(proto::v0::sign::TimestampRange { start, end }),
        _ => None,
    };

    let request = proto::v0::sign::StartSignRequest {
        message: message.clone(),
        derivation_id: derivation_id.clone(),
        valid_window,
    };

    let reader_did_pk = reader_did_pk.unwrap_or("test_jwt".to_string());
    let seed = did_seed(&reader_did_pk);
    let key_pair = generate::<DidEd25519KeyPair>(Some(&seed));
    let jwt_signer = JwtSigner::from_key_pair(key_pair);
    let token = jwt_signer
        .create_sign_jwt(&derivation_id, &message)
        .map_err(|e| anyhow!("Failed to create sign JWT: {}", e))?;

    let tonic_request = create_authenticated_request(request, &token)
        .map_err(|e| anyhow!("Failed to create authenticated request: {}", e))?;

    let response = client
        .start_sign(tonic_request)
        .await
        .context("Sign request failed")?;

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

/// Result of querying node info
#[derive(Debug, Clone)]
pub struct NodeInfoResult {
    pub public_address: String,
    pub peer_id: String,
    pub p2p_address: String,
    pub status: proto::info_service::NodeStatus,
    pub managed_ring_count: u32,
    /// Compressed secp256k1 pubkey hex — the node's on-chain key in x/orbis NodeInfo.
    pub node_key: String,
    pub supported_protocol_versions: Vec<u64>,
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
        "Node Info:\n{}\n  Public Address: {}\n  Peer ID: {}\n  Node Key: {}\n  P2P Address: {}\n  Status: {}\n  Managed Ring Count: {}\n  Supported Protocol Versions: {:?}",
        "=".repeat(60),
        node_info.public_address,
        node_info.peer_id,
        node_info.node_key,
        node_info.p2p_address,
        status.as_str_name(),
        node_info.managed_ring_count,
        node_info.supported_protocol_versions
    );

    println!("{}", output);

    Ok(NodeInfoResult {
        public_address: node_info.public_address,
        peer_id: node_info.peer_id,
        p2p_address: node_info.p2p_address,
        status,
        managed_ring_count: node_info.managed_ring_count,
        node_key: node_info.node_key,
        supported_protocol_versions: node_info.supported_protocol_versions,
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
