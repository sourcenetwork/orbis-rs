//! CLI command implementations
//!
//! This module contains the actual implementation of CLI commands,
//! separated from main.rs so they can be used in integration tests.

use anyhow::{anyhow, Result};
use ark_bls12_381::{Fr, G1Affine, G1Projective};
use ark_ec::Group;
use ark_std::UniformRand;
use authn::{create_authenticated_request, JwtSigner};
use common::blockchain::{
    acp::{Actor, Object, Relationship, Subject, SubjectKind},
    ChainConfig, SourceHubClient, TxSigner, TEST_ACCOUNT_HEX_KEY,
};
use crypto::bls12_381::pre::ThresholdDealerNode;
use crypto::r#trait::{Secret, ThresholdDealer};
use crypto::{CryptoDeserialize, CryptoSerialize};
use did_key::{generate, Ed25519KeyPair as DidEd25519KeyPair, Fingerprint};
use rand_core::OsRng;
use serde::Deserialize;

use proto::dkg_service::dkg_service_client::DkgServiceClient;
use proto::pre_service::pre_service_client::PreServiceClient;

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

pub async fn do_dkg(endpoint: String, threshold: u32, peer_ids: Vec<String>) -> Result<DkgResult> {
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
    println!();

    println!("Connecting to {}...", endpoint);

    let mut client = DkgServiceClient::connect(endpoint.clone())
        .await
        .map_err(|e| anyhow!("Failed to connect to {}: {}", endpoint, e))?;

    let request = proto::dkg_service::StartDkgRequest {
        threshold,
        peer_ids: peer_ids.clone(),
    };

    // JWT work
    let jwt_signer = JwtSigner::new();
    let token = jwt_signer
        .create_dkg_jwt(threshold, &peer_ids)
        .expect("Failed to create JWT");
    let tonic_request = create_authenticated_request(request, &token);

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

// TODO: Encrypt secret and post it to bulletin to a policy
//  Step 1: Encrypt the plaintext secret to the ring public key
// println!("Step 1: Encrypting secret to ring public key...");
// let (_enc_cmt, encrypted_secret) =
//     ThresholdDealerNode::encrypt_secret(&ring_pk_point, secret.as_bytes())
//         .map_err(|e| anyhow!("Encryption failed: {}", e))?;

// // Serialize the encrypted secret to JSON for the PRE request
// let encrypted_secret_json = serde_json::to_string(&encrypted_secret)
//     .map_err(|e| anyhow!("Failed to serialize encrypted secret: {}", e))?;

pub async fn do_pre(
    endpoint: String,
    ring_pk: String,
    reader_pk: String,
    reader_sk: String,
    object_id: String,
    reader_did_pk: Option<String>,
    namespace: String,
) -> Result<()> {
    println!("Starting PRE session:");
    println!("  Endpoint: {}", endpoint);
    println!("  Reader PK: {}...", &reader_pk[..reader_pk.len().min(20)]);

    // Parse the reader keys
    let reader_pk_bytes =
        hex::decode(&reader_pk).map_err(|e| anyhow!("Failed to decode reader_pk hex: {}", e))?;
    let _reader_pk_point = G1Affine::from_bytes(&reader_pk_bytes)
        .map_err(|e| anyhow!("Failed to deserialize reader_pk: {}", e))?;

    let reader_sk_bytes =
        hex::decode(&reader_sk).map_err(|e| anyhow!("Failed to decode reader_sk hex: {}", e))?;
    let reader_sk_scalar = Fr::from_bytes(&reader_sk_bytes)
        .map_err(|e| anyhow!("Failed to deserialize reader_sk: {}", e))?;

    println!("  Encrypted secret created");
    println!();

    // Step 2: Send to PRE service for re-encryption
    println!("Step 2: Sending to PRE service for re-encryption...");
    let mut client = PreServiceClient::connect(endpoint.clone())
        .await
        .map_err(|e| anyhow!("Failed to connect to {}: {}", endpoint, e))?;

    let request = proto::pre_service::StartPreRequest {
        rdr_pk: reader_pk.clone(),
        object_id: object_id.clone(),
        namespace: namespace.clone(),
    };

    // JWT work use determinitic key_pair for now
    let reader_did_pk = reader_did_pk.unwrap_or("test_jwt".to_string());
    let key_pair = generate::<DidEd25519KeyPair>(Some(reader_did_pk.as_bytes()));
    let jwt_signer = JwtSigner::from_key_pair(key_pair);
    let token = jwt_signer
        .create_pre_jwt(&reader_pk, &namespace, &object_id)
        .expect("Failed to create JWT");
    let tonic_request = create_authenticated_request(request, &token);

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
        println!();
        println!("Step 3: Decrypting with reader secret key...");

        // Parse the JSON response from server
        let pre_response: PreResponse = serde_json::from_str(&response.encrypted_secret)
            .map_err(|e| anyhow!("Failed to parse PRE response: {}", e))?;

        // Parse the re-encrypted commitment (xnc_cmt) from hex
        let xnc_cmt_bytes = hex::decode(&pre_response.xnc_cmt)
            .map_err(|e| anyhow!("Failed to decode xnc_cmt hex: {}", e))?;
        let xnc_cmt = G1Affine::from_bytes(&xnc_cmt_bytes)
            .map_err(|e| anyhow!("Failed to deserialize xnc_cmt: {}", e))?;

        // Parse the ring public key
        let ring_pk_bytes =
            hex::decode(&ring_pk).map_err(|e| anyhow!("Failed to decode ring_pk hex: {}", e))?;
        let ring_pk_point = G1Affine::from_bytes(&ring_pk_bytes)
            .map_err(|e| anyhow!("Failed to deserialize ring_pk: {}", e))?;

        // Decrypt using reader's secret key and the secret from the response
        let decrypted = ThresholdDealerNode::decrypt_secret(
            &ring_pk_point,
            &xnc_cmt,
            &reader_sk_scalar,
            &pre_response.secret,
        )
        .map_err(|e| anyhow!("Decryption failed: {}", e))?;

        let decrypted_str = String::from_utf8(decrypted)
            .map_err(|e| anyhow!("Decrypted data is not valid UTF-8: {}", e))?;

        println!("  Decrypted Secret: {}", decrypted_str);
    }

    Ok(())
}

pub async fn do_encrypt_secret(ring_pk: String, secret: String) -> Result<()> {
    println!("Encrypting secret to ring public key...");
    println!("  Ring PK: {}...", &ring_pk[..ring_pk.len().min(20)]);
    println!();

    // Parse the ring public key from hex
    let ring_pk_bytes =
        hex::decode(&ring_pk).map_err(|e| anyhow!("Failed to decode ring_pk hex: {}", e))?;

    let ring_pk_point = G1Affine::from_bytes(&ring_pk_bytes)
        .map_err(|e| anyhow!("Failed to deserialize ring_pk: {}", e))?;

    // Encrypt the secret
    let (_enc_cmt, encrypted_secret) =
        ThresholdDealerNode::encrypt_secret(&ring_pk_point, secret.as_bytes())
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
    let mut rng = OsRng;

    // Generate random secret key (scalar)
    let sk = Fr::rand(&mut rng);

    // Derive public key: pk = sk * G
    let pk: G1Affine = (G1Projective::generator() * sk).into();

    // Serialize to bytes then hex
    let sk_bytes = sk
        .to_bytes()
        .map_err(|e| anyhow!("Failed to serialize secret key: {}", e))?;
    let pk_bytes = pk
        .to_bytes()
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

const TEST_POLICY_YAML: &str = r#"
name: test-policy
resources:
  document:
    relations:
      owner:
        types:
          - actor
      reader:
        types:
          - actor
    permissions:
      read:
        expr: owner + reader
      write:
        expr: owner
actor:
  name: actor
"#;

pub async fn add_policy_to_chain() -> Result<String> {
    let client = SourceHubClient::with_signer(
        ChainConfig::local(),
        TxSigner::from_hex_key(TEST_ACCOUNT_HEX_KEY, ChainConfig::local()).expect("Tx signer"),
    )
    .await
    .map_err(|e| anyhow!("client builder issue: {}", e))?;

    let _result = client
        .acp_create_policy(TEST_POLICY_YAML, 1)
        .await
        .map_err(|e| anyhow!("Failed to create policy: {}", e))?;

    // TODO: This is dumb grabs the only policy id that exists, fine for now but fix later by grabbing policy id from event or something
    let policy_ids = client
        .acp_list_policy_ids()
        .await
        .map_err(|e| anyhow!("Failed to list policy IDs: {}", e))?;
    Ok(policy_ids.ids[0].clone())
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
    dbg!(&document);
    let _result = client
        .acp_register_object(&policy_id, document)
        .await
        .map_err(|e| anyhow!("Failed to register object: {}", e))?;

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
    let key_pair = generate::<DidEd25519KeyPair>(Some(reader_did_pk.as_bytes()));
    let did_uri = format!("did:key:{}", key_pair.fingerprint());

    let reader_relationship = Relationship {
        object: Some(document),
        relation,
        subject: Some(Subject {
            kind: Some(SubjectKind::Actor(Actor { id: did_uri })),
        }),
    };

    let _result = client
        .acp_set_relationship(&policy_id, reader_relationship)
        .await
        .map_err(|e| anyhow!("Failed to set reader relationship: {}", e))?;

    Ok(())
}
