use crate::constants::BULLETIN_RING_NAMESPACE;
use crate::pre::error::{PreError, Result};
use authn::{BearerToken, PreClaims};
use authz::r#trait::Authz;
use authz::sourcehub::{AccessCheckRequest, ValidWindow};
use bulletin::r#trait::{Bulletin, DocumentPayload, RingPayload};
use crypto::r#trait::{EncryptionProof, Secret, ThresholdDealer};
use crypto::{CryptoDeserialize, GroupAffine as G1Affine, PreImpl as ThresholdDealerNode};

/// Fetches and deserializes the document and ring payloads from the bulletin.
///
/// Reads the document by `namespace`/`object_id`, then follows the embedded
/// `ring_id` to load the corresponding ring payload.
pub async fn fetch_bulletin_payloads(
    bulletin: &(dyn Bulletin + Send + Sync),
    namespace: &str,
    object_id: &str,
) -> Result<(DocumentPayload, RingPayload)> {
    let object_info = bulletin
        .read(namespace.to_string(), object_id.to_string())
        .await
        .map_err(|e| PreError::Storage(format!("Failed to read object '{}': {}", object_id, e)))?;

    let document_payload = serde_json::from_slice::<DocumentPayload>(&object_info.payload)
        .map_err(|e| {
            PreError::Deserialization(format!("Failed to parse document payload: {}", e))
        })?;

    let ring_info = bulletin
        .read(
            BULLETIN_RING_NAMESPACE.to_string(),
            document_payload.ring_id.clone(),
        )
        .await
        .map_err(|e| {
            PreError::Storage(format!(
                "Failed to read ring '{}': {}",
                document_payload.ring_id, e
            ))
        })?;

    let ring_payload = serde_json::from_slice::<RingPayload>(&ring_info.payload)
        .map_err(|e| PreError::Deserialization(format!("Failed to parse ring payload: {}", e)))?;

    Ok((document_payload, ring_payload))
}

/// Checks whether the token issuer has the required policy access for a document.
pub async fn check_policy_access(
    authz: &(dyn Authz + Send + Sync),
    document_payload: &DocumentPayload,
    object_id: &str,
    issuer_id: &str,
    valid_window: Option<ValidWindow>,
) -> Result<()> {
    let permission = AccessCheckRequest::new(
        document_payload.policy_id.clone(),
        document_payload.resource.clone(),
        object_id.to_string(),
        document_payload.permission.clone(),
        document_payload.tier.clone(),
        document_payload.timestamp.clone(),
        valid_window,
    )
    .to_bytes()
    .map_err(|e| PreError::AuthZ(format!("Error formatting access request: {}", e)))?;

    authz
        .check(permission, &issuer_id.to_string())
        .await
        .map_err(|e| PreError::AuthZ(format!("Error in Authz request: {}", e)))?;

    Ok(())
}

/// Hex-decodes and deserializes the ring public key.
///
/// Returns both the raw bytes (for forwarding to peers) and the deserialized key.
pub fn decode_ring_pk(ring_pk_hex: &str) -> Result<(Vec<u8>, G1Affine)> {
    let ring_pk_bytes = hex::decode(ring_pk_hex)
        .map_err(|e| PreError::InvalidInput(format!("Invalid ring_pk hex encoding: {}", e)))?;

    let ring_pk = G1Affine::from_bytes(&ring_pk_bytes)
        .map_err(|e| PreError::Deserialization(format!("Failed to deserialize ring_pk: {}", e)))?;

    Ok((ring_pk_bytes, ring_pk))
}

/// Deserializes a `Secret` from the raw document JSON stored in a `DocumentPayload`.
pub fn deserialize_secret(document_json: &str) -> Result<Secret> {
    serde_json::from_slice(document_json.as_bytes())
        .map_err(|e| PreError::Deserialization(format!("Failed to deserialize secret: {}", e)))
}

/// Verifies that the encryption proof binds the ciphertext to the correct public key and policy.
///
/// Derives the actual public key (applying derivation if present), deserializes the
/// encryption proof and commitment, then verifies via `ThresholdDealerNode::verify_encryption`.
pub fn verify_encryption_binding(
    ring_pk: &G1Affine,
    derivation: Option<&[u8]>,
    proof_str: String,
    enc_cmt_bytes: &[u8],
    policy_metadata: &[u8],
) -> Result<()> {
    let actual_pk = if let Some(derivation) = derivation {
        ThresholdDealerNode::derive_public_key(ring_pk, derivation)
            .map_err(|e| PreError::Crypto(format!("derive_public_key error: {}", e)))?
    } else {
        *ring_pk
    };

    let proof: EncryptionProof = EncryptionProof::try_from(proof_str).map_err(|e| {
        PreError::Deserialization(format!("Failed to deserialize encryption proof: {}", e))
    })?;

    let enc_cmt = G1Affine::from_bytes(enc_cmt_bytes)
        .map_err(|e| PreError::Deserialization(format!("Failed to deserialize enc_cmt: {}", e)))?;

    ThresholdDealerNode::verify_encryption(&actual_pk, &enc_cmt, &proof, Some(policy_metadata))
        .map_err(|e| PreError::Crypto(format!("Policy binding verification failed: {}", e)))?;

    Ok(())
}

/// Validates JWT claims against the PRE request parameters.
pub fn validate_pre_claims(
    token: &BearerToken<PreClaims>,
    rdr_pk: &Vec<u8>,
    object_id: &String,
    namespace: &String,
    derivation: &Option<Vec<u8>>,
    salt: &Option<String>,
) -> Result<()> {
    if token.claims.rdr_pk != *rdr_pk {
        return Err(PreError::Unauthorized(format!(
            "Token rdr_pk '{:?}' does not match request rdr_pk '{:?}'",
            token.claims.rdr_pk, rdr_pk
        )));
    }

    if token.claims.object_id != *object_id {
        return Err(PreError::Unauthorized(format!(
            "Token object_id '{}' does not match request object_id '{}'",
            token.claims.object_id, object_id
        )));
    }

    if token.claims.namespace != *namespace {
        return Err(PreError::Unauthorized(format!(
            "Token namespace '{}' does not match request namespace '{}'",
            token.claims.namespace, namespace
        )));
    }

    if token.claims.derivation != *derivation {
        return Err(PreError::Unauthorized(format!(
            "Token derivation '{:?}' does not match request derivation '{:?}'",
            token.claims.derivation, derivation
        )));
    }

    if token.claims.salt != *salt {
        return Err(PreError::Unauthorized(format!(
            "Token salt '{:?}' does not match request salt '{:?}'",
            token.claims.salt, salt
        )));
    }
    Ok(())
}
