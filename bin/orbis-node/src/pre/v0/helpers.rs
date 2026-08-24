use crate::helpers::protocol_version::read_ring_for_route;
use crate::helpers::response_manager::ResponseStoreOutcome;
use crate::pre::v0::{
    error::{PreError, Result},
    messages::PreMessage,
    response_state::PreResponseManager,
};
use authn::{BearerToken, PreClaims};
use authz::r#trait::Authz;
use authz::sourcehub::{AccessCheckRequest, ValidWindow};
use bulletin::r#trait::{Bulletin, BulletinKind, DocumentPayload, RingPayload};
use common::blockchain::orbis::generate_document_id;
use crypto::r#trait::{EncryptionProof, Secret, ThresholdDealer};
use crypto::{CryptoDeserialize, GroupAffine as G1Affine, PreImpl as ThresholdDealerNode};
use network::PeerId;
use std::sync::Arc;

async fn fetch_document_payload(
    bulletin: &(dyn Bulletin + Send + Sync),
    object_id: &str,
) -> Result<DocumentPayload> {
    let object_info = bulletin
        .read(object_id.to_string(), BulletinKind::Document)
        .await
        .map_err(|e| PreError::Storage(format!("Failed to read object '{}': {}", object_id, e)))?;

    serde_json::from_slice::<DocumentPayload>(&object_info.payload)
        .map_err(|e| PreError::Deserialization(format!("Failed to parse document payload: {}", e)))
}

/// Confirms a caller-supplied document is genuinely the one `object_id` refers to.
///
/// `object_id` is `generate_document_id` over every field of `DocumentPayload` — the same
/// deterministic ID SourceHub assigns when a document is posted to the bulletin
/// (`crates/bulletin/src/sourcehub/mod.rs`). Recomputing and comparing it here means a document
/// supplied directly on the wire (never posted to the bulletin) is just as tightly bound to
/// `object_id` as one read back from chain — a caller cannot pair an `object_id` they're
/// authorized for with a different document's ciphertext/proof without this failing.
pub fn validate_inline_document_id(object_id: &str, document: &DocumentPayload) -> Result<()> {
    let expected = generate_document_id(
        &document.ring_id,
        &document.document,
        &document.proof,
        &document.policy_id,
        &document.resource,
        &document.permission,
        document.tier.as_deref(),
        document.timestamp,
    );

    if expected != object_id {
        return Err(PreError::Unauthorized(format!(
            "supplied document does not match object_id '{}'",
            object_id
        )));
    }

    Ok(())
}

/// Resolves the document and ring payloads for a PRE request, either from a caller-supplied
/// `DocumentPayload` (validated against `object_id` via [`validate_inline_document_id`]) or, when
/// none is supplied, by reading the document from the bulletin by `object_id`.
///
/// `ring_payload` is always read live from the bulletin regardless of the document's source —
/// ring membership/threshold and the live ACP check are not made caller-suppliable.
pub async fn resolve_document_and_ring_payloads(
    bulletin: &(dyn Bulletin + Send + Sync),
    object_id: &str,
    protocol_version: u64,
    inline_document: Option<DocumentPayload>,
) -> Result<(DocumentPayload, RingPayload)> {
    let document_payload = match inline_document {
        Some(document) => {
            validate_inline_document_id(object_id, &document)?;
            document
        }
        None => fetch_document_payload(bulletin, object_id).await?,
    };

    let ring_payload = read_ring_for_route(bulletin, &document_payload.ring_id, protocol_version)
        .await
        .map_err(PreError::ProtocolError)?;

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
        document_payload.timestamp,
        valid_window,
    )
    .to_bytes()
    .map_err(|e| PreError::AuthZ(format!("Error formatting access request: {}", e)))?;

    let is_authorized = authz
        .check(permission, issuer_id)
        .await
        .map_err(|e| PreError::AuthZ(format!("Error in Authz request: {}", e)))?;

    if !is_authorized {
        return Err(PreError::Unauthorized(
            "Access denied: policy check failed".to_string(),
        ));
    }

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

/// Store a received response (called by protocol handler)
///
/// The response is only accepted if the authenticated `sender_peer_id` is in the
/// expected responder set (established at init time). This rejects both unknown peers
/// and duplicate responses from the same peer. Fake `from_node_id` values are caught
/// downstream by crypto verification (`dealer.verify()`).
pub async fn store_response(
    protocol_version: u64,
    message: PreMessage,
    sender_peer_id: &PeerId,
    pre_response_state: &Arc<PreResponseManager>,
) -> bool {
    let request_id = message.request_id().to_string();

    tracing::debug!(
        request_id = %request_id,
        from_node_id = ?message.sender_node_id(),
        sender_peer = %hex::encode(sender_peer_id.as_bytes()),
        "PRE Coordinator: Storing response"
    );

    pre_response_state
        .store_response_for_version(
            protocol_version,
            &request_id,
            message,
            sender_peer_id.as_bytes(),
        )
        .await
        == ResponseStoreOutcome::Stored
}

#[cfg(test)]
mod tests {
    use super::*;

    fn document_b() -> DocumentPayload {
        DocumentPayload {
            ring_id: "ring-1".to_string(),
            document: "b-ciphertext".to_string(),
            proof: "b-proof".to_string(),
            policy_id: "policy-b".to_string(),
            resource: "document".to_string(),
            permission: "read".to_string(),
            tier: Some("gold".to_string()),
            timestamp: Some(1_700_000_000),
        }
    }

    fn object_id_for(document: &DocumentPayload) -> String {
        generate_document_id(
            &document.ring_id,
            &document.document,
            &document.proof,
            &document.policy_id,
            &document.resource,
            &document.permission,
            document.tier.as_deref(),
            document.timestamp,
        )
    }

    #[test]
    fn validate_inline_document_id_accepts_matching_document() {
        let document = document_b();
        let object_id = object_id_for(&document);
        assert!(validate_inline_document_id(&object_id, &document).is_ok());
    }

    #[test]
    fn validate_inline_document_id_rejects_tampered_fields() {
        let object_id = object_id_for(&document_b());

        let mutations: Vec<(&str, Box<dyn Fn(&mut DocumentPayload)>)> = vec![
            (
                "ring_id",
                Box::new(|d: &mut DocumentPayload| d.ring_id = "ring-2".to_string()),
            ),
            (
                "document",
                Box::new(|d: &mut DocumentPayload| d.document = "tampered".to_string()),
            ),
            (
                "proof",
                Box::new(|d: &mut DocumentPayload| d.proof = "tampered".to_string()),
            ),
            (
                "policy_id",
                Box::new(|d: &mut DocumentPayload| d.policy_id = "policy-attacker".to_string()),
            ),
            (
                "resource",
                Box::new(|d: &mut DocumentPayload| d.resource = "other-resource".to_string()),
            ),
            (
                "permission",
                Box::new(|d: &mut DocumentPayload| d.permission = "write".to_string()),
            ),
            (
                "tier",
                Box::new(|d: &mut DocumentPayload| d.tier = Some("silver".to_string())),
            ),
            (
                "timestamp",
                Box::new(|d: &mut DocumentPayload| d.timestamp = Some(1)),
            ),
        ];

        for (field, mutate) in mutations {
            let mut tampered = document_b();
            mutate(&mut tampered);
            assert!(
                matches!(
                    validate_inline_document_id(&object_id, &tampered),
                    Err(PreError::Unauthorized(_))
                ),
                "tampering '{field}' should have been rejected"
            );
        }
    }

    /// Regression test for the confused-deputy scenario found while designing this feature:
    /// an attacker who is genuinely authorized for `object_id = B` cannot get a *different*,
    /// honestly-generated document C's ciphertext/proof re-encrypted by pairing them with `B`.
    /// `object_id` commits to every field of the document (including the ciphertext and proof),
    /// so C's fields can never hash to B's object_id.
    #[test]
    fn validate_inline_document_id_rejects_a_different_honest_document_under_the_wrong_object_id() {
        let object_id_b = object_id_for(&document_b());

        let document_c = DocumentPayload {
            ring_id: "ring-1".to_string(),
            document: "c-ciphertext".to_string(),
            proof: "c-proof".to_string(),
            policy_id: "policy-b".to_string(),
            resource: "document".to_string(),
            permission: "read".to_string(),
            tier: Some("gold".to_string()),
            timestamp: Some(1_700_000_000),
        };
        // document_c is itself internally valid for its own object_id...
        assert!(validate_inline_document_id(&object_id_for(&document_c), &document_c).is_ok());
        // ...but cannot be smuggled in under B's object_id.
        assert!(matches!(
            validate_inline_document_id(&object_id_b, &document_c),
            Err(PreError::Unauthorized(_))
        ));
    }
}
