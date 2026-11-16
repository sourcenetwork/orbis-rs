//! Shared fixtures for this crate's own unit tests.

use orbis_reporting::PreReencryptResponseStatement;

use crate::envelope::{SignedStoredShareEnvelope, StoredShareEnvelope};

pub(crate) const SIGNING_KEY_HEX: &str =
    "c4a48e2fce1481cd3294b4490f6678090ea98d3d0e5cd984558ab0968741b104";
pub(crate) const PUBLIC_KEY_HEX: &str =
    "024f4e2ad99c34d60b9ba6283c9431a8418af8673212961f97a77b6377fcd05b62";

pub(crate) fn sample_statement() -> PreReencryptResponseStatement {
    PreReencryptResponseStatement {
        domain: "orbis-pre-reencrypt-response-v1".to_string(),
        chain_id: "test-chain".to_string(),
        ring_id: "ring-1".to_string(),
        ring_pk: "ring-pk".to_string(),
        ring_state_sha256: "deadbeef".to_string(),
        protocol_version: 0,
        request_id: "req-1".to_string(),
        signed_at: 1_700_000_000,
        responder_node_key: PUBLIC_KEY_HEX.to_string(),
        origin_protocol: "pre".to_string(),
        object_id: "object-1".to_string(),
        rdr_pk: vec![1, 2, 3],
        derivation: None,
        from_node_id: 1,
        share: vec![4, 5, 6],
        challenge: vec![7, 8, 9],
        proof: vec![10, 11, 12],
        crypto_backend: "bls12-381".to_string(),
        timestamp: Some(1_700_000_000),
        document_inline: false,
    }
}

pub(crate) fn signed_envelope() -> SignedStoredShareEnvelope {
    StoredShareEnvelope::new(sample_statement(), "poly-gen-1".to_string())
        .sign(SIGNING_KEY_HEX)
        .expect("sign envelope")
}
