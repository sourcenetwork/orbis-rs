use prost::Message;

use super::{
    decode_store_document_id, decode_store_key_derivation_id, generate_document_id,
    ring_reshare_sign_state_hash, DemeritConfig, MsgAddRingTrustedAuthRelayByAcp,
    MsgCancelPendingRing, MsgCreateRing, MsgFinalizeRing,
    MsgFinalizeRingReshareByThresholdSignature, MsgStoreDocumentResponse,
    MsgStoreKeyDerivationResponse, QueryNodeDemeritsRequest, QueryNodeDemeritsResponse,
    ReportingConfig, Ring, RingReshareSignState, UpgradeInfo,
};

/// Cross-implementation vector: `generate_document_id` must agree byte-for-byte
/// with Vera's Go `GenerateDocumentID`. Whitespace and field order must not
/// change the id (one semantic ciphertext = one authorization identity), while
/// any extra or differently-cased key must be rejected on both sides — Go's
/// case-insensitive JSON field matching would otherwise let `"ENC_CMT"`
/// override `"enc_cmt"` in Vera's hash but not here.
#[test]
fn generate_document_id_is_canonical_and_matches_vera() {
    const D1: &str =
        r#"{"enc_cmt":[1,2,3],"encrypted_data":[4,5,6],"nonce":[0,0,0,0,0,0,0,0,0,0,0,0]}"#;
    // Same three fields, whitespace + reordered.
    const D2: &str = "{ \"nonce\" : [0,0,0,0,0,0,0,0,0,0,0,0],\n  \"enc_cmt\": [1, 2, 3] ,\"encrypted_data\":[4,5,6] }";
    const P: &str = r#"{"challenge":[7,8],"response":[9,10]}"#;

    let id = |doc: &str, proof: &str| {
        generate_document_id(
            "ring-1",
            doc,
            proof,
            "policy-b",
            "document",
            "read",
            Some("gold"),
            Some(1_700_000_000),
            None,
            None,
        )
    };

    let id1 = id(D1, P).unwrap();
    assert_eq!(
        id1,
        id(D2, P).unwrap(),
        "whitespace/order must not change the id"
    );
    assert_eq!(
        id1,
        "e555cfcb145edf3d4cd8acbae93e05dc3a48eb0162b3af90f42064ab837c9a06"
    );

    // Rejections — each must fail identically on the Go side.
    assert!(id("{}", P).is_err(), "missing document fields");
    assert!(id(D1, "not json").is_err(), "malformed proof");
    assert!(
        id(
            r#"{"enc_cmt":[1,2,3],"encrypted_data":[4,5,6],"nonce":[0,0,0,0,0,0,0,0,0,0,0,0],"extra":1}"#,
            P
        )
        .is_err(),
        "unknown field"
    );
    assert!(
        id(
            r#"{"enc_cmt":[1,2,3],"ENC_CMT":[9,9,9],"encrypted_data":[4,5,6],"nonce":[0,0,0,0,0,0,0,0,0,0,0,0]}"#,
            P
        )
        .is_err(),
        "case-variant duplicate key"
    );
    assert!(
        id(
            D1,
            r#"{"challenge":[7,8],"response":[9,10],"Response":[0]}"#
        )
        .is_err(),
        "case-variant duplicate key in proof"
    );
    assert!(
        id(
            r#"{"enc_cmt":[1,2,3],"enc_cmt":[9,9,9],"encrypted_data":[4,5,6],"nonce":[0,0,0,0,0,0,0,0,0,0,0,0]}"#,
            P
        )
        .is_err(),
        "exact duplicate key (serde: 'duplicate field')"
    );
    assert!(
        id(
            r#"{"enc_cmt":null,"encrypted_data":[4,5,6],"nonce":[0,0,0,0,0,0,0,0,0,0,0,0]}"#,
            P
        )
        .is_err(),
        "explicit null value for a byte array"
    );
    assert!(
        id(
            r#"{"enc_cmt":[1,null,3],"encrypted_data":[4,5,6],"nonce":[0,0,0,0,0,0,0,0,0,0,0,0]}"#,
            P
        )
        .is_err(),
        "null array element"
    );
    assert!(
        id(D1, &format!("{P}  trailing")).is_err(),
        "trailing data after the JSON object"
    );
}

/// The PET tag attachment must be present or absent *together*, must change
/// the id when present, and — critically — must leave an ordinary (non-PET)
/// document's id byte-identical to before the attachment existed, since Vera
/// and every existing document computed their id without it.
#[test]
fn generate_document_id_pet_attachment_presence_and_binding() {
    const D1: &str =
        r#"{"enc_cmt":[1,2,3],"encrypted_data":[4,5,6],"nonce":[0,0,0,0,0,0,0,0,0,0,0,0]}"#;
    const P: &str = r#"{"challenge":[7,8],"response":[9,10]}"#;
    const TAG: &str = r#"{"ephemeral_point":[1,1],"masked_fingerprint":[2,2]}"#;
    const TAG_PROOF: &str = r#"{"challenge":[3,3],"response":[4,4]}"#;

    let id = |pet_tag: Option<&str>, pet_tag_proof: Option<&str>| {
        generate_document_id(
            "ring-1",
            D1,
            P,
            "policy-b",
            "document",
            "read",
            Some("gold"),
            Some(1_700_000_000),
            pet_tag,
            pet_tag_proof,
        )
    };

    let without_pet = id(None, None).unwrap();
    // Must reproduce the exact id from the vector above — a document with no
    // PET attachment must hash identically to one that never had the field.
    assert_eq!(
        without_pet,
        "e555cfcb145edf3d4cd8acbae93e05dc3a48eb0162b3af90f42064ab837c9a06"
    );

    let with_pet = id(Some(TAG), Some(TAG_PROOF)).unwrap();
    assert_ne!(
        without_pet, with_pet,
        "a present PET attachment must change the id"
    );

    // Presence must be all-or-nothing.
    assert!(id(Some(TAG), None).is_err(), "tag without its proof");
    assert!(id(None, Some(TAG_PROOF)).is_err(), "proof without its tag");

    // Malformed PET JSON must be rejected the same way document/proof are.
    assert!(id(Some("not json"), Some(TAG_PROOF)).is_err());
    assert!(id(Some(TAG), Some("not json")).is_err());
    assert!(
        id(
            Some(r#"{"ephemeral_point":[1,1],"masked_fingerprint":[2,2],"extra":1}"#),
            Some(TAG_PROOF)
        )
        .is_err(),
        "unknown field in pet_tag"
    );

    // Every field of the attachment participates in the binding.
    let other_tag = id(
        Some(r#"{"ephemeral_point":[9,9],"masked_fingerprint":[2,2]}"#),
        Some(TAG_PROOF),
    )
    .unwrap();
    assert_ne!(
        with_pet, other_tag,
        "changing ephemeral_point must change the id"
    );
    let other_proof = id(Some(TAG), Some(r#"{"challenge":[9,9],"response":[4,4]}"#)).unwrap();
    assert_ne!(
        with_pet, other_proof,
        "changing the tag knowledge proof must change the id"
    );
}

#[test]
fn create_ring_round_trips_pss_interval() {
    let msg = MsgCreateRing::new(
        "c",
        vec!["p1".to_string()],
        1,
        86400,
        "policy",
        None,
        0,
        None,
        Some(vec!["did:key:relay".to_string()]),
        false,
    );
    let bytes = msg.encode_to_vec();
    let decoded = MsgCreateRing::decode(bytes.as_slice()).expect("decode MsgCreateRing");
    assert_eq!(decoded.pss_interval, 86400);
    assert!(decoded.reporting.is_none());
    assert_eq!(decoded.trusted_auth_relay_dids, vec!["did:key:relay"]);
    assert!(decoded.allow_trusted_auth_relays);
}

#[test]
fn create_ring_round_trips_reporting_config() {
    let msg = MsgCreateRing::new(
        "c",
        vec!["p1".to_string()],
        1,
        86400,
        "policy",
        None,
        0,
        Some(ReportingConfig {
            demerit_config: Some(DemeritConfig {
                node_offline_demerits: 3,
                reset_interval_seconds: 42,
                invalid_crypto_response_demerits: 7,
                unauthorized_request_demerits: 9,
            }),
            backup_node_keys: vec!["backup-2".to_string(), "backup-1".to_string()],
            kick_threshold: 4,
        }),
        None,
        false,
    );
    let bytes = msg.encode_to_vec();
    let decoded = MsgCreateRing::decode(bytes.as_slice()).expect("decode MsgCreateRing");
    let reporting = decoded.reporting.expect("reporting");
    let config = reporting.demerit_config.expect("demerit_config");
    assert!(!decoded.allow_trusted_auth_relays);

    assert_eq!(config.node_offline_demerits, 3);
    assert_eq!(config.reset_interval_seconds, 42);
    assert_eq!(config.invalid_crypto_response_demerits, 7);
    assert_eq!(config.unauthorized_request_demerits, 9);
    assert_eq!(
        reporting.backup_node_keys,
        vec!["backup-2".to_string(), "backup-1".to_string()]
    );
    assert_eq!(reporting.kick_threshold, 4);
}

#[test]
fn ring_reporting_config_round_trips() {
    let ring = Ring {
        id: "ring-1".to_string(),
        reporting: Some(ReportingConfig {
            demerit_config: Some(DemeritConfig {
                node_offline_demerits: 5,
                reset_interval_seconds: 60,
                invalid_crypto_response_demerits: 2,
                unauthorized_request_demerits: 4,
            }),
            backup_node_keys: vec!["backup-a".to_string()],
            kick_threshold: 6,
        }),
        ..Default::default()
    };
    let bytes = ring.encode_to_vec();
    let decoded = Ring::decode(bytes.as_slice()).expect("decode");
    let reporting = decoded.reporting.expect("reporting");
    let config = reporting.demerit_config.expect("demerit_config");

    assert_eq!(config.node_offline_demerits, 5);
    assert_eq!(config.reset_interval_seconds, 60);
    assert_eq!(config.invalid_crypto_response_demerits, 2);
    assert_eq!(config.unauthorized_request_demerits, 4);
    assert_eq!(reporting.backup_node_keys, vec!["backup-a".to_string()]);
    assert_eq!(reporting.kick_threshold, 6);
}

#[test]
fn node_demerits_query_wire_fields_match_vera_proto() {
    let request = QueryNodeDemeritsRequest {
        ring_id: "r".to_string(),
        node_key: "n".to_string(),
    };
    assert_eq!(hex::encode(request.encode_to_vec()), "0a017212016e");

    let response = QueryNodeDemeritsResponse { points: 7 };
    assert_eq!(hex::encode(response.encode_to_vec()), "0807");
}

#[test]
fn finalize_ring_wire_fields_match_vera_proto() {
    let msg = MsgFinalizeRing::new("c", "r", "pk", None);

    assert_eq!(hex::encode(msg.encode_to_vec()), "0a01631201721a02706b");
}

#[test]
fn cancel_pending_ring_wire_fields_match_vera_proto() {
    let msg = MsgCancelPendingRing::new("c", "r");

    assert_eq!(
        MsgCancelPendingRing::TYPE_URL,
        "/vera.orbis.MsgCancelPendingRing"
    );
    assert_eq!(hex::encode(msg.encode_to_vec()), "0a0163120172");
}

#[test]
fn add_ring_trusted_auth_relay_wire_fields_match_vera_proto() {
    let msg = MsgAddRingTrustedAuthRelayByAcp::new("c", "r", "d");

    assert_eq!(
        MsgAddRingTrustedAuthRelayByAcp::TYPE_URL,
        "/vera.orbis.MsgAddRingTrustedAuthRelayByAcp"
    );
    assert_eq!(hex::encode(msg.encode_to_vec()), "0a01631201721a0164");
}

#[test]
fn finalize_ring_reshare_wire_fields_match_vera_proto() {
    let msg = MsgFinalizeRingReshareByThresholdSignature::new("c", "r", "s", vec![1, 2]);

    assert_eq!(
        hex::encode(msg.encode_to_vec()),
        "0a01631201721a017322020102"
    );
}

#[test]
fn ring_reshare_sign_state_hash_sorts_participant_lists() {
    let state = RingReshareSignState {
        ring_pk: "pk".to_string(),
        peer_node_keys: vec!["node-b".to_string(), "node-a".to_string()],
        threshold: 2,
        new_peer_node_keys: vec!["node-d".to_string(), "node-c".to_string()],
        new_threshold: Some(1),
        block_number_nonce: 9,
        policy_id: "policy".to_string(),
        trusted_auth_relay_dids: vec!["relay-b".to_string(), "relay-a".to_string()],
        allow_trusted_auth_relays: true,
    };
    let reordered = RingReshareSignState {
        peer_node_keys: vec!["node-a".to_string(), "node-b".to_string()],
        new_peer_node_keys: vec!["node-c".to_string(), "node-d".to_string()],
        trusted_auth_relay_dids: vec!["relay-a".to_string(), "relay-b".to_string()],
        ..state.clone()
    };

    assert_eq!(
        ring_reshare_sign_state_hash(&state),
        ring_reshare_sign_state_hash(&reordered)
    );
}

#[test]
fn decode_store_document_id_from_direct_response() {
    let response = MsgStoreDocumentResponse {
        document_id: "doc-id".to_string(),
    };
    let bytes = response.encode_to_vec();

    assert_eq!(
        decode_store_document_id(Some(&bytes)),
        Some("doc-id".to_string())
    );
}

#[test]
fn decode_store_key_derivation_id_from_direct_response() {
    let response = MsgStoreKeyDerivationResponse {
        key_derivation_id: "key-derivation-id".to_string(),
    };
    let bytes = response.encode_to_vec();

    assert_eq!(
        decode_store_key_derivation_id(Some(&bytes)),
        Some("key-derivation-id".to_string())
    );
}

#[test]
fn ring_upgrade_info_round_trips() {
    let ring = Ring {
        id: "ring-1".to_string(),
        upgrade_info: Some(UpgradeInfo {
            current_version: 0,
            next_version: Some(1),
            activation_time: Some(100),
        }),
        ..Default::default()
    };
    let bytes = ring.encode_to_vec();
    let decoded = Ring::decode(bytes.as_slice()).expect("decode");
    let info = decoded.upgrade_info.expect("upgrade_info");
    assert_eq!(info.current_version, 0);
    assert_eq!(info.next_version, Some(1));
    assert_eq!(info.activation_time, Some(100));
}
