use super::{generate_document_id, ring_reshare_sign_state_hash, RingReshareSignState};

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
