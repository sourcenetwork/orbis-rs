use super::*;

fn document_fixture() -> DocumentPayload {
    DocumentPayload {
        ring_id: "ring-1".into(),
        document:
            r#"{"enc_cmt":[1,2,3],"encrypted_data":[4,5,6],"nonce":[0,0,0,0,0,0,0,0,0,0,0,0]}"#
                .into(),
        proof: r#"{"challenge":[7,8],"response":[9,10]}"#.into(),
        policy_id: "policy-b".into(),
        resource: "document".into(),
        permission: "read".into(),
        tier: Some("gold".into()),
        timestamp: Some(1_700_000_000),
        pet_tag: None,
        pet_tag_proof: None,
    }
}

#[test]
fn native_pet_document_ids_match_existing_orbis_encoding() {
    // Structural ID vectors shared with Vera; the short arrays are not curve proofs.
    let mut document = document_fixture();
    for (pet, expected) in [
        (
            false,
            "e555cfcb145edf3d4cd8acbae93e05dc3a48eb0162b3af90f42064ab837c9a06",
        ),
        (
            true,
            "653ff17ab40e4b9a38c9af9da3454d16e01ddb95765329215d8d0ca55c720c7e",
        ),
    ] {
        if pet {
            document.pet_tag =
                Some(r#"{"ephemeral_point":[1,1],"masked_fingerprint":[2,2]}"#.into());
            document.pet_tag_proof = Some(r#"{"challenge":[3,3],"response":[4,4]}"#.into());
        }
        let orbis_id = common::blockchain::orbis::generate_document_id(
            &document.ring_id,
            &document.document,
            &document.proof,
            &document.policy_id,
            &document.resource,
            &document.permission,
            document.tier.as_deref(),
            document.timestamp,
            document.pet_tag.as_deref(),
            document.pet_tag_proof.as_deref(),
        )
        .unwrap();
        assert_eq!(orbis_id, expected);
        let object = ThresholdObject::Document(native_document(document.clone()));
        assert_eq!(object.id().unwrap(), expected);
        let restored: DocumentPayload = object_post(vera_client::threshold_objects::ObjectRecord {
            id: expected.into(),
            deployment_root: [7; 32],
            creator: "did:key:actor".into(),
            revision: Default::default(),
            object,
        })
        .unwrap()
        .try_into()
        .unwrap();
        assert_eq!(restored, document);
        let json = serde_json::to_value(native_document(document.clone())).unwrap();
        assert_eq!(json.get("pet_tag").is_some(), pet);
        assert_eq!(json.get("pet_tag_proof").is_some(), pet);
    }
}

#[test]
fn pet_document_preparation_retains_attachments_in_the_durable_call() {
    use commonware_math::algebra::CryptoGroup as _;

    let root = tempfile::tempdir().unwrap();
    let storage = RedbStorage::new(
        "test".into(),
        root.path().join("keys.redb").to_string_lossy().into_owned(),
    )
    .unwrap();
    storage
        .set_encrypted(
            LocalStorageKeys::NodeSigningKey,
            Zeroizing::new(hex::encode([31; 32]).into_bytes()),
        )
        .unwrap();
    let mut writer = NativeVeraClient::open(
        VeraClient::new("http://127.0.0.1:1"),
        ConsensusPublicKey::generator(),
        [7; 32],
        9001,
        &root.path().join("worker"),
        &storage,
    )
    .unwrap();
    let mut document = document_fixture();
    document.ring_id = "11".repeat(32);
    document.policy_id = "22".repeat(32);
    document.pet_tag = Some(r#"{"ephemeral_point":[1,1],"masked_fingerprint":[2,2]}"#.into());
    document.pet_tag_proof = Some(r#"{"challenge":[3,3],"response":[4,4]}"#.into());
    let object = ThresholdObject::Document(native_document(document.clone()));
    let expected = encode_threshold_object(&object, "token").unwrap();
    let id = writer.prepare_document(document.clone(), "token").unwrap();
    assert_eq!(writer.pending_call().unwrap(), Some(expected));
    assert_eq!(
        writer.prepare_document(document.clone(), "token").unwrap(),
        id
    );
    document.pet_tag_proof = Some(r#"{"challenge":[3,3],"response":[4,5]}"#.into());
    assert!(writer.prepare_document(document, "token").is_err());
    assert_eq!(writer.pending_id().unwrap(), Some(id));
}

#[test]
fn native_paired_ring_and_confirmation_match_v2_vectors() {
    let node = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    let config = RingConfig {
        policy_id: "11".repeat(32),
        peer_node_keys: vec![node.into()],
        threshold: 1,
        pss_interval: 86400,
        current_version: 0,
        requires_pet: true,
        nonce: [9; 32],
        trusted_auth_relay_dids: None,
        reporting: Default::default(),
    };
    let ring_id = config.id([7; 32], "did:key:fixture").unwrap();
    assert_eq!(
        ring_id,
        "58b39d87fc52b1e447cef0835a9a11dafcfd97be06424283bdb2cd4eba7ed8b9"
    );
    let request = RingParticipantRequest {
        deployment_root: [7; 32],
        deployment_id: 9001,
        ring_id,
        node_key: node.into(),
        command: RingParticipantCommand::Confirm(RingPublicKeys {
            public_key: "aabb".into(),
            pet_public_key: Some("ccdd".into()),
        }),
        expires_at: 200,
    };
    assert_eq!(
        hex::encode(request.signing_digest().unwrap()),
        "73d092c07a65a19a4d1e6c6f1dbcdb61aea7b2345d11cdb81b2d3f5f4da7a505"
    );
}
