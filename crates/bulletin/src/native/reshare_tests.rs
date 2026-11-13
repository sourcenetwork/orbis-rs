use super::*;

fn reshare_fixture(public_key: String) -> (tempfile::TempDir, NativeVeraClient, RingRecord) {
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
    let directory = root.path().join("worker");
    let writer = NativeVeraClient::open(
        VeraClient::new("http://127.0.0.1:1"),
        ConsensusPublicKey::generator(),
        [7; 32],
        9001,
        &directory,
        &storage,
    )
    .unwrap();
    let mut peers: Vec<_> = [31u8, 32]
        .map(|byte| {
            let key = SigningKey::from_slice(&[byte; 32]).unwrap();
            hex::encode(key.verifying_key().to_sec1_bytes())
        })
        .into();
    peers.sort();
    let creator =
        vera_crypto::secp256k1::did_from_secp256k1_pubkey(&hex::decode(writer.node_key()).unwrap())
            .unwrap();
    let config = RingConfig {
        policy_id: "11".repeat(32),
        peer_node_keys: peers.clone(),
        threshold: 1,
        pss_interval: 86400,
        current_version: 0,
        requires_pet: false,
        nonce: [4; 32],
        trusted_auth_relay_dids: None,
        reporting: Default::default(),
        pre_share_endpoints: Vec::new(),
    };
    let mut record = RingRecord {
        id: config.id().unwrap(),
        deployment_root: [7; 32],
        creator,
        config,
        state: RingState::Active {
            keys: RingPublicKeys {
                public_key,
                pet_public_key: None,
            },
        },
        revision: Default::default(),
        settings: None,
        sequence: 5,
    };
    record.revision.seconds = 100;
    record.revision.block_height = 5;
    let mut settings = record.current_settings();
    settings.pending_reshare = Some(ReshareTarget {
        peer_node_keys: peers,
        threshold: 2,
    });
    record.settings = Some(settings);
    (root, writer, record)
}

#[test]
fn reshare_preparation_rejects_mismatched_state_without_journaling() {
    let secret = blst::min_pk::SecretKey::key_gen(&[53; 32], &[]).unwrap();
    let (root, mut writer, record) = reshare_fixture(hex::encode(secret.sk_to_pk().to_bytes()));
    let message = record.reshare_signing_bytes(9001).unwrap();
    let signature = secret
        .sign(
            &message,
            b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_AUG_",
            &secret.sk_to_pk().to_bytes(),
        )
        .to_bytes();
    let scheme = ThresholdScheme::Bls12381AugV1;
    let journal = root.path().join("worker/state.json");
    let before = std::fs::read(&journal).unwrap();
    let mut stale = record.clone();
    stale.sequence = 4;
    let mut unannounced = stale.clone();
    unannounced.settings.as_mut().unwrap().pending_reshare = None;
    let mut foreign = record.clone();
    foreign.deployment_root = [8; 32];
    for wrong in [&stale, &unannounced, &foreign] {
        assert!(writer
            .prepare_ring_reshare(wrong, scheme, &signature)
            .is_err());
        assert_eq!(writer.pending_id().unwrap(), None);
        assert_eq!(std::fs::read(&journal).unwrap(), before);
    }
    let invalid_signature = [0; 96];
    assert!(writer
        .prepare_ring_reshare(&record, scheme, &invalid_signature)
        .is_err());
    assert_eq!(std::fs::read(&journal).unwrap(), before);
    let id = writer
        .prepare_ring_reshare(&record, scheme, &signature)
        .unwrap();
    assert_eq!(writer.pending_id().unwrap(), Some(id));
    let request = vera_client::rings::decode_ring_reshare(&writer.pending_call().unwrap().unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(request.expected_sequence, 5);
    assert_eq!(request.signature, hex::encode(signature));
}

#[test]
fn native_verifier_accepts_the_published_orbis_jubjub_vector() {
    // The shared E2E reshare scenario exercises Orbis's configured signer on
    // both curves. Keep the cross-project wire-compatibility assertion here
    // curve-independent by checking the published Orbis FROST vector directly,
    // without making bulletin depend on a selected crypto implementation.
    let vector: serde_json::Value = serde_json::from_str(include_str!(
        "../../../crypto/src/jubjub/test_vectors/frost.json"
    ))
    .unwrap();
    let scheme: ThresholdScheme = serde_json::from_value(vector["scheme"].clone())
        .expect("published Orbis scheme must be accepted by native Vera");
    assert_eq!(serde_json::to_value(scheme).unwrap(), vector["scheme"]);
    let vector_public_key = hex::decode(vector["public_key"].as_str().unwrap()).unwrap();
    let vector_message = hex::decode(vector["message"].as_str().unwrap()).unwrap();
    let vector_signature = hex::decode(vector["signature"].as_str().unwrap()).unwrap();
    vera_crypto::threshold::verify(
        scheme,
        &vector_public_key,
        &vector_message,
        &vector_signature,
    )
    .expect("native Vera must verify the published Orbis Jubjub vector");
}
