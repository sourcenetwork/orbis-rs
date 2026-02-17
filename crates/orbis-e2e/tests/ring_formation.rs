//! Ring formation tests: verify DKG ceremony completes and collective key is produced.
//!
//! Uses the shared DKG fixture so DKG only runs once per test binary.

use orbis_e2e::fixture::shared_dkg_fixture;

/// Verify the shared fixture produces a valid DKG'd ring with N=3, T=2.
#[tokio::test]
async fn ring_n3_t2_forms_and_certifies() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_test_writer()
        .try_init();

    let fixture = shared_dkg_fixture().await;

    assert_eq!(fixture.ring.node_count(), 3);
    assert_eq!(fixture.ring.threshold(), 2);
    assert!(!fixture.ring_pk_hex.is_empty(), "ring_pk should not be empty");
    assert!(!fixture.ring_id.is_empty(), "ring_id should not be empty");
    assert_eq!(fixture.node_infos.len(), 3);

    // Verify all nodes have unique peer IDs
    let peer_ids: Vec<&str> = fixture.node_infos.iter().map(|n| n.peer_id.as_str()).collect();
    for i in 0..peer_ids.len() {
        for j in (i + 1)..peer_ids.len() {
            assert_ne!(peer_ids[i], peer_ids[j], "peer IDs must be unique");
        }
    }

    // Verify all nodes have unique public addresses
    let addrs: Vec<&str> = fixture
        .node_infos
        .iter()
        .map(|n| n.public_address.as_str())
        .collect();
    for i in 0..addrs.len() {
        for j in (i + 1)..addrs.len() {
            assert_ne!(addrs[i], addrs[j], "public addresses must be unique");
        }
    }

    // Verify ring public key is valid hex and has expected length
    let pk_bytes = hex::decode(&fixture.ring_pk_hex).expect("ring_pk should be valid hex");
    assert!(pk_bytes.len() > 32, "ring_pk should be a group element (>32 bytes)");

    println!(
        "Ring formed: {} nodes, threshold {}, pk={}...",
        fixture.ring.node_count(),
        fixture.ring.threshold(),
        &fixture.ring_pk_hex[..40],
    );
}

/// Verify the ring payload was posted to the bulletin and can be read back.
#[tokio::test]
async fn ring_payload_readable_from_bulletin() {
    let fixture = shared_dkg_fixture().await;
    let chain_config = fixture.chain_config();

    let payload_bytes = cli_tool::read_bulletin_post(
        "orbis".to_string(),
        fixture.ring_id.clone(),
        chain_config,
    )
    .await
    .expect("should read ring payload from bulletin");

    let payload: bulletin::r#trait::RingPayload =
        serde_json::from_slice(&payload_bytes).expect("should parse RingPayload");

    assert_eq!(payload.ring_pk, fixture.ring_pk_hex);
    assert_eq!(payload.threshold, fixture.ring.threshold());
    assert_eq!(payload.peer_ids.len(), fixture.ring.node_count());

    println!("Ring payload verified on bulletin: {} peers, threshold {}",
        payload.peer_ids.len(), payload.threshold);
}
