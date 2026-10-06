//! Cross-checks `jubjub_wasm::verify_core` against orbis-rs's own test vector
//! (`crates/crypto/src/jubjub/sign.rs`'s `test_vectors/frost.json`, copied
//! verbatim into `tests/test_vectors/`). This is the one test that proves
//! this crate's standalone verify logic actually agrees with the production
//! Rust signing side, not just with itself.

fn decode_hex(s: &str) -> Vec<u8> {
    assert_eq!(s.len() % 2, 0, "odd-length hex string");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn verifies_the_orbis_rs_frost_vector() {
    let raw = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/test_vectors/frost.json"
    ))
    .unwrap();
    let vector: serde_json::Value = serde_json::from_str(&raw).unwrap();

    assert_eq!(vector["scheme"], "jubjub_frost");

    let public_key = decode_hex(vector["public_key"].as_str().unwrap());
    let message = decode_hex(vector["message"].as_str().unwrap());
    let signature = decode_hex(vector["signature"].as_str().unwrap());

    assert!(
        jubjub_wasm::verify_core(&public_key, &message, &signature),
        "the independently-generated orbis-rs FROST vector must verify"
    );
    assert!(
        !jubjub_wasm::verify_core(&public_key, b"a different message", &signature),
        "a mutated message must be rejected"
    );
    assert!(
        !jubjub_wasm::verify_core(&public_key, &message, &[0u8; 64]),
        "a garbage signature must be rejected"
    );
}
