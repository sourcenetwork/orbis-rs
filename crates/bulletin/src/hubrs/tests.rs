use super::*;
use alloy_sol_types::SolCall;

#[test]
fn test_compute_post_id() {
    // Same computation as SourceHub and Dummy: SHA256(namespace || payload)
    let namespace = "bulletin/orbis";
    let payload = b"hello world";
    let id = HubRsBulletin::compute_post_id(namespace, payload);

    // Verify deterministic
    let id2 = HubRsBulletin::compute_post_id(namespace, payload);
    assert_eq!(id, id2);

    // Verify it's a valid hex-encoded SHA256 (64 chars)
    assert_eq!(id.len(), 64);
    assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn test_name() {
    assert_eq!(HubRsBulletin::name(), "bulletin/hubrs");
}

#[test]
fn test_register_namespace_abi_encoding() {
    let call = abi::IBulletin::registerNamespaceCall {
        namespace: "orbis".to_string(),
    };
    let encoded = call.abi_encode();

    // Should have 4-byte selector + ABI-encoded string
    assert!(encoded.len() > 4);

    // Roundtrip decode
    let decoded = abi::IBulletin::registerNamespaceCall::abi_decode(&encoded).unwrap();
    assert_eq!(decoded.namespace, "orbis");
}

#[test]
fn test_create_post_abi_encoding() {
    let call = abi::IBulletin::createPostCall {
        namespace: "orbis".to_string(),
        payload: vec![1, 2, 3].into(),
        proof: vec![4, 5, 6].into(),
        artifact: "".to_string(),
    };
    let encoded = call.abi_encode();
    assert!(encoded.len() > 4);

    let decoded = abi::IBulletin::createPostCall::abi_decode(&encoded).unwrap();
    assert_eq!(decoded.namespace, "orbis");
    assert_eq!(decoded.payload.as_ref(), &[1, 2, 3]);
    assert_eq!(decoded.proof.as_ref(), &[4, 5, 6]);
    assert_eq!(decoded.artifact, "");
}

#[test]
fn test_get_post_abi_encoding() {
    let call = abi::IBulletin::getPostCall {
        namespace: "orbis".to_string(),
        id: "abc123".to_string(),
    };
    let encoded = call.abi_encode();
    assert!(encoded.len() > 4);

    let decoded = abi::IBulletin::getPostCall::abi_decode(&encoded).unwrap();
    assert_eq!(decoded.namespace, "orbis");
    assert_eq!(decoded.id, "abc123");
}

#[test]
fn test_precompile_address() {
    let addr = Address::from(abi::BULLETIN_PRECOMPILE_ADDRESS);
    assert_eq!(
        format!("{:?}", addr),
        "0x0000000000000000000000000000000000000811"
    );
}
