use crate::error::{AuthNError, Result};

/// P-256 (`p256-pub`) multicodec code `0x1200`, varint-encoded.
const P256_MULTICODEC_PREFIX: [u8; 2] = [0x80, 0x24];

pub(crate) fn ed25519_public_key(did: &str) -> Result<[u8; 32]> {
    let fingerprint = did.strip_prefix("did:key:z").ok_or_else(|| {
        AuthNError::DidError("issuer DID must be a base58btc did:key".to_string())
    })?;
    // Ed25519 multicodec prefix plus a 32-byte public key encodes to 48 chars.
    // Bound decoding before allocating on an untrusted issuer string.
    if fingerprint.len() > 48 {
        return Err(AuthNError::DidError(
            "invalid Ed25519 did:key length".to_string(),
        ));
    }
    let bytes = bs58::decode(fingerprint)
        .into_vec()
        .map_err(|_| AuthNError::DidError("invalid did:key encoding".to_string()))?;
    if bytes.len() != 34 || bytes[..2] != [0xed, 0x01] {
        return Err(AuthNError::DidError(
            "issuer DID must contain an Ed25519 public key".to_string(),
        ));
    }
    let mut key = [0; 32];
    key.copy_from_slice(&bytes[2..]);
    ed25519_dalek::VerifyingKey::from_bytes(&key)
        .map_err(|_| AuthNError::DidError("invalid Ed25519 public key".to_string()))?;
    Ok(key)
}

/// Decodes a `did:key` encoding a P-256 public key (compressed SEC1, 33 bytes).
pub(crate) fn p256_public_key(did: &str) -> Result<[u8; 33]> {
    let fingerprint = did.strip_prefix("did:key:z").ok_or_else(|| {
        AuthNError::DidError("issuer DID must be a base58btc did:key".to_string())
    })?;
    // P-256 multicodec prefix plus a 33-byte compressed public key encodes to
    // at most 50 chars. Bound decoding before allocating on an untrusted
    // issuer string.
    if fingerprint.len() > 50 {
        return Err(AuthNError::DidError(
            "invalid P-256 did:key length".to_string(),
        ));
    }
    let bytes = bs58::decode(fingerprint)
        .into_vec()
        .map_err(|_| AuthNError::DidError("invalid did:key encoding".to_string()))?;
    if bytes.len() != 35 || bytes[..2] != P256_MULTICODEC_PREFIX {
        return Err(AuthNError::DidError(
            "issuer DID must contain a P-256 public key".to_string(),
        ));
    }
    let mut key = [0; 33];
    key.copy_from_slice(&bytes[2..]);
    p256::ecdsa::VerifyingKey::from_sec1_bytes(&key)
        .map_err(|_| AuthNError::DidError("invalid P-256 public key".to_string()))?;
    Ok(key)
}

/// Encodes a compressed SEC1 P-256 public key as a `did:key` string. Used to
/// construct the identity a passkey's own credential public key stands for;
/// verification only ever decodes (`p256_public_key`), it never needs this.
pub(crate) fn encode_p256_did(compressed_pubkey: &[u8; 33]) -> String {
    let mut encoded = Vec::with_capacity(35);
    encoded.extend_from_slice(&P256_MULTICODEC_PREFIX);
    encoded.extend_from_slice(compressed_pubkey);
    format!("did:key:z{}", bs58::encode(encoded).into_string())
}

#[cfg(test)]
#[test]
fn ed25519_fingerprint_matches_existing_implementation() {
    let cases = [
        (0, "z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp"),
        (1, "z6Mkon3Necd6NkkyfoGoHxid2znGc59LU3K7mubaRcFbLfLX"),
        (43, "z6Mkj6joiZPz3kKe5PpGNLjCrTphanK4S5PXgpwVQPkyrvVk"),
        (255, "z6MknSLrJoTcukLrE435hVNQT4JUhbvWLX4kUzqkEStBU8Vi"),
    ];
    for (byte, fingerprint) in cases {
        let signer = crate::JwtSigner::from_seed([byte; 32]);
        assert_eq!(signer.did_uri, format!("did:key:{fingerprint}"));
        assert!(ed25519_public_key(&signer.did_uri).is_ok());
    }
}

#[cfg(test)]
#[test]
fn rejects_invalid_encodings_and_key_types() {
    assert!(ed25519_public_key("did:key:z0").is_err());
    assert!(ed25519_public_key(&format!("did:key:z{}", "1".repeat(49))).is_err());
    let mut wrong_codec = vec![0xec, 0x01];
    wrong_codec.extend_from_slice(&[7; 32]);
    assert!(ed25519_public_key(&format!(
        "did:key:z{}",
        bs58::encode(wrong_codec).into_string()
    ))
    .is_err());
    assert!(ed25519_public_key("did:web:example.com").is_err());

    let invalid_point = (0u8..=255)
        .map(|byte| [byte; 32])
        .find(|bytes| ed25519_dalek::VerifyingKey::from_bytes(bytes).is_err())
        .expect("invalid compressed point");
    let mut encoded = vec![0xed, 0x01];
    encoded.extend_from_slice(&invalid_point);
    let did = format!("did:key:z{}", bs58::encode(encoded).into_string());
    assert!(ed25519_public_key(&did).is_err());
    assert!(crate::validate_relay_issuer(&did).is_err());
}

#[cfg(test)]
#[test]
fn p256_roundtrip_encodes_and_decodes() {
    for scalar_byte in [1u8, 2, 3] {
        let mut scalar = [0u8; 32];
        scalar[31] = scalar_byte;
        let signing_key = p256::ecdsa::SigningKey::from_bytes((&scalar).into())
            .expect("small nonzero scalar is a valid P-256 key");
        let verifying_key = p256::ecdsa::VerifyingKey::from(&signing_key);
        let encoded_point = verifying_key.to_encoded_point(true);
        let compressed: [u8; 33] = encoded_point
            .as_bytes()
            .try_into()
            .expect("compressed P-256 point is 33 bytes");

        let did = encode_p256_did(&compressed);
        assert!(did.starts_with("did:key:z"));
        assert_eq!(p256_public_key(&did).expect("roundtrip decode"), compressed);
    }
}

#[cfg(test)]
#[test]
fn p256_rejects_invalid_encodings_and_key_types() {
    assert!(p256_public_key("did:key:z0").is_err());
    assert!(p256_public_key(&format!("did:key:z{}", "1".repeat(51))).is_err());

    // An Ed25519-tagged key must not decode as P-256.
    let mut wrong_codec = vec![0xed, 0x01];
    wrong_codec.extend_from_slice(&[7; 32]);
    assert!(p256_public_key(&format!(
        "did:key:z{}",
        bs58::encode(wrong_codec).into_string()
    ))
    .is_err());
    assert!(p256_public_key("did:web:example.com").is_err());

    // Right prefix, not a point on the curve.
    let mut invalid = P256_MULTICODEC_PREFIX.to_vec();
    invalid.push(0x04); // neither 0x02 nor 0x03: not a valid SEC1 compressed tag
    invalid.extend_from_slice(&[0; 32]);
    let did = format!("did:key:z{}", bs58::encode(invalid).into_string());
    assert!(p256_public_key(&did).is_err());
}
