use crate::error::{AuthNError, Result};

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
}
