pub mod error;
use did_key::{resolve, CoreSign};
use error::{AuthNError, Result};

pub fn resolve_and_verify_did_key(did_uri: &str, payload: &[u8], signature: &[u8]) -> Result<()> {
    let key = resolve(did_uri)
        .map_err(|_| AuthNError::DidError("Error resolving did_uri".to_string()))?;
    key.verify(payload, signature)
        .map_err(|_| AuthNError::DidError("Error verifying did signature".to_string()))?;
    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use did_key::{generate, CoreSign, Ed25519KeyPair, Fingerprint};

    #[test]
    fn test_resolve_and_verify_did_key_success() {
        let key_pair = generate::<Ed25519KeyPair>(None);
        let did_uri = format!("did:key:{}", key_pair.fingerprint());
        let payload = b"test message";
        let signature = key_pair.sign(payload);

        let result = resolve_and_verify_did_key(&did_uri, payload, &signature);
        assert!(result.is_ok());
    }

    #[test]
    fn test_resolve_and_verify_did_key_invalid_signature() {
        let key_pair = generate::<Ed25519KeyPair>(None);
        let did_uri = format!("did:key:{}", key_pair.fingerprint());
        let payload = b"test message";
        let invalid_signature = vec![0u8; 64];

        let result = resolve_and_verify_did_key(&did_uri, payload, &invalid_signature);
        assert!(result.is_err());
    }

    #[test]
    fn test_resolve_and_verify_did_key_wrong_payload() {
        let key_pair = generate::<Ed25519KeyPair>(None);
        let did_uri = format!("did:key:{}", key_pair.fingerprint());
        let payload = b"test message";
        let wrong_payload = b"wrong message";
        let signature = key_pair.sign(payload);

        let result = resolve_and_verify_did_key(&did_uri, wrong_payload, &signature);
        assert!(result.is_err());
    }

    #[test]
    fn test_resolve_and_verify_did_key_invalid_did() {
        let payload = b"test message";
        let signature = vec![0u8; 64];

        let result = resolve_and_verify_did_key("invalid_did", payload, &signature);
        assert!(result.is_err());
    }
}
