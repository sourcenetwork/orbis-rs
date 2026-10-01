//! Node message signatures shared by all backends.

use crate::blockchain::{BlockchainError, Result};
use k256::ecdsa::{
    signature::{Signer as _, Verifier as _},
    Signature as EcdsaSignature, SigningKey, VerifyingKey,
};

/// Sign a node message from a hex-encoded secp256k1 private key.
pub fn sign_node_message_with_hex_key(hex_key: &str, message: &[u8]) -> Result<Vec<u8>> {
    let key_bytes = hex::decode(hex_key)
        .map_err(|e| BlockchainError::Signing(format!("Invalid hex key: {}", e)))?;
    let signing_key = SigningKey::from_slice(&key_bytes)
        .map_err(|e| BlockchainError::Signing(format!("Invalid private key: {}", e)))?;
    let signature: EcdsaSignature = signing_key
        .try_sign(message)
        .map_err(|e| BlockchainError::Signing(format!("Failed to sign node message: {}", e)))?;
    Ok(signature.to_bytes().to_vec())
}

/// Verify a node message signature against a compressed secp256k1 public key hex.
///
/// secp256k1 ECDSA is malleable in principle — `(r, s)` and `(r, n - s)` both
/// satisfy the curve equation — so node evidence signatures could otherwise have
/// two valid encodings. `k256` / `ecdsa` sign in and verify only the canonical
/// low-S form, which is what keeps these signatures single-encoding. That
/// property is relied on but not enforced here; the regression test
/// `node_message_signatures_are_low_s_and_the_malleated_form_is_rejected` locks it
/// so a dependency change can't silently reintroduce malleability.
pub fn verify_node_message(public_key_hex: &str, message: &[u8], signature: &[u8]) -> Result<()> {
    let public_key_bytes = hex::decode(public_key_hex)
        .map_err(|e| BlockchainError::Signing(format!("Invalid public key hex: {}", e)))?;
    let verifying_key = VerifyingKey::from_sec1_bytes(&public_key_bytes)
        .map_err(|e| BlockchainError::Signing(format!("Invalid public key: {}", e)))?;
    let signature = EcdsaSignature::try_from(signature)
        .map_err(|e| BlockchainError::Signing(format!("Invalid signature: {}", e)))?;
    verifying_key
        .verify(message, &signature)
        .map_err(|e| BlockchainError::Signing(format!("Node message signature failed: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn public_key_hex(hex_key: &str) -> String {
        let key = SigningKey::from_slice(&hex::decode(hex_key).unwrap()).unwrap();
        hex::encode(key.verifying_key().to_encoded_point(true).as_bytes())
    }

    #[test]
    fn node_message_signature_round_trips_and_rejects_tampering() {
        let hex_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let public_key_hex = public_key_hex(hex_key);
        let message = b"orbis-pre-response-test";
        let signature = sign_node_message_with_hex_key(hex_key, message).unwrap();

        verify_node_message(&public_key_hex, message, &signature).unwrap();
        assert!(verify_node_message(&public_key_hex, b"tampered", &signature,).is_err());
        let mut bad_signature = signature.clone();
        bad_signature[0] ^= 0x01;
        assert!(verify_node_message(&public_key_hex, message, &bad_signature).is_err());
    }

    #[test]
    fn node_message_signatures_are_low_s_and_the_malleated_form_is_rejected() {
        use k256::{elliptic_curve::ff::PrimeField, FieldBytes, Scalar};

        let hex_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let public_key_hex = public_key_hex(hex_key);
        let message = b"orbis-evidence-canonical-test";
        let low = sign_node_message_with_hex_key(hex_key, message).unwrap();

        // What we emit is already canonical low-S, and it verifies.
        let parsed = EcdsaSignature::try_from(low.as_slice()).unwrap();
        assert!(
            parsed.normalize_s().is_none(),
            "sign_node_message must emit low-S"
        );
        verify_node_message(&public_key_hex, message, &low).unwrap();

        // Build the malleated (r, n - s) form: a well-formed signature encoding
        // for the same message and key.
        let s = Option::<Scalar>::from(Scalar::from_repr(FieldBytes::clone_from_slice(
            &low[32..64],
        )))
        .unwrap();
        let mut high = low.clone();
        high[32..64].copy_from_slice((-s).to_bytes().as_slice());
        let high_parsed = EcdsaSignature::try_from(high.as_slice())
            .expect("(r, n-s) is a structurally valid signature encoding");
        assert!(
            high_parsed.normalize_s().is_some(),
            "the constructed variant is high-S"
        );

        // Both `verify_node_message` and the underlying k256 `verify` reject it.
        // If a dependency bump ever starts accepting high-S, this test fails.
        let vk = VerifyingKey::from_sec1_bytes(&hex::decode(&public_key_hex).unwrap()).unwrap();
        assert!(vk.verify(message, &high_parsed).is_err());
        assert!(verify_node_message(&public_key_hex, message, &high).is_err());
    }
}
