use crypto::r#trait::Secret;

/// Validates the structure of a caller-supplied pre-encrypted document.
///
/// Parses `encrypted_document` as a `Secret`, confirms the embedded `enc_cmt` matches the
/// separately-supplied `enc_cmt` (both are provided by the caller; this just checks they're
/// mutually consistent), and confirms the nonce is the expected AES-GCM length. Shared by
/// `store_secret` and PRE's inline-document path — both accept the same wire shape for a
/// pre-encrypted document.
pub fn validate_encrypted_document(encrypted_document: &[u8], enc_cmt: &[u8]) -> Result<Secret, String> {
    let secret: Secret = serde_json::from_slice(encrypted_document)
        .map_err(|e| format!("Failed to parse encrypted_document as Secret: {}", e))?;

    if secret.enc_cmt != enc_cmt {
        return Err("enc_cmt in encrypted_document does not match provided enc_cmt".to_string());
    }

    if secret.nonce.len() != 12 {
        return Err(format!(
            "Invalid nonce length: expected 12 bytes, got {}",
            secret.nonce.len()
        ));
    }

    Ok(secret)
}
