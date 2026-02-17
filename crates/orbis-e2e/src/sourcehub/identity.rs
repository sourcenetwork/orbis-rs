use cosmrs::crypto::secp256k1::SigningKey;

/// Derive a `source1...` bech32 address from a secp256k1 private key hex string.
///
/// Uses the standard Cosmos SDK derivation:
/// secp256k1 pubkey -> SHA256 -> RIPEMD160 -> bech32("source", ...)
pub fn source_hub_address(private_key_hex: &str) -> eyre::Result<String> {
    let key_bytes = hex::decode(private_key_hex)
        .map_err(|e| eyre::eyre!("invalid hex key: {}", e))?;
    let signing_key = SigningKey::from_slice(&key_bytes)
        .map_err(|e| eyre::eyre!("invalid secp256k1 private key: {}", e))?;
    let public_key = signing_key.public_key();
    let account_id = public_key
        .account_id("source")
        .map_err(|e| eyre::eyre!("failed to derive source address: {}", e))?;
    Ok(account_id.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_source_address() {
        let key_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let addr = source_hub_address(key_hex).unwrap();
        assert!(
            addr.starts_with("source1"),
            "expected source1... prefix, got: {}",
            addr
        );
    }
}
