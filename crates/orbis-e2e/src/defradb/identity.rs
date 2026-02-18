//! DefraDB identity helpers: did:key derivation, ES256K JWT, and authenticated HTTP.
//!
//! DefraDB uses secp256k1-based `did:key` identities for ACP. Each request
//! carries a Bearer JWT signed with the identity's private key. The JWT
//! contains a `key_type: "secp256k1"` claim so DefraDB knows how to verify.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use eyre::{eyre, Result};
use k256::ecdsa::{signature::Signer, Signature, SigningKey};
use k256::elliptic_curve::sec1::ToEncodedPoint;

/// Derive a `did:key:z...` from a secp256k1 private key hex string.
///
/// Uses the multicodec prefix `0xe7 0x01` for secp256k1-pub and
/// base58btc encoding with the `z` multibase prefix.
///
/// DefraDB uses the **uncompressed** (65-byte) public key for did:key
/// derivation (matching Go's SerializeUncompressed), so we do the same.
///
/// Returns `(did_key_string, compressed_public_key_bytes)`.
pub fn did_key_from_secp256k1(private_key_hex: &str) -> Result<(String, Vec<u8>)> {
    let key_bytes =
        hex::decode(private_key_hex).map_err(|e| eyre!("invalid hex key: {}", e))?;
    let signing_key =
        SigningKey::from_slice(&key_bytes).map_err(|e| eyre!("invalid secp256k1 key: {}", e))?;
    let verifying_key = signing_key.verifying_key();
    let compressed = verifying_key.to_sec1_bytes();

    // DID uses uncompressed key (65 bytes: 0x04 || x || y) to match DefraDB/Go
    let uncompressed = verifying_key.to_encoded_point(false);

    // multicodec: varint(0xe7) = [0xe7, 0x01] for secp256k1-pub
    let mut multicodec = vec![0xe7, 0x01];
    multicodec.extend_from_slice(uncompressed.as_bytes());

    let encoded = bs58::encode(&multicodec).into_string();
    let did = format!("did:key:z{}", encoded);

    Ok((did, compressed.to_vec()))
}

/// Generate an ES256K JWT compatible with DefraDB's identity extractor.
///
/// Claims:
/// - `sub`: hex-encoded compressed public key
/// - `iss`: did:key:z...
/// - `exp`: now + 900s
/// - `nbf`: now
/// - `iat`: now
/// - `aud`: [audience] (host:port without scheme)
/// - `key_type`: "secp256k1"
pub fn generate_defra_jwt(private_key_hex: &str, audience: &str) -> Result<String> {
    let key_bytes =
        hex::decode(private_key_hex).map_err(|e| eyre!("invalid hex key: {}", e))?;
    let signing_key =
        SigningKey::from_slice(&key_bytes).map_err(|e| eyre!("invalid secp256k1 key: {}", e))?;

    let (did_key, compressed_pub) = did_key_from_secp256k1(private_key_hex)?;
    let sub = hex::encode(&compressed_pub);

    // Strip scheme from audience: "http://127.0.0.1:9181" -> "127.0.0.1:9181"
    let aud = audience
        .strip_prefix("http://")
        .or_else(|| audience.strip_prefix("https://"))
        .unwrap_or(audience);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| eyre!("system time error: {}", e))?
        .as_secs();

    // Header: {"alg":"ES256K","typ":"JWT"}
    let header = serde_json::json!({"alg": "ES256K", "typ": "JWT"});
    let header_b64 = URL_SAFE_NO_PAD.encode(header.to_string().as_bytes());

    // Claims
    let claims = serde_json::json!({
        "sub": sub,
        "iss": did_key,
        "exp": now + 900,
        "nbf": now,
        "iat": now,
        "aud": [aud],
        "key_type": "secp256k1",
    });
    let claims_b64 = URL_SAFE_NO_PAD.encode(claims.to_string().as_bytes());

    // Sign: ECDSA-secp256k1 over SHA-256(header.claims)
    // The Signer trait hashes internally, so pass raw message bytes.
    let message = format!("{}.{}", header_b64, claims_b64);

    let signature: Signature = signing_key
        .try_sign(message.as_bytes())
        .map_err(|e| eyre!("signing failed: {}", e))?;

    // DefraDB expects raw 64-byte signature (r || s), not DER-encoded
    let sig_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());

    Ok(format!("{}.{}", message, sig_b64))
}

/// HTTP client that adds Bearer JWT for identity-authenticated DefraDB requests.
pub struct DefraHttpClient {
    http: reqwest::Client,
    base_url: String,
}

impl DefraHttpClient {
    pub fn new(base_url: &str) -> Self {
        Self {
            http: reqwest::Client::new(),
            base_url: base_url.to_string(),
        }
    }

    /// Execute a GraphQL query/mutation, optionally with identity authentication.
    ///
    /// When `identity_hex` is Some, generates a JWT and sends it as Bearer token.
    /// When None, sends unauthenticated (world-readable documents only).
    pub async fn graphql(
        &self,
        query: &str,
        identity_hex: Option<&str>,
    ) -> Result<serde_json::Value> {
        let url = format!("{}/api/v0/graphql", self.base_url);
        let body = serde_json::json!({"query": query});

        let mut request = self.http.post(&url).json(&body);

        if let Some(key_hex) = identity_hex {
            let jwt = generate_defra_jwt(key_hex, &self.base_url)?;
            request = request.header("Authorization", format!("Bearer {}", jwt));
        }

        let resp = request
            .send()
            .await
            .map_err(|e| eyre!("graphql request failed: {}", e))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(eyre!("graphql HTTP {}: {}", status, body));
        }

        resp.json()
            .await
            .map_err(|e| eyre!("failed to parse graphql response: {}", e))
    }

    /// Add a schema (SDL string) to DefraDB.
    pub async fn schema_add(&self, sdl: &str) -> Result<()> {
        let url = format!("{}/api/v0/schema", self.base_url);
        let resp = self
            .http
            .post(&url)
            .header("Content-Type", "text/plain")
            .body(sdl.to_string())
            .send()
            .await
            .map_err(|e| eyre!("schema add request failed: {}", e))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(eyre!("schema add HTTP {}: {}", status, body));
        }

        Ok(())
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn did_key_roundtrip() {
        let key_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let (did, pub_bytes) = did_key_from_secp256k1(key_hex).unwrap();
        assert!(did.starts_with("did:key:z"), "got: {}", did);
        assert_eq!(pub_bytes.len(), 33, "compressed secp256k1 pubkey is 33 bytes");
    }

    #[test]
    fn jwt_has_three_parts() {
        let key_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let jwt = generate_defra_jwt(key_hex, "http://127.0.0.1:9181").unwrap();
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3, "JWT should have 3 parts: {}", jwt);

        // Decode header and verify alg
        let header_json = URL_SAFE_NO_PAD.decode(parts[0]).unwrap();
        let header: serde_json::Value = serde_json::from_slice(&header_json).unwrap();
        assert_eq!(header["alg"], "ES256K");

        // Decode claims and verify key_type + aud
        let claims_json = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
        let claims: serde_json::Value = serde_json::from_slice(&claims_json).unwrap();
        assert_eq!(claims["key_type"], "secp256k1");
        assert_eq!(claims["aud"][0], "127.0.0.1:9181");
        assert!(claims["iss"].as_str().unwrap().starts_with("did:key:z"));
    }
}
