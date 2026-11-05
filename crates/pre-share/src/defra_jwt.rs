//! Mints a Defra-compatible bearer JWT from a secp256k1 keypair — specifically, the
//! same `node_key`/node-signing-key pair orbis-node already uses for every other
//! node-identity signature (`response_signature`, `ack_signature`). Confirmed against
//! the actual DefraDB implementation (`crates/identity/src/token/{mod,claims,encoding,
//! decoding}.rs`, `crates/http/src/identity_extractor.rs` in the pinned defradb.rs
//! revision), not guessed: DefraDB's identity system already natively supports
//! secp256k1 (`IdentityKeyType::Secp256k1`) — this is not a workaround, it's the
//! existing on-chain node identity authenticating directly, with no separate
//! credential to provision. The same identity (`sub`) is what a future Defra-side
//! authorization check could compare against a ring's on-chain `peer_node_keys`.
//!
//! Wire shape (must match exactly or DefraDB's verifier silently 403s):
//! - Header: `{"alg":"ES256K","typ":"JWT"}`.
//! - Claims: `sub` = hex-encoded *compressed* secp256k1 public key (same string as
//!   `node_key`); `iss` = `did:key:` + base58btc (`z` prefix) of the secp256k1
//!   multicodec (`0xe7, 0x01`, varint-encoded, mirroring the `[0xed, 0x01]` Ed25519
//!   prefix `cli-tool`'s own did:key generation already hardcodes) followed by the
//!   **uncompressed** 65-byte SEC1 point — DefraDB derives the DID from the
//!   uncompressed form specifically; `exp`/`nbf`/`iat` Unix seconds; `aud` —
//!   *required*, DefraDB rejects a token with no audience at all; `key_type`:
//!   `"secp256k1"`.
//! - Signature: base64url (no padding) of the raw 64-byte R‖S ECDSA signature (RFC
//!   7518) over `base64url(header) + "." + base64url(claims)` — exactly the form
//!   `common::blockchain::sign_node_message_with_hex_key` already produces, so no
//!   DER↔raw conversion is needed here (DefraDB's own signer produces DER internally
//!   and converts to raw for the wire; ours is already in the target form).

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use common::blockchain::sign_node_message_with_hex_key;
use k256::elliptic_curve::sec1::ToSec1Point;
use k256::PublicKey;
use serde::Serialize;

use crate::error::{PreShareError, Result};

/// secp256k1-pub multicodec (`0xe7`), varint-encoded — two bytes, since `0xe7` (231)
/// doesn't fit in a varint's 7 data bits per byte. Mirrors the same hardcoded-prefix
/// approach `cli-tool` already uses for Ed25519's `[0xed, 0x01]`, rather than pulling
/// in a full varint-encoding dependency for one constant pair.
const SECP256K1_DID_KEY_PREFIX: [u8; 2] = [0xe7, 0x01];

#[derive(Serialize)]
struct IdentityClaims<'a> {
    sub: &'a str,
    iss: String,
    exp: u64,
    nbf: u64,
    iat: u64,
    aud: Vec<String>,
    key_type: &'a str,
}

/// The `host[:port]` audience DefraDB's verifier expects — it checks the JWT's `aud`
/// against the lowercased `Host` header value the HTTP request itself presents. Must
/// be derived from the same `Url` the request is actually sent to, not reconstructed
/// independently, so it can't drift from what `reqwest` sends.
pub fn audience_for_url(url: &reqwest::Url) -> String {
    let host = url.host_str().unwrap_or_default();
    match url.port() {
        Some(port) => format!("{host}:{port}").to_lowercase(),
        None => host.to_lowercase(),
    }
}

fn did_key_from_compressed_secp256k1(compressed_hex: &str) -> Result<String> {
    let compressed = hex::decode(compressed_hex)
        .map_err(|error| PreShareError::Jwt(format!("invalid public key hex: {error}")))?;
    let public_key = PublicKey::from_sec1_bytes(&compressed)
        .map_err(|error| PreShareError::Jwt(format!("invalid secp256k1 public key: {error}")))?;
    let uncompressed = public_key.to_sec1_point(false);

    let mut codec_bytes = Vec::with_capacity(SECP256K1_DID_KEY_PREFIX.len() + 65);
    codec_bytes.extend_from_slice(&SECP256K1_DID_KEY_PREFIX);
    codec_bytes.extend_from_slice(uncompressed.as_bytes());

    Ok(format!(
        "did:key:z{}",
        bs58::encode(codec_bytes).into_string()
    ))
}

fn unix_now() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| PreShareError::Jwt(format!("system clock before Unix epoch: {error}")))
}

/// Mints a bearer JWT DefraDB will accept as this node's own identity, signed with
/// `signing_key_hex` (the same node signing key used for `response_signature`/
/// `ack_signature`). `public_key_hex` must be that key's own public counterpart —
/// typically `app_state.node_key`, never re-derived independently.
pub fn mint_node_bearer_jwt(
    signing_key_hex: &str,
    public_key_hex: &str,
    audience: &str,
    ttl: Duration,
) -> Result<String> {
    let iss = did_key_from_compressed_secp256k1(public_key_hex)?;
    let now = unix_now()?;
    let claims = IdentityClaims {
        sub: public_key_hex,
        iss,
        exp: now
            .checked_add(ttl.as_secs())
            .ok_or_else(|| PreShareError::Jwt("JWT expiration overflow".to_string()))?,
        nbf: now,
        iat: now,
        aud: vec![audience.to_string()],
        key_type: "secp256k1",
    };

    let header_b64 = URL_SAFE_NO_PAD.encode(r#"{"alg":"ES256K","typ":"JWT"}"#);
    let claims_json = serde_json::to_vec(&claims)
        .map_err(|error| PreShareError::Jwt(format!("failed to serialize claims: {error}")))?;
    let claims_b64 = URL_SAFE_NO_PAD.encode(claims_json);
    let signing_input = format!("{header_b64}.{claims_b64}");

    let signature = sign_node_message_with_hex_key(signing_key_hex, signing_input.as_bytes())
        .map_err(|error| PreShareError::Jwt(format!("failed to sign JWT: {error}")))?;
    let signature_b64 = URL_SAFE_NO_PAD.encode(signature);

    Ok(format!("{signing_input}.{signature_b64}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIGNING_KEY_HEX: &str =
        "c4a48e2fce1481cd3294b4490f6678090ea98d3d0e5cd984558ab0968741b104";
    const PUBLIC_KEY_HEX: &str =
        "024f4e2ad99c34d60b9ba6283c9431a8418af8673212961f97a77b6377fcd05b62";

    fn decode_segment(segment: &str) -> Vec<u8> {
        URL_SAFE_NO_PAD.decode(segment).expect("valid base64url")
    }

    #[test]
    fn mint_node_bearer_jwt_has_three_segments_with_the_right_header() {
        let jwt = mint_node_bearer_jwt(
            SIGNING_KEY_HEX,
            PUBLIC_KEY_HEX,
            "defra.example:9181",
            Duration::from_secs(3600),
        )
        .expect("mint JWT");
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3);

        let header: serde_json::Value =
            serde_json::from_slice(&decode_segment(parts[0])).expect("valid header JSON");
        assert_eq!(header["alg"], "ES256K");
        assert_eq!(header["typ"], "JWT");
    }

    #[test]
    fn mint_node_bearer_jwt_claims_match_the_signer_and_audience() {
        let jwt = mint_node_bearer_jwt(
            SIGNING_KEY_HEX,
            PUBLIC_KEY_HEX,
            "defra.example:9181",
            Duration::from_secs(3600),
        )
        .expect("mint JWT");
        let parts: Vec<&str> = jwt.split('.').collect();
        let claims: serde_json::Value =
            serde_json::from_slice(&decode_segment(parts[1])).expect("valid claims JSON");

        assert_eq!(claims["sub"], PUBLIC_KEY_HEX);
        assert_eq!(claims["key_type"], "secp256k1");
        assert_eq!(claims["aud"], serde_json::json!(["defra.example:9181"]));
        assert!(claims["iss"].as_str().unwrap().starts_with("did:key:z"));
        let exp = claims["exp"].as_u64().unwrap();
        let nbf = claims["nbf"].as_u64().unwrap();
        assert!(exp > nbf);
        assert_eq!(exp - nbf, 3600);
    }

    /// Replicates DefraDB's own `verify_auth_token_with_skew` checks (can't import
    /// its crate here) against a minted token, as the closest thing to an actual
    /// round trip through the real verifier available in this crate's tests.
    #[test]
    fn mint_node_bearer_jwt_signature_verifies_against_the_public_key() {
        let jwt = mint_node_bearer_jwt(
            SIGNING_KEY_HEX,
            PUBLIC_KEY_HEX,
            "defra.example:9181",
            Duration::from_secs(3600),
        )
        .expect("mint JWT");
        let parts: Vec<&str> = jwt.split('.').collect();
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let signature = decode_segment(parts[2]);
        assert_eq!(signature.len(), 64, "JWT signature must be raw R||S");

        common::blockchain::verify_node_message(
            PUBLIC_KEY_HEX,
            signing_input.as_bytes(),
            &signature,
        )
        .expect("signature should verify against the signer's own public key");
    }

    #[test]
    fn mint_node_bearer_jwt_rejects_a_malformed_public_key() {
        let error = mint_node_bearer_jwt(
            SIGNING_KEY_HEX,
            "not hex",
            "defra.example:9181",
            Duration::from_secs(3600),
        )
        .expect_err("malformed public key");
        assert!(matches!(error, PreShareError::Jwt(_)));
    }

    #[test]
    fn audience_for_url_includes_a_non_default_port() {
        let url = reqwest::Url::parse("http://Defra.Example:9181/api/v0").unwrap();
        assert_eq!(audience_for_url(&url), "defra.example:9181");
    }

    #[test]
    fn audience_for_url_omits_the_default_port() {
        let url = reqwest::Url::parse("http://defra.example/api/v0").unwrap();
        assert_eq!(audience_for_url(&url), "defra.example");
    }
}
