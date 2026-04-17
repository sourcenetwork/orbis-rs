use crate::constants::{MAX_JWT_BYTES, MAX_TOKEN_LIFETIME_SECS};
use authn::{extract_bearer_token, resolve_jwt_did, BearerToken};
use serde::de::DeserializeOwned;
use std::fmt::Debug;
use std::time::{SystemTime, UNIX_EPOCH};

/// Return the current time as seconds since the Unix epoch.
///
/// Returns an error string on the (essentially impossible) case where the
/// system clock is set before the epoch.
pub fn current_unix_time() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| format!("Failed to get timestamp: {}", e))
}

/// Extract the bearer token from a tonic request and validate it as a DID JWT.
///
/// Returns `(raw_token_string, validated_bearer_token)` on success, or an
/// error string that callers should wrap in their module-specific error type
/// (e.g. `DkgError::Unauthorized`, `PreError::Unauthorized`).
pub fn extract_and_validate_jwt<C, B>(
    request: &tonic::Request<B>,
    current_time: u64,
) -> Result<(String, BearerToken<C>), String>
where
    C: DeserializeOwned + Debug,
{
    let token_str = extract_bearer_token(request)
        .map_err(|e| e.to_string())?
        .to_string();
    let token = resolve_jwt_did(
        &token_str,
        current_time,
        MAX_TOKEN_LIFETIME_SECS,
        MAX_JWT_BYTES,
    )
    .map_err(|e| format!("JWT validation failed: {}", e))?;
    Ok((token_str, token))
}
