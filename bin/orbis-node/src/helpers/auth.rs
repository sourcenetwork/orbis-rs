use crate::constants::{JWT_CLOCK_SKEW_LEEWAY_SECS, MAX_JWT_BYTES, MAX_TOKEN_LIFETIME_SECS};
use authn::{extract_bearer_token, resolve_actor_id, resolve_jwt_did, BearerToken};
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
        JWT_CLOCK_SKEW_LEEWAY_SECS,
    )
    .map_err(|e| format!("JWT validation failed: {}", e))?;
    Ok((token_str, token))
}

pub fn request_actor<C>(
    token: &BearerToken<C>,
    trusted_relay_issuers: Option<&[String]>,
) -> Result<String, String> {
    resolve_actor_id(token, trusted_relay_issuers.unwrap_or_default())
        .map(str::to_string)
        .map_err(|error| error.to_string())
}

/// Rings with configured relays require delegation for PRE; signing keeps its own policy.
pub fn request_pre_actor<C>(
    token: &BearerToken<C>,
    trusted_relay_issuers: Option<&[String]>,
) -> Result<String, String> {
    if trusted_relay_issuers.is_some() && token.subject_id.as_deref().is_none_or(str::is_empty) {
        return Err("protected PRE requires an approved intermediary".to_owned());
    }
    request_actor(token, trusted_relay_issuers)
}

#[cfg(test)]
mod pre_tests {
    use super::*;

    #[test]
    fn protected_pre_requires_delegation_without_changing_signing() {
        let mut token = BearerToken {
            issuer_id: "did:key:auditor".into(),
            subject_id: None,
            issued_time: 1,
            expiration_time: 2,
            not_before: None,
            jwt_id: "nonce".into(),
            claims: (),
        };
        let relays = vec!["did:key:intermediary".into()];
        assert!(request_pre_actor(&token, Some(&relays)).is_err());
        assert_eq!(
            request_actor(&token, Some(&relays)).unwrap(),
            "did:key:auditor"
        );
        assert_eq!(request_pre_actor(&token, None).unwrap(), "did:key:auditor");
        token.subject_id = Some("did:key:auditor".into());
        assert!(request_pre_actor(&token, Some(&relays)).is_err());
        token.issuer_id = "did:key:intermediary".into();
        assert_eq!(
            request_pre_actor(&token, Some(&relays)).unwrap(),
            "did:key:auditor"
        );
        assert!(request_pre_actor(&token, Some(&[])).is_err());
        token.subject_id = None;
        assert!(request_pre_actor(&token, Some(&relays)).is_err());
        assert!(request_pre_actor(&token, Some(&[])).is_err());
    }
}
