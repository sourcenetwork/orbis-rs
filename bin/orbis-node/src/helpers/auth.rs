use authn::{resolve_actor_id, BearerToken};
use authz::request::ValidWindow;
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

pub fn request_actor<C>(
    token: &BearerToken<C>,
    trusted_relay_issuers: Option<&[String]>,
) -> Result<String, String> {
    resolve_actor_id(token, trusted_relay_issuers.unwrap_or_default())
        .map(str::to_string)
        .map_err(|error| error.to_string())
}

/// Convert a client-supplied optional timestamp range (PRE's and Sign's
/// generated `TimestampRange` are distinct wire types with the same two
/// `u64` fields) into the `authz::request::ValidWindow` used for ACP checks.
pub fn client_valid_window(range: Option<(u64, u64)>) -> Option<ValidWindow> {
    range.map(|(start, end)| ValidWindow { start, end })
}
