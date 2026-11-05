//! Node-local Defra access: a cache of [`DefraClient`]s keyed by endpoint URL, each
//! authenticated with a bearer JWT this node mints itself from its own node signing
//! key — the same secp256k1 identity already registered on-chain as this node's
//! `node_key` (see `pre_share::mint_node_bearer_jwt`'s doc comment for why DefraDB's
//! own identity system accepts this directly, with nothing to separately provision).
//!
//! The endpoint URL itself is ring config (public, from `RingPayload::pre_share_endpoints`);
//! the signing key is node-local — see the Defra PRE-Share Storage plan's Step 1.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use pre_share::{mint_node_bearer_jwt, DefraClient, Url};
use tokio::sync::RwLock;

use crate::pre::v0::error::PreError;

/// How long a minted JWT is valid for (DefraDB's side) — generous relative to a PRE
/// collection round, so minting is rare, matching `authn::JwtSigner::TOKEN_TTL`'s
/// existing 1-hour convention.
const TOKEN_TTL: Duration = Duration::from_secs(60 * 60);

/// How long a cached client is trusted before this node mints a fresh JWT for it —
/// comfortably shorter than `TOKEN_TTL` so a cached client is never used right up to
/// (or past) the point DefraDB would reject it as expired.
const CACHE_VALIDITY: Duration = Duration::from_secs(55 * 60);

pub struct DefraNodeConfig {
    clients: RwLock<HashMap<String, (Arc<DefraClient>, Instant)>>,
}

impl DefraNodeConfig {
    pub fn new() -> Self {
        Self {
            clients: RwLock::new(HashMap::new()),
        }
    }

    /// Returns a shared client for `endpoint`, minting a fresh bearer JWT from
    /// `signing_key_hex`/`node_key_hex` (the caller already has these in hand — see
    /// `stored_delivery::build_and_store_envelope`, which loads the same signing key
    /// for envelope/ack signing) and constructing a new client whenever the cached
    /// one is missing or its JWT has aged past `CACHE_VALIDITY`.
    pub async fn client_for(
        &self,
        endpoint: &str,
        signing_key_hex: &str,
        node_key_hex: &str,
    ) -> Result<Arc<DefraClient>, PreError> {
        if let Some((client, minted_at)) = self.clients.read().await.get(endpoint) {
            if minted_at.elapsed() < CACHE_VALIDITY {
                return Ok(client.clone());
            }
        }

        let mut clients = self.clients.write().await;
        // Re-check under the write lock: another task may have raced us here.
        if let Some((client, minted_at)) = clients.get(endpoint) {
            if minted_at.elapsed() < CACHE_VALIDITY {
                return Ok(client.clone());
            }
        }

        let url = Url::parse(endpoint)
            .map_err(|error| PreError::DefraStorage(format!("invalid Defra endpoint: {error}")))?;
        let audience = pre_share::audience_for_url(&url);
        let bearer_jwt = mint_node_bearer_jwt(signing_key_hex, node_key_hex, &audience, TOKEN_TTL)
            .map_err(|error| PreError::DefraStorage(error.to_string()))?;
        let client = Arc::new(
            DefraClient::new(url, bearer_jwt)
                .map_err(|error| PreError::DefraStorage(error.to_string()))?,
        );
        clients.insert(endpoint.to_string(), (client.clone(), Instant::now()));
        Ok(client)
    }
}

impl Default for DefraNodeConfig {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIGNING_KEY_HEX: &str =
        "c4a48e2fce1481cd3294b4490f6678090ea98d3d0e5cd984558ab0968741b104";
    const NODE_KEY_HEX: &str =
        "024f4e2ad99c34d60b9ba6283c9431a8418af8673212961f97a77b6377fcd05b62";

    #[tokio::test]
    async fn client_for_mints_a_client_for_a_valid_endpoint() {
        let config = DefraNodeConfig::new();
        config
            .client_for("http://localhost:9181", SIGNING_KEY_HEX, NODE_KEY_HEX)
            .await
            .expect("mint client");
    }

    #[tokio::test]
    async fn client_for_rejects_a_malformed_endpoint() {
        let config = DefraNodeConfig::new();
        let error = config
            .client_for("not a url", SIGNING_KEY_HEX, NODE_KEY_HEX)
            .await
            .expect_err("malformed endpoint");
        assert!(matches!(error, PreError::DefraStorage(_)));
    }

    #[tokio::test]
    async fn client_for_rejects_a_malformed_node_key() {
        let config = DefraNodeConfig::new();
        let error = config
            .client_for("http://localhost:9181", SIGNING_KEY_HEX, "not hex")
            .await
            .expect_err("malformed node key");
        assert!(matches!(error, PreError::DefraStorage(_)));
    }

    #[tokio::test]
    async fn client_for_reuses_the_cached_client_for_the_same_endpoint() {
        let config = DefraNodeConfig::new();
        let first = config
            .client_for("http://localhost:9181", SIGNING_KEY_HEX, NODE_KEY_HEX)
            .await
            .expect("first client");
        let second = config
            .client_for("http://localhost:9181", SIGNING_KEY_HEX, NODE_KEY_HEX)
            .await
            .expect("second client");
        assert!(Arc::ptr_eq(&first, &second));
    }
}
