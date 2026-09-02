//! Chain configuration for Vera.

use super::{BlockchainError, Result};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Gas price configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GasPrice {
    /// Amount per gas unit (e.g., 0.025)
    pub amount: f64,
    /// Denomination (e.g., "uvera")
    pub denom: String,
}

impl Default for GasPrice {
    fn default() -> Self {
        Self {
            amount: 0.025,
            denom: "uopen".to_string(),
        }
    }
}

/// Configuration for connecting to a Vera chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainConfig {
    /// Chain ID (e.g., "vera-testnet")
    pub chain_id: String,

    /// Tendermint RPC URL (e.g., "http://localhost:26657")
    pub rpc_url: String,

    /// Cosmos REST API URL (e.g., "http://localhost:1317")
    pub rest_url: String,

    /// gRPC URL (e.g., "http://localhost:9090")
    pub grpc_url: String,

    /// Account address prefix (e.g., "vera")
    pub account_prefix: String,

    /// Default gas limit for transactions
    pub default_gas_limit: u64,

    /// Gas price configuration
    pub gas_price: GasPrice,

    /// Safety buffer multiplier (e.g., 1.2 for 20% extra)
    pub gas_multiplier: f64,

    /// Opt out of [`ChainConfig::validate_endpoints`]'s plaintext-to-untrusted-host
    /// check for `rpc_url` / `rest_url`.
    ///
    /// The chain RPC/REST responses are this node's authorization anchor: an ACP
    /// verdict, a bulletin record, or block metadata returned by the endpoint is
    /// trusted as-is. `https://` removes the wire-tamper risk; so does an endpoint
    /// reachable only over a network the operator controls. Set this to `true`
    /// only when a plaintext `http://` endpoint on a public-looking host is in
    /// fact reached over such a trusted path (e.g. a VPN/overlay, or a lab
    /// network). Defaults to `false`.
    #[serde(default)]
    pub allow_insecure_rpc: bool,
}

impl ChainConfig {
    /// Create a new ChainConfig builder.
    pub fn builder() -> ChainConfigBuilder {
        ChainConfigBuilder::default()
    }

    /// Configuration for local development (default Docker setup).
    pub fn local() -> Self {
        Self {
            chain_id: "vera-localnet".to_string(),
            rpc_url: "http://localhost:26657".to_string(),
            rest_url: "http://localhost:1317".to_string(),
            grpc_url: "http://localhost:9090".to_string(),
            account_prefix: "vera".to_string(),
            default_gas_limit: 300_000,
            gas_price: GasPrice::default(),
            gas_multiplier: 1.2,
            allow_insecure_rpc: false,
        }
    }

    /// Calculate fee from gas limit.
    pub fn calculate_fee(&self, gas_limit: u64) -> u64 {
        ((gas_limit as f64) * self.gas_price.amount).ceil() as u64
    }

    /// Reject a chain endpoint that would send reads — ACP verdicts, bulletin
    /// records, block metadata — in plaintext to a host outside the operator's
    /// trust boundary. Called by [`VeraClient::new`](super::VeraClient::new).
    ///
    /// A lying or man-in-the-middled endpoint can return `authorized = true` or a
    /// doctored record, so `rpc_url` / `rest_url` are effectively an authorization
    /// anchor for this node. This does **not** verify endpoint responses
    /// cryptographically (that would need a light client); it only refuses the
    /// case where a plaintext channel to an untrusted host makes tampering
    /// trivial.
    ///
    /// Allowed without `allow_insecure_rpc`:
    /// - any `https` / `wss` / `grpcs` URL — channel authenticated and encrypted;
    /// - plaintext to loopback (`127.0.0.0/8`, `::1`, `localhost`, `*.localhost`);
    /// - plaintext to a network the operator controls: RFC-1918 / unique-local /
    ///   link-local / CGNAT IPs, single-label hostnames (container / service
    ///   names), and `*.internal` / `*.local` / `*.lan` / `*.home.arpa` names.
    ///
    /// Everything else (plaintext `http://` to a public IP or FQDN) is rejected
    /// unless `allow_insecure_rpc` is set.
    pub fn validate_endpoints(&self) -> Result<()> {
        if self.allow_insecure_rpc {
            return Ok(());
        }
        for (label, url) in [("rpc_url", &self.rpc_url), ("rest_url", &self.rest_url)] {
            if endpoint_is_insecure_to_untrusted_host(url) {
                return Err(BlockchainError::Config(format!(
                    "{label} {url:?} would send chain reads — including authorization \
                     decisions — in plaintext to a host outside this machine and any \
                     private network. Use an https:// endpoint, point at a chain node \
                     reachable only over a network you control, or set \
                     allow_insecure_rpc = true (orbis-node: --allow-insecure-rpc) to \
                     accept the risk."
                )));
            }
        }
        Ok(())
    }
}

/// True when `raw` is a plaintext (non-TLS) URL whose host is neither loopback
/// nor on an operator-controlled private network.
///
/// An unparseable URL returns `false` here — downstream URL parsing rejects it
/// with a clearer message than this check could give.
fn endpoint_is_insecure_to_untrusted_host(raw: &str) -> bool {
    let Some((scheme, host)) = split_scheme_host(raw) else {
        return false;
    };
    if matches!(
        scheme.to_ascii_lowercase().as_str(),
        "https" | "wss" | "grpcs"
    ) {
        return false;
    }
    host_is_untrusted(host)
}

/// A host is "untrusted" if it is reachable across a network the operator does
/// not necessarily control (public internet / shared datacenter fabric).
fn host_is_untrusted(host: &str) -> bool {
    let host = host.trim().to_ascii_lowercase();
    if host.is_empty() {
        return false;
    }
    if host == "localhost" || host.ends_with(".localhost") {
        return false;
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        return !ip_is_operator_controlled(ip);
    }
    // Hostname. A single label (no dot) is a container / service / mDNS name on
    // a network the operator defined; common private suffixes likewise.
    if !host.contains('.') {
        return false;
    }
    const PRIVATE_SUFFIXES: [&str; 5] =
        [".internal", ".local", ".lan", ".localdomain", ".home.arpa"];
    !PRIVATE_SUFFIXES.iter().any(|suffix| host.ends_with(suffix))
}

fn ip_is_operator_controlled(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                // CGNAT / carrier / overlay (Tailscale et al.) 100.64.0.0/10 —
                // never publicly routable.
                || (a == 100 && (64..128).contains(&b))
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            v6.is_loopback()
                || (s[0] & 0xfe00) == 0xfc00 // fc00::/7  unique local
                || (s[0] & 0xffc0) == 0xfe80 // fe80::/10 link-local
        }
    }
}

/// Extract `(scheme, host)` from `scheme://[user@]host[:port][/...]`, handling
/// bracketed IPv6 literals. Returns `None` when there is no `://`.
fn split_scheme_host(raw: &str) -> Option<(&str, &str)> {
    let (scheme, rest) = raw.split_once("://")?;
    if scheme.is_empty() {
        return None;
    }
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    let host_port = authority
        .rsplit_once('@')
        .map_or(authority, |(_userinfo, hp)| hp);
    let host = if let Some(after_bracket) = host_port.strip_prefix('[') {
        // [::1]:26657 -> ::1
        after_bracket.split(']').next().unwrap_or(after_bracket)
    } else if let Some((h, port)) = host_port.rsplit_once(':') {
        // Only strip a genuine :<digits> port. A bare IPv6 literal has several
        // ':' and no all-digit tail, so it is left intact for IpAddr parsing.
        if !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit()) {
            h
        } else {
            host_port
        }
    } else {
        host_port
    };
    Some((scheme, host))
}

/// Builder for ChainConfig.
#[derive(Debug, Default, Clone)]
pub struct ChainConfigBuilder {
    pub chain_id: Option<String>,
    pub rpc_url: Option<String>,
    pub rest_url: Option<String>,
    pub grpc_url: Option<String>,
    pub account_prefix: Option<String>,
    pub default_gas_limit: Option<u64>,
    pub gas_price: Option<GasPrice>,
    pub gas_multiplier: Option<f64>,
    pub allow_insecure_rpc: Option<bool>,
}

impl ChainConfigBuilder {
    pub fn chain_id(mut self, chain_id: Option<String>) -> Self {
        self.chain_id = chain_id;
        self
    }

    pub fn rpc_url(mut self, rpc_url: Option<String>) -> Self {
        self.rpc_url = rpc_url;
        self
    }

    pub fn rest_url(mut self, rest_url: Option<String>) -> Self {
        self.rest_url = rest_url;
        self
    }

    pub fn grpc_url(mut self, grpc_url: Option<String>) -> Self {
        self.grpc_url = grpc_url;
        self
    }

    pub fn account_prefix(mut self, prefix: Option<String>) -> Self {
        self.account_prefix = prefix;
        self
    }

    pub fn default_gas_limit(mut self, gas_limit: Option<u64>) -> Self {
        self.default_gas_limit = gas_limit;
        self
    }

    pub fn gas_price(mut self, gas_price: Option<GasPrice>) -> Self {
        self.gas_price = gas_price;
        self
    }

    pub fn denom(mut self, denom: Option<String>) -> Self {
        if let Some(denom) = denom {
            self.gas_price.get_or_insert_with(GasPrice::default).denom = denom;
        }
        self
    }

    pub fn gas_multiplier(mut self, gas_multiplier: Option<f64>) -> Self {
        self.gas_multiplier = gas_multiplier;
        self
    }

    /// Accept a plaintext `http://` chain endpoint on a public-looking host.
    /// See [`ChainConfig::allow_insecure_rpc`]. `None` leaves the default
    /// (`false`).
    pub fn allow_insecure_rpc(mut self, allow_insecure_rpc: Option<bool>) -> Self {
        self.allow_insecure_rpc = allow_insecure_rpc;
        self
    }

    /// Build the ChainConfig. Uses local defaults for any unset values.
    pub fn build(self) -> ChainConfig {
        let local = ChainConfig::local();
        ChainConfig {
            chain_id: self.chain_id.unwrap_or(local.chain_id),
            rpc_url: self.rpc_url.unwrap_or(local.rpc_url),
            rest_url: self.rest_url.unwrap_or(local.rest_url),
            grpc_url: self.grpc_url.unwrap_or(local.grpc_url),
            account_prefix: self.account_prefix.unwrap_or(local.account_prefix),
            default_gas_limit: self.default_gas_limit.unwrap_or(local.default_gas_limit),
            gas_price: self.gas_price.unwrap_or(local.gas_price),
            gas_multiplier: self.gas_multiplier.unwrap_or(local.gas_multiplier),
            allow_insecure_rpc: self.allow_insecure_rpc.unwrap_or(local.allow_insecure_rpc),
        }
    }
}

#[cfg(test)]
mod endpoint_validation_tests {
    use super::*;

    fn cfg(rpc: &str) -> ChainConfig {
        ChainConfig {
            rpc_url: rpc.to_string(),
            rest_url: "https://rest.example.com".to_string(),
            ..ChainConfig::local()
        }
    }

    #[test]
    fn allows_loopback_and_private_and_tls() {
        for url in [
            "http://localhost:26657",
            "http://127.0.0.1:26657",
            "http://[::1]:26657",
            "http://sourcehub:26657", // docker/k8s service name
            "http://node-003:9090",
            "http://10.4.0.7:26657", // RFC-1918
            "http://192.168.1.50:26657",
            "http://172.16.9.9:26657",
            "http://100.100.10.1:26657", // CGNAT / tailscale
            "http://vera.internal:26657",
            "http://rpc.cluster.local:26657",
            "https://rpc.example.com:26657",
            "https://1.2.3.4:26657",
            "wss://rpc.example.com",
        ] {
            assert!(
                cfg(url).validate_endpoints().is_ok(),
                "expected {url} to be allowed"
            );
        }
    }

    #[test]
    fn rejects_plaintext_to_public_host() {
        for url in [
            "http://rpc.example.com:26657",
            "http://1.2.3.4:26657",
            "http://[2001:db8::1]:26657",
            "http://vera-rpc.somecloud.io",
        ] {
            assert!(
                cfg(url).validate_endpoints().is_err(),
                "expected {url} to be rejected"
            );
        }
    }

    #[test]
    fn allow_insecure_rpc_opt_out_bypasses_the_check() {
        let mut config = cfg("http://rpc.example.com:26657");
        assert!(config.validate_endpoints().is_err());
        config.allow_insecure_rpc = true;
        assert!(config.validate_endpoints().is_ok());
    }

    #[test]
    fn rest_url_is_checked_too() {
        let config = ChainConfig {
            rest_url: "http://rest.example.com:1317".to_string(),
            ..ChainConfig::local()
        };
        assert!(config.validate_endpoints().is_err());
    }

    #[test]
    fn serde_default_keeps_old_configs_deserializing() {
        let json = r#"{
            "chain_id":"x","rpc_url":"http://localhost:26657","rest_url":"http://localhost:1317",
            "grpc_url":"http://localhost:9090","account_prefix":"vera","default_gas_limit":1,
            "gas_price":{"amount":0.025,"denom":"uopen"},"gas_multiplier":1.2
        }"#;
        let config: ChainConfig = serde_json::from_str(json).unwrap();
        assert!(!config.allow_insecure_rpc);
    }
}
