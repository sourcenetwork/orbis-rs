use regex::Regex;

/// A named log pattern for event-driven test verification.
pub struct NamedPattern {
    pub name: &'static str,
    pub regex: Regex,
}

/// Log patterns for SourceHub node readiness.
pub fn sourcehub_patterns() -> Vec<NamedPattern> {
    vec![NamedPattern {
        name: "first_block",
        regex: Regex::new(r"committed state.*height=1\b").unwrap(),
    }]
}

/// Log patterns for orbis-node events.
pub fn orbis_node_patterns() -> Vec<NamedPattern> {
    vec![
        NamedPattern {
            name: "network_initialized",
            regex: Regex::new(r"Network initialized").unwrap(),
        },
        NamedPattern {
            name: "server_ready",
            regex: Regex::new(r"Server is ready to accept connections").unwrap(),
        },
        NamedPattern {
            name: "router_started",
            regex: Regex::new(r"Router started with DKG").unwrap(),
        },
        NamedPattern {
            name: "signing_key_ready",
            regex: Regex::new(r"Signing key ready").unwrap(),
        },
    ]
}
