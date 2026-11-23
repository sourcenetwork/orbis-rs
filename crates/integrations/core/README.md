# orbis-integration-core

Shared operation description for the flow integrations: `SignOperation`,
`PreOperation`, and `StoreSecretOperation` are the exact Sign/PRE/StoreSecret
request a piece of authentication evidence (e.g. a WebAuthn assertion) must
commit to, each via `CanonicalOperation::canonical_bytes()`, its
deterministic, domain-separated encoding.

Encoding is one-way by design. A verifier reconstructs the *expected*
operation from the live request it already has (ring id, derivation id,
message digest, plus the evidence's own expiry/nonce), re-encodes it, and
compares the result against what the evidence actually committed to — it
never parses an untrusted encoding back apart. This keeps the crate small
and independent of HTTP frameworks, databases, mail delivery, and node
startup.

A verified actor returned inside one process is not proof for another process.
Participating nodes must independently verify the original evidence.
