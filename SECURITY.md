# Security

## Reporting a vulnerability

Please report suspected vulnerabilities privately to the maintainers rather than
opening a public issue. Include a description of the problem, the affected
component, and a reproduction if you have one.

## Deployment trust assumptions

Orbis is a threshold system, but it does not run in a vacuum. Operating a node
safely depends on the assumptions below. This section is the authoritative list;
individual findings in `docs/security-review-findings.md` reference it.

### The Vera chain RPC/REST endpoint is an authorization anchor

Each node reads authorization decisions (`x/acp` `VerifyAccessRequest`), ring
configuration, key-derivation records, bulletin documents, and block height/time
from a Vera RPC/REST endpoint (`--chain-rpc` / `--chain-rest`). These responses
are **trusted as returned** — the node does not currently verify them against a
validator set or Merkle proofs (see `docs/security-review-findings.md` SEC-01,
phase b). A lying or man-in-the-middled endpoint can therefore return
`authorized = true` for a request that policy would deny, or hand back a doctored
ring record.

Consequently:

- **Run the endpoint yourself, co-located with the node**, or point at an
  endpoint operated by a party you trust to the same degree you trust the node
  process itself.
- **Use `https://` for any non-local endpoint.** `VeraClient` enforces this:
  plaintext `http://` is accepted only to loopback, RFC-1918 / unique-local /
  link-local / CGNAT addresses, single-label hostnames (container/service
  names), and `*.internal` / `*.local` / `*.lan` / `*.home.arpa` names. A
  plaintext endpoint on any other host is rejected at startup unless
  `--allow-insecure-rpc` (env `ORBIS_ALLOW_INSECURE_RPC`) is set — use that only
  when the endpoint is reached over a private network you control (e.g. a
  VPN/overlay).

Removing the "trust the endpoint's honesty" part of this assumption (as opposed
to the "trust the channel" part, which `https://` already covers) requires a
light client and is tracked as SEC-01 phase (b). Note that the ACP verdict
itself is computed Go logic with no Merkle proof, so a light client does not make
it verifiable — that needs capability materialization or client-side evaluation.

### The signing coordinator is trusted for liveness

DKG is abort-only; PRE and Sign rounds are driven by a coordinator. A malicious
coordinator that equivocates (hands different signers inconsistent commitment
sets, etc.) can cause a round to fail and can generate spurious fault-report
traffic, but cannot extract key material or forge a signature — FROST nonce
state is single-use and message content is bound to the caller's JWT / an
on-chain record. Equivocation attribution is deliberate future work.

### Client requests are authenticated with bearer JWTs over a trusted transport

gRPC requests carry a DID-signed JWT whose claims are bound to the specific
operation (reader key, object id, message digest, derivation). There is no
per-request nonce or audience binding yet (SEC-03), so a captured token is
replayable for the same operation within its validity window. Terminate client
connections with TLS and keep token lifetimes short.

### Local key material is encrypted at rest under an operator-supplied password

Ring shares and the node signing key are stored AES-256-GCM encrypted, keyed by
Argon2 from `--password-file` / `ORBIS_PASSWORD`. The at-rest encryption does not
yet bind a ciphertext to its storage slot or carry a rollback counter (SEC-04),
so an attacker with write access to the database file is a partial threat.
Protect the node's data directory with filesystem permissions.

## Out of scope

- Compromise of a threshold (≥ t) of ring nodes.
- Compromise of the host OS / root on a node.
- Denial of service from a peer within the configured ingress rate limits.
