# Security

## Reporting a vulnerability

Please report suspected vulnerabilities privately to the maintainers rather than
opening a public issue. Include a description of the problem, the affected
component, and a reproduction if you have one.

## Deployment trust assumptions

Orbis is a threshold system, but operating a node safely depends on the trust
assumptions below. This section describes the current implementation.

### Cosmos service endpoints require trust in the operator

In Cosmos mode, each node reads authorization decisions (`x/acp` `VerifyAccessRequest`), ring
configuration, key-derivation records, bulletin documents, and block height/time
from Vera RPC/REST endpoints (`--chain-rpc` / `--chain-rest`). These responses
are **trusted as returned** — the node does not currently verify them against a
validator set or Merkle proofs. A lying or man-in-the-middled endpoint can return
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

Removing the "trust the endpoint's honesty" part of this assumption would
require authenticated chain-state reads. The ACP verdict itself is computed Go
logic with no Merkle proof, so a light client alone would not make it verifiable;
that would also require capability materialization or client-side evaluation.

### Native Vera reads require independently configured consensus trust

Native mode verifies finality against its configured consensus key and checks the
configured deployment root before serving requests. Authorization evaluates ACP
locally from authenticated policy and relationship evidence at one revision.
Current relation identities and target-object incarnations are authenticated with
the policy. Removing and recreating a relation, or archiving and unarchiving an
object, cannot make its previous grants valid again. Invalid, oversized,
unavailable or stale evidence produces an error, never an allow decision.

Current reads enforce a configured maximum age and a nondecreasing observed
revision. A valid proof describes that revision; it cannot prove that no newer
revocation exists. Exact revision anchors authenticate historical state without
applying the current-read maximum age; callers must decide whether that revision
is suitable for their operation. An endpoint can withhold evidence or serve older
certified state within the current-read freshness window. Availability and the
chosen window remain operational considerations. Protect the provisioned
consensus key and deployment root.

Native validators, clients and verifiers must use the same ACP storage/proof
format. Native relationship keys use `relationship/v5/` with `v3` suffixes and
mandatory incarnation stamps; owner records always use incarnation zero.
Specialized relationship proofs require an `objects` witness array for every
non-owner target. A certified absent state point means initial incarnation zero;
a missing witness is an error. This cutover requires fresh state, with no fallback
to older namespaces or proof shapes.

### The signing coordinator is trusted for liveness

DKG is abort-only; PRE and Sign rounds are driven by a coordinator. A malicious
coordinator that equivocates (hands different signers inconsistent commitment
sets, etc.) can cause a round to fail and can generate spurious fault-report
traffic, but cannot extract key material or forge a signature — FROST nonce
state is single-use and message content is bound to the caller's JWT / an
on-chain record. Equivocation attribution is deliberate future work.

### Client requests are authenticated with bearer JWTs over a trusted transport

gRPC requests carry a DID-signed JWT whose claims are bound to the specific
operation (reader key, object id, message digest, derivation). `StartPre` and
`StartSign` require a nonempty token ID (`jti`) and record accepted IDs in a
single-use cache after authorization. PRE responders and FROST nonce responders
apply the same guard to forwarded tokens. FROST signing round two reuses the
token but atomically consumes its nonce state. BLS signing responders re-check
the token and policy but do not record its `jti`. `StoreSecret` also has no
single-use guard: the bulletin deduplicates repeated document posts, although
retrying with `with_proof` may initiate another signing round.

The replay cache is in memory and local to each node. There is no audience
binding or committee-wide replay state: a captured token may still be used
before its first acceptance on a node, at a different node that has not seen it,
or after a node restart while it remains valid. At capacity, the cache can evict
an unexpired ID. Terminate client connections with TLS and keep token lifetimes
short; the node's gRPC server does not configure TLS itself and binds to loopback
by default.

### Local key material is encrypted at rest under an operator-supplied password

Ring shares and node keys are stored AES-256-GCM encrypted under a key derived
with Argon2id from an operator-supplied password. The node reads the password
from `~/.orbis_password` by default, or from a path set with
`ORBIS_PASSWORD_FILE`; it falls back to `ORBIS_PASSWORD` and then an interactive
prompt. Encrypted values authenticate their storage slot as AES-GCM associated
data, preventing substitution between slots and between databases with
different salts.

The encrypted store has no rollback counter: an earlier valid ciphertext can
replace a newer value in the same slot. Unencrypted metadata such as `RingIndex`
is not authenticated by this at-rest encryption. Protect the node's data
directory with filesystem permissions and keep trusted backups.

## Out of scope

- Compromise of a threshold (≥ t) of ring nodes.
- Compromise of the host OS / root on a node.
- Denial of service from a peer within the configured ingress rate limits.
