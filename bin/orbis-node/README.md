# Orbis node

The **`orbis-node`** binary is the **ring node**: it exposes **gRPC** APIs for operators and clients, runs **iroh QUIC** for MPC traffic with peers, and connects to **Vera** for authorization and the bulletin board.

## Responsibilities

| Layer | What happens here |
|-------|-------------------|
| **gRPC (tonic)** | [`proto`](../../crates/proto) services: DKG, PRE, Sign, StoreSecret, Info — see [`src/runtime.rs`](src/runtime.rs). |
| **P2P (network)** | **`NetworkImpl`** router with ALPN **`DKG`**, **`REENCRYPT`**, **`SIGN`**; per-stream handlers in [`helpers/create_routers.rs`](src/helpers/create_routers.rs). |
| **Coordinators** | [`dkg/v0/coordinator`](src/dkg/v0/coordinator), [`pre/v0/coordinator`](src/pre/v0/coordinator), [`sign/v0/coordinator`](src/sign/v0/coordinator) — protocol logic on top of **`crypto`**. |
| **Shared state** | [`app_state.rs`](src/app_state.rs): **`PeerConnectionPool`**, **`SessionStateManager`**, PRE/Sign response managers, **bulletin** + **authz** + **local storage**. |
| **PSS** | [`pss/mod.rs`](src/pss/mod.rs) — background scheduler for automatic **refresh** ceremonies (when `reshare_interval_secs` is non-zero and ring bulletin metadata allows it). |

**Control plane vs data plane:** Clients talk **gRPC** to one node; nodes talk **QUIC** to each other for DKG/PRE/Sign messages. **`GenericProtocolHandler`** ([`helpers/protocol_handler.rs`](src/helpers/protocol_handler.rs)) implements the `network::ProtocolHandler` receive loop for all three MPC protocols.

Ingress limits are applied in two places:

- The gRPC server caps per-connection request concurrency and HTTP/2 streams in [`src/runtime.rs`](src/runtime.rs).
- The P2P router applies connection-, stream-, frame-, byte-, and work-level admission before DKG/PRE/Sign handlers run; defaults live in [`src/constants.rs`](src/constants.rs) and most are overridable via `--network-*` flags / `ORBIS_NETWORK_*` env vars (see CLI reference).

## Workspace crates

Depends on **`crypto`**, **`network`**, **`local-storage`**, **`proto`**, **`authn`**, **`authz`**, **`bulletin`**, **`common`**, and **`tonic`**.

## Cargo features

Defined in [`Cargo.toml`](Cargo.toml):

| Feature | Default | Meaning |
|---------|---------|---------|
| `bls12-381` | yes | BLS12-381 crypto + CLI alignment |
| `jubjub` | no | Jubjub / FROST path — mutually exclusive with `bls12-381` |
| `redb` | yes | Persistent local storage (`local-storage/redb`) |
| `memory` | no | In-memory local storage (`local-storage/memory`) |
| `authz-vera` | yes | `authz/vera` |
| `bulletin-vera` | yes | `bulletin/vera` |
| `iroh` | yes | `network/iroh` |
| `integration-test` | no | `cli-tool` + test-only chain funding |
| `fault-injection` | no | `network/fault-injection` for partition tests |

## CLI (quick reference)

From [`helpers/launch.rs`](src/helpers/launch.rs) (`clap` **`Args`**):

- **`--addr`** — gRPC bind (default `[::1]:50051`).
- **`--authz-grpc`**, **`--bulletin-grpc`**, **`--chain-rpc`**, **`--chain-rest`**, **`--denom`** — chain endpoints for authz and bulletin.
- **`--metrics-addr`** — optional Prometheus scrape HTTP server.
- **`--loki-url`** — optional Loki log shipping.
- **`--runtime-base-path`** — base directory for runtime files. The database is stored as `<PATH>/dbs/orbis.<backend>` (`orbis.redb` with the default backend), and the node public key is written to `<PATH>/public_key.txt`.
- **`--reshare-interval-secs`** — how often the PSS scheduler wakes to check rings (`0` disables scheduler ticks; ring-level `pss_interval` still comes from bulletin).
- **P2P ingress limits** — every flag below has a matching `ORBIS_<UPPER_SNAKE>` environment variable (CLI arg wins, then env, then the [`src/constants.rs`](src/constants.rs) default). Each `usize` limit rejects `0` during argument parsing. The `authorized_reserve_percent` Sybil-defense ratio is deliberately *not* exposed — it is a protocol-wide security parameter, not a per-machine capacity choice.
  - **`--network-max-concurrent-ingress-work`** — node-wide cap on concurrently executing inbound *request* P2P work items shared by direct QUIC streams and Gossip frames (default `1024`).
  - **`--network-max-concurrent-reply-ingress-work`** — separate node-wide cap for *reply* work items read on client-opened streams (default `1024`), so a request handler awaiting replies can never starve them.
  - **`--network-max-ingress-events-per-peer-per-second`** — per-immediate-peer cap on inbound P2P frames per second, across direct streams and Gossip frames (default `512`).
  - **`--network-max-concurrent-connections`** / **`--network-max-connections-per-peer`** — node-wide and per-endpoint-key caps on accepted-but-open inbound QUIC connections (defaults `2048` / `32`).
  - **`--network-max-concurrent-streams`** / **`--network-max-streams-per-peer`** — node-wide and per-endpoint-key caps on accepted-but-open inbound direct streams (defaults `4096` / `32`).
  - **`--network-max-inbound-request-body-bytes`** / **`--network-max-inbound-reply-body-bytes`** — node-wide receive-byte budgets for request and reply frame bodies, separate pools (defaults `192 MiB` / `64 MiB`). Each must be at least the largest route `max_message_size`, checked at startup.
  - **`--network-stream-read-timeout-ms`** — per-read deadline for one length-prefixed frame (default `30000`). Rejected below `MIN_NETWORK_STREAM_READ_TIMEOUT_MS` (`2 x PEER_RESPONSE_TIMEOUT`) so it can only ever fire on a genuinely stalled stream.

  Raise the node-wide caps on a node provisioned to take on more work; the per-peer caps bound a single endpoint identity's share and should be raised only with reason.

Password and node identity: see **`constants`**, **`get_password`**, **`get_network_key_secret`**, **`derive_secret_key_bytes`** in the same module.

## Secure secret provisioning

`orbis-node` needs two local secret classes: the password used to encrypt local
storage and the node network identity key. Treat both as production secrets.

- Prefer a secrets manager or a read-only mounted file for the storage password.
  The file path checked by default is `~/.orbis_password`; set owner-only
  permissions (`chmod 600 ~/.orbis_password`) and keep it out of backups that are
  not also encrypted.
- Use `ORBIS_PASSWORD` only for local development, CI, or short-lived test
  containers. Environment variables are commonly visible through process,
  container, crash-report, and orchestration inspection paths.
- Let the node generate and persist its network identity on first start, or
  restore a previously encrypted local store. Avoid raw `ORBIS_SECRET_KEY` in
  production unless a secret manager injects it directly at process launch and
  your runtime prevents environment inspection.
- The checked-in Docker compose files contain fixed `ORBIS_PASSWORD` and
  `ORBIS_SECRET_KEY` values for deterministic local tests only. Do not reuse
  them for any shared, staging, or production network.
- Back up encrypted local storage and the password together under an operational
  key-management policy. Losing either the encrypted share store or its password
  can permanently strand a node's DKG/PSS shares.
- Rotate node identity and storage passwords through a maintenance window. A
  node identity change must be reflected in bulletin committee metadata before
  peers will treat it as the same operational participant.

## Cosmos endpoint trust

In Cosmos mode, the node **fully trusts** the Vera endpoints it is configured with
(`--chain-rpc`, `--chain-rest`, `--bulletin-grpc`, `--authz-grpc`). Bulletin
reads are plain RPC responses — there is **no light-client or Merkle-proof
verification**. Everything security-critical flows from those reads: ring
payloads and committee membership, peer routing (`NodeInfo`), reporting
config, protocol-version upgrades, and ACP authorization decisions. An
attacker who controls the RPC endpoint can present a forged ring state to
this node.

Operational rules:

- **Run your own Vera full node** and point every chain endpoint flag at
  it — colocated on the same host or on an operator-controlled network path.
  Never use a third-party or public RPC endpoint for a production ring node.
- If the chain node is not on localhost, protect the path to it (TLS and/or a
  private network); the RPC connection is the root of trust for this node.
  This is **enforced**: `--chain-rpc` / `--chain-rest` are rejected at startup
  if they are plaintext `http://` to a host that is not loopback, RFC-1918 /
  unique-local / link-local / CGNAT, a single-label container/service name, or
  a `*.internal` / `*.local` / `*.lan` / `*.home.arpa` name. Use `https://`, a
  local/private endpoint, or — only if the endpoint is reached over a private
  network you control — `--allow-insecure-rpc` (env `ORBIS_ALLOW_INSECURE_RPC`).
- The `ring_state_sha256` bound into signed reporting statements limits
  *silent* divergence between honest nodes (statements built from different
  ring states will not co-sign), but it does not protect a node whose own RPC
  view is forged. Detection is not prevention — the trusted-endpoint
  requirement above is the actual control.

## Trusted authentication relays

Direct client JWTs continue to use their issuer DID as the actor. A ring may
list trusted Ed25519 `did:key` issuers in `trusted_auth_relay_dids`; those relays
may sign a JWT with the user DID as `sub`. Every committee node reads the same
list from Vera before accepting delegation.

A trusted relay can assert any actor DID, so its signing key is a privileged
credential. Declare relays when creating the ring and revoke compromised or
retired relays through the ring's ACP-governed removal transaction. `StoreSecret`
rejects delegated JWTs because its
Vera transaction is signed by the Orbis node; delegated callers must store
the document through a Vera signer that preserves their actor identity.

## In-repo docs

- [`src/dkg/README.md`](src/dkg/README.md) — implemented DKG, refresh, and reshare flow.
- **[`src/constants.rs`](src/constants.rs)** — JWT limits, session TTL, network ingress limits, timeouts, limits.

## Running

```bash
cargo run -p orbis-node --release
```

To explicitly choose where runtime files are stored:

```bash
cargo run -p orbis-node --release -- --runtime-base-path /var/lib/orbis
```

When the option is omitted, the node keeps the existing fallback order: Cargo project root, `/data` when available, then the current directory.

### Browser CORS

Cross-origin browser access to the gRPC-Web endpoint is disabled by default.
Native gRPC clients are not affected. Allow each trusted web application by
passing its exact origin (scheme, host, and optional port) every time the node
starts:

```bash
cargo run -p orbis-node --release -- \
  --cors-allow-origin https://app.example.com \
  --cors-allow-origin http://localhost:5173
```

Origin values cannot contain paths, queries, fragments, credentials, wildcards,
or comma-separated lists. Repeat the flag for multiple origins. To explicitly
restore the historical policy that allows every browser origin, method, and
header:

```bash
cargo run -p orbis-node --release -- --cors-permissive
```

These options are local, per-node launch settings. They are not persisted or
recorded in Vera, so every committee operator chooses and supplies their
own policy on each launch. CORS is enforced by browsers only; it is not
authentication and does not prevent native clients from calling the node's
network-accessible RPCs. Keep endpoint authentication and network controls in
place even when using a restrictive origin allowlist.

Use matching **`crypto`** features with the rest of the workspace when you switch curves (`--no-default-features --features jubjub,...`).

## Tests

```bash
cargo test -p orbis-node
```

Integration tests may require Docker (see **`common`** crate **`IntegrationTestNetwork`**). **`fault-injection`** tests exercise blocked peers.

## Native Vera service

The native integration is under qualification. Vera verifies the selected BLS or
Jubjub signature scheme; Defra uses Orbis's augmented BLS suite. Legacy basic-BLS
signature types and verification paths are removed. Local process fixtures cover Defra
signing and replication, permission revocation, PRE, graceful restart, and
committee replacement. Deployment qualification still requires sustained load,
multi-host networks, crash/power-loss recovery, and operational security review.

Native ACP uses `relationship/v5/` keys with `v3` incarnation-qualified suffixes.
Deploy the matching Vera validator and proof consumers together. Policy catalogs,
relation identities and target-object incarnations are authenticated at the same
revision. Archiving retires existing non-owner grants; unarchiving does not revive
them. Owners retain incarnation zero. Specialized relationship proofs require
same-root object-state witnesses for non-owner rows: certified absence means
initial incarnation zero, while missing evidence is an error. This is a fresh-state
cutover without older namespace or proof-shape fallback. See
[security assumptions](../../SECURITY.md) for native proof freshness and
consensus-key provisioning.

Build a native-only node with:

```sh
cargo build --locked -p orbis-node --no-default-features --features native,bls12-381,iroh --bin orbis-node
```

The native backend supports signing, ordinary PRE and PET-backed PRE on BLS12-381
and Jubjub rings. PET rings preserve their main/PET key pair and document tag/proof
attachments through native Vera. `requires_pet` is mandatory and immutable. Deploy
the pinned Vera validator, SDK consumers and PET v2 participants together on fresh
state with a new deployment root; old ring state, pending worker journals and
signed requests cannot be reused. Encrypting clients and node verifiers must use
matching ciphertext-context encoding.

Select `jubjub` instead of `bls12-381` for the Jubjub crypto implementation. Start with
`--vera-config /path/to/vera.json --node-controller-key <compressed-secp256k1-public-key>`.
The configuration selects native authorization and bulletin operations through the
existing `Authz` and `Bulletin` traits. Both backends use the same bootstrap
handoff, node initialization, request handlers and shutdown path. Backend setup
provides the identity and service adapters. This build excludes the Cosmos SDK and
CometBFT transport dependencies. Default builds retain the existing backend; adding
`--features native` to a default build includes both. Native-only startup requires
`--vera-config` and reports a missing configuration before opening node state.
The separate `harness` and `integration-test` features retain the dependencies used
by their existing test identities and fixtures.

Supply the controller public key as 33 hex-encoded bytes. Existing connection and
fee options cannot be combined with `--vera-config`.

```json
{
  "endpoint": "http://127.0.0.1:8545",
  "deployment_id": 9001,
  "deployment_root": "<32-byte genesis digest, hex without prefix>",
  "consensus_key": "<Commonware-encoded consensus public key, hex without prefix>",
  "max_evidence_age_secs": 30,
  "request_timeout_secs": 30
}
```

Provision the deployment ID, genesis digest and consensus key through the operator's
trusted deployment configuration. The consensus key is separate from Orbis's node
and threshold service keys. Startup verifies the first certified revision against
the configured genesis digest before opening the submission journal. Current reads
reject stale evidence; the two time bounds default to 30 seconds. Configurations
reject unknown and duplicate fields and are limited to 16 KiB.

Use `--runtime-base-path` for persistent node state and `ORBIS_PASSWORD_FILE` for the
file holding its encryption password. Node signing keys use 64 hex characters in
the encrypted key slot. Startup preserves existing keys and rejects raw, prefixed
or invalid key bytes without replacing them. New keys are generated once. Keep the encrypted database and its `native-vera/<deployment-root>`
worker journal together when backing up or restoring a node. Native worker keys use
their own storage slots; ring history and pending reshare records retain their existing
slots. The journal retains
uncertain submissions for recovery on the next write.

Native startup registers the node with Vera or verifies the existing controller and
peer identity. Controller-owned allow-list changes require explicit authenticated
updates. Startup does not wait for funding. `public_key.txt` and the info service's
`public_address` field contain the compressed node public key in native mode.

The focused startup fixture launches the actual Orbis binary against four local
Vera members and checks certified registration and identity/journal persistence
across restart. Set `ORBIS_NODE_BINARY` to an independently built node executable
when validating the native-only package; otherwise the fixture uses Cargo's test
binary:

```sh
VERAD_BINARY=/path/to/verad cargo test -p orbis-node --features native \
  --test native_startup native_startup_registers_and_preserves_identity_on_restart -- --ignored
```

This fixture does not qualify distributed DKG, signing, or decryption. Migration of
existing ring and encrypted-record identifiers requires a separate migration plan.

For a group using direct peer routes, bind each node to a reachable local IPv4
interface with `--network-bind-addr <ip:port>`. Local development can use
`--network-bind-addr 127.0.0.1:0`. The info service includes a bound socket in
`p2p_address` only when its IP is concrete; a wildcard bind returns the peer
identity alone. An operator must publish the reachable route through the node's
authenticated controller update. Binding an interface does not configure NAT
forwarding or make a private address reachable from other networks.

The distributed threshold fixture uses three separate Orbis processes and a 2-of-3
BLS or Jubjub ring. It completes DKG through native Vera, abruptly restarts every node
with the same encrypted store and peer binding, and checks the recovered public
polynomials and identities. It then verifies a threshold signature, stores an
encrypted document, and decrypts it through PRE. Signing and decryption are denied
before their respective ACP grants and after revocation. Removing and recreating
the signer or reader relation must keep access denied until a fresh grant. The
signing path also restarts an Orbis process between policy edits and checks that
Defra cannot create a new signed document while authorization is revoked. Verified
relationship enumeration follows every continuation, including an empty page
while retired records await cleanup. The fixture then admits
a new participant through authenticated controller and policy updates. Scheduled
resharing replaces a member while retaining the ring public key. With only two
members online, the incoming share must participate in signing and decrypting the
document stored before the transition.
The remaining members also co-sign an offline report. A certified fault-score
query verifies its effect on the unavailable member and the absence of penalties
for healthy members.

```sh
VERAD_BINARY=/path/to/verad cargo test -p orbis-node --features native \
  --test native_startup native_distributed_threshold_workflows -- --ignored
```

The ignored `native_pet_scheduled_refresh_after_restart` scenario uses normal
native binaries and the ring's unchanged 86,400-second refresh interval. With all
three nodes stopped, it backdates only the persisted PET completion timestamp,
then restarts the same identities and lets their background schedulers rotate the
PET shares. It checks the persisted ring index, main bundles, certified key pair,
and document tags remain unchanged, and both stored and inline PRE still return
the exact plaintext. The fixture polls every second; this is synthetic overdue
state coverage, not a 24-hour soak or the production one-hour polling cadence.

```sh
VERAD_BINARY=/path/to/verad ORBIS_NODE_BINARY=/path/to/orbis-node \
  cargo test -p orbis-node --no-default-features \
  --features native,redb,iroh,bls12-381 --test native_startup \
  native_pet_scheduled_refresh_after_restart -- --ignored --exact
```

The ignored `native_pet_member_replacement` scenario admits a fresh fourth node,
then replaces one member of a 2-of-3 PET ring without changing either certified
public key. It requires both new polynomials to converge, keeps the departed node
running until its scheduler removes the paired material, and checks its stopped
store has no main/PET secret, pending reshare record or ring-index entry. With
another current member stopped, the incoming member must participate in stored
and inline PRE before and after abrupt restart. Reopened current shares must match
the new committee indices and polynomials. Cleanup means logical record absence;
it does not erase copied secrets or revoke a previously recovered threshold
secret. Public RPC coordination is allowed for nonmembers, so this fixture does
not assert blanket RPC rejection. Use the scheduled-refresh command above with
`native_pet_member_replacement` as the exact selector.

The ignored `native_pet_fault_reports` scenario uses a separate diagnostic binary
built with `native,redb,iroh,unsafe-testing` and either `bls12-381` or `jubjub`.
It enables the existing testing service only on that scenario's child processes,
injects one ring-scoped signed PET decrypt-proof fault, and requires successful
PRE plus certified report retention and exactly one accused-member demerit.
The retained signed transaction and verified receipt must bind that report ID to
v2 PET decrypt evidence. Encrypted main/PET bundles must remain unchanged. This feature-enabled scenario
is separate from normal-release qualification; it does not run reshare phases.

```sh
VERAD_BINARY=/path/to/verad ORBIS_NODE_BINARY=/path/to/diagnostic-orbis-node \
  cargo test -p orbis-node --no-default-features \
  --features native,redb,iroh,bls12-381,unsafe-testing \
  --test native_startup native_pet_fault_reports -- --ignored --exact
```

Signing and PRE apply their 10-second peer deadline to connection setup, sending
and receiving together. This keeps unresponsive peers within the background
collection window so timeout observations reach reporting.

`HubClient::read_threshold_node_demerits` returns the stored score or certified
absence with its revision and timestamp. Apply the ring's configured reset
interval with `NodeDemerits::effective_points` when displaying the current score.

Both curve variants cover fresh ordinary rings, abrupt restart, member replacement,
offline reports and live policy checks. Power-loss recovery and other fault
evidence types require their own checks.

The **Native lifecycle** CI workflow runs `native_pet_threshold_workflows`,
`native_distributed_threshold_workflows` and `native_pet_member_replacement` once per curve. BLS includes the Defra
checks below. The driver builds the Vera revision declared by all native SDK
pins and stages normal release Vera/Orbis executables before compiling the test
harness. It rejects Cosmos dependencies in the normal native node and uses
production Argon2 defaults without deadline overrides. Each run has a fresh build
target; only dependency downloads are cached.

```sh
python3 scripts/test-native-lifecycle-unit.py
python3 scripts/test-native-lifecycle.py --curve bls12-381
python3 scripts/test-native-lifecycle.py --curve jubjub
```

The live commands require Rust 1.98.0 and the native build dependencies. Reserve
one local compiler/cluster slot and run them sequentially. Command logs, source
and binary hashes, and retained Vera/Orbis state stay under a unique private
`RUNNER_TEMP` directory (the system temporary directory locally). CI prints fixed
phase names, exit codes and timings; it does not upload runtime evidence.
Failures also emit an allowlisted summary: curve/stage/scenario, test counts (or
`null` without a unique libtest footer), PET phase bits, compiler error/warning
counts and `E####` codes, and panic/assertion/`Elapsed(())` marker counts. Known
fixture locations use fixed file IDs with numeric line/column values. Raw
messages, source snippets, filesystem paths and environment values stay private.
Marker counts are observations, not a root-cause diagnosis. PET phase bits 0–3
mean paired DKG, permissions/revoke/regrant, reshare and restart respectively.

The PET scenario checks paired DKG, stored and inline PRE, document/audit denial
and revoke/regrant, committee shrink with both share polynomials rotated, and
recovery after abrupt restart. These bounded local-process scenarios do not cover
the 24-hour scheduled refresh, native PET fault-report/demerit lifecycle,
production capacity or power-loss recovery.

The Defra signing scenario uses the actual Defra client against three Orbis
processes and native Vera. It checks denial before an ACP grant, signed-document
creation in Regolith after the grant, persisted signature verification after
reopening the database, and rejection of new documents after revocation. A second
store rejects a forged signature with recomputed content IDs, merges the genuine
document, and preserves its queried contents and signature after reopen. Blocks
are transferred directly to the merge handler for the forgery check. Two embedded
Defra nodes also replicate an Orbis-signed GraphQL mutation over loopback Iroh/QUIC,
verify the received history signatures, and reject a new mutation after revocation.
Relay and discovery are disabled for this local transport scenario.
It shares the
DKG setup and stops before the PRE and resharing portions of the broader fixture.

```sh
VERAD_BINARY=/path/to/verad cargo test -p orbis-node --features native \
  --test native_startup native_defra_signing -- --ignored
```
