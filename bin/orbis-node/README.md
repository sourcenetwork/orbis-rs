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
- The P2P router caps inbound concurrent streams per protocol and per-peer stream rate before DKG/PRE/Sign handlers run; values live in [`src/constants.rs`](src/constants.rs).

## Workspace crates

Depends on **`crypto`**, **`network`**, **`local-storage`**, **`proto`**, **`authn`**, **`authz`**, **`bulletin`**, **`common`**, and **`tonic`**.

## Cargo features

Defined in [`Cargo.toml`](Cargo.toml):

| Feature | Default | Meaning |
|---------|---------|---------|
| `bls12-381` | yes | BLS12-381 crypto + CLI alignment |
| `decaf377` | no | Decaf377 / FROST path — mutually exclusive with `bls12-381` |
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
- **`--network-max-concurrent-ingress-work`** — node-wide cap on concurrently executing inbound P2P work items shared by direct QUIC streams and Gossip frames (default `1024`). Raise on a node provisioned to take on more work; minimum `1` (a value below `1` is rejected during argument parsing).
- **`--network-max-ingress-events-per-peer-per-second`** — per-immediate-peer cap on inbound P2P work items per second, across direct streams and Gossip frames (default `512`). Raise on a node provisioned to take on more work; minimum `1` (a value below `1` is rejected during argument parsing).

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

## Chain endpoint trust (hard requirement)

The node **fully trusts** the Vera endpoints it is configured with
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

Use matching **`crypto`** features with the rest of the workspace when you switch curves (`--no-default-features --features decaf377,...`).

## Tests

```bash
cargo test -p orbis-node
```

Integration tests may require Docker (see **`common`** crate **`IntegrationTestNetwork`**). **`fault-injection`** tests exercise blocked peers.

## Native Vera service

Build with `cargo build -p orbis-node --features native`, then start with
`--vera-config /path/to/vera.json --node-controller-key <compressed-secp256k1-public-key>`.
The configuration selects native authorization and bulletin operations. Supply the
controller public key as 33 hex-encoded bytes. Existing connection and fee options
cannot be combined with `--vera-config`.

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
file holding its encryption password. Existing encrypted node keys retain their
identity; early native raw keys are normalized to the stored hex format. New keys
are generated once. Keep the encrypted database and its `native-vera/<deployment-root>`
worker journal together when backing up or restoring a node. The journal retains
uncertain submissions for recovery on the next write.

Native startup registers the node with Vera or verifies the existing controller and
peer identity. Controller-owned allow-list changes require explicit authenticated
updates. Startup does not wait for funding. `public_key.txt` and the info service's
`public_address` field contain the compressed node public key in native mode.

The focused startup fixture launches the actual Orbis binary against four local
Vera members and checks certified registration and identity/journal persistence
across restart:

```sh
HUBD_BINARY=/path/to/hubd cargo test -p orbis-node --features native \
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
BLS ring. It completes DKG through native Vera, gracefully restarts every node
with the same encrypted store and peer binding, and checks the recovered public
polynomials and identities. It then verifies a threshold signature, stores an
encrypted document, and decrypts it through PRE. Signing and decryption are denied
before their respective ACP grants and after revocation. The fixture then admits
a new participant through authenticated controller and policy updates. Scheduled
resharing replaces a member while retaining the ring public key. With only two
members online, the incoming share must participate in signing and decrypting the
document stored before the transition.
The remaining members also co-sign an offline report. A certified fault-score
query verifies its effect on the unavailable member and the absence of penalties
for healthy members.

```sh
HUBD_BINARY=/path/to/hubd cargo test -p orbis-node --features native \
  --test native_startup native_distributed_threshold_workflows -- --ignored
```

Signing and PRE apply their 10-second peer deadline to connection setup, sending
and receiving together. This keeps unresponsive peers within the background
collection window so timeout observations reach reporting.

`HubClient::read_threshold_node_demerits` returns the stored score or certified
absence with its revision and timestamp. Apply the ring's configured reset
interval with `NodeDemerits::effective_points` when displaying the current score.

This covers fresh BLS rings, graceful restart, member replacement, offline reports
and live policy checks. Crash/power-loss recovery, other fault evidence types and
other curves require their own checks.

The Defra signing scenario uses the actual Defra client against three Orbis
processes and native Vera. It checks denial before an ACP grant, signed-document
creation in Regolith after the grant, persisted signature verification after
reopening the database, and rejection of new documents after revocation. A second
store rejects a forged signature with recomputed content IDs, merges the genuine
document, and preserves its queried contents and signature after reopen. Blocks
are transferred directly to the merge handler; this does not test peer transport.
It shares the
DKG setup and stops before the PRE and resharing portions of the broader fixture.

```sh
HUBD_BINARY=/path/to/hubd cargo test -p orbis-node --features native \
  --test native_startup native_defra_signing -- --ignored
```
