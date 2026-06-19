# Orbis node

The **`orbis-node`** binary is the **ring node**: it exposes **gRPC** APIs for operators and clients, runs **iroh QUIC** for MPC traffic with peers, and connects to **SourceHub** for authorization and the bulletin board.

## Responsibilities

| Layer | What happens here |
|-------|-------------------|
| **gRPC (tonic)** | [`proto`](../../crates/proto) services: DKG, PRE, Sign, StoreSecret, Info — see [`src/main.rs`](src/main.rs). |
| **P2P (network)** | **`NetworkImpl`** router with ALPN **`DKG`**, **`REENCRYPT`**, **`SIGN`**; per-stream handlers in [`helpers/create_routers.rs`](src/helpers/create_routers.rs). |
| **Coordinators** | [`dkg/coordinator`](src/dkg/coordinator), [`pre/coordinator`](src/pre/coordinator), [`sign/coordinator`](src/sign/coordinator) — protocol logic on top of **`crypto`**. |
| **Shared state** | [`app_state.rs`](src/app_state.rs): **`PeerConnectionPool`**, **`SessionStateManager`**, PRE/Sign response managers, **bulletin** + **authz** + **local storage**. |
| **PSS** | [`pss/mod.rs`](src/pss/mod.rs) — background scheduler for automatic **refresh** ceremonies (when `reshare_interval_secs` is non-zero and ring bulletin metadata allows it). |

**Control plane vs data plane:** Clients talk **gRPC** to one node; nodes talk **QUIC** to each other for DKG/PRE/Sign messages. **`GenericProtocolHandler`** ([`helpers/protocol_handler.rs`](src/helpers/protocol_handler.rs)) implements the `network::ProtocolHandler` receive loop for all three MPC protocols.

Ingress limits are applied in two places:

- The gRPC server caps per-connection request concurrency and HTTP/2 streams in [`src/main.rs`](src/main.rs).
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
| `authz-sourcehub` | yes | `authz/sourcehub` |
| `bulletin-sourcehub` | yes | `bulletin/sourcehub` |
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

## In-repo docs

- [`src/dkg/PROTOCOL_FLOW.md`](src/dkg/PROTOCOL_FLOW.md) — DKG session flow (when present).
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

Use matching **`crypto`** features with the rest of the workspace when you switch curves (`--no-default-features --features decaf377,...`).

## Tests

```bash
cargo test -p orbis-node
```

Integration tests may require Docker (see **`common`** crate **`IntegrationTestNetwork`**). **`fault-injection`** tests exercise blocked peers.
