# Common crate

Shared **SourceHub (Cosmos / Tendermint) blockchain** client code, configuration, and **test harnesses** that spin up Docker Compose stacks. Used by **`authz`**, **`bulletin`**, **`orbis-node`**, and integration tests.

## `blockchain` module

[`src/blockchain/mod.rs`](src/blockchain/mod.rs) re-exports:

| Item | Role |
|------|------|
| [`ChainConfig`](src/blockchain/config.rs) / [`ChainConfigBuilder`](src/blockchain/config.rs) | RPC, REST, gRPC URLs, gas, chain ID, account prefix |
| [`SourceHubClient`](src/blockchain/client.rs) | Queries + tx broadcast; optional [`TxSigner`](src/blockchain/signer.rs) for signed txs |
| [`TxSigner`](src/blockchain/signer.rs) | secp256k1 signing for Cosmos-style transactions |
| [`acp`](src/blockchain/acp.rs) | Access-control policy types and verify/query helpers (used by `authz`) |
| [`bulletin`](src/blockchain/bulletin.rs) | Bulletin-board chain messages (used by `bulletin` crate) |
| [`bank`](src/blockchain/bank.rs), [`events`](src/blockchain/events.rs) | Bank transfers and event subscriptions as needed by the client |

Typical wiring: build a **`ChainConfig`** (often via **`ChainConfigBuilder::default()`** with `.grpc_url()`, `.rpc_url()`, `.rest_url()`, `.denom()`), then **`SourceHubClient::new`** or **`SourceHubClient::with_signer`**.

## Test-only helpers (crate root)

[`src/lib.rs`](src/lib.rs) also defines:

- **`SourceHubTestContainer`** — Starts `docker/docker-compose-sourcehub-test.yml` under a unique Compose project, discovers Docker-assigned RPC/REST/gRPC host ports, waits for health, and tears down only its own project. Use `chain_config()` or the URL accessors for connections.
- **`IntegrationTestNetwork`** — Starts `docker/docker-compose-integration-test.yml` (SourceHub + three orbis nodes) under a unique Compose project and exposes the dynamically assigned SourceHub and node endpoints. **`ORBIS_INTEGRATION_CRYPTO`** remains synchronized with compile-time `bls12-381` / `decaf377` features.

Both require **Docker** and **`curl`** on the host. Independent Cargo test processes may run their Docker stacks concurrently because project names and published host ports are isolated.

## Features

| Feature | Purpose |
|---------|---------|
| `bls12-381` | Compile-time marker for crypto alignment in tests (e.g. integration test env defaults). |
| `decaf377` | Same for decaf377 builds. |

These flags do not change `blockchain` APIs by themselves; they coordinate with **`orbis-node`** / **`cli-tool`** feature sets.

## Dependencies (high level)

- **Cosmos / Tendermint:** `cosmrs`, `tendermint`, `tendermint-rpc`, `prost`, `tonic`
- **HTTP:** `reqwest`
- **Keys:** `k256`, `bip32`
- **Async:** `tokio`, `async-trait`, `backoff`, `futures`

## Tests

```bash
cargo test -p common
```

Docker-backed tests live under [`src/blockchain/tests.rs`](src/blockchain/tests.rs) and in **`authz`** / **`bulletin`** crates that depend on **`SourceHubTestContainer`**.
