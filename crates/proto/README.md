# Proto crate

[gRPC](https://grpc.io/) API definitions for Orbis nodes, compiled to Rust with **[tonic](https://github.com/hyperium/tonic)** + **[prost](https://github.com/tokio-rs/prost)**. This crate only holds **`.proto` sources** and **`include_proto!`** modules; servers and clients live in **`bin/orbis-node`** and other workspace crates.

## Generated modules

[`build.rs`](build.rs) runs **`tonic_prost_build::compile_protos`** on each file under [`proto/`](proto/). [`src/lib.rs`](src/lib.rs) exposes one Rust module per package:

| Rust module | Proto package | Service(s) |
|-------------|---------------|------------|
| `v0::dkg` | `orbis.v0.dkg` | `DkgService` — start DKG |
| `pre_service` | `pre_service` | `PreService` — start PRE |
| `sign_service` | `sign_service` | `SignService` — start threshold signing |
| `store_secret_service` | `store_secret_service` | `StoreSecretService` — store encrypted secret + proof |
| `info_service` | `info_service` | `InfoService` — node info, ring state |

Use paths like `proto::v0::dkg::dkg_service_client::DkgServiceClient`, `proto::v0::dkg::dkg_service_server::DkgServiceServer`, and the generated request/response types. The corresponding gRPC method path is `/orbis.v0.dkg.DkgService/StartDkg`.

## RPC overview

- **`DkgService::StartDkg`** — Threshold, peer ids (iroh peer IDs), optional `pss_interval` for automatic PSS refresh cadence.
- **`PreService::StartPre`** — Reader pubkey, object/namespace, optional derivation/salt, optional validity window.
- **`SignService::StartSign`** — Message bytes, bulletin derivation (`namespace` + `derivation_id`), optional validity window.
- **`StoreSecretService::StoreSecret`** — Encrypted document + encryption‑proof fields (Schnorr PoK of the encryption randomness) + policy metadata; optional storage proof signature.
- **`InfoService::GetNodeInfo`** — Public address, peer id, `p2p_address` (`peer_id@host:port`), managed ring count.
- **`InfoService::GetRingState`** — Current public polynomial hex and last PSS timestamp for a ring.

Field-level documentation is in the **`.proto`** files.


## Build

Code generation runs in **`build.rs`** whenever you `cargo build` / `cargo test` this package. Editing a `.proto` requires a rebuild to refresh generated Rust types.

## Go Generation

The repository also uses [Buf](https://buf.build/) to generate Go stubs of the API  [`../../gen/go`](../../gen/go).

From the repository root:

```bash
go tool buf generate
```

## Dependencies

- **Runtime:** `tonic`, `tonic-prost`, `prost`
- **Build:** `tonic-build`, `tonic-prost-build`

## Versioning

Keep `.proto` changes backward compatible where possible (add fields, optional fields). Breaking changes to RPCs must be coordinated with all clients and servers in the workspace.
