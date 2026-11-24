# Common crate

Shared Orbis wire types, object IDs, node message signatures, and the Vera client configuration used by **`authz`**, **`bulletin`**, **`orbis-node`** and **`cli-tool`**.

## `blockchain` module

[`src/blockchain/mod.rs`](src/blockchain/mod.rs) exposes:

| Item | Role |
|------|------|
| [`acp`](src/blockchain/acp/mod.rs) | Access-control policy types |
| [`bulletin`](src/blockchain/bulletin/mod.rs) | Bulletin message types and ids |
| [`orbis`](src/blockchain/orbis/mod.rs) | Ring, document and key-derivation types and ids |
| [`node_signing`](src/blockchain/node_signing.rs) | secp256k1 node message signatures (`sign_node_message_with_hex_key`, `verify_node_message`, `node_public_key_hex`) |
| [`vera`](src/blockchain/vera/mod.rs) (`vera` feature) | `VeraChainConfig`/`VeraConfig`, deployment-trust bootstrap and the worker-key store shared by `authz::vera` and `bulletin::vera` |

[`src/startup.rs`](src/startup.rs) (`startup` feature) holds the startup-progress types shared by the `authz` and `bulletin` factory traits.

## Features

| Feature | Purpose |
|---------|---------|
| `vera` | Vera client configuration and deployment trust |
| `startup` | Shared factory startup types |
| `test-helpers` | Test-only helpers reachable from dependent crates' tests |

## Tests

```bash
cargo test -p common --features vera
cargo test -p common --no-default-features
```
