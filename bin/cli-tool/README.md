# Orbis CLI Tool

A command-line tool for interacting with an **Orbis** network. Intended for **development and testing only** — not for production use.

Requires a running orbis node (gRPC, default `http://localhost:50051`) and, for chain/bulletin commands, a local chain (e.g. SourceHub) with the test account pre-funded.

## Building

From the workspace root:

```bash
cargo build -p cli-tool
```

Optional crypto backends (see `Cargo.toml`):

- `default`: BLS12-381
- `decaf377`: enable with `--features decaf377`

## Commands

### Node & key management

| Command | Description |
|--------|-------------|
| `info` | Query node info (public address, peer ID, P2P address). Default endpoint: `http://localhost:50051`. |
| `dkg` | Start a Distributed Key Generation session. Requires `--threshold`, `--peer-ids` (one or more), and optionally `--endpoint`, `--policy-id`. |
| `generate-reader-key` | Generate a reader keypair (hex). Use the output as `--reader-pk` / `--reader-sk` for PRE. |
| `get-latest-ring` | Read the latest ring from the bulletin (e.g. after DKG). Prints `RING_ID=` and `RING_PK=` for use in scripts. Optional `--namespace` (default: `orbis`). |

### Secrets: encrypt, store, re-encrypt

| Command | Description |
|--------|-------------|
| `encrypt-secret` | Encrypt a secret to a ring public key locally (no node). Outputs encrypted secret JSON. Options: `--secret`, `--ring-pk`, `--policy-id`, `--resource`, `--permission`, optional `--derivation` (hex). |
| `prepare-secret` | Encrypt a secret locally and print a **prepared secret** JSON. Use this with `store-prepared-secret` for idempotent storage (same input → same object ID on retries). Same policy/resource/permission/derivation options as above. |
| `store-prepared-secret` | Send a prepared secret (from `prepare-secret`) to the node. Options: `--endpoint`, `--prepared-json`, `--ring-id`, `--namespace`, `--policy-id`, `--resource`, `--permission`, optional `--reader-did-pk`, `--effective-pk` (must match any derivation used at prepare time), `--with-proof`. |
| `store-secret` | One-shot: encrypt locally and store on the node. Same args as above plus `--secret`, `--ring-pk-hex`; optional `--derivation`, `--reader-did-pk`, `--with-proof`. |
| `pre` | Run Proxy Re-Encryption: re-encrypt a stored secret for a reader and decrypt with reader keys. Options: `--endpoint`, `--ring-pk`, `--reader-pk`, `--reader-sk`, `--object-id`, `--namespace`, optional `--reader-did-pk`, `--derivation`. |

### Chain (policy, objects, relationships)

These use the **local** chain config and a built-in test account; for dev/test only.

| Command | Description |
|--------|-------------|
| `add-policy-to-chain` | Create the default test policy on chain. Returns the new policy ID (from listing). |
| `register-object-to-chain` | Register an object under a policy. Options: `--policy-id`, `--object-id`, `--resource`. |
| `set-relationship-on-chain` | Set a relationship on an object (e.g. reader). Options: `--policy-id`, `--object-id`, `--resource`, `--relation`, optional `--reader-did-pk`. |

### Bulletin

Bulletin commands also target the local chain and test account.

| Command | Description |
|--------|-------------|
| `register-bulletin-namespace` | Register a bulletin namespace. Option: `--namespace`. |
| `add-bulletin-collaborator` | Add a collaborator to a namespace. Options: `--namespace`, `--collaborator`. |
| `create-bulletin-post` | Create a post. Options: `--namespace`, `--payload` (hex), `--proof` (hex). |
| `read-bulletin-post` | Read a post by namespace and ID. Options: `--namespace`, `--id`. |
| `list-bulletin-post` | List posts in a namespace. Option: `--namespace`. |

### Dev / testing

| Command | Description |
|--------|-------------|
| `fund` | Fund an address from the pre-funded test account on the local chain. Option: `--address`. |

## Examples

```bash
# Node info
cargo run -p cli-tool -- info
cargo run -p cli-tool -- info --endpoint http://localhost:50051

# DKG (e.g. 2-of-2 with one peer)
cargo run -p cli-tool -- dkg --threshold 2 --peer-ids <PEER_ID>
cargo run -p cli-tool -- dkg --threshold 2 --peer-ids <PEER_ID> --policy-id <POLICY_ID>

# Reader keypair for PRE
cargo run -p cli-tool -- generate-reader-key

# Encrypt secret locally (no node)
cargo run -p cli-tool -- encrypt-secret --secret "my secret" --ring-pk <HEX> --policy-id <ID> --resource document --permission read

# Prepare then store (idempotent)
cargo run -p cli-tool -- prepare-secret --secret "data" --ring-pk-hex <HEX> --policy-id <ID> --resource document --permission read
cargo run -p cli-tool -- store-prepared-secret --endpoint http://localhost:50051 --prepared-json '<JSON>' --ring-id <ID> --namespace <NS> --policy-id <ID> --resource document --permission read

# One-shot store
cargo run -p cli-tool -- store-secret --endpoint http://localhost:50051 --secret "data" --ring-pk-hex <HEX> --ring-id <ID> --namespace <NS> --policy-id <ID> --resource document --permission read

# PRE (after storing a secret and setting relationship)
cargo run -p cli-tool -- pre --endpoint http://localhost:50051 --ring-pk <HEX> --reader-pk <HEX> --reader-sk <HEX> --object-id <ID> --namespace <NS>

# Local chain / bulletin
cargo run -p cli-tool -- fund --address <ADDRESS>
cargo run -p cli-tool -- add-policy-to-chain
cargo run -p cli-tool -- register-bulletin-namespace --namespace my-ns
```

## Scripts

A full walkthrough is available as shell scripts in `scripts/`. From the workspace root:

- **Docker integration (3 nodes, threshold 2)** — matches `test_cli_calls_dkg_and_pre_endpoint` and uses `docker/docker-compose-integration-test.yml`:
  ```bash
  docker compose -f docker/docker-compose-integration-test.yml up -d --build
  ./bin/cli-tool/scripts/run_integration.sh
  ```

See [scripts/README.md](scripts/README.md) for step-by-step usage and variables.

## Integration tests

The command implementations live in `src/commands.rs` and are re-exported from `src/lib.rs` so they can be called from integration tests without invoking the CLI binary.
