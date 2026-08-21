# Orbis CLI Tool

A command-line tool for interacting with an **Orbis** network. Intended primarily for **development and testing**, but can be pointed at any SourceHub chain and orbis node via the network flags below.

## Building

From the workspace root:

```bash
cargo build -p cli-tool
```

Optional crypto backends (see `Cargo.toml`):

- `default`: BLS12-381
- `decaf377`: enable with `--features decaf377`

## Network & signing configuration

Every subcommand shares one set of global flags (env var equivalents in parentheses; flag > env var > default):

| Flag | Env var | Default | Used by |
|------|---------|---------|---------|
| `-e, --endpoint <URL>` | `ORBIS_ENDPOINT` | `http://localhost:50051` | orbis node gRPC service |
| `--chain-id <ID>` | `ORBIS_CHAIN_ID` | `sourcehub-localnet` | SourceHub chain ID |
| `--rpc-url <URL>` | `ORBIS_RPC_URL` | `http://localhost:26657` | Tendermint RPC |
| `--rest-url <URL>` | `ORBIS_REST_URL` | `http://localhost:1317` | Cosmos REST API |
| `--chain-grpc-url <URL>` | `ORBIS_CHAIN_GRPC_URL` | `http://localhost:9090` | SourceHub gRPC (distinct from `--endpoint`) |
| `--account-prefix <PREFIX>` | `ORBIS_ACCOUNT_PREFIX` | `source` | Bech32 address prefix |
| `--signing-key <HEX>` | `ORBIS_SIGNING_KEY` | *(none)* | Signs any chain-writing command |

`--signing-key`/`ORBIS_SIGNING_KEY` has **no default** and is required by any command that writes to chain (policy/object/relationship, bulletin namespace/collaborator, ring lifecycle commands, `fund`, `post-key-derivation`). Commands that only talk to the orbis node over gRPC, or that are purely local, don't need it.

**Pointing at a real testnet:**

```bash
cargo run -p cli-tool -- \
  --chain-id sourcehub-testnet-1 \
  --rpc-url https://rpc.testnet.example \
  --rest-url https://rest.testnet.example \
  --chain-grpc-url https://grpc.testnet.example \
  --signing-key $MY_PRIVATE_KEY_HEX \
  add-policy-to-chain
```

**Zero-config local devnet** (all defaults point at `localhost`, matching the Docker Compose setup):

```bash
ORBIS_SIGNING_KEY=c4a48e2fce1481cd3294b4490f6678090ea98d3d0e5cd984558ab0968741b104 \
  cargo run -p cli-tool -- add-policy-to-chain
```

That hex value is the well-known SourceHub localnet devnet key (mnemonic `abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about`), pre-funded only in local Docker Compose setups. It is public and deterministic — **never fund it, or use it, on a real network.**

## Secret input

Passing secrets as plain CLI arguments leaves them visible in shell history and to other processes on the same machine (e.g. via `ps`). To avoid that:

- `--secret` (on `encrypt-secret`, `prepare-secret`, `store-secret`) is optional. If omitted, you're prompted for it interactively with hidden input. Keep passing `--secret` directly for scripted/CI use.
- `--reader-sk` (on `pre`) falls back to `ORBIS_READER_SK` if the flag isn't given.
- `--reader-did-pk` (on `pre`, `set-relationship-on-chain`, `store-prepared-secret`, `store-secret`, `sign`) falls back to `ORBIS_READER_DID_PK` — the same env var across all of them, so you can `export` it once per session instead of repeating the flag.

## Commands

### Node & key management

| Command | Description |
|---------|-------------|
| `info` | Query node info (public address, peer ID, P2P address, status). |
| `create-ring` | Create a blank ring on-chain, to be targeted by a subsequent `dkg` session. Requires `--signing-key`/`ORBIS_SIGNING_KEY`. Options: `--peer-node-keys` (comma-separated), `--threshold`, `--policy-id`, optional `--pss-interval` (default `86400`, the chain-enforced minimum), `--nonce`, `--current-version` (default `0`), `--trusted-auth-relay-dids` (comma-separated). Prints `RING_ID=`. |
| `dkg` | Start a Distributed Key Generation session. Requires `--ring-id` for a pre-created blank ring entry (create one with `create-ring`). |
| `ring-state` | Query the local ring state (public polynomial + last PSS refresh timestamp). Requires `--ring-pk-hex`. |
| `generate-reader-key` | Generate a reader keypair (hex). Use the output as `--reader-pk` / `--reader-sk` for PRE. |
| `get-latest-ring` | Fetch a ring from the orbis module by `--ring-id`. Prints `RING_ID=` and `RING_PK=`. |

### Secrets: encrypt, store, re-encrypt

| Command | Description |
|---------|-------------|
| `encrypt-secret` | Encrypt a secret to a ring public key locally (no node). Options: `--secret` (omit to be prompted), `--ring-pk`, `--policy-id`, `--resource`, `--permission`, optional `--derivation` (hex), `--tier`, `--timestamp`, `--salt`. |
| `prepare-secret` | Encrypt a secret locally and print a **prepared secret** JSON. Use with `store-prepared-secret` for idempotent storage (same input → same object ID on retries). Same options as `encrypt-secret` plus `--ring-pk-hex`. |
| `store-prepared-secret` | Send a prepared secret (from `prepare-secret`) to the node. Options: `--prepared-json`, `--ring-id`, `--policy-id`, `--resource`, `--permission`, optional `--reader-did-pk` (or `ORBIS_READER_DID_PK`), `--with-proof`, `--tier`, `--timestamp`. |
| `store-secret` | One-shot: encrypt locally and store on the node. Options: `--secret` (omit to be prompted), `--ring-pk-hex`, `--ring-id`, `--policy-id`, `--resource`, `--permission`, optional `--reader-did-pk` (or `ORBIS_READER_DID_PK`), `--derivation`, `--with-proof`, `--tier`, `--timestamp`, `--salt`. |
| `pre` | Run Proxy Re-Encryption: re-encrypt a stored secret for a reader and decrypt with reader keys. Options: `--ring-pk`, `--reader-pk`, `--object-id`, `--reader-sk` (or `ORBIS_READER_SK`; required unless `--xnc-only`), optional `--reader-did-pk` (or `ORBIS_READER_DID_PK`), `--derivation`, `--salt`, `--valid-window-start`/`--valid-window-end` (must be given together), `--xnc-only`. |

### Signing (derivation + threshold sign)

| Command | Description |
|---------|-------------|
| `post-key-derivation` | Post a `KeyDerivation` to the bulletin, registering a sign key derivation config. Options: `--ring-id`, `--derivation`, `--policy-id`, `--resource`, `--permission`. Prints `DERIVATION_ID=` and `DERIVED_PK=`. |
| `sign` | Start a threshold Sign session. Options: `--message` (hex), `--derivation-id` (from `post-key-derivation`), optional `--reader-did-pk` (or `ORBIS_READER_DID_PK`), `--valid-window-start`/`--valid-window-end` (must be given together). |

### Chain (policy, objects, relationships)

Requires `--signing-key`/`ORBIS_SIGNING_KEY`.

| Command | Description |
|---------|-------------|
| `add-policy-to-chain` | Create the default test policy on chain. Prints the new `POLICY_ID`. |
| `register-object-to-chain` | Register an object under a policy. Options: `--policy-id`, `--object-id`, `--resource`. |
| `set-relationship-on-chain` | Set a relationship on an object (e.g. reader). Options: `--policy-id`, `--object-id`, `--resource`, `--relation`, optional `--reader-did-pk` (or `ORBIS_READER_DID_PK`). |

### Bulletin

Requires `--signing-key`/`ORBIS_SIGNING_KEY`, except `read-bulletin-post` and `list-bulletin-post` which are read-only.

| Command | Description |
|---------|-------------|
| `register-bulletin-namespace` | Register a bulletin namespace. Option: `--namespace`. |
| `add-bulletin-collaborator` | Add a collaborator to a namespace. Options: `--namespace`, `--collaborator`. |
| `read-bulletin-post` | Read a post by ID. Option: `--id`. |
| `list-bulletin-post` | List posts in a namespace. Option: `--namespace`. |

### Ring lifecycle (ACP-authorized)

Requires `--signing-key`/`ORBIS_SIGNING_KEY`, and requires the caller to be authorized by the ring's/node's ACP policy.

| Command | Description |
|---------|-------------|
| `start-ring-reshare` | Initiate a committee/threshold reshare. Options: `--ring-id`, `--new-peer-node-keys` (comma-separated), optional `--new-threshold`. |
| `set-ring-pss-interval` | Set the PSS refresh interval. Options: `--ring-id`, `--pss-interval` (seconds). |
| `schedule-ring-upgrade` | Schedule a protocol version upgrade. Options: `--ring-id`, `--next-version`, `--activation-time` (Unix timestamp, must be at least 10 minutes in the future). |
| `cancel-ring-upgrade` | Cancel a pending protocol version upgrade. Option: `--ring-id`. |
| `update-node-peer-id` | Update the peer ID of a registered node. Options: `--node-key`, `--peer-id`. |
| `transfer-node-controller` | Transfer a registered node's controller key. Options: `--node-key`, `--controller-key`. |
| `add-node-to-whitelist` | Add a policy or ring to a node's whitelist. Options: `--node-key`, and exactly one of `--policy-id` / `--ring-id`. |
| `remove-node-from-whitelist` | Remove a policy or ring from a node's whitelist. Same options as above. |

### Dev / testing

| Command | Description |
|---------|-------------|
| `fund` | Fund an address from the account behind `--signing-key`. Only useful when that account has funds (e.g. the local devnet test key on a Docker Compose chain). Option: `--address`. |

## Examples

```bash
# Node info
cargo run -p cli-tool -- info
cargo run -p cli-tool -- --endpoint http://localhost:50051 info

# Create a blank ring, then run DKG against it
cargo run -p cli-tool -- --signing-key $KEY create-ring --peer-node-keys <NODE_KEY_1>,<NODE_KEY_2> --threshold 2 --policy-id <POLICY_ID>
cargo run -p cli-tool -- dkg --ring-id <RING_ID>

# Reader keypair for PRE
cargo run -p cli-tool -- generate-reader-key

# Encrypt secret locally (no node)
cargo run -p cli-tool -- encrypt-secret --secret "my secret" --ring-pk <HEX> --policy-id <ID> --resource document --permission read

# Prepare then store (idempotent)
cargo run -p cli-tool -- prepare-secret --secret "data" --ring-pk-hex <HEX> --policy-id <ID> --resource document --permission read
cargo run -p cli-tool -- --signing-key $KEY store-prepared-secret --prepared-json '<JSON>' --ring-id <ID> --policy-id <ID> --resource document --permission read

# One-shot store
cargo run -p cli-tool -- --signing-key $KEY store-secret --secret "data" --ring-pk-hex <HEX> --ring-id <ID> --policy-id <ID> --resource document --permission read

# PRE (after storing a secret and setting relationship)
cargo run -p cli-tool -- pre --ring-pk <HEX> --reader-pk <HEX> --reader-sk <HEX> --object-id <ID>

# Chain / bulletin (requires a signing key)
cargo run -p cli-tool -- --signing-key $KEY fund --address <ADDRESS>
cargo run -p cli-tool -- --signing-key $KEY add-policy-to-chain
cargo run -p cli-tool -- --signing-key $KEY register-bulletin-namespace --namespace my-ns
```

## Integration tests

The command implementations live in `src/commands.rs` and are re-exported from `src/lib.rs` so they can be called from integration tests without invoking the CLI binary.
