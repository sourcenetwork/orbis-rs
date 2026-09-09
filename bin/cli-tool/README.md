# Orbis CLI Tool

## Native Vera administration

`vera-admin` manages native participant nodes and threshold rings.

Build the operator tool with `cargo build -p cli-tool --features native --bin vera-admin`.
It accepts the same `--vera-config` trust file as `orbis-node`. Its worker identity
and pending request live in a separate operator directory; the worker key uses the
existing encrypted local store. Supply its password through `--password-file` or
`ORBIS_PASSWORD_FILE`.

```sh
vera-admin --vera-config vera.json --directory operator --password-file password worker
vera-admin --vera-config vera.json ring-id create.json --actor "$ACTOR_DID"
vera-admin --vera-config vera.json --directory operator --password-file password \
  prepare-ring create.json --token-file ring-token
vera-admin --vera-config vera.json --directory operator --password-file password submit
vera-admin --vera-config vera.json ring "$RING_ID"
vera-admin --vera-config vera.json --directory operator --password-file password \
  acknowledge "$SUBMISSION_ID"
```

Before preparing a request, obtain a `ManageRings` delegation from the policy actor
to the DID printed by `worker`. The actor needs the corresponding ACP permission.
Participant nodes must already be registered. `create.json` contains the SDK's
`RingCommand` JSON, for example:

```json
{
  "Create": {
    "policy_id": "<64-character policy ID>",
    "peer_node_keys": ["<compressed participant public key>"],
    "threshold": 1,
    "pss_interval": 86400,
    "current_version": 0,
    "nonce": [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
              0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    "trusted_auth_relay_dids": null,
    "reporting": {
      "node_offline_demerits": 1,
      "invalid_crypto_response_demerits": 1,
      "unauthorized_request_demerits": 1,
      "reset_interval_seconds": 86400,
      "kick_threshold": 3,
      "backup_node_keys": []
    }
  }
}
```

Choose a distinct nonce for each new ring and sort participant keys. The resulting
ring is pending DKG; pass its ID to the existing `dkg` command against a native
Orbis node. `prepare-ring` also accepts SDK `Update` and `Cancel` requests. Read
the certified ring sequence before constructing an update.

Preparation persists the signed request before network submission. Repeating it
with identical inputs returns the same ID; different inputs cannot replace a
pending request. `submit` first checks for its certified receipt, then submits
the exact journaled bytes if needed. Repeating `submit` recovers the same result
across process restarts. Rejected commands print `success: false` and exit with an
error. Both successful and rejected results remain recoverable until explicitly
acknowledged by ID. Record the result before acknowledging it.

Ring reads include their certified revision and timestamp and enforce the trust
file's freshness bound. `--minimum-revision` rejects older evidence. The tool
checks the configured deployment root before opening any worker store or making
a submission.

For node/controller changes, first read the current certified node record. Its
`sequence` is the value to sign for the next command; registration uses zero.
Create `node-command.json` using an SDK `NodeCommand`, such as:

```json
{"SetPeer":"<peer identity>@127.0.0.1:4555"}
```

```sh
vera-admin --vera-config vera.json node "$NODE_KEY"
vera-admin --vera-config vera.json sign-node node-command.json \
  --node-key "$NODE_KEY" --sequence "$SEQUENCE" --expires-at "$UNIX_EXPIRY" \
  --key-file controller-key > signed-node.json
vera-admin --vera-config vera.json --directory operator --password-file password \
  prepare-node signed-node.json
vera-admin --vera-config vera.json --directory operator --password-file password submit
```

`sign-node` runs locally without contacting the service or opening worker storage.
The key file accepts 32 raw bytes or a hexadecimal key, optionally prefixed with
`0x`. Sign on the machine holding the controller key and transfer the resulting
authorization to the submission machine. Only the signed authorization enters
the submission journal. It binds the deployment, node, sequence, expiry and exact
command. `prepare-node` rejects a different deployment before journaling it.

Supported commands are `Register`, `SetPeer`, `TransferController`, `Allow` and
`Disallow`. Admission targets use `{"Allow":{"Policy":"<policy ID>"}}` or
`{"Allow":{"Ring":"<ring ID>"}}`; use `Disallow` to remove a target. Controller
transfer uses `{"TransferController":"<new compressed public key>"}`.
Registration requires the node's key; subsequent changes require the current
controller. Transfer preserves the node identity and removes the former
controller's authority. Node commands use the same explicit receipt
acknowledgement as ring commands.

The focused process fixture covers creation, certified reads, process-restart
recovery, rejected requests and acknowledgement guards. A separate node workflow
covers routes, policy/ring admission, controller transfer and former-controller
rejection:

```sh
HUBD_BINARY=/path/to/hubd cargo test -p cli-tool --features native \
  --test native_admin -- --ignored
```

## Existing service commands

A command-line tool for interacting with an **Orbis** network. Intended primarily for **development and testing**, but can be pointed at any Vera chain and orbis node via the network flags below.

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
| `--chain-id <ID>` | `ORBIS_CHAIN_ID` | `vera-localnet` | Vera chain ID |
| `--rpc-url <URL>` | `ORBIS_RPC_URL` | `http://localhost:26657` | Tendermint RPC |
| `--rest-url <URL>` | `ORBIS_REST_URL` | `http://localhost:1317` | Cosmos REST API |
| `--chain-grpc-url <URL>` | `ORBIS_CHAIN_GRPC_URL` | `http://localhost:9090` | Vera gRPC (distinct from `--endpoint`) |
| `--account-prefix <PREFIX>` | `ORBIS_ACCOUNT_PREFIX` | `vera` | Bech32 address prefix |
| `--signing-key <HEX>` | `ORBIS_SIGNING_KEY` | *(none)* | Signs any chain-writing command |

`--signing-key`/`ORBIS_SIGNING_KEY` has **no default** and is required by any command that writes to chain (policy/object/relationship, bulletin namespace/collaborator, ring lifecycle commands, `fund`, `post-key-derivation`). Commands that only talk to the orbis node over gRPC, or that are purely local, don't need it.

**Pointing at a real testnet:**

```bash
cargo run -p cli-tool -- \
  --chain-id vera-testnet-1 \
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

That hex value is the well-known Vera localnet devnet key (mnemonic `abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about`), pre-funded only in local Docker Compose setups. It is public and deterministic — **never fund it, or use it, on a real network.**

## Secret input

Passing secrets as plain CLI arguments leaves them visible in shell history and to other processes on the same machine (e.g. via `ps`). To avoid that:

- `--secret` (on `encrypt-secret`, `prepare-secret`, `store-secret`) is optional. If omitted, you're prompted for it interactively with hidden input. Keep passing `--secret` directly for scripted/CI use.
- `--reader-sk` (on `pre`) falls back to `ORBIS_READER_SK` if the flag isn't given.
- `--reader-did-pk` (on `pre`, `set-relationship-on-chain`, `store-prepared-secret`, `store-secret`, `sign`) is **required** — pass it directly or set `ORBIS_READER_DID_PK` (same env var across all of them, so you can `export` it once per session). There is no shared default: each user needs their own value, since reusing one would collapse everyone onto the same on-chain DID identity. On `set-relationship-on-chain` only, `--actor-pubkey` is an alternative to `--reader-did-pk` (mutually exclusive) — see `derive-signer-did` below.

## Commands

### Node & key management

| Command | Description |
|---------|-------------|
| `info` | Query node info (public address, peer ID, P2P address, status). |
| `create-ring` | Create a blank ring on-chain, to be targeted by a subsequent `dkg` session. Requires `--signing-key`/`ORBIS_SIGNING_KEY`. Options: `--peer-node-keys` (comma-separated), `--threshold`, `--policy-id`, optional `--pss-interval` (default `86400`, the chain-enforced minimum), `--nonce`, `--current-version` (default `0`), `--trusted-auth-relay-dids` (comma-separated). Prints `RING_ID=`. |
| `dkg` | Start a Distributed Key Generation session. Requires `--ring-id` for a pre-created blank ring entry (create one with `create-ring`). |
| `ring-state` | Query the local ring state (public polynomial + last PSS refresh timestamp). Requires `--ring-pk-hex`. |
| `generate-reader-key` | Generate a reader keypair (hex). Use the output as `--reader-pk` / `--reader-sk` for PRE. |
| `derive-signer-did` | Derive the secp256k1 public key and `did:key` for `--signing-key`/`ORBIS_SIGNING_KEY`. Pure local computation, no network calls. This is the identity Vera resolves for ACP checks on signed transactions (e.g. `create-ring`'s `create_ring` permission) — use it to find out, ahead of time, which DID needs a relation granted (via `set-relationship-on-chain --actor-pubkey`) before such a transaction will be authorized. Prints `PUBLIC_KEY=` and `DID=`. |
| `get-latest-ring` | Fetch a ring from the orbis module by `--ring-id`. Prints `RING_ID=` and `RING_PK=`. |

### Secrets: encrypt, store, re-encrypt

| Command | Description |
|---------|-------------|
| `encrypt-secret` | Encrypt a secret to a ring public key locally (no node). Options: `--secret` (omit to be prompted), `--ring-pk`, `--policy-id`, `--resource`, `--permission`, optional `--derivation` (hex), `--tier`, `--timestamp`, `--salt`. |
| `prepare-secret` | Encrypt a secret locally and print a **prepared secret** JSON. Use with `store-prepared-secret` for idempotent storage (same input → same object ID on retries). Same options as `encrypt-secret` plus `--ring-pk-hex`. |
| `store-prepared-secret` | Send a prepared secret (from `prepare-secret`) to the node. Options: `--prepared-json`, `--ring-id`, `--policy-id`, `--resource`, `--permission`, `--reader-did-pk` (or `ORBIS_READER_DID_PK`; required), `--with-proof`, `--tier`, `--timestamp`. |
| `store-secret` | One-shot: encrypt locally and store on the node. Options: `--secret` (omit to be prompted), `--ring-pk-hex`, `--ring-id`, `--policy-id`, `--resource`, `--permission`, `--reader-did-pk` (or `ORBIS_READER_DID_PK`; required), `--derivation`, `--with-proof`, `--tier`, `--timestamp`, `--salt`. |
| `pre` | Run Proxy Re-Encryption: re-encrypt a stored secret for a reader and decrypt with reader keys. Options: `--ring-pk`, `--reader-pk`, `--object-id`, `--reader-sk` (or `ORBIS_READER_SK`; required unless `--xnc-only`), `--reader-did-pk` (or `ORBIS_READER_DID_PK`; required), `--derivation`, `--salt`, `--valid-window-start`/`--valid-window-end` (must be given together), `--xnc-only`. |

### Signing (derivation + threshold sign)

| Command | Description |
|---------|-------------|
| `post-key-derivation` | Post a `KeyDerivation` to the bulletin, registering a sign key derivation config. Options: `--ring-id`, `--derivation`, `--policy-id`, `--resource`, `--permission`. Prints `DERIVATION_ID=` and `DERIVED_PK=`. |
| `sign` | Start a threshold Sign session. Options: `--message` (hex), `--derivation-id` (from `post-key-derivation`), `--reader-did-pk` (or `ORBIS_READER_DID_PK`; required), `--valid-window-start`/`--valid-window-end` (must be given together). |

### Chain (policy, objects, relationships)

Requires `--signing-key`/`ORBIS_SIGNING_KEY`.

| Command | Description |
|---------|-------------|
| `add-policy-to-chain` | Create the default test policy on chain. Prints the new `POLICY_ID`. |
| `register-object-to-chain` | Register an object under a policy. Options: `--policy-id`, `--object-id`, `--resource`. |
| `set-relationship-on-chain` | Set a relationship on an object (e.g. reader). Options: `--policy-id`, `--object-id`, `--resource`, `--relation`, and exactly one of `--reader-did-pk` (or `ORBIS_READER_DID_PK`) for an Ed25519 DID derived from a seed, or `--actor-pubkey` for the secp256k1 `did:key` of a given public key (see `derive-signer-did`) — use the latter to grant relations checked against a transaction signer's own identity, e.g. `ring_creator` on a `ring_policy` object for `create-ring`. |

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
| `cancel-ring-reshare` | Cancel a pending reshare, reverting to the ring's prior committee/threshold. Option: `--ring-id`. |
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
cargo run -p cli-tool -- store-prepared-secret --prepared-json '<JSON>' --ring-id <ID> --policy-id <ID> --resource document --permission read --reader-did-pk <YOUR_ID>

# One-shot store
cargo run -p cli-tool -- store-secret --secret "data" --ring-pk-hex <HEX> --ring-id <ID> --policy-id <ID> --resource document --permission read --reader-did-pk <YOUR_ID>

# PRE (after storing a secret and setting relationship)
cargo run -p cli-tool -- pre --ring-pk <HEX> --reader-pk <HEX> --reader-sk <HEX> --object-id <ID> --reader-did-pk <YOUR_ID>

# Chain / bulletin (requires a signing key)
cargo run -p cli-tool -- --signing-key $KEY fund --address <ADDRESS>
cargo run -p cli-tool -- --signing-key $KEY add-policy-to-chain
cargo run -p cli-tool -- --signing-key $KEY register-bulletin-namespace --namespace my-ns
```

## Testing

Fast, local unit tests (no Docker, no live chain) live in `src/tests.rs` — argument-validation helpers (`require_signing_key`, `require_reader_did_pk`, `require_valid_window_pair`, `resolve_whitelist_target`), clap parsing sanity checks, `did_seed`'s hashing, and `prepare_secret`'s local encryption. Run with:

```bash
cargo test -p cli-tool
```

The command implementations in `src/commands.rs` are also re-exported from `src/lib.rs` so they can be driven directly (bypassing the CLI binary and its arg parsing) from `orbis-node`'s Docker-Compose-based integration tests, which cover real DKG/PRE/Sign/PSS/reporting flows against a live chain and node cluster.

## Scripts

`scripts/remote_smoke_test.sh` drives the compiled binary through create-ring → dkg → store-secret → pre → post-key-derivation → sign against an already-deployed remote network (not one it creates itself) — see `scripts/README.md` for prerequisites and usage.
