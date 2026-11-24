# Orbis CLI Tool

## Vera administration

`vera-admin` manages participant nodes and threshold rings.

Build the operator tool with `cargo build -p cli-tool --features vera --bin vera-admin`.
Its trust file is the same shape as the `bulletin` section of orbis-node's
`--services-config`. Its worker identity
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
    "requires_pet": false,
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
ring is pending DKG; pass its ID to the `dkg` command against an Orbis node. `prepare-ring` also accepts SDK `Update` and `Cancel` requests. Read
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
VERAD_BINARY=/path/to/verad cargo test -p cli-tool --features vera \
  --test vera_admin -- --ignored
```

## Node commands

`cli-tool` talks to an Orbis node over gRPC and runs local cryptography.

```bash
cargo build -p cli-tool
```

Optional crypto backends (see `Cargo.toml`):

- `default`: BLS12-381
- `jubjub`: enable with `--no-default-features --features jubjub`

### Global flags

Env var equivalents in parentheses; flag > env var > default:

| Flag | Env var | Default | Used by |
|------|---------|---------|---------|
| `-e, --endpoint <URL>` | `ORBIS_ENDPOINT` | `http://localhost:50051` | orbis node gRPC service |
| `--chain-id <ID>` | `ORBIS_CHAIN_ID` | `vera-localnet` | Chain ID bound into PRE requests |
| `--signing-key <HEX>` | `ORBIS_SIGNING_KEY` | *(none)* | `derive-signer-did` |

### Secret input

Passing secrets as plain CLI arguments leaves them visible in shell history and to other processes on the same machine (e.g. via `ps`). To avoid that:

- `--secret` (on `encrypt-secret`, `prepare-secret`, `store-secret`) is optional. If omitted, you're prompted for it interactively with hidden input. Keep passing `--secret` directly for scripted/CI use.
- `--reader-did-pk` (on `pre`, `store-prepared-secret`, `store-secret`, `sign`) is **required** — pass it directly or set `ORBIS_READER_DID_PK`. There is no shared default: each user needs their own value, since reusing one would collapse everyone onto the same DID identity.

### Commands

| Command | Description |
|---------|-------------|
| `info` | Query node info (public address, peer ID, P2P address, status). |
| `dkg` | Start a Distributed Key Generation session for `--ring-id`, a ring pending DKG (create one with `vera-admin prepare-ring`). |
| `ring-state` | Query the local ring state (public polynomial + last PSS refresh timestamp). Requires `--ring-pk-hex`. |
| `pet-ring-state` | Query the local PET checking-key state. Requires `--ring-id`. |
| `derive-signer-did` | Derive the compressed secp256k1 public key and `did:key` for `--signing-key`. Pure local computation. Prints `PUBLIC_KEY=` and `DID=`. |
| `encrypt-secret` | Encrypt a secret to a ring public key locally (no node). Options: `--secret` (omit to be prompted), `--ring-pk`, `--policy-id`, `--resource`, `--permission`, optional `--derivation` (hex), `--tier`, `--timestamp`, `--salt`. |
| `prepare-secret` | Encrypt a secret locally and print a **prepared secret** JSON. Use with `store-prepared-secret` for idempotent storage (same input → same object ID on retries). |
| `store-prepared-secret` | Send a prepared secret to the node. Options: `--prepared-json`, `--ring-id`, `--reader-did-pk` (required), `--with-proof`. |
| `store-secret` | One-shot: encrypt locally and store on the node. |
| `pre` | Run Proxy Re-Encryption: re-encrypt a stored secret and decrypt it. Always generates a fresh ephemeral reader keypair. Options: `--ring-pk`, `--object-id`, `--reader-did-pk` (required), `--derivation`, `--salt`, `--valid-window-start`/`--valid-window-end` (together), `--save-only`. |
| `retrieve-pre` | Decrypt a response saved by `pre --save-only`. Option: `--pending-json`. |
| `sign` | Start a threshold Sign session. Options: `--message` (hex), `--derivation-id` (a key derivation registered with Vera), `--reader-did-pk` (required), `--valid-window-start`/`--valid-window-end` (together). |

### Examples

```bash
cargo run -p cli-tool -- --endpoint http://localhost:50051 info
cargo run -p cli-tool -- dkg --ring-id <RING_ID>
cargo run -p cli-tool -- encrypt-secret --secret "my secret" --ring-pk <HEX> --policy-id <ID> --resource document --permission read
cargo run -p cli-tool -- store-secret --secret "data" --ring-pk-hex <HEX> --ring-id <ID> --policy-id <ID> --resource document --permission read --reader-did-pk <YOUR_ID>
cargo run -p cli-tool -- pre --ring-pk <HEX> --object-id <ID> --reader-did-pk <YOUR_ID>
```

## Testing

Unit tests in `src/tests.rs` cover argument validation, clap parsing, `did_seed`, `derive_signer_did` and `prepare_secret`:

```bash
cargo test -p cli-tool
```

The command implementations are re-exported from `src/lib.rs` so `orbis-node`'s E2E scenarios drive them directly.
