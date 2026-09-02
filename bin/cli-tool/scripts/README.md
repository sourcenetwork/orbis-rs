# `remote_smoke_test.sh`

A smoke test that proves `create-ring` → `dkg` → `store-secret` → `pre` → `post-key-derivation` → `sign` work end-to-end against an **already-deployed, already-running** orbis network — a real testnet, not a network this script creates itself. It needs nothing but the compiled `cli-tool` binary: no Rust toolchain, no cargo, no Docker on whatever machine runs it.

Each run creates a fresh ring, DKG ceremony, stored secret, ACP object policy/objects/relationships, and key derivation on-chain. There is currently no cleanup command in the CLI, so every run leaves permanent artifacts on the target chain — an accepted cost of testing the real create-then-use flow, not something this script attempts to reverse.

## Prerequisites

- **The compiled binary.** Build once anywhere with the Rust toolchain (`cargo build --release -p cli-tool`) and ship just the resulting `target/release/cli-tool` binary to wherever this script runs — that machine itself needs no build tooling.
- **A funded `ORBIS_SIGNING_KEY`.** Every write this script performs (`derive-signer-did`, `add-policy-to-chain`, `create-ring`, `register-object-to-chain`, `set-relationship-on-chain`, `post-key-derivation`) only needs ordinary funded-account rights. It does **not** need node-controller privileges — this script never calls `add-node-to-whitelist`/`update-node-peer-id`.
- **The whitelist-policy-id assumption.** `create-ring --policy-id <P>` creates a brand-new ring every run, so target nodes must already be authorized for whatever `--whitelist-policy-id`/`ORBIS_WHITELIST_POLICY_ID` you pass — set up **once, out-of-band**, by each node's own controller key adding that policy_id to its `NodeInfo.whitelisted_policy_ids`. This is exactly what DKG authorization checks (`bin/orbis-node/src/dkg/v0/helpers.rs`, `validate_dkg_node_authorization_for_committee`): a node is authorized if the ring's `policy_id` is in its whitelist, or the specific `ring_id` is. Only the policy_id path works for a repeatable "fresh ring every run" script without this script also performing privileged per-run whitelisting — if your target network instead whitelists nodes by fixed `ring_id`, this script's fresh-ring-per-run design won't work as-is.
- **Target peer node keys and DKG threshold** for the ring being created — this script doesn't discover them, you provide them.
- **Standard `cli-tool` network env vars pointed at the real network** — see below. Left at defaults, they point at `localhost`, which is almost certainly not what you want for a remote target.

The object/secret-access ACP policy is **not** pre-provisioned — the script creates a fresh one every run via `add-policy-to-chain` (fixed schema: resource `document`, relations `creator`/`reader`, permissions `read = creator + reader`, `write = creator` — no chain-side gating, safe to create on every run). This is a different policy from `ORBIS_WHITELIST_POLICY_ID`, which governs which nodes may participate in DKG (checked against each node's `NodeInfo.whitelisted_policy_ids`) and genuinely must be pre-provisioned since it isn't something `add-policy-to-chain`'s fixed schema can satisfy. Don't assume these two are (or should be) the same policy.

On every object it registers (the stored secret, the key derivation), the script grants **both**:
- the `--creator-relation`/`ORBIS_SMOKE_CREATOR_RELATION` relation (default `creator`, giving full read+write per the schema above) to `ORBIS_SIGNING_KEY`'s own identity — derived via `derive-signer-did` and granted with `set-relationship-on-chain --actor-pubkey`, so the signing key can always read/manage what it creates without a separate reader identity.
- the `--relation`/`ORBIS_SMOKE_RELATION` relation (default `reader`, read-only) to the generated reader key — this is the identity `pre`/`sign` actually authenticate as (a JWT-claimed Ed25519 `did:key`, unrelated to the signing key's own secp256k1 `did:key`), so it's the one that must hold `reader` for those RPCs to succeed.

## Usage

CI-style, everything via environment variables:

```bash
export ORBIS_RPC_URL=https://rpc.testnet.example
export ORBIS_REST_URL=https://rest.testnet.example
export ORBIS_CHAIN_GRPC_URL=https://grpc.testnet.example
export ORBIS_ENDPOINT=https://node1.testnet.example:50051
export ORBIS_CHAIN_ID=vera-testnet-1
export ORBIS_SIGNING_KEY=$MY_FUNDED_KEY_HEX
export ORBIS_WHITELIST_POLICY_ID=$KNOWN_WHITELIST_POLICY_ID
export ORBIS_SMOKE_PEER_NODE_KEYS=$NODE1_KEY,$NODE2_KEY,$NODE3_KEY
export ORBIS_SMOKE_THRESHOLD=2

./remote_smoke_test.sh
```

Manual run with explicit flags instead:

```bash
./remote_smoke_test.sh \
  --cli-bin /path/to/cli-tool \
  --whitelist-policy-id "$KNOWN_WHITELIST_POLICY_ID" \
  --peer-node-keys "$NODE1_KEY,$NODE2_KEY,$NODE3_KEY" \
  --threshold 2 \
  --dkg-timeout 240
```

Re-running just the store-secret → sign portion against an already-finalized ring (skips `create-ring`/`dkg`, so `--whitelist-policy-id`/`--peer-node-keys`/`--threshold` aren't needed):

```bash
./remote_smoke_test.sh --ring-id "$EXISTING_RING_ID"
```

`./remote_smoke_test.sh --help` prints the full flag/env-var/default reference.

Exit code 0 = pass, non-zero = first step that failed. Output is one `==> step... ok` / `==> step... FAILED: <reason>` line per step, ending with `SMOKE TEST PASSED` / `SMOKE TEST FAILED` and a summary of the resources created (policy/ring/object/derivation IDs) — useful for manually inspecting or cleaning up a failed run.

## Config reference

| Flag | Env var | Default | Required |
|---|---|---|---|
| `--cli-bin <path>` | `CLI_BIN` | autodetect `target/release/cli-tool` relative to the repo root | yes (must resolve to an executable) |
| `--ring-id <id>` | `ORBIS_SMOKE_RING_ID` | none | no — if set, skips `create-ring`/`dkg` entirely and targets this already-finalized ring instead |
| `--whitelist-policy-id <id>` | `ORBIS_WHITELIST_POLICY_ID` | none | **yes, unless `--ring-id` is set** |
| `--peer-node-keys <csv>` | `ORBIS_SMOKE_PEER_NODE_KEYS` | none | **yes, unless `--ring-id` is set** |
| `--threshold <n>` | `ORBIS_SMOKE_THRESHOLD` | none | **yes, unless `--ring-id` is set** |
| `--dkg-timeout <secs>` | `ORBIS_SMOKE_DKG_TIMEOUT_SECS` | `180` | no |
| `--dkg-poll-interval <secs>` | `ORBIS_SMOKE_DKG_POLL_INTERVAL_SECS` | `5` | no |
| `--secret <string>` | `ORBIS_SMOKE_SECRET` | generated (`orbis-remote-smoke-test-secret-<epoch>`) | no |
| `--derivation <string>` | `ORBIS_SMOKE_DERIVATION` | `orbis-remote-smoke-test-derivation` | no |
| `--sign-message <string>` | `ORBIS_SMOKE_SIGN_MESSAGE` | `orbis-remote-smoke-test-sign-message` | no |
| `--resource`/`--permission`/`--relation`/`--creator-relation` | `ORBIS_SMOKE_RESOURCE`/`_PERMISSION`/`_RELATION`/`_CREATOR_RELATION` | `document`/`read`/`reader`/`creator` | no — must match the script's built-in `add-policy-to-chain` schema |
| `--ring-nonce <string>` | `ORBIS_SMOKE_RING_NONCE` | generated | no — collision insurance on rapid repeated runs |

Plus all of `cli-tool`'s own network/signing env vars, used as-is (never re-invented as script-specific flags): `ORBIS_ENDPOINT`, `ORBIS_CHAIN_ID`, `ORBIS_RPC_URL`, `ORBIS_REST_URL`, `ORBIS_CHAIN_GRPC_URL`, `ORBIS_ACCOUNT_PREFIX`, `ORBIS_SIGNING_KEY` (required). The script also exports `ORBIS_READER_SK`/`ORBIS_READER_DID_PK` itself partway through (after `generate-reader-key`), so later steps don't need to repeat those flags.

## Known limitation

The final `sign` step only confirms the RPC succeeded and returned a plausible-looking hex signature — it does **not** cryptographically verify the signature against the derived public key the way the Rust integration test (`test_cli_calls_dkg_and_pre_endpoint`) does with `SignImpl::verify`. Reimplementing curve math in bash isn't worthwhile for a smoke test; this is a deliberately shallow check.

## Follow-up idea (not done here)

`generate-reader-key`, `store-secret`, `pre`, and `sign` are the only `cli-tool` commands that don't print a grep-able `KEY=value` line (unlike `create-ring`/`add-policy-to-chain`/`get-latest-ring`/`post-key-derivation`), so this script has to `grep`+`sed` their indented human-readable output instead. Adding `OBJECT_ID=`/`DECRYPTED_SECRET=`/`SIGNATURE=`/`READER_SK=`/`READER_PK=` lines to those commands would make this more robust. Not done as part of this script — left for a separate `cli-tool` change.

## Prior art

An older `bin/cli-tool/scripts/` directory (numbered per-step scripts + `run_integration.sh`) existed on `main` and was removed on this branch. It targeted a self-managed local Docker Compose network and predates `create-ring`/the current `dkg --ring-id` flow (it used `dkg --threshold ... --peer-ids ...` directly), so it wasn't a usable template structurally — only its output-parsing idioms (`grep -A1 ... | tail -1` for `generate-reader-key`) carried over here.
