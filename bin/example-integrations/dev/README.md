# `orbis-dev-cluster`: local reference environment

Spins up a real, local, Docker-backed native Vera cluster (a chain plus a
handful of `orbis-node` containers) and seeds one ring+policy covering both
resources every example-integrations app needs — `key`/`signer` (Sign) and
`document`/`reader` (PRE/StoreSecret) — so passkey-sign, yubikey-sign, and
email-decrypt can all point at the same cluster, not a passkey-sign-specific
one.

Real policy grant/deny, not a mock: the in-process `harness` feature
(`bin/orbis-node/src/harness.rs`) was considered instead, since it needs no
Docker and starts in seconds, but its own doc comment rules it out —
authorization there is always a permissive `DummyAuthZ` ("not ACP policy
enforcement"), so grant/revoke would be silent no-ops. This tool is slower to
start (a minute or two the first time, since it builds the chain and node
Docker images from source; faster once those images are cached) but the
grant → sign → revoke → deny → re-grant cycle these example apps exist to
demonstrate actually works — verified end to end with a real passkey sign,
not just that the pieces compile.

## Usage

Start a cluster (defaults: 3 nodes, threshold 2):

```sh
cargo run -p orbis-dev-cluster -- up
```

This prints each node's gRPC endpoint, the chain RPC URL, the seeded
policy/ring ids, the finalized ring public key, and a ready-to-use **Sign key
derivation id** once DKG completes — something like:

```
==================== Cluster ready ====================
Node endpoints:
  node0: http://127.0.0.1:61167
  node1: http://127.0.0.1:61168
  node2: http://127.0.0.1:61169
Chain RPC:     http://127.0.0.1:60927
Policy id:     4483224d1055373be0a9cbe9939fb25ffb5454711f587cfefe50456ab9da365a
Ring id:       a1d98fea20e5fe8f034afa7ab7bbd899a2f756712d21c6caeccdbc59b535186a
Ring pk:       8a4ec83d876d66e2c260209bca1b0a7a544d0a0fe76f77f897d007202c71a2d...
Derivation id: a49b21e38fcc82d54f04146b1f80467f0690e4d80b88466ea3e40aa532a723ca  (Sign's own object id — grant against this, not the ring id)
```

Point an example app at it (`node0`'s endpoint; `9000` is this tool's fixed
deployment/chain id):

```sh
cargo run -p passkey-sign -- --orbis-endpoint http://127.0.0.1:61167 --chain-id 9000
```

`up` also sets `--webauthn-rp-id`/`--webauthn-origin` on every node — default
`localhost`/`http://localhost:8787`, matching `passkey-sign`'s own defaults,
so you normally don't need to pass either flag to the example app. Override
both with `up`'s own `--webauthn-rp-id`/`--webauthn-origin` flags if an
example needs different values, and pass the same values to the example app.

After registering a passkey in the browser, grant its `did:key` **signing**
access — `cli-tool set-relationship-on-chain` can't be used here (its admin
commands only talk to the Cosmos backend, not native/Vera), so this is a
subcommand of the same binary instead, run from a second terminal against the
already-running cluster. Use the **derivation id** printed above as
`--object-id`, not the ring id — Sign's permission checks key on the named
key-derivation object `up` already created, not the ring itself:

```sh
cargo run -p orbis-dev-cluster -- grant \
  --rpc-url <chain RPC URL printed by `up`> \
  --policy-id <printed> --resource key --object-id <derivation id printed by `up`> \
  --relation signer --subject-did <the passkey's did:key>
```

`revoke` takes the same flags. This is also the whole recovery story for a
lost or compromised passkey: revoke the old DID, grant a new one — no separate
enrollment/binding registry involved.

PRE/StoreSecret's `document` objects don't exist yet at this point — an
example app's own store-secret call creates one, and its returned object id
is what you grant `reader` on (same `grant`/`revoke` subcommands, `--resource
document --relation reader`).

Press Ctrl-C on the `up` process to tear the cluster down.

## What it does

Ported (not imported — that code is `#[cfg(test)]`-private to `orbis-node`)
from `bin/orbis-node/src/tests/e2e/vera_environment.rs`'s native chain-admin
glue, trimmed to what an interactive tool needs: no light-client header-sync
rigor, no fixture/scenario machinery, one ring shape, one caller. See
`src/native_admin.rs`'s own doc comment for the exact admin-key derivation and
why it's safe to reproduce outside a test.
