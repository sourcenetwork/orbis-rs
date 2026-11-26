# ACP setup

A passkey's own public key *is* the identity — there is no separate enrollment
step. After registering a passkey in the app (step 1), grant the resulting
`did:key` permission to sign under your key derivation directly.

## Against a local `orbis-dev-cluster`

If you're running [`../../dev/`](../../dev/README.md)'s `orbis-dev-cluster`,
use its own `grant`/`revoke` subcommands; `cli-tool` has no ACP relationship
commands. `up` already
registered a Sign key-derivation object for you (its id is in the `up`
summary), so there's no separate `register-object` step:

```sh
cargo run -p orbis-dev-cluster -- grant \
  --rpc-url <chain RPC URL printed by `up`> --policy-id <printed> \
  --resource key --object-id <derivation id printed by `up`> \
  --relation signer --subject-did <DID_FROM_STEP_1>
```

For the PRE decrypt flow instead, grant against the document's own
resource/permission (typically `document`/`reader`/`read` — whatever the
document was actually stored under). Unlike the key derivation, a document's
object doesn't exist until you store one, so register it first:

```sh
cargo run -p orbis-dev-cluster -- register-object \
  --rpc-url <chain RPC URL> --policy-id <printed> --resource document --object-id <OBJECT_ID>

cargo run -p orbis-dev-cluster -- grant \
  --rpc-url <chain RPC URL> --policy-id <printed> \
  --resource document --object-id <OBJECT_ID> \
  --relation reader --subject-did <DID_FROM_STEP_1>
```

Revoking the old DID (so a captured passkey stops working, not just adding a
competing one) is the same command with `revoke` in place of `grant` — this
*is* the whole recovery story for a lost or compromised passkey: revoke the
old DID, grant a new one, no separate credential-rotation step.
