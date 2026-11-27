# ACP setup

A mailbox's own address *is* the identity — there is no separate enrollment
step. The ACP subject is `did:emailhash:sha256(normalized address)`
(lowercased, trimmed, then SHA-256'd) — its own dedicated DID method, not a
real decoded key (see `orbis_email`'s own `build_token` doc comment for the
full reasoning). Grant that computed string permission before trying to
sign or decrypt with it — e.g. for `alice@example.com`:

```sh
python3 -c "import hashlib; print('did:emailhash:' + hashlib.sha256('alice@example.com'.strip().lower().encode()).hexdigest())"
```

## Against a local `orbis-dev-cluster` (native/Vera)

If you're running [`../../dev/`](../../dev/README.md)'s `orbis-dev-cluster`,
use its own `grant`/`revoke` subcommands instead of `cli-tool`'s —
`cli-tool register-object-to-chain`/`set-relationship-on-chain` only talk to
the Cosmos backend, not native/Vera, so they won't work here. `up` already
registered a Sign key-derivation object for you (its id is in the `up`
summary), so there's no separate `register-object` step:

```sh
cargo run -p orbis-dev-cluster -- grant \
  --rpc-url <chain RPC URL printed by `up`> --policy-id <printed> \
  --resource key --object-id <derivation id printed by `up`> \
  --relation signer --subject-did did:emailhash:<SHA256_OF_YOUR_ADDRESS>
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
  --relation reader --subject-did did:emailhash:<SHA256_OF_YOUR_ADDRESS>
```

Revoking the old identity (so a compromised mailbox stops working, not just
adding a competing one) is the same command with `revoke` in place of
`grant` — this *is* the whole recovery story for a compromised mailbox:
revoke the old identity, grant a new one, no separate credential-rotation
step.

## Against a real Cosmos deployment

`cli-tool`'s own admin commands are the right ones here instead. Both need a
funded account's `--signing-key`/`ORBIS_SIGNING_KEY` set — unlike
`orbis-dev-cluster`'s `grant`/`register-object` above, `cli-tool` has no
default signing key of its own (see `cli-tool/README.md`'s own flag table):

```sh
export ORBIS_SIGNING_KEY=<your funded account's hex private key>

cli-tool register-object-to-chain \
  --policy-id <POLICY_ID> --resource key --object-id <DERIVATION_ID>

cli-tool set-relationship-on-chain \
  --policy-id <POLICY_ID> --resource key --object-id <DERIVATION_ID> \
  --relation signer --subject-did did:emailhash:<SHA256_OF_YOUR_ADDRESS>
```

`--subject-did` grants the relation to that exact string verbatim, rather
than one `cli-tool` derives itself from a seed or pubkey — the right shape
for an externally-computed identity like this.

The same document-resource substitution as above applies here too. `cli-tool`
has no `revoke-relationship-on-chain` subcommand (only
`set-relationship-on-chain`, which grants) — until it does, revoke through
the chain's own ACP module directly.

## Enabling email evidence on the node(s)

Every node in the ring needs `--email-evidence-enabled` (or
`ORBIS_EMAIL_EVIDENCE_ENABLED=true`) set — off by default, the safe default
for a ring that doesn't use email authentication. `orbis-dev-cluster up`
already sets this unconditionally, so a local dev cluster needs no extra
flag. Key resolution uses live DNS by default, which is correct here: real
mail providers (Gmail included) really do publish DKIM keys over DNS, unlike
the Docker e2e tests' synthetic domains, which need the separate
`--email-dkim-keys-file` pinned-key path instead (see
`crates/integrations/email/README.md`).
