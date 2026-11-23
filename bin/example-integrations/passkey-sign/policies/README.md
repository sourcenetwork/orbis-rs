# ACP setup

A passkey's own public key *is* the identity — there is no separate enrollment
step. After registering a passkey in the app (step 1), grant the resulting
`did:key` permission to sign under your key derivation directly:

```sh
cli-tool register-object-to-chain \
  --policy-id <POLICY_ID> --resource key --object-id <DERIVATION_ID>

cli-tool set-relationship-on-chain \
  --policy-id <POLICY_ID> --resource key --object-id <DERIVATION_ID> \
  --relation signer --subject-did <DID_FROM_STEP_1>
```

`--subject-did` grants the relation to that exact DID string verbatim, rather
than one `cli-tool` derives itself from a seed or pubkey — the right shape for
an externally-supplied identity like a passkey's.

For the PRE decrypt flow instead, grant against the document's own
resource/permission (typically `document`/`reader`/`read` — whatever the
document was actually stored under):

```sh
cli-tool register-object-to-chain \
  --policy-id <POLICY_ID> --resource document --object-id <OBJECT_ID>

cli-tool set-relationship-on-chain \
  --policy-id <POLICY_ID> --resource document --object-id <OBJECT_ID> \
  --relation reader --subject-did <DID_FROM_STEP_1>
```

Recovering a lost or compromised passkey is just: register a new one, grant
*its* DID the same relation. No separate credential-rotation step — the
identity is the DID, and ACP's own grant mechanism is the whole story.

Revoking the old DID (so a captured passkey stops working, not just adding a
competing one) needs a chain-side ACP revoke. `cli-tool` doesn't currently
expose a `revoke-relationship-on-chain` subcommand (only `set-relationship-on-chain`,
which grants) — until it does, revoke through the chain's own ACP module
directly.
