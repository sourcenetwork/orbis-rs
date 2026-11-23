# Passkey signing (and PRE decryption)

Register a passkey, then use it to either approve a message and obtain an
Orbis threshold signature, or decrypt a PRE-encrypted document — no JWT, no
password. The passkey's own public key *is* the identity ACP grants or
revokes directly; both flows share the same registration step.

## Layout

- `src/main.rs`: a thin HTTP↔gRPC bridge (axum). Browsers can't speak gRPC
  directly, so this turns the browser's WebAuthn output into a
  `StartSignRequest`/`StartPreRequest` and forwards it to orbis-node. It
  never verifies anything itself — every ring node does that
  independently. The PRE flow is the one place this app holds any state:
  PRE's ephemeral reader keypair has to exist *before* the WebAuthn
  challenge can be built (the challenge embeds `rdr_pk`), so a decrypt
  spans two calls (`/api/pre/challenge` then `/api/pre/decrypt`) with the
  pending request held in memory in between (`cli_tool::PendingPasskeyPre`
  — see that type's doc comment). The Sign flow needs no such state.
- `web/`: the browser UI — registers a passkey, drives the WebAuthn
  ceremony, talks to `src/main.rs`'s small JSON API.
- `policies/`: how to grant (and recover) an ACP relation for the resulting
  DID.
- [`../dev/`](../dev/README.md): shared local Orbis and ACP environment.

## Run it

Point it at a running orbis-node cluster whose nodes were started with
matching `--webauthn-rp-id`/`--webauthn-origin` flags (defaults here are
`localhost`/`http://localhost:8787`, i.e. a local dev cluster):

```sh
cargo run -p passkey-sign -- --orbis-endpoint http://127.0.0.1:50051 --chain-id <RING_CHAIN_ID>
```

`--chain-id` only matters for the PRE flow (it's bound into the reader-key
proof-of-possession transcript) — any value works if you're only trying
Sign.

Then open <http://localhost:8787>, register a passkey, grant its DID
permission per `policies/README.md`, and sign or decrypt.

## Implementation boundary

The actual WebAuthn verification (`orbis_webauthn::verify_assertion`), the
P-256 `did:key` encoding (`authn::did_from_p256_public_key`/
`p256_public_key_from_did`), and the entire PRE reader-keypair/signature/
decrypt dance (`cli_tool::{build_passkey_pre_challenge, finish_passkey_pre}`)
are reused directly from the same code orbis-node and `cli-tool` already
use — this app never reimplements any of it. See
`crates/integrations/webauthn/README.md` for why WebAuthn verification
doesn't go through `webauthn-rs`'s higher-level ceremony API.
