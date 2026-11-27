# Email document decryption (and signing)

Reply to an email from your own mailbox, and use that DKIM-signed reply to
either approve a message and obtain an Orbis threshold signature, or decrypt
a PRE-encrypted document — no password, no passkey. Your mailbox's own
address *is* the identity ACP grants or revokes; both flows share the same
send/reply/check loop.

## Layout

- `src/main.rs`: a thin HTTP↔gRPC bridge (axum) that also does the one
  thing a browser can't: it sends the challenge email itself (SMTP, via
  `lettre`) and, on request, checks the same inbox for the reply (IMAP, via
  `async-imap`). It never verifies the DKIM signature itself — every ring
  node does that independently; a verification result produced here would
  not be proof for anyone else.
- `web/`: the browser UI — collects inputs, triggers the send/check calls,
  shows results. No in-browser ceremony (see `web/README.md`).
- `policies/`: how to grant (and recover) an ACP relation for the resulting
  `did:emailhash:sha256(address)` identity, and how to enable email
  evidence on the node(s).
- [`../dev/`](../dev/README.md): shared local Orbis and ACP environment —
  already sets `--email-evidence-enabled` on every node it starts.

## Prerequisites

- A running orbis-node cluster whose nodes were started with
  `--email-evidence-enabled` (`orbis-dev-cluster up` already does this).
- A real Gmail account with 2-factor authentication enabled, and an [App
  Password](https://myaccount.google.com/apppasswords) generated for it —
  the regular account password does not work over SMTP/IMAP. This account
  is the ring's own mailbox: every challenge email is sent from it, and its
  inbox is what "check for reply" polls.

## Run it

```sh
cp .env.example .env   # then fill in GMAIL_ADDRESS/GMAIL_APP_PASSWORD
cargo run -p email-decrypt -- --orbis-endpoint http://127.0.0.1:50051 --chain-id <RING_CHAIN_ID>
```

`--chain-id` only matters for the PRE flow (it's bound into the reader-key
proof-of-possession transcript) — any value works if you're only trying
Sign.

Then open <http://localhost:8788>, grant your email identity permission per
`policies/README.md`, type in your own address, and sign or decrypt.

## Implementation boundary

The actual DKIM verification (`orbis_email::verify_email_message`), the
`did:emailhash:sha256(address)` identity format, and the entire PRE
reader-keypair/signature/decrypt dance
(`orbis_sdk::{build_pre_challenge, OrbisClient::submit_pre_with_evidence}`)
are reused directly from the same code orbis-node and the Docker e2e
scenarios (`bin/orbis-node/src/tests/e2e/email_{sign,pre}_scenario.rs`)
already use — this app never reimplements any of it. See
`crates/integrations/email/README.md` for why DKIM verification doesn't
hand-roll RSA/Ed25519 either.
