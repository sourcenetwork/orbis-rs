# Integration examples

Small reference applications demonstrating user-facing Orbis integrations.
All three binaries are members of the root Cargo workspace.

**Status: scaffold only.** Each executable prints its status and exits.
Registration, proof verification, ACP setup, and Orbis requests are not wired up.

| Directory / package | Intended experience |
| --- | --- |
| [passkey-sign](passkey-sign/README.md) | Register a passkey, approve a message, receive and verify an Orbis threshold signature |
| [yubikey-sign](yubikey-sign/README.md) | Use a FIDO2 YubiKey with the same WebAuthn integration |
| [email-decrypt](email-decrypt/README.md) | Share an encrypted document by email and decrypt locally after threshold PRE |

Each example owns its Rust application in `src/`, browser assets in `web/`, and
ACP setup in `policies/`. Shared local ring configuration belongs in
[`dev/`](dev/README.md). These supporting directories currently contain planning
notes only.

Reusable protocol code belongs in
[`crates/integrations/`](../../crates/integrations/README.md).

## Development

Run these commands from the repository root:

```sh
cargo check -p passkey-sign -p yubikey-sign -p email-decrypt --all-targets
cargo fmt -p passkey-sign -p yubikey-sign -p email-decrypt -- --check
cargo run -p passkey-sign
cargo run -p yubikey-sign
cargo run -p email-decrypt
```

The examples share the root workspace dependencies, lockfile, and Rust toolchain.
Start with the passkey example, then the FIDO2 YubiKey variation and email flow.
