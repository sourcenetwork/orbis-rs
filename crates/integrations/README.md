# Orbis integrations

Reusable Rust libraries connecting external authentication methods to Orbis
operations. These crates belong to the root Orbis Cargo workspace.

**Status: scaffold only.** Public API types and protocol implementations have
not been added yet.

| Directory | Package | Responsibility |
| --- | --- | --- |
| `core/` | `orbis-integration-core` | Shared operation description, portable evidence, and local verification result |
| `webauthn/` | `orbis-webauthn` | Enrollment and request authorization using passkeys and FIDO2 security keys |
| `email/` | `orbis-email` | Request-bound email challenges and DKIM evidence verification |

## Integration boundaries

- Applications obtain authentication evidence bound to an exact Orbis operation.
- Every participating node must receive and independently verify the original
  evidence. A coordinator's authentication result is not a substitute for it.
- ACP evaluates permission for the authenticated actor; the configured Orbis
  threshold governs the cryptographic operation.
- Passkeys and FIDO2 YubiKeys share the WebAuthn integration. PIV, OpenPGP, and
  OTP uses of a YubiKey are separate possible integrations.
- Email delivery, reply capture, credential storage, and trusted DKIM-key lookup
  are adapter boundaries. Their implementations and trust models remain to be selected.
- Direct proof verification requires integration with Orbis's node authentication
  and request formats. An application dependency alone does not enable these
  flows on an unchanged ring.

The integration crates currently use only local path dependencies. Select
protocol libraries as the first example establishes the API requirements.

Application routing, browser assets, policy setup, and local ring configuration
live with the [reference examples](../../bin/example-integrations/README.md).

## Development

From the repository root:

```sh
cargo check -p orbis-integration-core -p orbis-webauthn -p orbis-email --all-targets
cargo fmt -p orbis-integration-core -p orbis-webauthn -p orbis-email -- --check
```

Develop the passkey example and WebAuthn library together, then exercise the same
integration with the YubiKey example. Use the email example to refine the shared
operation and evidence boundary.
