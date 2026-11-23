# Passkey signing

**Status: scaffold only.** The executable prints its status and exits.

## Intended experience

Register a passkey, approve an exact message, obtain an Orbis threshold signature,
and verify the result.

## Layout

- `src/`: Rust application orchestration and eventual HTTP endpoints.
- `web/`: browser interaction and user interface.
- `policies/`: ACP policy and grant setup for this example.
- [`../dev/`](../dev/README.md): shared local Orbis and ACP environment.

## Run the placeholder

From the workspace root:

```sh
cargo run --offline -p passkey-sign
```

## Implementation boundary

Use `orbis-webauthn` for reusable proof handling. Carry original evidence to
participating nodes for independent verification before ACP authorization.
The reference app will supply routing, storage, and its user interface.

Local node startup, ACP configuration, and real authentication are not wired up yet.
