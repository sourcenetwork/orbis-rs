# Email document decryption

**Status: scaffold only.** The executable prints its status and exits.

## Intended experience

Grant access to an email identity, obtain a request-bound signed reply, request
threshold PRE, and decrypt locally using a fresh recipient key.

## Layout

- `src/`: Rust application orchestration and eventual HTTP endpoints.
- `web/`: browser interaction and user interface.
- `policies/`: ACP policy and grant setup for this example.
- [`../dev/`](../dev/README.md): shared local Orbis and ACP environment.

## Run the placeholder

From the workspace root:

```sh
cargo run --offline -p email-decrypt
```

## Implementation boundary

Use `orbis-email` for reusable proof handling. Carry original evidence to
participating nodes for independent verification before ACP authorization.
The reference app will supply routing, storage, and its user interface.

Local node startup, ACP configuration, and real authentication are not wired up yet.
