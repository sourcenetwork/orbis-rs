# Browser code

Plain HTML/JS (`index.html`/`app.js`), no framework — served directly by
`src/main.rs` via `include_str!`, no build step.

- **Register** (`navigator.credentials.create`): generates a passkey
  locally, extracts its public key via
  `AuthenticatorAttestationResponse.getPublicKey()`, and asks the backend
  (`POST /api/register`) to encode it as a `did:key` — pure encoding, no
  storage, no verification. The resulting DID and the credential id are
  kept in `localStorage` only, for this browser's own convenience; nothing
  server-side remembers them.
- **Sign** (`navigator.credentials.get`): fetches an exact, single-use
  challenge for the message/derivation from the backend
  (`POST /api/challenge` — the same `SignOperation::canonical_bytes`
  encoding the node will independently recompute), runs the WebAuthn
  ceremony, and submits the resulting assertion (`POST /api/sign`) to be
  forwarded to orbis-node as the request's `webauthn_assertion`.

WebAuthn requires a secure context — `https:`, or `http://localhost` (the
default here) during development.
