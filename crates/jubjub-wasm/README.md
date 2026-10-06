# jubjub-wasm

Minimal Jubjub FROST Schnorr **verification**, compiled to `wasm32-unknown-unknown` so
Vera (the Go chain, a separate repo) can call the real signing-side verify logic
directly — no cgo, no Rust toolchain required on Vera's side, no second
implementation of the curve math to keep in sync by hand.

See `src/lib.rs`'s module doc comment for the full design rationale (why this
depends only on `jubjub`+`group`+`sha2` rather than on `crates/crypto` directly,
why there's a fixed-size static buffer instead of a bump allocator, why
`verify_core` mirrors `crates/crypto/src/jubjub/sign.rs`'s
`ThresholdJubjubSigner::verify` exactly).

## Building

Fast iteration — native target, runs the unit tests and the interop test against
orbis-rs's own `crates/crypto/src/jubjub/sign.rs` test vector:

```sh
cargo test -p jubjub-wasm
```

The actual artifact, for the `wasm32-unknown-unknown` target:

```sh
rustup target add wasm32-unknown-unknown   # one-time, if not already installed
cargo build --release --target wasm32-unknown-unknown -p jubjub-wasm
```

This produces `target/wasm32-unknown-unknown/release/jubjub_wasm.wasm`. Always run
`cargo test -p jubjub-wasm` first — it's much faster to catch a logic error there
than after cross-compiling.

## Shipping the binary into Vera

The compiled `.wasm` is vendored directly into Vera's repo (a separate checkout,
e.g. `/Users/jesse/Desktop/source/vera`), not published or fetched over the
network. After building, copy it to:

```sh
cp target/wasm32-unknown-unknown/release/jubjub_wasm.wasm \
  ../../../vera/x/orbis/jubjub/wasm/jubjub_wasm.wasm
```

(adjust the relative path for wherever your Vera checkout actually lives). Vera's
`x/orbis/jubjub` package embeds this file via `//go:embed` and calls into it
through `wazero` (a pure-Go WASM runtime) — see that package's own doc comments
for the Go side of this boundary.

**Whenever `src/lib.rs` changes in any way that affects the exported functions'
behavior or ABI** (the challenge transcript, the buffer layout, the set of
exported functions, the generator constant, etc.), you must:

1. Rebuild for `wasm32-unknown-unknown` (command above).
2. Copy the new binary into Vera as shown above.
3. Run Vera's test suite (`go test ./...` from the Vera repo root) to confirm
   nothing broke — this is the only thing that actually exercises the compiled
   artifact end-to-end against Vera's call sites.

There is currently no automated step that does this for you; it's a manual,
infrequent operation (this crate's own verify logic is expected to be stable —
it's a thin, deliberately minimal wrapper around zkcrypto's `jubjub` crate).

## Test vector

`tests/test_vectors/frost.json` is a copy of
`crates/crypto/src/jubjub/sign.rs`'s own `test_vectors/frost.json` (an
independently-computed FROST signature vector). Vera's
`x/orbis/jubjub/testdata/frost_vector.json` is the same file, copied again, so
Vera's Go tests can prove the WASM-compiled verify logic agrees with the real
Rust signing side end-to-end. If that vector ever changes or is regenerated,
update all three copies together.
