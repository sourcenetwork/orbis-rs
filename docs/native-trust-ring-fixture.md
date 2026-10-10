# Native Trust ring/DKG fixture

The ignored `native_trust_gateway_ring_dkg` selector runs the real Trust gateway
contract against four native Vera validators and three normal Orbis containers.
It reuses `NativeWorkflow` and its registered peers, policy and normal startup
limits. Its baseline Pending ring is not a substituted gateway result: the Go
contract creates two distinct PET rings through authenticated HTTP, starts their
DKG, checks creator denial and public DKG-trigger semantics, and checks duplicate
and original-outcome recovery after restarting the gateway.

The test adds operators only to its fresh genesis. Their signed administrative
request grants the fixture secp256k1 relay only `orbis:ring`. The actual OIDC actor
gets only `create_ring` on the fixture policy's `ring_policy` object. The allowed
Ed25519 Orbis authentication relay is a separate identity. This fixture checks
its configured presence versus relay-disabled mode; it does not perform relay PRE.

The companion Go source provides `TestNativeGatewayRingDKGContract`. Supply its
compiled test executable as `TRUST_NATIVE_GATEWAY_TEST_BINARY`, a normal
`TRUST_NATIVE_GATEWAY_BINARY` or immutable `TRUST_NATIVE_GATEWAY_IMAGE`, and
`DEFRADB_RUST_BINARY`. Stage those artifacts against the same native Vera SDK and
verifier revision as this repository. Supply the existing shared container inputs
`ORBIS_NATIVE_VERA_IMAGE` and `ORBIS_NATIVE_IMAGE`; this test never selects the
unsafe diagnostic image. Build production artifacts before compiling test targets.

With the matching artifacts staged, run the single selector per curve:

```sh
cargo +1.98.0 test --release --frozen -j2 -p orbis-node \
  --no-default-features --features native,redb,iroh,bls12-381 \
  --test native_startup native_trust_gateway_ring_dkg -- --exact --ignored --nocapture
```

Use `jubjub` in place of `bls12-381` for the other curve. No storage KDF or deadline
overrides are accepted. The Go contract has a five-minute context and a two-minute
limit for each ring activation. Its test watchdog is 360 seconds, allowing cleanup
after the contract context expires; Rust limits the Go process to 365 seconds.
A shorter outer watchdog could kill the test before its activation deadline reports
the failed stage. Node readiness, receipt and certified-read limits are unchanged. After Go succeeds, Rust checks both full ring configurations
and Active main/PET keys against certified records on every Vera replica. It
stops all three Orbis nodes and reopens their existing stores to assert persisted
KDF parameters `262144/3/1/0x13` through the local-storage API.

The owner-only descriptor is outside the fresh owner-only Go working directory.
It binds native endpoint, consensus key, deployment/root, policy and minimum
revision, registered peer keys/addresses, scoped relay grant sequence and the
first OIDC provider's reserved loopback address. Go returns two private results
for nonces `[71; 32]` and `[72; 32]`. Rust rejects unexpected fields, modes, counts,
ring IDs, configurations or paired keys. Both descriptor and result contract are
version 1; there is no fallback to Cosmos or injected authenticated principals.

Retain evidence with `ORBIS_NATIVE_E2E_DIR`, `VERA_E2E_DIR` and `VERA_E2E_KEEP=1`.
The descriptor, operation IDs, complete Go output, passwords, logs and stores stay
private. Go subprocess output is redirected to an owner-only file because shared
failure helpers may print logs. The Go process group is terminated on unwind;
container cleanup on abrupt external cancellation still depends on the outer
Docker runner. Publish only the fixed success marker and test counts.

This source is not yet compiled or executed. The existing native lifecycle CI
selection is unchanged and does not invoke this cross-repository fixture. Building
the matching Go executable/verifier, normal runtime images, running both curves
and both gateway packaging modes, and adding remote CI orchestration remain
qualification work. A source review alone does not establish DKG or restart success.
