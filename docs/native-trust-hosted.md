# Opt-in hosted native Trust ring qualification

The existing Rust workflow accepts `scope: full` (the default), `common`, or
`native`, or `gateway`. Full retains the usual CI jobs; Common retains its existing focused
checks. Gateway runs only the two normal Orbis image builds, matching native Vera
image, one shared artifact build, and two focused curve jobs. It does not run the
legacy suites or build/use the unsafe diagnostic image.

The intended Trust fixture revision is
`11630c1a0b3241bed2799a6c162c4c8e16a4e502`. The immutable manual input is checked
against its checkout, native Dockerfile pin and Defra workflow pin. The native Vera and Defra revisions are declared in
`scripts/native_trust_hosted.py`; the Vera runtime pin is also in
`docker/NATIVE_VERA_REF`. These must match the native SDK and fixture dependency
revisions when selecting a compatible Trust build.

The artifact job builds Defra's normal native CLI once, stages it, and removes
only its own new target directory. A single BuildKit bake graph uses the real
Trust `Dockerfile.native` for its builder and unchanged final production stage.
Identical source, build arguments and shared vertices reuse the normal Go gateway
and Rust verifier build. The Go test executable is then compiled inside that
builder's existing toolchain/module/cache environment. It neither rebuilds the
normal gateway nor substitutes a different runtime Dockerfile. Registry caches
and Cargo source caches remain reusable.

Only named binaries, the verifier header/library and a source/build/binary hash
manifest are transferred between Ubuntu runners. The final Trust image stays
immutable by digest, retains UID/GID 65532 and its exact source/Vera labels. Each
curve job verifies transferred hashes, resolves normal Vera/Orbis image IDs and
labels, and hashes the actual runtime binaries. It checks that both packaging
modes use the identical gateway and verifier bytes.

Each curve compiles only the `native_startup` target once and directly runs
`native_trust_gateway_ring_dkg` twice: the normal executable, then the normal
container. Both use UID/GID 65532 and the same staged artifacts. Every run must
execute exactly one Rust test and one inner Go test, produce the exact paired-ring
success marker, and assert persisted production KDF headers in all three stopped
Orbis stores. Existing fixture readiness/receipt/DKG limits and Go 120/125-second
bounds remain unchanged. The outer process watchdog is 600 seconds; it cannot
extend the inner deadlines. Build-job limits are 120 minutes and native compilation
is bounded at 90 minutes.

Private roots are fresh per packaging mode. Complete build/test logs, descriptor,
operation IDs, passwords and stores are never uploaded. Console output is fixed
numeric status, stage, duration and execution counts. Bounded diagnostics add
Rust compiler error counts/E-codes, panic/Elapsed counts and numeric line locations
for the two known fixture files (IDs 1 and 2). They never include raw messages or
paths. BuildKit/Go errors retain stage-only summaries; their private raw logs are
not retained after the ephemeral runner is destroyed. The artifact upload contains
only the explicit build products and hashes. Cleanup removes only the exact Trust
fixture label and Compose containers mounted beneath these private roots, with
no daemon-wide prune. Source and staged binary hashes are checked again afterward.

This candidate is source-only. Hosted disk/RAM/time fit, cold-cache BuildKit
behavior and all four curve/packaging runs remain unqualified. Compilation must
use the eventual published Orbis commit that contains the companion hook and
workflow; its run-scoped images and labels must bind that same commit. A passing
older SDK fixture or this source review does not establish that qualification.

The reuse is the existing native fixture setup and Docker lifecycle, not a port
of the older Cosmos `bin/orbis-node/src/tests/integration.rs` bodies. No production
runtime or backend trait implementation is added. The exact ignored selector
spins up four normal native Vera containers and three normal Orbis containers
through `NativeWorkflow`, `NativeTestNetwork` and `ContainerNode`.

After review and publication, the existing Rust workflow's manual dispatch uses
`scope=gateway` and the immutable Trust revision above. For an already staged
Linux environment, the focused invocation is:

```sh
ORBIS_NATIVE_VERA_IMAGE="$VERA_IMAGE_ID" \
ORBIS_NATIVE_IMAGE="$ORBIS_IMAGE_ID" \
TRUST_NATIVE_GATEWAY_TEST_BINARY="$GO_FIXTURE_BINARY" \
TRUST_NATIVE_GATEWAY_BINARY="$NORMAL_GATEWAY_BINARY" \
DEFRADB_RUST_BINARY="$DEFRADB_BINARY" \
LD_LIBRARY_PATH="$VERIFIER_LIB_DIR" \
"$NATIVE_STARTUP_TEST_BINARY" native_trust_gateway_ring_dkg \
  --exact --ignored --nocapture --test-threads=1
```

The hosted driver performs the same selection for both curves and separately
checks the unchanged production container as UID/GID 65532. It stages and hashes
these artifacts first; no fresh or ad hoc Vera runtime replaces the selected image.


The `native` scope selects the existing native backend checks and Compose-backed
lifecycle suite for both curves, with the normal native Vera and Orbis images.
It also builds the established diagnostic image for the fault-report scenario.
The lifecycle suite includes restart, signing, encryption, PET member replacement
and scheduled refresh. The Trust gateway fixture has its separate `gateway`
scope and requires a matching immutable Trust revision.

After adopting a source-consistent dependency lockfile, dispatch native lifecycle
qualification with:

```sh
gh workflow run rust.yml --ref "$ORBIS_REVISION" -f scope=native
```

Release qualification requires the results from that exact source and both
curves; changing these pins does not establish a passing deployment.
